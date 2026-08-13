/**
 * Everything a host has to wire up, wired up once.
 *
 * This is the whole body of what used to be the VS Code extension's
 * `activate()`: build both embedders, load the matching centroids, decide
 * whether MiniLM is actually available and fall back if it isn't, construct
 * the semantic matcher only when it's meaningful, construct the syntax
 * analyzer, open the audit log, and translate settings into ScanOptions on
 * every message. None of that is editor-specific, and all of it is easy to
 * get subtly wrong — particularly the invariant that centroids and embedder
 * must move together — so it belongs here rather than in each host.
 *
 * A host's activation now reads roughly:
 *
 *     const engine = VaultlineEngine.create(new MyEditorHost(...));
 *     const session = engine.createSession(sessionMappingPath);
 *     // ... adapt the editor's chat API to session.guardPrompt() etc.
 *     // ... on shutdown: engine.dispose()
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { AuditLog, mappingsToDetail, matchesToDetail } from "./auditLog";
import { categoryExamplesPath, centroidsPath, semanticSeedsPath } from "./assets";
import { buildCentroids } from "./centroidBuilder";
import { ScanOptions, scanCurrentMessage } from "./detectionPipeline";
import { ApiEmbedder } from "./embeddings/apiEmbedder";
import { Embedder } from "./embeddings/embedder";
import { HashingEmbedder } from "./embeddings/hashingEmbedder";
import { EmbeddingServerManager } from "./embeddings/serverManager";
import { EmbeddingRouter } from "./embeddingRouter";
import { GuardContext, GuardSession } from "./guardSession";
import { LogChannel, VaultlineHost } from "./host";
import { Match } from "./patternMatcher";
import { PolicyConfig, PolicyDecision, decide } from "./policyEngine";
import { SemanticKeywordMatcher } from "./semanticKeywordMatcher";
import { SyntaxAnalyzer } from "./syntax/syntaxAnalyzer";
import { EmbeddingBackend, RELOAD_REQUIRED_SETTINGS, SERVER_AFFECTING_SETTINGS, VaultlineSettings, disabledRuleIds } from "./settings";
import { TokenMapping, tokenize } from "./tokenizer";

/**
 * What a settings change means for the running engine.
 *  - "applied": nothing to do, the change is picked up on the next message.
 *  - "server-restarted": the engine re-ran the embedding-server decision itself.
 *  - "reload-required": the host should ask the user to reload; see RELOAD_REQUIRED_SETTINGS.
 */
export type SettingsChangeOutcome = "applied" | "server-restarted" | "reload-required";

/** Result of running the pipeline over a piece of text without sending it anywhere — backs a host's "test detection on this selection" command. */
export interface InspectionReport {
  decision: PolicyDecision;
  matches: Match[];
  businessMatches: Match[];
  /** What would have been sent, had it not been blocked. */
  redactedText: string;
  mappings: TokenMapping[];
}

export class VaultlineEngine implements GuardContext {
  readonly auditLog: AuditLog;

  // ApiEmbedder, not the Embedder interface: this one has to be repointable at
  // run time (see repointApiEmbedder), since the local server doesn't always
  // land on the configured port. The hashing embedder below stays an Embedder —
  // it has no address to follow.
  private readonly apiEmbedder: ApiEmbedder;
  private readonly hashingEmbedder: Embedder;
  private readonly router: EmbeddingRouter | null;
  private readonly semanticMatcher: SemanticKeywordMatcher | null;
  private readonly syntaxAnalyzer: SyntaxAnalyzer | null;
  private readonly serverManager: EmbeddingServerManager;
  private readonly log: LogChannel;

  /** The backend routing is CURRENTLY scoring against, which is not necessarily the configured one — see applyBackend(). */
  private activeBackend: EmbeddingBackend;
  private readonly configuredBackend: EmbeddingBackend;

  private constructor(private readonly host: VaultlineHost) {
    const settings = host.settings();
    this.log = host.createLogChannel("Vaultline");
    this.auditLog = new AuditLog(host.storagePath());

    this.configuredBackend = settings.embeddingBackend;
    this.activeBackend = this.configuredBackend;

    // Both embedders are constructed up front, because which one is ACTIVE
    // can change after activation: the api backend is only real if the MiniLM
    // server actually comes up, and that isn't known until it has been
    // installed and the model loaded (minutes, on a first run). Keeping both
    // alive makes switching a pointer swap rather than a rebuild.
    this.apiEmbedder = buildApiEmbedder(settings);
    this.hashingEmbedder = new HashingEmbedder();

    // Precomputed category centroids (see scripts/buildEmbeddings.js) — loaded
    // once. If this is missing or invalid, router is null and
    // detectionPipeline.ts fails OPEN: every contextual detector just runs
    // unconditionally instead of being routing-gated. Losing routing should
    // never mean losing detection.
    //
    // The centroids MUST come from the same embedder that will be scoring
    // against them — mixing vector spaces produces meaningless cosine
    // similarities. That invariant is enforced structurally rather than by
    // convention: the centroids file is chosen BY backend here, and
    // EmbeddingRouter.useBackend() only ever swaps the two together.
    // centroidsPathFor, not centroidsPath: a previous session may already have
    // rebuilt centroids for this endpoint, in which case we start on them
    // rather than briefly scoring against the bundled MiniLM ones.
    const startingCentroids = this.centroidsPathFor(this.configuredBackend);
    this.router = EmbeddingRouter.load(
      startingCentroids,
      this.configuredBackend === "api" ? this.apiEmbedder : this.hashingEmbedder,
      this.wholeMessageCapableFor(this.configuredBackend)
    );
    if (!this.router) {
      this.log.append(
        `Category embeddings not found or invalid at ${startingCentroids} — routing disabled, all contextual ` +
          "detectors will run unconditionally. Run `npm run build:embeddings:all` to generate them."
      );
    }

    // Semantic keyword matcher (last line of defense) — deliberately ONLY
    // constructed when the API backend is configured. It's meaningless with
    // the hashing embedder (see semanticKeywordMatcher.ts's module comment
    // for the empirical reason why), so this is enforced here instead of
    // being left to be misconfigured downstream. It's also switched off by
    // applyBackend() below if the server turns out not to be available.
    this.semanticMatcher =
      this.configuredBackend === "api" ? new SemanticKeywordMatcher(semanticSeedsPath(), this.apiEmbedder) : null;

    // Syntax-aware suppression (tree-sitter). Constructed once and shared —
    // it caches the WASM runtime and each compiled grammar for the session.
    // If the grammars aren't installed, every lookup simply misses and the
    // pipeline runs exactly as it did before.
    this.syntaxAnalyzer = settings.enableSyntaxAwareRedaction ? new SyntaxAnalyzer() : null;

    // Bring up the local MiniLM server that ApiEmbedder talks to (installing
    // its native dependencies on first run). Deliberately NOT awaited by
    // start(): activation must stay fast, and the first run can take minutes
    // while it npm-installs and downloads ~90MB of model weights. Everything
    // here is safe to run without it.
    this.serverManager = new EmbeddingServerManager(host);
  }

  static create(host: VaultlineHost): VaultlineEngine {
    const engine = new VaultlineEngine(host);
    engine.syncBackendWithServer();
    return engine;
  }

  /** One guard session — one EntityStore, one conversation. See GuardSession for why that lifetime matters. */
  createSession(persistPath?: string): GuardSession {
    return new GuardSession(this, persistPath);
  }

  // -------------------------------------------------------------------
  // GuardContext — re-read per message, never cached
  // -------------------------------------------------------------------

  scanOptions(): ScanOptions {
    const settings = this.host.settings();
    return {
      enablePii: settings.enablePiiDetection,
      enableInfra: settings.enableInfraDetection,
      enableConversationalSecrets: settings.enableConversationalSecretDetection,
      // NOTE: no conversationContext here on purpose — that is per-SESSION
      // state, attached by GuardSession.liveScanOptions(). These two are the
      // config half of the same feature.
      enableCrossTurnSecrets: settings.enableCrossTurnSecretCarryover,
      crossTurnSecretTurns: settings.crossTurnSecretTurns,
      enableBusinessContentDetection: settings.enableBusinessContentDetection,
      pii: { enablePersonNameHeuristic: settings.enableHeuristicNameDetection },
      router: this.router,
      routingMinSimilarity: settings.routingMinSimilarity,
      businessContentThreshold: settings.businessContentThreshold,
      alwaysRunAllDetectors: settings.alwaysRunAllDetectors,
      semanticMatcher: this.semanticMatcher,
      enableSemanticKeywordMatching: settings.enableSemanticKeywordMatching,
      semanticMatchThreshold: settings.semanticMatchThreshold,
      disabledRuleIds: disabledRuleIds(settings),
      syntaxAnalyzer: this.syntaxAnalyzer,
    };
  }

  policyConfig(): PolicyConfig {
    const settings = this.host.settings();
    return {
      blockOnHighSeverity: settings.blockOnHighSeverity,
      blockOnBusinessContent: settings.blockOnBusinessContent,
    };
  }

  auditIncludesValues(): boolean {
    return this.host.settings().auditLogIncludeValues;
  }

  // -------------------------------------------------------------------
  // Ad-hoc inspection
  // -------------------------------------------------------------------

  /**
   * Run the full pipeline over `text` and report what would happen, without
   * sending anything anywhere. Backs a host's "test detection on selection"
   * command, and is the easiest way to demo or tune rules.
   *
   * Uses a THROWAWAY entity store rather than a session's: this is an
   * inspection, and it must not mint tokens that a real conversation would
   * then be expected to resolve.
   */
  async inspect(text: string, codeLanguage?: string | null): Promise<InspectionReport> {
    const { matches, businessMatches } = await scanCurrentMessage(text, {
      ...this.scanOptions(),
      codeLanguage: codeLanguage ?? null,
    });
    const decision = decide(matches, businessMatches, this.policyConfig());
    // `matches` only — see GuardSession's module comment on businessMatches.
    const { redactedText, mappings } = tokenize(text, matches);

    const includeValues = this.auditIncludesValues();
    this.auditLog.record({
      source: "testPipelineCommand",
      action: decision.action,
      reason: decision.reason,
      details:
        decision.action === "block"
          ? matchesToDetail([...matches, ...businessMatches], includeValues)
          : mappingsToDetail(mappings, includeValues),
    });

    return { decision, matches, businessMatches, redactedText, mappings };
  }

  // -------------------------------------------------------------------
  // Embedding backend lifecycle
  // -------------------------------------------------------------------

  /** Which backend routing is scoring against right now — "hashing" here with an "api" configuration means the fallback is in effect. */
  currentBackend(): EmbeddingBackend {
    return this.activeBackend;
  }

  showEmbeddingServerLog(): void {
    this.serverManager.showLog();
  }

  /**
   * Recover from a server that died, was killed by another window closing
   * (see serverManager.ts's dispose() note), or was started before a settings
   * change that should apply to it. A successful restart on a session that
   * had fallen back to hashing promotes routing back to MiniLM in place, with
   * no reload.
   */
  async restartEmbeddingServer(): Promise<boolean> {
    const ready = await this.serverManager.restart();
    this.repointApiEmbedder();
    this.applyBackend(ready ? "api" : "hashing");
    return ready;
  }

  // -------------------------------------------------------------------
  // Custom embedding endpoints
  // -------------------------------------------------------------------

  /**
   * Is the configured embedder producing vectors in a space the SHIPPED
   * centroids don't describe?
   *
   * True for a non-loopback URL, or for any explicitly named model — both mean
   * "something other than the bundled MiniLM server". The default setup answers
   * false, which is what keeps this whole feature off the common path: no
   * fingerprinting, no rebuild, no extra network call on an ordinary activation.
   *
   * A remote endpoint that happens to serve MiniLM too gets rebuilt
   * unnecessarily. That costs one batch call, once, and is the right way to be
   * wrong — the alternative is trusting a guess about somebody else's service.
   */
  private usesCustomEmbeddingSpace(): boolean {
    const s = this.host.settings();
    if (s.embeddingBackend !== "api") return false;
    if (s.embeddingApiModel.trim().length > 0) return true;
    try {
      const host = new URL(s.embeddingApiUrl).hostname;
      return !(host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "0.0.0.0");
    } catch {
      return false;
    }
  }

  /**
   * Where a rebuilt centroid set for the CURRENT endpoint lives.
   *
   * The fingerprint is part of the FILENAME rather than a separate stamp file,
   * so existence is the entire validity check — and flipping between two
   * endpoints reuses each one's cached build instead of rebuilding every swap.
   *
   * What this deliberately cannot detect: the same URL quietly starting to
   * serve a different model. Nothing observable changes, so the cache stays
   * valid. That's what the "Rebuild Category Embeddings" command is for.
   */
  private customCentroidsPath(): string {
    const s = this.host.settings();
    const fp = crypto
      .createHash("sha256")
      .update(`${s.embeddingApiUrl} ${s.embeddingApiModel}`)
      .digest("hex")
      .slice(0, 16);
    return path.join(this.host.storagePath(), "centroids", `categoryEmbeddings.${fp}.json`);
  }

  /** Which centroids the router should load for `backend`, preferring a rebuilt set when one applies. */
  private centroidsPathFor(backend: EmbeddingBackend): string {
    if (backend === "api" && this.usesCustomEmbeddingSpace()) {
      const custom = this.customCentroidsPath();
      if (fs.existsSync(custom)) return custom;
    }
    return centroidsPath(backend);
  }

  /**
   * Rebuilt centroids gate detection but do NOT block whole messages, unless the
   * user has explicitly said they trust their model. Same reasoning as the
   * hashing fallback (see EmbeddingRouter's wholeMessageCapable note): a
   * blocking decision made on similarity alone needs an embedder someone has
   * actually measured, and an arbitrary endpoint is unmeasured by definition.
   */
  private wholeMessageCapableFor(backend: EmbeddingBackend): boolean {
    if (backend !== "api") return false;
    if (!this.usesCustomEmbeddingSpace()) return true;
    return this.host.settings().trustCustomEmbeddingsForBlocking;
  }

  /**
   * Build centroids for a custom endpoint if we don't have them cached.
   * Never throws — a failure just leaves the bundled centroids in place, and
   * scoreAll()'s dimension guard still catches the gross mismatch case.
   */
  private async ensureCustomCentroids(force = false): Promise<void> {
    if (!this.usesCustomEmbeddingSpace()) return;

    const target = this.customCentroidsPath();
    if (force) await fs.promises.rm(target, { force: true }).catch(() => {});
    else if (fs.existsSync(target)) return;

    try {
      const result = await this.host.withProgress(
        { location: "notification", title: "Vaultline: rebuilding category embeddings for your endpoint" },
        () => buildCentroids(categoryExamplesPath(), this.apiEmbedder, target)
      );
      this.log.append(
        `Rebuilt ${result.categories} category centroids (${result.dim}-dim) against ` +
          `${this.host.settings().embeddingApiUrl} -> ${target}`
      );
    } catch (err) {
      this.log.append(
        `Could not rebuild category embeddings against ${this.host.settings().embeddingApiUrl}: ${err}. ` +
          "Keeping the bundled centroids — if your endpoint serves a different model, routing scores will be " +
          "unreliable until this succeeds."
      );
    }
  }

  /**
   * Force a rebuild against the current endpoint. Backs the "Rebuild Category
   * Embeddings" command, which exists for the case the fingerprint can't see:
   * the same URL now serving a different model.
   */
  async rebuildCategoryEmbeddings(): Promise<boolean> {
    if (!this.usesCustomEmbeddingSpace()) {
      void this.host.info(
        "Vaultline is using the bundled embedding model, whose category embeddings ship with the extension — " +
          "there is nothing to rebuild. This applies when vaultline.embeddingApiUrl points at your own endpoint."
      );
      return false;
    }
    await this.ensureCustomCentroids(true);
    const built = fs.existsSync(this.customCentroidsPath());
    if (built) this.applyBackend(this.activeBackend, true);
    return built;
  }

  /**
   * Follow the server to wherever it actually landed.
   *
   * The configured port is a request, not a guarantee — if something else holds
   * it, the manager starts on the next free one. Without this the embedder
   * would keep calling the configured port, i.e. whatever foreign process
   * displaced us, and every embed call would fail (or worse, reach something
   * unrelated). Null means there's nothing local to follow — a remote endpoint,
   * which must keep using exactly the URL the user configured.
   */
  private repointApiEmbedder(): void {
    const url = this.serverManager.effectiveBaseUrl();
    if (url) this.apiEmbedder.setBaseUrl(url);
  }

  /**
   * Tell the engine some settings changed. `affects` is asked about
   * individual setting names so a host can pass its own change-event
   * predicate straight through (VS Code: `event.affectsConfiguration`).
   */
  settingsChanged(affects: (setting: keyof VaultlineSettings) => boolean): SettingsChangeOutcome {
    // Switching backends outright changes which objects exist at all
    // (SemanticKeywordMatcher is constructed only for api), so this is one of
    // the settings that genuinely needs a reload rather than a half-applied
    // in-place update.
    if (RELOAD_REQUIRED_SETTINGS.some(affects)) return "reload-required";

    // These only change WHERE the server is or how it starts, which re-running
    // the same decision handles on its own.
    if (SERVER_AFFECTING_SETTINGS.some(affects)) {
      this.syncBackendWithServer();
      return "server-restarted";
    }

    // Everything else is read fresh in scanOptions()/policyConfig().
    return "applied";
  }

  /** Ask the server manager what's actually available, and match routing to the answer. */
  private syncBackendWithServer(): void {
    if (this.configuredBackend !== "api") return; // nothing to wait on; hashing is already live
    void this.serverManager.ensureRunning().then(async (ready) => {
      // Repoint BEFORE promoting the backend, so the first embed call after the
      // swap already targets the port the server actually bound.
      this.repointApiEmbedder();
      // Then make sure the centroids describe THIS endpoint's vector space,
      // also before the swap — applyBackend picks the file, so building after
      // it would leave the router on the bundled centroids until something else
      // happened to trigger another swap. No-ops entirely for the default
      // bundled server.
      if (ready) await this.ensureCustomCentroids();
      this.applyBackend(ready ? "api" : "hashing");
    });
  }

  /**
   * Repoint routing at one backend or the other, mid-session.
   *
   * This is the "middle option" fallback: rather than losing routing entirely
   * when MiniLM is unavailable, drop to the hashing embedder and its matching
   * 256-dim centroids, so the per-category gate in front of the contextual
   * detectors keeps working.
   *
   * Two layers do NOT survive the downgrade and are switched off rather than
   * left to produce noise, because both would BLOCK or REDACT on a lexical
   * similarity score that measurement shows can't carry it:
   *   - semantic keyword matching (scores single words — noise at that
   *     granularity means false redactions);
   *   - whole-message business-content detection (see the
   *     wholeMessageCapable note in embeddingRouter.ts — benign developer
   *     questions and real business content overlap under hashing, so no
   *     threshold separates them).
   */
  private applyBackend(target: EmbeddingBackend, force = false): void {
    // `force` exists for the rebuild command: the backend hasn't changed, but
    // the FILE behind it has, so the early return would otherwise skip the
    // reload and leave the router scoring against the centroids it built from
    // the previous model.
    if (!this.router || (this.activeBackend === target && !force)) return;

    const swapped = this.router.useBackend(
      this.centroidsPathFor(target),
      target === "api" ? this.apiEmbedder : this.hashingEmbedder,
      this.wholeMessageCapableFor(target)
    );
    if (!swapped) {
      this.log.append(
        `Could not load the ${target} centroids — staying on the ${this.activeBackend} backend. ` +
          "Run `npm run build:embeddings:all` if you're running from source."
      );
      return;
    }

    this.activeBackend = target;
    this.semanticMatcher?.setEnabled(target === "api");
    this.log.append(`Routing now using the ${target} embedding backend.`);
  }

  dispose(): void {
    this.serverManager.dispose();
    this.log.dispose();
  }
}

function buildApiEmbedder(settings: VaultlineSettings): ApiEmbedder {
  return new ApiEmbedder({
    baseUrl: settings.embeddingApiUrl,
    timeoutMs: settings.embeddingApiTimeoutMs,
    model: settings.embeddingApiModel.length > 0 ? settings.embeddingApiModel : undefined,
    authType: settings.embeddingApiAuthType,
    authToken: settings.embeddingApiAuthToken || undefined,
    apiKeyHeader: settings.embeddingApiKeyHeader,
  });
}
