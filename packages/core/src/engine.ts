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

import { AuditLog, mappingsToDetail, matchesToDetail } from "./auditLog";
import { centroidsPath, semanticSeedsPath } from "./assets";
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

  private readonly apiEmbedder: Embedder;
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
    const startingCentroids = centroidsPath(this.configuredBackend);
    this.router = EmbeddingRouter.load(
      startingCentroids,
      this.configuredBackend === "api" ? this.apiEmbedder : this.hashingEmbedder,
      this.configuredBackend === "api"
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
    this.applyBackend(ready ? "api" : "hashing");
    return ready;
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
    void this.serverManager.ensureRunning().then((ready) => this.applyBackend(ready ? "api" : "hashing"));
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
  private applyBackend(target: EmbeddingBackend): void {
    if (!this.router || this.activeBackend === target) return;

    const swapped = this.router.useBackend(
      centroidsPath(target),
      target === "api" ? this.apiEmbedder : this.hashingEmbedder,
      target === "api"
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

function buildApiEmbedder(settings: VaultlineSettings): Embedder {
  return new ApiEmbedder({
    baseUrl: settings.embeddingApiUrl,
    timeoutMs: settings.embeddingApiTimeoutMs,
    model: settings.embeddingApiModel.length > 0 ? settings.embeddingApiModel : undefined,
    authType: settings.embeddingApiAuthType,
    authToken: settings.embeddingApiAuthToken || undefined,
    apiKeyHeader: settings.embeddingApiKeyHeader,
  });
}
