/**
 * The settings contract, and the single source of truth for their defaults.
 *
 * These used to live only in the VS Code extension manifest, read back one
 * `config.get("name", fallback)` call at a time. That arrangement had a real
 * failure mode, not a theoretical one: the fallback written at the call site
 * is DEAD CODE whenever the manifest declares a default, because the editor
 * always supplies the declared one. So a manifest default and a code default
 * could disagree indefinitely with the manifest silently winning — which is
 * exactly what happened to semanticMatchThreshold (declared 0.4, calibrated
 * and documented as 0.5, so the calibrated value never actually ran).
 *
 * Defining them once, here, in the package that consumes them removes that
 * class of bug and means a second host gets the same defaults for free
 * instead of transcribing them. The VS Code manifest is checked against this
 * file by packages/vscode-extension/scripts/checkSettings.js.
 */

import { DEFAULT_CROSS_TURN_TURNS, DEFAULT_SEMANTIC_THRESHOLD } from "./detectionPipeline";

export type EmbeddingBackend = "hashing" | "api";
export type EmbeddingAuthType = "none" | "bearer" | "apiKey" | "basic";
/** Request/response shape an embedding endpoint speaks. */
export type EmbeddingApiFormat = "vaultline" | "openai" | "custom";

export interface VaultlineSettings {
  // --- Policy ---
  blockOnHighSeverity: boolean;
  blockOnBusinessContent: boolean;

  // --- Detection layers ---
  enablePiiDetection: boolean;
  enableInfraDetection: boolean;
  enableConversationalSecretDetection: boolean;
  /** Carry a credential keyword's context into following turns — see core/conversationContext.ts. Has no effect when enableConversationalSecretDetection is off. */
  enableCrossTurnSecretCarryover: boolean;
  /** How many messages a credential keyword keeps cross-turn detection armed for. */
  crossTurnSecretTurns: number;
  enableHeuristicNameDetection: boolean;
  enableBusinessContentDetection: boolean;
  enableSemanticKeywordMatching: boolean;
  enableSyntaxAwareRedaction: boolean;

  // --- Thresholds ---
  routingMinSimilarity: number;
  businessContentThreshold: number;
  semanticMatchThreshold: number;
  alwaysRunAllDetectors: boolean;

  // --- Embedding backend ---
  embeddingBackend: EmbeddingBackend;
  autoStartEmbeddingServer: boolean;
  embeddingServerNodePath: string;
  embeddingApiUrl: string;
  embeddingApiTimeoutMs: number;
  embeddingApiModel: string;
  embeddingApiAuthType: EmbeddingAuthType;
  embeddingApiAuthToken: string;
  embeddingApiKeyHeader: string;
  /** Which request/response shape the endpoint speaks — see embeddings/apiEmbedder.ts. */
  embeddingApiFormat: EmbeddingApiFormat;
  /** Path appended to embeddingApiUrl for embedding calls. Empty picks the format's default. */
  embeddingApiEmbedPath: string;
  /** Path used to check the endpoint is up. EMPTY means don't probe at all — many hosted services have no health route. */
  embeddingApiHealthPath: string;
  /** format "custom": field name the input array is sent under. */
  embeddingApiRequestField: string;
  /** format "custom": where the vectors live in the response, e.g. "data[].embedding". */
  embeddingApiResponsePath: string;
  /**
   * Whether centroids rebuilt against a CUSTOM embedding endpoint may carry the
   * whole-message business-content BLOCK. Off by default — see
   * embeddingRouter.ts's wholeMessageCapable note for the measured reasoning.
   */
  trustCustomEmbeddingsForBlocking: boolean;

  // --- Per-rule opt-outs (see RULE_IDS) ---
  disabledSecretRules: string[];
  disabledPiiRules: string[];
  disabledInfraRules: string[];
  disabledConversationalSecretRules: string[];
  disabledSemanticRules: string[];

  // --- Audit ---
  auditLogIncludeValues: boolean;
  /**
   * Mirror this session's token -> real value table to a JSON file on disk.
   *
   * OFF by default and for the same reason as auditLogIncludeValues: the file
   * holds every secret Vaultline catches, in plain text. See entityStore.ts.
   */
  persistSessionMappings: boolean;

  // --- Host capabilities the core only needs to report on ---
  /** Not read by the core — hosts that can expose a tool registry to the model check this themselves. Declared here so all settings live in one type. */
  enableToolCalling: boolean;
  /** Ceiling on how many tools may be offered to the model in one request. See toolSelection.ts — exceeding the provider's limit fails the whole call. */
  maxTools: number;
  /** Tool-name patterns to never offer the model. `*` is a wildcard. */
  toolDenyList: string[];
  /** How many model round trips a single request may take when the model keeps calling tools. */
  maxToolRounds: number;
}

export const DEFAULT_SETTINGS: VaultlineSettings = {
  // Redact rather than block by default: blocking a whole message on a
  // high-severity hit is the safer setting but a much worse first-run
  // experience, and redaction already means the value never leaves.
  blockOnHighSeverity: false,
  // Blocking IS the default here, because there is no sensible "redact" for
  // a whole-message judgment — see businessContentDetector.ts.
  blockOnBusinessContent: true,

  enablePiiDetection: true,
  enableInfraDetection: true,
  enableConversationalSecretDetection: true,
  // On by default: a credential supplied one turn after the word that names it
  // is ordinary conversation, not an edge case, and it used to go through
  // unredacted. See core/conversationContext.ts.
  enableCrossTurnSecretCarryover: true,
  crossTurnSecretTurns: DEFAULT_CROSS_TURN_TURNS,
  enableHeuristicNameDetection: false, // experimental, high false-positive rate
  enableBusinessContentDetection: true,
  enableSemanticKeywordMatching: true,
  enableSyntaxAwareRedaction: true,

  routingMinSimilarity: 0.15,
  businessContentThreshold: 0.4,
  // Imported, not repeated: detectionPipeline.ts carries the measurement
  // that produced this number, so it stays the one place it's written down.
  semanticMatchThreshold: DEFAULT_SEMANTIC_THRESHOLD,
  alwaysRunAllDetectors: false,

  embeddingBackend: "api",
  autoStartEmbeddingServer: true,
  embeddingServerNodePath: "",
  embeddingApiUrl: "http://localhost:9000",
  embeddingApiTimeoutMs: 3000,
  embeddingApiModel: "",
  embeddingApiAuthType: "none",
  embeddingApiAuthToken: "",
  embeddingApiKeyHeader: "x-api-key",
  embeddingApiFormat: "vaultline",
  // Empty rather than "/embed-batch": the right default depends on the format,
  // and resolving it in one place (defaultEmbedPathFor) beats making the user
  // set two settings that must agree.
  embeddingApiEmbedPath: "",
  embeddingApiHealthPath: "/health",
  embeddingApiRequestField: "texts",
  embeddingApiResponsePath: "embeddings",
  // Conservative by default, for the same measured reason the hashing fallback
  // keeps routing but gives up the block: an uncalibrated embedder must not be
  // the thing that decides an entire message is confidential. A user who has
  // validated their own model can opt back in.
  trustCustomEmbeddingsForBlocking: false,

  disabledSecretRules: [],
  disabledPiiRules: [],
  disabledInfraRules: [],
  disabledConversationalSecretRules: [],
  disabledSemanticRules: [],

  auditLogIncludeValues: false,
  // Off, matching auditLogIncludeValues exactly. This used to be unconditional:
  // every password, API key and AWS secret Vaultline caught was written to
  // globalStorage/sessions/<uuid>.json in clear, with no setting, no warning and
  // no cleanup — while the audit log right beside it defaulted to hiding values
  // for precisely that reason. It also bought nothing, since the host mints a
  // fresh session id per activation and so never read the file back.
  persistSessionMappings: false,

  enableToolCalling: true,
  // 128 is the limit Copilot enforces today, and the value that made
  // @vaultline fail outright for a user whose extensions and MCP servers
  // together exceeded it. Treated as a default rather than a constant because
  // it is a provider detail — see parseToolLimitFromError in toolSelection.ts.
  maxTools: 128,
  toolDenyList: [],
  // Was a hardcoded 8, which a "review the whole codebase" request exhausted
  // routinely — and exhausting it produced NO answer at all, since the final
  // text was only ever captured on a round that made no tool calls. 25 is
  // roomy enough for real multi-step work while still bounding a runaway loop,
  // and it is now a setting because the right number depends on the task.
  maxToolRounds: 25,
};

/**
 * Every rule ID a user can switch off, grouped by the setting that switches
 * it off. Hosts use these to build their settings UI (VS Code renders them
 * as checkbox lists via the manifest's `enum`), and the manifest check script
 * asserts the two stay in sync — so adding a rule in a detector module and
 * forgetting to expose it is caught at build time rather than never.
 */
export const RULE_IDS = {
  secret: [
    "aws-access-key",
    "aws-secret-key",
    "private-key-block",
    "generic-api-key",
    "openai-api-key",
    "stripe-api-key",
    "jwt",
    "slack-token",
    "github-token",
    "generic-password-assignment",
    "env-var-secret",
    "db-connection-string",
    "sqlserver-connection-string",
  ],
  pii: [
    "username-assignment",
    "email",
    "pan-india",
    "ifsc-india",
    "ssn-us",
    "credit-card",
    "aadhaar-india",
    "aadhaar-india-contextual",
    "amount-inr",
    "amount-usd",
    "contextual-phone",
    "contextual-account-number",
    "contextual-customer-id",
    "contextual-passport-us",
    "contextual-drivers-license-us",
  ],
  infra: [
    "private-ip-standalone",
    "public-ip-standalone",
    "internal-url",
    "external-url",
    "unix-file-path",
    "windows-file-path",
    "mac-address",
    "ipv6-standalone",
    "ipv6-link-local",
    "internal-hostname-contextual",
    "port-contextual",
  ],
  conversationalSecret: [
    "proximity-password",
    "proximity-passwd",
    "proximity-pwd",
    "proximity-pass",
    "proximity-passphrase",
    "proximity-secret",
    "proximity-cred",
    "proximity-username",
    "proximity-user-name",
    "proximity-userid",
    "proximity-user-id",
    "proximity-login",
    "proximity-account-name",
    "proximity-creds",
    "proximity-credential",
    "proximity-credentials",
    "proximity-api-key",
    "proximity-apikey",
    "proximity-access-token",
    "proximity-auth-token",
    "proximity-bearer-token",
    "proximity-client-secret",
    "proximity-private-key",
    "proximity-connection-string",
    "proximity-token",
  ],
  semantic: ["semantic-credential", "semantic-api-key", "semantic-pii-identifier", "semantic-infrastructure"],
} as const;

/** Flattens the five per-category opt-out lists into the one array the pipeline filters on. */
export function disabledRuleIds(settings: VaultlineSettings): string[] {
  return [
    ...settings.disabledSecretRules,
    ...settings.disabledPiiRules,
    ...settings.disabledInfraRules,
    ...settings.disabledConversationalSecretRules,
    ...settings.disabledSemanticRules,
  ];
}

/**
 * Settings that cannot be applied in place.
 *
 * Changing the backend changes which OBJECTS EXIST — SemanticKeywordMatcher
 * is only constructed for the api backend — so there is nothing sensible to
 * mutate; the host asks the user to reload instead. Everything else is either
 * read fresh per message or handled by VaultlineEngine.settingsChanged().
 */
export const RELOAD_REQUIRED_SETTINGS = ["embeddingBackend"] as const;

/** Settings that change WHERE the embedding server is or how it starts — re-running the startup decision is enough. */
export const SERVER_AFFECTING_SETTINGS = [
  "embeddingApiUrl",
  "autoStartEmbeddingServer",
  "embeddingServerNodePath",
] as const;

/**
 * Coerce an untrusted settings bag into VaultlineSettings, falling back
 * per-key whenever a value isn't the shape its default says it should be.
 *
 * WHY THIS EXISTS, measured rather than theorised. A VS Code host reads
 * settings with `config.get(key)`, which returns whatever is in settings.json
 * WITHOUT validating it against the manifest schema. A hand-edited file, a
 * synced one, or a workspace `.vscode/settings.json` committed to a repo can
 * therefore put any value under any key. Feeding that straight through
 * produced silent, dangerous failure:
 *
 *   routingMinSimilarity = NaN   ->  0 matches: `score >= NaN` is always
 *                                    false, so every contextual detector is
 *                                    skipped and secrets pass through, with
 *                                    no error and nothing in the log
 *   crossTurnSecretTurns = NaN   ->  the credential expectation never decays
 *   maxTools             = NaN   ->  `slice(0, NaN)` offers zero tools
 *
 * The first is the reason this is in the core rather than in one host: a
 * detection tool that quietly stops detecting is the worst failure it has, and
 * a second host would have reproduced it exactly.
 *
 * NaN deserves its own mention. It passes `typeof x === "number"`, so a naive
 * type check lets through the single value that caused the damage — hence the
 * explicit `Number.isFinite`.
 *
 * Falling back to the default is deliberate: it fails toward WORKING detection.
 * `rejected` is returned rather than logged here so the host can surface it
 * once per settings change instead of once per message.
 */
export function sanitizeSettings(raw: Record<string, unknown>): {
  settings: VaultlineSettings;
  rejected: string[];
} {
  const settings = { ...DEFAULT_SETTINGS };
  const rejected: string[] = [];

  for (const key of Object.keys(DEFAULT_SETTINGS) as (keyof VaultlineSettings)[]) {
    const value = raw[key];
    // Absent is not invalid — it just means "not configured", which is the
    // overwhelmingly common case and must stay silent.
    if (value === undefined) continue;

    const expected = DEFAULT_SETTINGS[key];
    const ok = Array.isArray(expected)
      ? Array.isArray(value) && value.every((v) => typeof v === "string")
      : typeof expected === "number"
        ? typeof value === "number" && Number.isFinite(value)
        : typeof value === typeof expected;

    if (ok) (settings as Record<string, unknown>)[key] = value;
    else rejected.push(key);
  }

  return { settings, rejected };
}
