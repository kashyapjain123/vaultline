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

  // --- Per-rule opt-outs (see RULE_IDS) ---
  disabledSecretRules: string[];
  disabledPiiRules: string[];
  disabledInfraRules: string[];
  disabledConversationalSecretRules: string[];
  disabledSemanticRules: string[];

  // --- Audit ---
  auditLogIncludeValues: boolean;

  // --- Host capabilities the core only needs to report on ---
  /** Not read by the core — hosts that can expose a tool registry to the model check this themselves. Declared here so all settings live in one type. */
  enableToolCalling: boolean;
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

  disabledSecretRules: [],
  disabledPiiRules: [],
  disabledInfraRules: [],
  disabledConversationalSecretRules: [],
  disabledSemanticRules: [],

  auditLogIncludeValues: false,

  enableToolCalling: true,
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
