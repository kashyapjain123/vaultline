/**
 * @vaultline/core — the public surface.
 *
 * A host integration needs three things from here and can ignore the rest:
 *
 *   1. VaultlineHost   — implement it for your editor (settings, storage,
 *                        logging, notifications, progress, clipboard).
 *   2. VaultlineEngine — construct once at activation; it owns the embedders,
 *                        routing, backend fallback, and audit log.
 *   3. GuardSession    — one per conversation; call its methods around your
 *                        editor's chat/model calls.
 *
 * Everything below that line is exported because it's genuinely useful to a
 * host that wants to go deeper (run one detector, inspect a Match, build a
 * settings UI from RULE_IDS), not because a host is expected to need it.
 */

// --- The three things a host actually needs ---
export {
  ConsoleHost,
  NEVER_CANCELLED,
  type LogChannel,
  type ProgressOptions,
  type ProgressToken,
  type VaultlineHost,
} from "./host";
export { VaultlineEngine, type InspectionReport, type SettingsChangeOutcome } from "./engine";
export {
  GuardSession,
  type ConversationTurn,
  type GuardContext,
  type HistoryGuardResult,
  type PromptGuardResult,
  type RestoreGuardResult,
  type ToolResultGuardResult,
} from "./guardSession";

// --- Settings contract (defaults, rule IDs, reload semantics) ---
export {
  DEFAULT_SETTINGS,
  RELOAD_REQUIRED_SETTINGS,
  RULE_IDS,
  SERVER_AFFECTING_SETTINGS,
  disabledRuleIds,
  sanitizeSettings,
  type EmbeddingApiFormat,
  type EmbeddingAuthType,
  type EmbeddingBackend,
  type VaultlineSettings,
} from "./settings";

// --- Where the package keeps its own data, for hosts that must ship it ---
export { categoryExamplesPath, centroidsPath, dataDir, embeddingServerDir, grammarDir, semanticSeedsPath } from "./assets";
export { buildCentroids, type CentroidBuildResult } from "./centroidBuilder";
export {
  parseToolLimitFromError,
  selectTools,
  type ToolDescriptor,
  type ToolSelectionOptions,
  type ToolSelectionResult,
} from "./toolSelection";

// --- Detection pipeline ---
export {
  DEFAULT_SEMANTIC_THRESHOLD,
  scanAll,
  scanCurrentMessage,
  splitNonBlankLines,
  type ScanOptions,
  type ScanResult,
} from "./detectionPipeline";
export { DEFAULT_RULES, SEVERITY_RANK, scan, type Category, type Match, type PatternRule, type Severity } from "./patternMatcher";
export { scanPii, scanPiiContextual, scanPiiStructural, scanPersonNamesHeuristic, type PiiScanOptions } from "./piiDetector";
export { scanInfra, scanInfraContextual, scanInfraStructural } from "./infraDetector";
export {
  scanCarriedOver,
  scanProximity,
  scanProximityWithContext,
  type KeywordSighting,
  type ProximityScanResult,
} from "./nlpProximityMatcher";
export { ConversationContext, type CredentialExpectation } from "./conversationContext";
export { scanBusinessContent } from "./businessContentDetector";
export { SemanticKeywordMatcher } from "./semanticKeywordMatcher";

// --- Decision + redaction ---
export { decide, type Action, type PolicyConfig, type PolicyDecision } from "./policyEngine";
export {
  TOKEN_PRESERVATION_INSTRUCTION,
  findUnrestoredTokens,
  redactKnownValues,
  restore,
  tokenize,
  type TokenMapping,
  type TokenizeResult,
} from "./tokenizer";
export { EntityStore, type EntityMapping } from "./entityStore";
export { entityTypeFor } from "./entityTypes";
export { AuditLog, mappingsToDetail, matchesToDetail, type AuditEntry, type AuditMatchDetail } from "./auditLog";

// --- Embeddings + routing ---
export { EmbeddingRouter, type RouteResult } from "./embeddingRouter";
export { embedBatchFallback, type Embedder } from "./embeddings/embedder";
export { EMBEDDING_DIM, HashingEmbedder, averageVectors, cosineSimilarity, embed } from "./embeddings/hashingEmbedder";
export {
  ApiEmbedder,
  defaultEmbedPathFor,
  resolveVectorsPath,
  type ApiAuthType,
  type ApiEmbedFormat,
  type ApiEmbedderOptions,
} from "./embeddings/apiEmbedder";
export { EmbeddingServerManager } from "./embeddings/serverManager";

// --- Syntax awareness ---
export { SyntaxAnalyzer, grammarForFile, isWithinSpans, type Span } from "./syntax/syntaxAnalyzer";

// --- Tool gateway (for hosts whose tools DON'T come through a shared registry) ---
export { ToolGateway, type ToolExecutionResult } from "./toolGateway/toolGateway";
export { type ToolAdapter, type ToolType } from "./toolGateway/toolAdapter";
export { McpAdapter, type McpCaller } from "./toolGateway/mcpAdapter";
export { ShellAdapter, type ShellExecResult } from "./toolGateway/shellAdapter";
export { redactJson, rehydrateJson, type JsonRedactResult } from "./toolGateway/jsonRedactor";
