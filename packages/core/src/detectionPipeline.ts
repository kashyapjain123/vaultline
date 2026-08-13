/**
 * Combines detection layers into a result the caller can act on. Two kinds
 * of output, kept deliberately separate:
 *
 *  - `matches`: entity-level spans (structural regex always-on, plus
 *    routing-gated contextual PII/infra/conversational-secret detectors).
 *    This is what tokenizer.ts redacts — every span here is small and
 *    specific.
 *  - `businessMatches`: at most one whole-message flag from
 *    businessContentDetector.ts. This NEVER goes to the tokenizer — its
 *    span is the entire message by definition, and tokenizing "the whole
 *    message" would just replace the prompt with a single opaque token,
 *    which defeats the point. It exists to inform the policy decision
 *    (see policyEngine.ts), not to be redacted-and-forwarded.
 *
 * Routing (embeddingRouter.ts) decides which CONTEXTUAL detectors bother
 * running — structural regex always runs regardless, so losing routing
 * (missing/corrupt centroids file, or explicitly disabled) fails OPEN:
 * every contextual detector just runs unconditionally instead of being
 * skipped. Losing routing should never mean losing detection, only losing
 * a bit of unnecessary work — these detectors are all cheap enough that
 * "run them all anyway" is a perfectly fine fallback.
 *
 * TWO ENTRY POINTS, deliberately different granularity:
 *
 *  - scanAll(text): routes on a SINGLE embedding of the whole `text`. Used
 *    for anything that isn't the live user message — history replay, tool
 *    output, editor/file-path context — where the text is either already
 *    short (a path) or was already fully scanned once when it WAS the
 *    live message.
 *
 *  - scanCurrentMessage(text): routes PER LINE instead of on the whole
 *    message. A sentence-transformer embedding is a pooled average over
 *    every token in its input — a long message with one sensitive line
 *    buried in several paragraphs of unrelated context dilutes that line's
 *    signal into the surrounding noise, and the whole-message similarity
 *    score can drop below routingMinSimilarity even though the sensitive
 *    line, embedded alone, would clear it easily. Scoring each line on its
 *    own keeps that line's signal undiluted regardless of how much other
 *    text sits around it elsewhere in the message. This is what
 *    chatParticipant.ts uses for the developer's live prompt; business
 *    content detection stays whole-message even here (see step 3 below) —
 *    that category IS a whole-message judgment by design.
 */

import { scan, DEFAULT_RULES, Match } from "./patternMatcher";
import { scanProximity } from "./nlpProximityMatcher";
import { scanPiiStructural, scanPiiContextual, scanPersonNamesHeuristic, PiiScanOptions } from "./piiDetector";
import { scanInfraStructural, scanInfraContextual } from "./infraDetector";
import { scanBusinessContent } from "./businessContentDetector";
import { EmbeddingRouter } from "./embeddingRouter";
import { SemanticKeywordMatcher } from "./semanticKeywordMatcher";
import { SyntaxAnalyzer, isWithinSpans } from "./syntax/syntaxAnalyzer";

export interface ScanOptions {
  pii?: PiiScanOptions;
  enablePii?: boolean; // default true
  enableInfra?: boolean; // default true
  enableConversationalSecrets?: boolean; // default true
  enableBusinessContentDetection?: boolean; // default true

  /** Pass null/undefined to disable routing entirely — every contextual detector then just always runs. */
  router?: EmbeddingRouter | null;
  /** Gates "should this cheap contextual detector run" — low-stakes, so the default is generous. */
  routingMinSimilarity?: number;
  /** Gates the (higher-stakes) whole-message business-content flag — deliberately much stricter. */
  businessContentThreshold?: number;

  /** Bypass routing entirely and run every contextual detector regardless of score — debugging / safety fallback. */
  alwaysRunAllDetectors?: boolean;

  /**
   * Rule IDs to exclude from results entirely — the sub-category checkbox
   * settings in package.json (vaultline.disabled*Rules) all funnel into
   * this one flat list. Filtering happens here, once, after every
   * detector has already run, rather than threading an exclusion list
   * through each individual detector module — keeps every detector file
   * ignorant of settings/config entirely, which is the same separation of
   * concerns the rest of this pipeline already follows (detectors find
   * things; policyEngine.ts and this option decide what to do about it).
   */
  disabledRuleIds?: string[];

  /**
   * Last line of defense — real semantic embedding similarity for tokens
   * no earlier layer matched. Only pass this when using the API-backed
   * embedder (see semanticKeywordMatcher.ts's module comment for why);
   * leave undefined/null to skip this layer entirely, which is the
   * correct choice when vaultline.embeddingBackend is "hashing".
   */
  semanticMatcher?: SemanticKeywordMatcher | null;
  enableSemanticKeywordMatching?: boolean; // default true (only takes effect if semanticMatcher is provided)
  semanticMatchThreshold?: number;

  /**
   * Syntax-aware suppression. BOTH of these must be set for it to do
   * anything — the analyzer itself, plus a file path or VS Code languageId
   * telling it which grammar to parse `text` with. Leave either unset (the
   * common case: chat prose, or tool output whose origin we can't identify)
   * and the pipeline behaves exactly as it does without tree-sitter.
   *
   * See syntax/syntaxAnalyzer.ts for what this buys and why it fails open,
   * and COMMENT_ACTIVE_RULE_IDS below for which rules keep firing in
   * comments regardless.
   */
  syntaxAnalyzer?: SyntaxAnalyzer | null;
  codeLanguage?: string | null;
}

export interface ScanResult {
  matches: Match[];
  businessMatches: Match[];
}

const DEFAULT_MIN_SIMILARITY = 0.15;
const DEFAULT_BUSINESS_THRESHOLD = 0.4;
// CALIBRATED (measured, not guessed) against all-MiniLM-L6-v2 — the
// embedding-server/ model — by embedding every seed in
// data/semanticKeywordSeeds.json against wanted synonyms and unwanted
// ordinary/coding words:
//
//   unwanted, highest: passed 0.476, enabled 0.393, taken 0.363,
//     bypass 0.362, required 0.356, class 0.339
//   wanted, lowest:    "mobile number" 0.598, "secret word" 0.632,
//     masterkey 0.648, passport 0.711
//   wanted, highest:   passcode/otp/dob 1.000, apikey 0.916, upi 0.857,
//     credentials 0.841, aadhaar 0.825, "pan card" 0.824, ifsc 0.805
//
// 0.5 separates these cleanly: 0.476 below, 0.598 above. (An earlier seed
// set left only a 0.046-wide gap; broadening the seeds and stopwording the
// generic head nouns widened it to 0.122.) Re-run the calibration (see
// README) for any other embedding model.
//
// This constant is also the single source of truth for the setting's
// default. package.json used to declare 0.4 while this file said 0.5, and
// since VS Code always supplies the declared default, 0.4 was what actually
// ran — below "passed", "license" and "string", all three of which
// therefore registered as credential keywords.
//
// "aadhaar"/"pan"/"ifsc"/"upi"/"dob"/"otp" used to score as pure noise
// (0.23-0.32) because MiniLM has no concept of them out of the box. They are
// now explicit entries in data/semanticKeywordSeeds.json and score 0.80-1.00.
// That is the pattern for any term this model doesn't know: add a SEED,
// never lower this floor.
export const DEFAULT_SEMANTIC_THRESHOLD = 0.5;

interface RoutingDecision {
  shouldRunPii: boolean;
  shouldRunInfra: boolean;
  shouldRunConversationalSecrets: boolean;
}

const ALWAYS_RUN_DECISION: RoutingDecision = {
  shouldRunPii: true,
  shouldRunInfra: true,
  shouldRunConversationalSecrets: true,
};

/**
 * Scores `scoringText` against the category centroids and turns that into
 * a per-detector run/skip decision. Split out of scanAll so scanAll (whole
 * message) and scanCurrentMessage (per line) can share the exact same
 * fail-open logic while scoring different-sized chunks of text.
 */
async function computeRoutingDecision(
  scoringText: string,
  router: EmbeddingRouter | null,
  alwaysAll: boolean,
  minSimilarity: number
): Promise<RoutingDecision> {
  if (alwaysAll || !router) return ALWAYS_RUN_DECISION;

  const scoreList = await router.scoreAll(scoringText);
  // Empty scoreList here means the embed call itself failed (API backend
  // down, dimension mismatch, etc.) — MUST still fail open, same reasoning
  // as the module comment above: a failed embed call must never look like
  // "every category scored 0", which would silently skip every contextual
  // detector instead of running them all.
  if (scoreList.length === 0) return ALWAYS_RUN_DECISION;

  const scores: Record<string, number> = {};
  for (const r of scoreList) scores[r.category] = r.score;
  const clears = (category: string): boolean => (scores[category] ?? 0) >= minSimilarity;

  return {
    shouldRunPii: clears("pii"),
    shouldRunInfra: clears("infrastructure"),
    shouldRunConversationalSecrets: clears("credentials"),
  };
}

function shiftMatch(match: Match, offset: number): Match {
  return offset === 0 ? match : { ...match, start: match.start + offset, end: match.end + offset };
}

/** Runs the routing-gated contextual detectors over `text` and offsets every resulting span by `offset` (0 when `text` already IS the full original text). */
function runContextualDetectors(
  text: string,
  options: ScanOptions,
  decision: RoutingDecision,
  offset: number
): Match[] {
  const contextual: Match[] = [];
  if (options.enablePii !== false && decision.shouldRunPii) {
    contextual.push(...scanPiiContextual(text).map((m) => shiftMatch(m, offset)));
    if (options.pii?.enablePersonNameHeuristic) {
      contextual.push(...scanPersonNamesHeuristic(text).map((m) => shiftMatch(m, offset)));
    }
  }
  if (options.enableInfra !== false && decision.shouldRunInfra) {
    contextual.push(...scanInfraContextual(text).map((m) => shiftMatch(m, offset)));
  }
  if (options.enableConversationalSecrets !== false && decision.shouldRunConversationalSecrets) {
    contextual.push(...scanProximity(text).map((m) => shiftMatch(m, offset)));
  }
  return contextual;
}

/**
 * Business content — separate, stricter threshold, whole-message flag,
 * shared verbatim by both entry points below since a paragraph-level
 * strategy judgment doesn't make sense computed per line. Requires
 * business-strategy to not just clear the threshold but to be the
 * TOP-ranked category — an absolute threshold alone let an ordinary coding
 * question through at ~0.41 (this category runs a diffusely elevated
 * baseline across a lot of unrelated text), while it was still clearly
 * outranked by "benign" at ~0.55. Requiring top rank is what actually
 * separates a real signal from that baseline noise.
 */
async function detectBusinessContent(text: string, options: ScanOptions): Promise<Match[]> {
  const router = options.router ?? null;
  const alwaysAll = options.alwaysRunAllDetectors ?? false;
  if (options.enableBusinessContentDetection === false || !router || alwaysAll) return [];

  // This layer BLOCKS a whole message on a similarity score alone, so it
  // only runs behind centroids precise enough to carry that decision — see
  // EmbeddingRouter.load()'s wholeMessageCapable note. On the hashing
  // fallback this goes quiet rather than firing on benign questions.
  if (!router.supportsWholeMessageClassification()) return [];

  const businessThreshold = options.businessContentThreshold ?? DEFAULT_BUSINESS_THRESHOLD;
  const scoreList = await router.scoreAll(text);
  if (scoreList.length === 0) return [];

  const bizScore = scoreList.find((r) => r.category === "business-strategy")?.score ?? 0;
  const isTopRanked = scoreList[0].category === "business-strategy";
  if (isTopRanked && bizScore >= businessThreshold) {
    return scanBusinessContent(text, bizScore);
  }
  return [];
}

/**
 * Steps 4-6 shared by both entry points: merge structural + contextual by
 * overlapping span (higher-priority layer wins), run the semantic
 * last-line-of-defense over whatever's left unclaimed, then apply the
 * user's disabled-rule-ID filter.
 */
async function mergeAndFinalize(
  text: string,
  structural: Match[],
  contextual: Match[],
  businessMatches: Match[],
  options: ScanOptions
): Promise<ScanResult> {
  const layered: Array<{ match: Match; priority: number }> = [
    ...structural.map((match) => ({ match, priority: 0 })),
    ...contextual.map((match) => ({ match, priority: 1 })),
  ];
  layered.sort((a, b) => (a.match.start !== b.match.start ? a.match.start - b.match.start : a.priority - b.priority));

  const accepted: Match[] = [];
  for (const { match } of layered) {
    const overlaps = accepted.some((a) => match.start < a.end && match.end > a.start);
    if (overlaps) continue;
    accepted.push(match);
  }

  if (options.enableSemanticKeywordMatching !== false && options.semanticMatcher) {
    const claimedSpans: Array<[number, number]> = accepted.map((m) => [m.start, m.end]);
    const threshold = options.semanticMatchThreshold ?? DEFAULT_SEMANTIC_THRESHOLD;
    const semanticMatches = await options.semanticMatcher.scan(text, claimedSpans, threshold);
    for (const match of semanticMatches) {
      const overlaps = accepted.some((a) => match.start < a.end && match.end > a.start);
      if (overlaps) continue;
      accepted.push(match);
    }
  }

  const disabled = new Set(options.disabledRuleIds ?? []);
  let filtered = disabled.size > 0 ? accepted.filter((m) => !disabled.has(m.ruleId)) : accepted;

  // Syntax-aware suppression — see syntaxAnalyzer.ts for why, and
  // firesInsideComments() below for the precision split. Applied last, over
  // the fully merged result, so it works identically for both entry points
  // and for every detector without any of them knowing about it.
  if (options.syntaxAnalyzer && options.codeLanguage) {
    const comments = await options.syntaxAnalyzer.commentSpans(text, options.codeLanguage);
    if (comments.length > 0) {
      filtered = filtered.filter((m) => firesInsideComments(m.ruleId) || !isWithinSpans(m.start, m.end, comments));
    }
  }

  return {
    matches: filtered.sort((a, b) => a.start - b.start),
    businessMatches,
  };
}

/**
 * Rules that keep firing INSIDE comments. Everything not listed here is
 * suppressed there when syntax awareness is available.
 *
 * The split is by PRECISION, and the asymmetry is deliberate:
 *
 *  - Missing a real secret because it sat in a comment is a leak.
 *    Commenting out a config line is one of the most ordinary ways a
 *    credential ends up in a file, so a commented-out `DB_PASSWORD=` line
 *    and an AWS key inside a `//` line must still be caught.
 *  - Flagging an EXAMPLE in a comment corrupts the model's view of the code
 *    for no security benefit at all.
 *
 * So the listed rules are the ones whose shape is specific enough that a
 * match is essentially never incidental prose: vendor key formats, PEM
 * blocks, JWTs, connection strings, and explicit `name = value` credential
 * assignments. The suppressed remainder is everything contextual or
 * low-signal — currency amounts, IP/IPv6 literals, hostnames, ports, URLs,
 * file paths, contextual PII, the conversational proximity matcher and the
 * semantic layer. Those are precisely the rules that fire on documentation
 * *about* credentials rather than on credentials.
 */
const COMMENT_ACTIVE_RULE_IDS = new Set([
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
]);

function firesInsideComments(ruleId: string): boolean {
  return COMMENT_ACTIVE_RULE_IDS.has(ruleId);
}

function scanStructural(text: string, options: ScanOptions): Match[] {
  return [
    ...scan(text, DEFAULT_RULES),
    ...(options.enablePii === false ? [] : scanPiiStructural(text)),
    ...(options.enableInfra === false ? [] : scanInfraStructural(text)),
  ];
}

export async function scanAll(text: string, options: ScanOptions = {}): Promise<ScanResult> {
  const structural = scanStructural(text, options);

  const router = options.router ?? null;
  const alwaysAll = options.alwaysRunAllDetectors ?? false;
  const minSimilarity = options.routingMinSimilarity ?? DEFAULT_MIN_SIMILARITY;

  const decision = await computeRoutingDecision(text, router, alwaysAll, minSimilarity);
  const contextual = runContextualDetectors(text, options, decision, 0);
  const businessMatches = await detectBusinessContent(text, options);

  return mergeAndFinalize(text, structural, contextual, businessMatches, options);
}

/**
 * Non-empty, non-whitespace-only lines of `text`, each tagged with its start
 * offset in the original string (so per-line match spans can be translated
 * back to full-text coordinates). \r\n and \n line endings both supported.
 *
 * Exported because any host that runs the contextual detectors itself has to
 * segment text the SAME way this pipeline does. Scanning contextual rules
 * over a whole document instead of per line does not merely miss things — it
 * invents wrong ones, by pairing a keyword on one line with a candidate value
 * on another. Sharing this function is what stops a second implementation
 * from drifting into that.
 */
export function splitNonBlankLines(text: string): Array<{ text: string; start: number }> {
  const lines: Array<{ text: string; start: number }> = [];
  const re = /\r?\n/g;
  let lastIndex = 0;
  let m: RegExpExecArray | null;
  const pushIfNonBlank = (start: number, end: number) => {
    const chunk = text.slice(start, end);
    if (chunk.trim().length > 0) lines.push({ text: chunk, start });
  };
  while ((m = re.exec(text)) !== null) {
    pushIfNonBlank(lastIndex, m.index);
    lastIndex = m.index + m[0].length;
  }
  pushIfNonBlank(lastIndex, text.length);
  return lines;
}

/**
 * Entry point for the developer's LIVE message only (see module comment
 * above for why this is separate from scanAll) — routes pii/infra/
 * conversational-secret detection per line instead of on one pooled
 * whole-message embedding, so a sensitive line surrounded by a lot of
 * unrelated context doesn't get its routing signal diluted away. Every
 * other step (structural regex, business-content, semantic last-line-of-
 * defense, disabled-rule filtering) is unchanged from scanAll and still
 * operates on the whole message, since none of those are subject to the
 * same whole-message-pooling dilution problem.
 */
export async function scanCurrentMessage(text: string, options: ScanOptions = {}): Promise<ScanResult> {
  const structural = scanStructural(text, options);

  const router = options.router ?? null;
  const alwaysAll = options.alwaysRunAllDetectors ?? false;
  const minSimilarity = options.routingMinSimilarity ?? DEFAULT_MIN_SIMILARITY;

  const lines = splitNonBlankLines(text);
  const contextual: Match[] = [];
  for (const line of lines) {
    const decision = await computeRoutingDecision(line.text, router, alwaysAll, minSimilarity);
    contextual.push(...runContextualDetectors(line.text, options, decision, line.start));
  }

  const businessMatches = await detectBusinessContent(text, options);

  return mergeAndFinalize(text, structural, contextual, businessMatches, options);
}
