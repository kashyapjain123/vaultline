/**
 * Layer 2c: Semantic Keyword Matcher — LAST LINE OF DEFENSE
 *
 * Runs after every other detector (structural regex, contextual PII/infra,
 * conversational-secret proximity matching). Only looks at tokens NOT
 * already covered by an existing match, and only exists to catch keyword
 * synonyms none of the earlier, cheaper, more precise layers know about —
 * an org-specific term for "password" nobody thought to hardcode, say.
 *
 * This is deliberately NOT the same technique that failed inside
 * nlpProximityMatcher.ts (see that file's module comment for the full
 * writeup). That attempt used the local hashing embedder, which measures
 * character shape and confused "pass" with "bypass" — wanted synonyms and
 * unwanted ordinary words scored in overlapping ranges, so no threshold
 * separated them. This module should ONLY ever be wired up with a real,
 * semantic, API-backed Embedder (see embeddings/apiEmbedder.ts) — the
 * whole point is meaning instead of string shape. detectionPipeline.ts is
 * expected to only construct/pass this when vaultline.embeddingBackend is
 * "api", never with the hashing embedder.
 *
 * Cost-consciousness: embedding every token individually would be one HTTP
 * round-trip per word. This batches every candidate token in a message
 * into a single embedBatch() call, and the seed keyword embeddings are
 * computed once per matcher instance (cached for its lifetime), not once
 * per message — so construct ONE SemanticKeywordMatcher at extension
 * activation and reuse it, the same way EmbeddingRouter is reused.
 *
 * Fail-open, consistent with the rest of this pipeline: if the embedder
 * call fails for any reason, scan() logs a warning and returns [] rather
 * than throwing — a failure here should never block a message, only mean
 * this one extra safety net didn't run for it.
 */

import * as fs from "fs";
import { Match, Severity, Category, SEVERITY_RANK } from "./patternMatcher";
import { Embedder, embedBatchFallback } from "./embeddings/embedder";
import { cosineSimilarity } from "./embeddings/hashingEmbedder";
import { tokenize, trimPunct, looksLikeSecretValue, stripValueQuotes, Token, unquotedSpan } from "./proximityUtils";

interface SeedGroup {
  label: string;
  category: Category;
  severity: Severity;
  seeds: string[];
}

type SeedFile = Record<string, SeedGroup>;

// The "does this look like a value" heuristic used to be duplicated here in
// miniature. It is now imported from proximityUtils, shared with
// nlpProximityMatcher.ts — the two copies had already drifted (this one
// silently had no denylist check at all), which is exactly why a
// security-relevant rule shouldn't be copy-pasted. See
// looksLikeSecretValue()'s comment for the rule and its tradeoffs.

// Confidence bands for the similarity score, applied on top of the
// configured threshold (which is the gate — see DEFAULT_SEMANTIC_THRESHOLD
// in detectionPipeline.ts for the full measured calibration). Against
// all-MiniLM-L6-v2 the observed structure is:
//
//   >=0.75  exact-synonym cluster   passcode/otp/dob 1.000, apikey 0.916,
//                                   upi 0.857, credentials 0.841,
//                                   aadhaar 0.825, ifsc 0.805
//   0.60-0.75 paraphrase cluster    passport 0.711, masterkey 0.648,
//                                   "secret word" 0.632
//   gate-0.60 weak tail             "mobile number" 0.598
//
// Re-run that calibration (see README) before trusting these against a
// different embedding model.
const SEMANTIC_HIGH_CONFIDENCE = 0.75;
const SEMANTIC_MEDIUM_CONFIDENCE = 0.6;

/**
 * Maps a similarity score onto a severity, CAPPED at the seed group's own
 * declared severity so banding can only ever DE-escalate. That cap is a
 * safety property, not a detail: policyEngine.ts BLOCKS on "high", and an
 * unvalidated embedding guess from the least precise layer in the pipeline
 * must never be able to block a message on its own.
 */
function bandedSeverity(score: number, groupCeiling: Severity): Severity {
  const band: Severity =
    score >= SEMANTIC_HIGH_CONFIDENCE ? "high" : score >= SEMANTIC_MEDIUM_CONFIDENCE ? "medium" : "low";
  return SEVERITY_RANK[band] < SEVERITY_RANK[groupCeiling] ? band : groupCeiling;
}

// Ceiling on how many distinct candidate tokens get embedded for one piece
// of text. Tool output can be an entire file, and this layer runs on it —
// without a cap a single large read could turn into a many-hundred-item
// embedding batch. Candidates are deduplicated first (below), so this is a
// bound on DISTINCT words, which real text hits far more slowly.
const MAX_SEMANTIC_CANDIDATES = 300;

// Cuts the candidate set (and therefore batch size / API cost) before any
// network call happens — too short, too long, non-alphabetic, or common
// enough to not be worth embedding at all.
//
// The second block exists for a structural reason worth understanding before
// editing the seed file. A CANDIDATE is always a single word
// (isCandidateToken below), but many SEEDS are phrases — and MiniLM places a
// phrase and its head noun almost on top of each other. Measured against
// data/semanticKeywordSeeds.json: the bare word "port" scores 0.810 against
// the seed "port number", "connection" 0.677 against "database connection",
// "access" 0.619 against "access token", "key" 0.615 against "signing key".
// So every phrase seed silently promotes its generic head noun into a
// keyword, far above the 0.5 gate.
//
// Listing those head nouns here is the correct fix rather than deleting the
// phrase seeds, because each of these words is ALREADY handled by an earlier,
// deterministic layer: "port"/"host" by infraDetector's contextual scanners,
// "key"/"token"/"secret"/"password" by nlpProximityMatcher's keyword list,
// "account"/"phone"/"customer" by piiDetector's number-context groups. This
// module is explicitly the last line of defense for synonyms those layers
// DON'T know — so re-detecting their vocabulary is pure duplicate noise, and
// their spans are skipped here anyway (see `alreadyMatchedSpans` in scan()).
const STOPWORDS = new Set([
  "the", "a", "an", "and", "or", "but", "is", "are", "was", "were", "be",
  "to", "of", "in", "on", "at", "for", "with", "my", "your", "our", "this",
  "that", "it", "as", "by", "from", "can", "you", "help", "me", "please",
  "write", "what", "how", "does", "do", "here", "there", "and", "server",
  // Generic head nouns of phrase seeds — see the note above.
  "port", "number", "address", "key", "keys", "access", "node", "service",
  "connection", "identifier", "name", "host", "hostname", "id", "code",
  "account", "phone", "card", "login", "user", "username", "secret", "token",
  "password", "credential", "credentials", "value", "config", "record",
  "index", "count", "status", "message", "request", "response", "header",
  "field", "label", "type", "data", "string", "license", "date", "birth",
]);

function isCandidateToken(tok: Token): boolean {
  const w = trimPunct(tok.text);
  if (w.length < 3 || w.length > 24) return false;
  if (!/^[A-Za-z][A-Za-z_-]*$/.test(w)) return false; // looking for KEYWORD candidates, not values
  if (STOPWORDS.has(w.toLowerCase())) return false;
  return true;
}

export class SemanticKeywordMatcher {
  private seedGroups: SeedFile;
  private embedder: Embedder;
  private seedVectorsByGroup: Map<string, { group: SeedGroup; vectors: number[][] }> | null = null;
  private seedLoadFailed = false;
  private enabled = true;

  constructor(seedFilePath: string, embedder: Embedder) {
    this.seedGroups = JSON.parse(fs.readFileSync(seedFilePath, "utf-8"));
    this.embedder = embedder;
  }

  /**
   * Turn this layer off (or back on) at runtime.
   *
   * Needed because the hashing-embedder fallback (see extension.ts) leaves
   * this class with a WORKING embedder that produces meaningless results:
   * unlike a dead server, hashing embeds every seed and candidate happily,
   * it just does so lexically, so single-word similarity is noise — the
   * empirical reason this class is only ever constructed for the api
   * backend in the first place. Noise here means false redactions, so
   * falling back to hashing has to silence it explicitly rather than let it
   * keep scoring.
   *
   * Disabling drops the cached seed vectors, since they belong to the
   * outgoing embedder's vector space; re-enabling re-embeds them against
   * whichever embedder is current by then.
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
    if (!enabled) {
      this.seedVectorsByGroup = null;
      this.seedLoadFailed = false;
    }
  }

  private async ensureSeedVectors(): Promise<boolean> {
    if (this.seedVectorsByGroup) return true;
    if (this.seedLoadFailed) return false; // don't retry an expensive failure every single message

    const allSeeds: string[] = [];
    const seedOwners: string[] = [];
    for (const [key, group] of Object.entries(this.seedGroups)) {
      for (const seed of group.seeds) {
        allSeeds.push(seed);
        seedOwners.push(key);
      }
    }

    try {
      const vectors = await embedBatchFallback(this.embedder, allSeeds);
      const byGroup = new Map<string, { group: SeedGroup; vectors: number[][] }>();
      for (const [key, group] of Object.entries(this.seedGroups)) {
        byGroup.set(key, { group, vectors: [] });
      }
      for (let i = 0; i < allSeeds.length; i++) {
        byGroup.get(seedOwners[i])!.vectors.push(vectors[i]);
      }
      this.seedVectorsByGroup = byGroup;
      return true;
    } catch (err) {
      console.warn("Vaultline: semantic keyword matcher failed to embed seed keywords, disabling for this session:", err);
      this.seedLoadFailed = true;
      return false;
    }
  }

  /**
   * `alreadyMatchedSpans` — spans already claimed by earlier, more precise
   * layers. Tokens inside them are skipped entirely; this is what makes
   * this pass a genuine last line of defense rather than a redundant
   * second opinion on everything.
   */
  async scan(text: string, alreadyMatchedSpans: Array<[number, number]>, threshold: number): Promise<Match[]> {
    if (!this.enabled) return [];

    const seedsReady = await this.ensureSeedVectors();
    if (!seedsReady) return [];

    const tokens = tokenize(text);
    const overlapsExisting = (start: number, end: number) =>
      alreadyMatchedSpans.some(([s, e]) => start < e && end > s);

    const candidateIndices: number[] = [];
    for (let i = 0; i < tokens.length; i++) {
      if (overlapsExisting(tokens[i].start, tokens[i].end)) continue;
      if (!isCandidateToken(tokens[i])) continue;
      candidateIndices.push(i);
    }
    if (candidateIndices.length === 0) return [];

    // Embed each DISTINCT candidate word once, not once per occurrence. The
    // same word ("token", "server", "config") recurs constantly in real
    // text, and this layer runs on tool output that can be a whole file — so
    // deduplicating before the batch call is what keeps "run it everywhere"
    // affordable. Vectors are mapped back to occurrences by index below.
    const candidateTexts = candidateIndices.map((i) => trimPunct(tokens[i].text));
    const vectorIndexByWord = new Map<string, number>();
    const uniqueTexts: string[] = [];
    const vectorIndexOfCandidate: number[] = [];
    for (const text of candidateTexts) {
      const dedupeKey = text.toLowerCase();
      let vecIdx = vectorIndexByWord.get(dedupeKey);
      if (vecIdx === undefined) {
        if (uniqueTexts.length >= MAX_SEMANTIC_CANDIDATES) {
          vectorIndexOfCandidate.push(-1); // over the cap — skipped below
          continue;
        }
        vecIdx = uniqueTexts.length;
        vectorIndexByWord.set(dedupeKey, vecIdx);
        uniqueTexts.push(text);
      }
      vectorIndexOfCandidate.push(vecIdx);
    }
    if (vectorIndexOfCandidate.some((i) => i === -1)) {
      console.warn(
        `Vaultline: semantic keyword matcher hit its ${MAX_SEMANTIC_CANDIDATES}-distinct-candidate cap ` +
          `for this text; candidates beyond the cap were skipped by this layer. Earlier layers ` +
          `(structural regex, proximity) still scanned all of it.`
      );
    }

    let uniqueVectors: number[][];
    try {
      uniqueVectors = await embedBatchFallback(this.embedder, uniqueTexts);
    } catch (err) {
      console.warn("Vaultline: semantic keyword matcher embed call failed for this message:", err);
      return [];
    }

    const matches: Match[] = [];
    const WINDOW = 6;

    for (let c = 0; c < candidateIndices.length; c++) {
      const vecIdx = vectorIndexOfCandidate[c];
      if (vecIdx === -1) continue; // beyond MAX_SEMANTIC_CANDIDATES
      const tokenIdx = candidateIndices[c];

      let best: { key: string; group: SeedGroup; score: number } | null = null;
      for (const [key, entry] of this.seedVectorsByGroup!) {
        for (const seedVec of entry.vectors) {
          const score = cosineSimilarity(uniqueVectors[vecIdx], seedVec);
          if (!best || score > best.score) best = { key, group: entry.group, score };
        }
      }
      // The configured threshold is the GATE; distance above it then decides
      // confidence via bandedSeverity(). Note deliberately NOT implemented:
      // retrying with a progressively lower threshold until something
      // matches. That would guarantee a non-empty result, making "this text
      // contains nothing sensitive" unrepresentable and manufacturing a
      // redaction on every clean message.
      if (!best || best.score < threshold) continue;

      const lo = Math.max(0, tokenIdx - WINDOW);
      const hi = Math.min(tokens.length - 1, tokenIdx + WINDOW);
      for (let j = lo; j <= hi; j++) {
        if (j === tokenIdx) continue;
        if (overlapsExisting(tokens[j].start, tokens[j].end)) continue;
        // Span first, then test — same reason as nlpProximityMatcher: the value
        // test must see the trimmed value, not the token with a sentence's full
        // stop attached.
        const span = unquotedSpan(tokens[j].text, tokens[j].start);
        if (!looksLikeSecretValue(span.value)) continue;

        matches.push({
          ruleId: `semantic-${best.key}`,
          label: `${best.group.label} (similarity ${best.score.toFixed(2)})`,
          severity: bandedSeverity(best.score, best.group.severity),
          category: best.group.category,
          value: span.value,
          start: span.start,
          end: span.end,
        });
        break; // one value per keyword hit is enough
      }
    }

    return matches.sort((a, b) => a.start - b.start);
  }
}
