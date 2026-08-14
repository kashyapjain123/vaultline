/**
 * Layer 2b: Proximity / Windowed NLP Matcher
 *
 * The strict regex rules in patternMatcher.ts require a rigid operator
 * ([:=]) directly after a keyword — "password=X", "password:X". That misses
 * completely ordinary conversational phrasing like "my password is X" or
 * "the api key was X", since there's no [:=] for the regex to anchor on.
 *
 * This module closes that gap using a technique borrowed from full-text
 * search engines (OpenSearch/Elasticsearch's span_near / match with slop):
 * tokenize the text, find sensitive keywords, then check whether a
 * value-looking token appears within N tokens of it — regardless of what
 * grammatical glue sits between them ("is", "was", "equals", "should be",
 * nothing at all). No embeddings, no neural net, no bundled model. Pure
 * tokenization + a small keyword/synonym list + a "does this look like a
 * value" heuristic.
 *
 * Why the keyword list is exact-match, not embedding-similarity-based:
 * tried it. The hashing embedder (src/embeddings/hashingEmbedder.ts) works
 * well for whole-MESSAGE routing because dozens of words average out the
 * noise, but at the single-word level it measures character shape, not
 * meaning — "pass" and "bypass" are nearly identical strings and unrelated
 * concepts, while "pwrd" and "password" share almost no characters despite
 * meaning the same thing. Empirically, wanted synonyms (0.44-0.71
 * similarity) and unwanted ordinary words like "bypass"/"compass"/"passed"
 * (0.29-0.52) overlapped enough that no threshold safely separated them.
 * A real semantic embedding model would likely do better here since it's
 * trained on meaning rather than character overlap — worth revisiting if
 * one gets bundled later. Until then, a maintained synonym list (below,
 * grown via the audit-log feedback loop) is the more precise choice.
 *
 * What this CANNOT do: catch sensitivity that has no trigger keyword at
 * all — e.g. a budget figure next to a project codename has nothing to anchor
 * a proximity window around. That gap is handled separately, at the
 * message level, by businessContentDetector.ts + embedding routing — which
 * IS a good fit for embeddings, because there the whole message provides
 * enough words to average over.
 *
 * FUZZY MATCHING: exact keyword matching misses ordinary typos —
 * "passowrd", "creditial", "credentails". Each token is also checked
 * against every keyword via bounded Damerau-Levenshtein edit distance (see
 * levenshteinWithinBound below), restricted to keywords of at least
 * FUZZY_MIN_KEYWORD_LENGTH characters.
 *
 * That floor is 8, and it is deliberately high. At 5 a 1-edit budget
 * reached ordinary English words that are everywhere in coding
 * conversation: "passed" -> passwd, "taken" -> token, "crews" -> creds are
 * all edit-distance 1. So "the screenshot was taken at 1280x720" flagged
 * a screen resolution as a token value. Short keywords (pass/pwd/key/creds/
 * secret/passwd/apikey) are therefore exact-only, and plurals — the recall
 * a low floor was really buying — are handled by exact stemming in
 * wordMatchesKeyword() instead, which is both more precise and can't reach
 * unrelated words. Cost of the higher floor: "toekn"-class typos on short
 * keywords are no longer caught. Typos on long keywords still are.
 *
 * WHAT COUNTS AS A VALUE lives in proximityUtils.looksLikeSecretValue(),
 * shared with semanticKeywordMatcher.ts — see that function's comment for
 * why quoting grants no leniency and what recall was traded away.
 */

import { Match, Severity } from "./patternMatcher";
import { looksLikeSecretValue, stripValueQuotes } from "./proximityUtils";

interface Token {
  text: string;
  lower: string;
  start: number;
  end: number;
}

/**
 * Keywords that indicate "a sensitive value might be nearby". Multi-word
 * entries are matched as consecutive tokens. This list is meant to grow via
 * the audit-log feedback loop, same as the regex rules.
 */
const SENSITIVE_KEYWORDS: { phrase: string[]; label: string }[] = [
  { phrase: ["password"], label: "Password (conversational)" },
  { phrase: ["passwd"], label: "Password (conversational)" },
  { phrase: ["pwd"], label: "Password (conversational)" },
  { phrase: ["pwrd"], label: "Password (conversational)" },
  { phrase: ["pd"], label: "Password (conversational)" },
  { phrase: ["pass"], label: "Password (conversational)" },
  { phrase: ["passphrase"], label: "Passphrase (conversational)" },
  { phrase: ["secret"], label: "Secret (conversational)" },
  { phrase: ["cred"], label: "Credential (conversational)" },
  { phrase: ["creds"], label: "Credential (conversational)" },
  { phrase: ["credential"], label: "Credential (conversational)" },
  { phrase: ["credentials"], label: "Credential (conversational)" },
  { phrase: ["api", "key"], label: "API Key (conversational)" },
  { phrase: ["key"], label: "API Key (conversational)" },
  { phrase: ["apikey"], label: "API Key (conversational)" },
  { phrase: ["access", "token"], label: "Access Token (conversational)" },
  { phrase: ["auth", "token"], label: "Auth Token (conversational)" },
  { phrase: ["bearer", "token"], label: "Bearer Token (conversational)" },
  { phrase: ["client", "secret"], label: "Client Secret (conversational)" },
  { phrase: ["private", "key"], label: "Private Key (conversational)" },
  { phrase: ["connection", "string"], label: "Connection String (conversational)" },
  { phrase: ["token"], label: "Token (conversational)" },
  // Vowel-dropped abbreviation, same treatment as pwd/pwrd/pd for
  // "password": too far from the full word for the edit-distance budget to
  // bridge now that the fuzzy floor is 8, so it's listed explicitly. Safe as
  // an exact match — "tokn" is not an English word.
  { phrase: ["tokn"], label: "Token (conversational)" },
];

// NOTE: there used to be a COMMON_WORD_DENYLIST here ("required", "policy",
// "protected", ...) meant to stop ordinary words passing the value
// heuristic. It was deleted rather than fixed: it was unreachable dead code.
// Every entry is pure lowercase letters, but the only branch that consulted
// it also required a digit, so no entry could ever have been tested. Under
// looksLikeSecretValue() a plain English word now fails STRUCTURALLY (a
// match needs digits alongside letters, or base64 padding), so a word list
// can never fire — keeping one would just relocate the same misleading dead
// code one layer down.

const WINDOW_SIZE = 6; // tokens to look ahead/behind a keyword match

function tokenize(text: string): Token[] {
  const tokens: Token[] = [];
  // Quoted/backticked spans become single tokens; otherwise word-ish runs.
  // Two guards, both load-bearing:
  //
  //   (?<!\\)  — an escaped quote (\") is not a delimiter. One \" inside a
  //              JSON-escaped tool-output blob used to flip quote parity for
  //              the entire rest of the text, so every subsequent "token"
  //              was a garbage span straddling two unrelated strings (this
  //              is where `") rather than as code-style assignments (e.g. "`
  //              came from).
  //
  //   [^"\s]*  — a quoted span may not contain whitespace. Under the unified
  //              value rule a whitespace-bearing span can never BE a value,
  //              so swallowing quoted prose into one opaque token only ever
  //              hurt: it manufactured garbage "values" AND hid real
  //              keywords sitting inside those quotes from keyword matching.
  const re = /(?<!\\)"[^"\s]*"|(?<!\\)'[^'\s]*'|(?<!\\)`[^`\s]*`|[A-Za-z0-9_./@-]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    tokens.push({ text: m[0], lower: m[0].toLowerCase(), start: m.index, end: m.index + m[0].length });
  }
  return tokens;
}

// Minimum keyword-word length eligible for fuzzy (typo-tolerant) matching —
// below this, only exact (or exact-plural) matches count.
//
// This was 5, which let a 1-edit budget reach ordinary English words that
// are extremely common in coding conversation:
//   "passed" -> passwd   (d=1)   "tests passed", "the build passed"
//   "taken"  -> token    (d=1)   "the screenshot was taken"
//   "crews"  -> creds    (d=1)
// Raising the floor to 8 makes every short keyword (pass/pwd/key/token/
// creds/secret/passwd/apikey) exact-only, which kills that whole class at
// the root while keeping typo tolerance where the word is long enough for a
// single edit to still be unambiguous ("passowrd", "creditial",
// "credentails", "connction string").
const FUZZY_MIN_KEYWORD_LENGTH = 8;

/** Edit-distance budget for a keyword of this length — grows slowly so a long word tolerates more than a single transposed letter. */
function fuzzyBudget(keywordLength: number): number {
  return keywordLength >= 9 ? 2 : 1;
}

/**
 * Damerau-Levenshtein distance (optimal string alignment variant — insert,
 * delete, substitute, or transpose two ADJACENT characters, each costing
 * 1), bailing out early once the result is certain to exceed `bound`.
 * Plain Levenshtein (no transposition op) scores a swapped-letter typo like
 * "passowrd"/"toekn" as 2 edits, not 1 — exactly the most common real typo
 * shape (fat-fingering two adjacent keys) — which meant a budget of 1
 * silently rejected precisely the typos this is meant to catch. Adding
 * transposition as a unit-cost operation fixes that.
 */
function levenshteinWithinBound(a: string, b: string, bound: number): number {
  if (Math.abs(a.length - b.length) > bound) return bound + 1;

  let prev2 = new Array(b.length + 1).fill(0); // row i-2, for transpositions
  let prev = new Array(b.length + 1);
  let curr = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    let rowMin = curr[0];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let best = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        best = Math.min(best, prev2[j - 2] + 1);
      }
      curr[j] = best;
      if (curr[j] < rowMin) rowMin = curr[j];
    }
    if (rowMin > bound) return bound + 1; // whole row already too far, no need to finish
    [prev2, prev, curr] = [prev, curr, prev2];
  }
  return prev[b.length];
}

/** Exact match, exact plural, or — for keywords long enough to make it meaningful — a small-edit-distance fuzzy match tolerating typos. */
function wordMatchesKeyword(rawTokenLower: string, keyword: string): boolean {
  // The tokenizer keeps a quoted span's quotes, so a dict/kwargs key arrives as
  // `"opensearch_password"` — quotes included. Strip them before matching, or
  // the compound split below yields `password"` and matches nothing.
  const tokenLower = stripValueQuotes(rawTokenLower);
  if (tokenLower === keyword) return true;

  // Compound identifiers. The tokenizer keeps `_` inside a token, so
  // OPENSEARCH_PASSWORD arrives as ONE opaque token that equals no keyword —
  // which is why `os.environ.get("OPENSEARCH_PASSWORD", "Av3Xz21@UAT")` had
  // nothing to anchor on and the password went through. Testing the
  // underscore-separated parts costs nothing and is how these are named in
  // practice.
  //
  // EXACT on the parts only, never fuzzy: a fragment like "pass" or "key" is
  // short enough that an edit-distance budget would start reaching ordinary
  // words, which is the whole reason FUZZY_MIN_KEYWORD_LENGTH is 8.
  if (tokenLower.includes("_") && tokenLower.split("_").some((part) => part === keyword)) return true;

  // Plurals handled EXACTLY, not fuzzily ("secrets", "tokens", "keys",
  // "passwords"). Relying on the edit-distance budget for these is what
  // forced the fuzzy floor low enough to also admit "passed"/"taken".
  //
  // Adding plural KEYWORD ENTRIES instead was tried and rejected: "passwords"
  // is 9 characters, so fuzzyBudget() grants it 2 edits, and it then
  // fuzzy-matches the literal string "PASSWORD_1" — i.e. our own placeholder
  // token — manufacturing a fresh false positive on already-redacted text.
  // Stemming has no such reach.
  if (tokenLower.endsWith("s") && tokenLower.slice(0, -1) === keyword) return true;

  if (keyword.length < FUZZY_MIN_KEYWORD_LENGTH) return false;
  const bound = fuzzyBudget(keyword.length);
  return levenshteinWithinBound(tokenLower, keyword, bound) <= bound;
}

function matchesKeywordAt(tokens: Token[], index: number, phrase: string[]): boolean {
  if (index + phrase.length > tokens.length) return false;
  for (let i = 0; i < phrase.length; i++) {
    if (!wordMatchesKeyword(tokens[index + i].lower, phrase[i])) return false;
  }
  return true;
}

/** A credential keyword found in a message, whether or not a value was found alongside it. */
export interface KeywordSighting {
  ruleId: string;
  label: string;
}

export interface ProximityScanResult {
  matches: Match[];
  /**
   * Every keyword occurrence, in the order encountered — including ones with
   * NO value in their window. That "keyword but no value" case is precisely
   * the leak this feeds: "...and password is" ends a turn with nothing for
   * this scan to match, and the value arrives in the next message. See
   * conversationContext.ts.
   */
  keywordsSeen: KeywordSighting[];
}

/** Backwards-compatible entry point — the matches half of scanProximityWithContext(). */
export function scanProximity(text: string): Match[] {
  return scanProximityWithContext(text).matches;
}

export function scanProximityWithContext(text: string): ProximityScanResult {
  const tokens = tokenize(text);
  const matches: Match[] = [];
  const keywordsSeen: KeywordSighting[] = [];
  // Tracks which token indices have already been consumed by a keyword
  // match, longest phrase first, so a single-word keyword like "token"
  // doesn't ALSO fire on top of an already-matched "access token".
  const claimed = new Set<number>();
  const keywordsByLength = [...SENSITIVE_KEYWORDS].sort((a, b) => b.phrase.length - a.phrase.length);

  for (let i = 0; i < tokens.length; i++) {
    for (const kw of keywordsByLength) {
      if (!matchesKeywordAt(tokens, i, kw.phrase)) continue;

      const kwStartIdx = i;
      const kwEndIdx = i + kw.phrase.length - 1;

      let alreadyClaimed = false;
      for (let k = kwStartIdx; k <= kwEndIdx; k++) {
        if (claimed.has(k)) alreadyClaimed = true;
      }
      if (alreadyClaimed) continue;
      for (let k = kwStartIdx; k <= kwEndIdx; k++) claimed.add(k);

      // Recorded BEFORE the value search below, and regardless of whether it
      // finds anything — a keyword with no value is exactly the signal that
      // arms cross-turn detection.
      keywordsSeen.push({ ruleId: "proximity-" + kw.phrase.join("-"), label: kw.label });

      // Search both directions within the window for a value-looking token.
      const searchStart = Math.max(0, kwStartIdx - WINDOW_SIZE);
      const searchEnd = Math.min(tokens.length - 1, kwEndIdx + WINDOW_SIZE);

      for (let j = searchStart; j <= searchEnd; j++) {
        if (j >= kwStartIdx && j <= kwEndIdx) continue; // skip the keyword itself
        if (!looksLikeSecretValue(tokens[j].text)) continue;

        // IMPORTANT: only the value token itself gets tokenized/redacted —
        // NOT the keyword or connector words ("is", "was", "="). This keeps
        // "password" visible to the model in the outgoing redacted text
        // (e.g. "my password is [SEC-2]") instead of swallowing it into the
        // token (e.g. "my [SEC-2]"), which would lose useful context for no
        // privacy benefit — the keyword alone reveals nothing sensitive.
        const valueTok = tokens[j];
        const cleanValue = stripValueQuotes(valueTok.text);

        matches.push({
          ruleId: "proximity-" + kw.phrase.join("-"),
          label: kw.label,
          severity: "medium" as Severity,
          category: "SECRET",
          value: cleanValue,
          start: valueTok.start,
          end: valueTok.end,
        });

        // One value hit per keyword occurrence is enough; move to next keyword.
        break;
      }
    }
  }

  return { matches: matches.sort((a, b) => a.start - b.start), keywordsSeen };
}

/**
 * Placeholders this project has already issued, e.g. "<<PASSWORD_1>>". The
 * tokenizer below strips the angle brackets and hands back "PASSWORD_1", which
 * sails through looksLikeSecretValue() (letters + digits, 10 chars) — so
 * without this guard the carry-over pass would happily "redact" our own tokens
 * back into fresh ones. Mirrors the shape findUnrestoredTokens() looks for.
 */
const ISSUED_PLACEHOLDER_RE = /<<\s*[A-Za-z][A-Za-z0-9_]*?_\d+\s*>>/g;

/**
 * Value-only pass for a message that has NO keyword of its own but follows one
 * that did — see conversationContext.ts for when this is armed.
 *
 * The bar for "is this a value" is the same looksLikeSecretValue() every other
 * detector uses, unchanged and deliberately strict (8+ chars, no whitespace,
 * letters AND digits, or real base64 padding). That strictness is doing all the
 * precision work here: with the keyword anchor gone, it is the only thing
 * standing between this and redacting ordinary prose.
 *
 * Every value-shaped token is emitted, not just the first — a follow-up like
 * "use admin1234 / hunter1x2y3z" is two secrets, not one. Overlap resolution in
 * detectionPipeline.mergeAndFinalize() drops any span the in-message proximity
 * matcher already claimed, so double-flagging is not possible.
 */
export function scanCarriedOver(text: string, expectation: { ruleId: string; label: string }): Match[] {
  const skip: Array<[number, number]> = [];
  for (const m of text.matchAll(ISSUED_PLACEHOLDER_RE)) {
    if (m.index !== undefined) skip.push([m.index, m.index + m[0].length]);
  }

  const matches: Match[] = [];
  for (const tok of tokenize(text)) {
    if (skip.some(([s, e]) => tok.start < e && tok.end > s)) continue;
    if (!looksLikeSecretValue(tok.text)) continue;

    matches.push({
      ruleId: expectation.ruleId,
      // Relabelled so the chat banner explains ITSELF — a redaction with no
      // visible keyword in the message looks arbitrary otherwise, and
      // "why did it redact that?" is the fastest way to lose a user's trust
      // in a security tool. The existing "(conversational)" qualifier is
      // dropped rather than appended to, so the banner reads
      // "Password (carried from previous turn)" and not the double-
      // parenthesised "Password (conversational) (carried from previous turn)".
      label: expectation.label.replace(/\s*\(conversational\)\s*$/, "") + " (carried from previous turn)",
      severity: "medium" as Severity,
      category: "SECRET",
      value: stripValueQuotes(tok.text),
      start: tok.start,
      end: tok.end,
    });
  }
  return matches;
}
