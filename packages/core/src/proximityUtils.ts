/**
 * Shared helpers for the context/proximity-based detectors.
 *
 * TWO DIFFERENT KINDS OF SHARED THING LIVE HERE, with deliberately
 * different sharing policies:
 *
 *  - `looksLikeSecretValue()` / `stripValueQuotes()` — the ONE canonical
 *    answer to "does this token look like a secret VALUE". Every detector
 *    that asks that question must get the identical answer, so this is
 *    shared by nlpProximityMatcher.ts AND semanticKeywordMatcher.ts. It
 *    used to be copy-pasted into both, and the copies had already drifted
 *    apart (one silently skipped its own denylist) — exactly the failure
 *    mode duplicating a security-relevant rule produces.
 *
 *  - `tokenize()` — NOT shared with nlpProximityMatcher.ts, on purpose.
 *    That module needs word-character runs; this one needs
 *    whitespace-delimited tokens that trimPunct/isNumericToken then clean
 *    up for numeric PII. Unifying them would move piiDetector spans for no
 *    benefit. The two tokenizers are kept in sync only where correctness
 *    demands it (both must treat an escaped quote as not-a-delimiter).
 */

export interface Token {
  text: string;
  start: number;
  end: number;
}

export function tokenize(text: string): Token[] {
  const tokens: Token[] = [];
  // (?<!\\) — a quote that is itself backslash-escaped is NOT a string
  // delimiter. Text arriving from tool output is frequently JSON-escaped,
  // and without this guard a single \" flips quote parity for everything
  // after it: the regex then pairs the closing quote of one string with the
  // opening quote of the next, emitting "tokens" that straddle two
  // unrelated strings. Those garbage spans were being handed to the value
  // heuristic and redacted as if they were secrets.
  const re = /(?<!\\)"[^"]*"|(?<!\\)'[^']*'|[^\s"']+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    tokens.push({ text: m[0], start: m.index, end: m.index + m[0].length });
  }
  return tokens;
}

/** Strips a surrounding quote pair, requiring the SAME quote character at both ends ("x", 'x', `x`). */
export function stripValueQuotes(s: string): string {
  const m = /^(['"`])(.*)\1$/.exec(s);
  return m ? m[2] : s;
}

/**
 * THE single "does this look like a secret VALUE" rule, shared by
 * nlpProximityMatcher.ts and semanticKeywordMatcher.ts.
 *
 * Quoting buys NO leniency. The rule this replaced treated any quoted span
 * of 4+ characters as a plausible secret, on the theory that a human
 * putting something in quotes is pointing at a value. In prose that's
 * often true; in the code, JSON and documentation that flows through tool
 * output it is catastrophically wrong — it redacted the word
 * "description", the string "username:password", and entire sentences of
 * prose out of this project's own package.json, purely because the words
 * "secret"/"password"/"token" appear nearby in that file's setting
 * descriptions.
 *
 * ACCEPTED RECALL LOSS, deliberate: a quoted all-lowercase, no-digit
 * password ("letmein") is no longer detected. It is structurally
 * indistinguishable from an ordinary quoted English word, and guessing
 * wrong on that class was the single largest false-positive source in the
 * pipeline. Values with any digit, or base64 padding, are still caught.
 */
export function looksLikeSecretValue(raw: string): boolean {
  const v = stripValueQuotes(raw);
  if (v.length < 8) return false;
  if (/\s/.test(v)) return false; // whitespace => prose, never the body of a secret

  // Shape A — generated alphanumeric secret: letters AND digits together.
  if (/^[A-Za-z0-9_-]+$/.test(v) && /[A-Za-z]/.test(v) && /\d/.test(v)) return true;

  // Shape B — base64/base64url blob. Requires real encoding evidence: a '+'
  // anywhere, or '='/'==' padding at the very END. A lone '/' is NOT
  // evidence (that would swallow "api/v2/users"), and a mid-string '=' is
  // not either (that would swallow "key=value").
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(v) && (v.includes("+") || v.endsWith("="))) return true;

  return false;
}

/** Strips leading/trailing punctuation that isn't part of the actual value. */
export function trimPunct(s: string): string {
  return s.replace(/^[.,;:!?)\]]+|[.,;:!?([]+$/g, "");
}

export function cleanWord(s: string): string {
  return trimPunct(s).toLowerCase();
}

export function isNumericToken(s: string): string | null {
  const stripped = trimPunct(s).replace(/[-.\s]/g, "");
  return /^\d+$/.test(stripped) ? stripped : null;
}

/**
 * True if `keyword` (a single word) appears within `window` tokens of
 * `centerIdx`, not counting the token at centerIdx itself.
 */
export function hasKeywordNear(
  tokens: Token[],
  centerIdx: number,
  keywords: string[],
  window: number
): boolean {
  const lo = Math.max(0, centerIdx - window);
  const hi = Math.min(tokens.length - 1, centerIdx + window);
  for (let i = lo; i <= hi; i++) {
    if (i === centerIdx) continue;
    if (keywords.includes(cleanWord(tokens[i].text))) return true;
  }
  return false;
}

/** Luhn checksum — used to validate candidate credit card numbers and cut down false positives on arbitrary long digit runs. */
export function luhnValid(digitsOnly: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digitsOnly.length - 1; i >= 0; i--) {
    let d = parseInt(digitsOnly[i], 10);
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}
