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
 * The span of a token's value INSIDE any surrounding quote pair.
 *
 * A token that arrives as `"hunter2"` must be redacted as `"<<PASSWORD_1>>"`,
 * not `<<PASSWORD_1>>`. The matchers were taking the whole token as the span
 * while storing the STRIPPED value, so the two disagreed and the round trip
 * silently destroyed the quotes:
 *
 *     password = "hunter2isnotsecure"   ->   password = <<PASSWORD_1>>
 *     ...restored                       ->   password = hunter2isnotsecure
 *
 * which is not valid syntax in most languages — the developer's own code came
 * back broken. The structural rules already got this right in 1.2.7 by keeping
 * quotes outside their capture group; this is the same rule for the token-based
 * matchers, shared so the two cannot drift apart again.
 */
export function unquotedSpan(token: string, start: number): { start: number; end: number; value: string } {
  const value = stripValueQuotes(token);
  // A quote pair was found and removed exactly when the value is two characters
  // shorter, so the offset is one on each side.
  const quoted = value.length === token.length - 2;
  return quoted
    ? { start: start + 1, end: start + 1 + value.length, value }
    : { start, end: start + token.length, value };
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
  // A quote INSIDE the value (after the outer pair is stripped) means this is a
  // fragment of code rather than a value — `LLM_KEY="zgfd-..."` arrives as one
  // token when the surrounding text is itself quoted, and matched as a whole.
  if (/['"`]/.test(v)) return false;

  // Shape A — generated alphanumeric secret: letters AND digits together.
  if (/^[A-Za-z0-9_-]+$/.test(v) && /[A-Za-z]/.test(v) && /\d/.test(v)) return true;

  // Shape B — base64/base64url blob. Requires real encoding evidence: a '+'
  // anywhere, or '='/'==' padding at the very END. A lone '/' is NOT
  // evidence (that would swallow "api/v2/users"), and a mid-string '=' is
  // not either (that would swallow "key=value").
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(v) && (v.includes("+") || v.endsWith("="))) return true;

  // Shape C — a human-chosen password with punctuation in it. Shape A's
  // character class is alphanumerics plus _ and -, so `Hunter@123` and
  // `Av3Xz21@UAT` failed on the '@' alone and went through unredacted.
  //
  // All THREE of letter, digit and symbol are required together, which is what
  // keeps this narrow: prose has no digits or symbols, `os.environ.get` has no
  // digit, a version string like `v1.2.3` has no symbol from this set, and an
  // email only qualifies if it also carries a digit — where the structural
  // email rule outranks this anyway (it is higher priority in the merge).
  if (
    /^\S+$/.test(v) &&
    /[A-Za-z]/.test(v) &&
    /\d/.test(v) &&
    CREDENTIAL_SYMBOLS.test(v)
  ) {
    return true;
  }

  return false;
}

/**
 * Symbols that make an unquoted token look like a credential rather than an
 * identifier.
 *
 * `.` and `_` are deliberately absent, and that absence is the whole point:
 * `os.environ.get` and `get_api_Key` are dotted/underscored precisely BECAUSE
 * they are code. Counting either as evidence would readmit every case this
 * exists to reject.
 *
 * `=` and `+` were here and are now gone for the same reason, found by scanning
 * this project's own test files: `=` made
 * `LLM_KEY="zgfd-xhfj-lfgj-hlfhjf-gh76kd"` qualify as a single secret VALUE, so
 * the key name and the quotes were swallowed into the redaction. An assignment
 * operator is evidence of an assignment, not of a credential. Cost: a password
 * whose only symbol is `+` or `=` — which Shape A already covers whenever it is
 * otherwise alphanumeric.
 */
const CREDENTIAL_SYMBOLS = /[@#$%^&*!?~]/;

/**
 * Is a captured assignment value a literal, or a reference to code?
 *
 * The structural rules find a value by anchoring on its key (`password =`,
 * `API_KEY =`), which tells you something follows the operator but nothing
 * about WHAT. On real Python that produced a run of false positives — a type
 * annotation (`password: Optional[str])`), a call (`PWD = os.environ.get(`), a
 * subscript (`get_api_Key(os.environ[`), and a bare `return` picked up from the
 * next line. In a security tool that direction of error is the expensive one: a
 * developer who sees `return` highlighted as a secret stops reading the
 * highlights altogether.
 *
 * Two signals, in order:
 *
 *  - **Quoted in the source → accept.** A string literal is a value by
 *    construction, whatever it contains. This is what keeps `"letmein"` working.
 *  - **Unquoted → require a digit or a credential symbol.** After
 *    `password =`, a bare word is far more likely a variable being passed along
 *    than the secret itself.
 *
 * ACCEPTED RECALL LOSS, deliberate and the same trade looksLikeSecretValue()
 * already makes one function below: an unquoted, digit-free `password = letmein`
 * is no longer flagged. It is structurally indistinguishable from
 * `password = default_password`, and guessing wrong on that class is what
 * produced every false positive above.
 */
export function looksLikeAssignedLiteral(value: string, wholeMatch: string): boolean {
  if (value.length === 0) return false;

  // Quoted in the ORIGINAL text, not in the captured group — 1.2.7 deliberately
  // leaves the quotes outside the value span so the redacted line stays
  // syntactically valid, which means the evidence lives in the whole match.
  const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (new RegExp(`['"\`]${escaped}['"\`]`).test(wholeMatch)) return true;

  return /\d/.test(value) || CREDENTIAL_SYMBOLS.test(value);
}

/**
 * Words that are a TYPE or a placeholder rather than somebody's account name.
 *
 * This list is the entire mechanism, and that is worth stating plainly rather
 * than dressing up: `svc_corp_uat` and `string` are both bare identifiers, so
 * after shape there is nothing structural left to separate a username from a
 * type annotation. A denylist is the honest tool for the job.
 */
const TYPE_WORDS = new Set([
  "string", "str", "int", "integer", "bool", "boolean", "float", "double", "decimal",
  "none", "null", "nil", "undefined", "any", "unknown", "object", "text", "varchar",
  "char", "uuid", "guid", "optional", "union", "list", "dict", "array", "number",
  "date", "datetime", "timestamp", "self", "this", "value", "name", "user", "username",
  "input", "field", "required", "default", "example", "todo", "changeme",
  // Ordinary parameter and field names. looksLikeUsername is deliberately
  // permissive — it has to accept `svc_corp_uat`, which has no digit or symbol
  // to prove itself with — so the words that surround a username keyword in
  // real code have to be excluded by name. Without these, `def login(self,
  // email, password)` had "email" redacted as an account name.
  "email", "mail", "password", "passwd", "pwd", "secret", "token", "key", "id",
  "url", "uri", "host", "hostname", "port", "path", "data", "config", "params",
  "args", "kwargs", "options", "opts", "request", "response", "req", "res",
  "session", "client", "server", "context", "ctx", "payload", "body", "headers",
  "result", "error", "err", "callback", "cb", "func", "fn", "def", "class",
  "return", "async", "await", "import", "export", "const", "let", "var",
  "credentials", "credential", "profile", "handler", "manager", "account",
]);

/**
 * Is this an account name — a person's login, or a service account?
 *
 * SEPARATE from looksLikeSecretValue() and looksLikeAssignedLiteral() because
 * both of those demand a digit or a symbol, and a username usually has neither:
 * `svc_corp_uat` was reported unredacted in this project's very first bug and
 * failed both tests. Usernames are ordinary identifiers, which is exactly what
 * makes them hard — `username: string` has the identical shape.
 *
 * So: identifier-shaped, with a length floor that drops single letters, minus
 * the type and placeholder words above. Verified to accept `svc_corp_uat`,
 * `kashyap.jain`, `svc-prod-01`, `deploy_bot` and `admin` while rejecting
 * `string`, `Optional`, `None`, `self`, `boolean`, `uuid`, `user` and `x`.
 */
export function looksLikeUsername(raw: string): boolean {
  const v = stripValueQuotes(raw);
  if (v.length < 3 || v.length > 64) return false;
  if (!/^[A-Za-z][A-Za-z0-9._@-]*$/.test(v)) return false;

  // MUST be qualified — contain a `.`, `_`, `-` or `@`.
  //
  // This is the structural half, and it is what makes the feature safe. A word
  // list alone is whack-a-mole: extending it caught `string` and `email`, then
  // `not` slipped through from `if not username or not password`, and the next
  // ordinary word would have followed. Requiring a separator disqualifies every
  // bare English and language keyword at once, without needing to name them.
  //
  // It fits the threat too. What matters here is service accounts and corporate
  // logins — `svc_corp_uat`, `deploy_bot`, `kashyap.jain`, `svc-prod-01` — and
  // those are qualified by construction.
  //
  // ACCEPTED RECALL LOSS: a single-word login (`jdoe`, `admin`) is not detected.
  // It is indistinguishable from any other bare identifier, and the generic ones
  // reveal nothing anyway — the same reasoning that stopped `/usr/bin` being
  // redacted as a file path.
  if (!/[._@-]/.test(v)) return false;

  // Test each dot/underscore/hyphen separated part, not just the whole string.
  // `username = user.name` is a property access, and rejecting it needs
  // "user" and "name" to be recognised individually — as a single string
  // `user.name` is in no denylist and sailed through, redacting code. Real
  // account names (`kashyap.jain`, `svc_corp_uat`, `deploy_bot`) have no
  // segment that is a type or placeholder word.
  //
  // ANY segment disqualifies, rather than all of them: `obj.username` is a
  // property access too. The cost is an unusual account name built entirely
  // from generic words (`admin.user`), which is a fair trade against redacting
  // ordinary code.
  const segments = v.toLowerCase().split(/[._-]/).filter(Boolean);
  return !segments.some((part) => TYPE_WORDS.has(part));
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
