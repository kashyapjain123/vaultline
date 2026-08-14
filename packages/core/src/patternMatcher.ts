/**
 * Layer 2: Pattern Matcher
 *
 * Pure regex/rule-based detection of structurally identifiable secrets.
 * No ML, no network calls, sub-millisecond per invocation.
 *
 * This is the always-on baseline. Every other layer can degrade — routing
 * needs centroids, semantic matching needs an embedding server, syntax-aware
 * suppression needs a grammar — and each of them fails open when it can't
 * run. This one has no such dependency, so whatever else is unavailable,
 * vendor API keys, PEM blocks, JWTs and connection strings are still caught.
 */

export type Severity = "low" | "medium" | "high";

/** Orders severities for comparison. Exported here (rather than kept private in policyEngine.ts) so every module that needs to compare or clamp a severity shares one definition. */
export const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2 };

/**
 * High-level tag for what kind of sensitive thing a match represents.
 * SECRET: credentials, keys, tokens. PII: personal/financial identifiers.
 * INFRA: internal infrastructure details (hosts, ports, internal URLs,
 * file paths) that aren't personal data but still shouldn't leave the
 * machine.
 */
// proximityUtils imports nothing, so this direction introduces no cycle. The
// "is this a literal or is it code" judgement lives there beside
// looksLikeSecretValue(), so every layer that has to answer a question about a
// candidate value gets one shared answer rather than a private copy.
import { looksLikeAssignedLiteral, looksLikeUsername } from "./proximityUtils";

export type Category = "SECRET" | "PII" | "INFRA" | "BUSINESS";

export interface PatternRule {
  id: string;
  label: string;
  severity: Severity;
  category: Category;
  regex: RegExp;

  /**
   * Which capture group holds the sensitive VALUE, when the pattern has to
   * match more than the value in order to find it.
   *
   * A rule like `API_KEY = <secret>` needs the key name in its pattern as an
   * anchor, but the key name is NOT the secret — and redacting the whole match
   * threw it away, so a `.env` file came back as a column of bare tokens with
   * every variable name destroyed. Worse, the stored mapping then WAS the whole
   * assignment, so rehydrating `<<API_KEY_1>>` in generated code produced
   * `os.environ["API_KEY"] = "API_KEY = sk_live_..."`.
   *
   * Naming the group here keeps the anchor in the pattern and out of the
   * redaction, which is what every other detector already does (see
   * nlpProximityMatcher's note on not swallowing the keyword).
   *
   * REQUIRES the `d` flag on `regex` — that is what populates match indices.
   * Omit this field entirely when the whole match genuinely is the secret, as
   * for connection strings, where the host is as sensitive as the password.
   */
  valueGroup?: number;

  /**
   * Last word on whether a captured value is really a value. The match is
   * discarded entirely when this returns false.
   *
   * A regex can say "something follows `password =`" but not "that something is
   * a literal rather than an expression", and the difference is what made
   * `password: Optional[str])`, `PWD = os.environ.get(` and a bare `return` on
   * the following line all register as secrets. Character classes alone could
   * not express it: after excluding brackets, `Optional` and `return` are still
   * perfectly good 6+ character words.
   *
   * A predicate here rather than an ever-more-baroque regex keeps the rule
   * readable, makes the judgement unit-testable on its own, and applies
   * everywhere scan() is used — including the editor highlighting path, which
   * is where these were being seen.
   */
  valueFilter?: (value: string, wholeMatch: string) => boolean;
}

export interface Match {
  ruleId: string;
  label: string;
  severity: Severity;
  category: Category;
  value: string;
  start: number;
  end: number;
}

/**
 * Starter rule set. This is intentionally small for this — the real
 * product's rule set is meant to grow from the audit-log feedback loop
 * (see auditLog.ts) rather than being hand-maintained forever.
 */
export const DEFAULT_RULES: PatternRule[] = [
  {
    id: "aws-access-key",
    label: "AWS Access Key ID",
    severity: "high",
    category: "SECRET",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    id: "aws-secret-key",
    label: "AWS Secret Access Key (assignment)",
    severity: "high",
    category: "SECRET",
    regex: /\b(?:aws_secret_access_key|secret_access_key)[ \t]*[:=][ \t]*['"`]?([A-Za-z0-9/+=]{40})['"`]?/gid,
    valueGroup: 1,
  },
  {
    id: "private-key-block",
    label: "PEM Private Key Block",
    severity: "high",
    category: "SECRET",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  },
  {
    id: "generic-api-key",
    label: "Generic API Key Assignment",
    severity: "high",
    category: "SECRET",
    // The `["']?` on BOTH sides of the key name is what makes the JSON form
    // work. Without it, `"api_key": "abc..."` never matched: the closing
    // quote of the key sits between the name and the ':', so `\s*[:=]` failed
    // and only the bare YAML/env form (`api_key: abc...`) was ever caught —
    // a large blind spot, since JSON is the most common shape this arrives in.
    // Key names are the unambiguous compound credential fields; bare "secret"
    // / "token" are deliberately NOT here (they'd hit TypeScript annotations
    // like `token: string`), and are left to the proximity matcher.
    regex:
      /["'`]?\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|secret[_-]?key|client[_-]?secret|access[_-]?key)\b["'`]?[ \t]*[:=][ \t]*['"`]?([A-Za-z0-9_\-]{16,})['"`]?/gid,
    valueGroup: 1,
  },
  {
    id: "openai-api-key",
    label: "OpenAI API Key",
    severity: "high",
    category: "SECRET",
    // Classic `sk-<48>` plus the newer prefixed forms (sk-proj-, sk-svcacct-,
    // sk-admin-). Requires 20+ trailing key characters so a bare "sk-" in
    // ordinary prose can't trip it. Note the HYPHEN — Stripe's keys use an
    // underscore (sk_live_...) and are matched by the separate rule below,
    // so the two never collide.
    regex: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "stripe-api-key",
    label: "Stripe API Key",
    severity: "high",
    category: "SECRET",
    // pk_ = publishable, sk_ = secret, rk_ = restricted; each in test or live
    // mode. Publishable keys are technically safe to expose, but they still
    // identify the account, and a developer pasting one usually means the
    // secret key is nearby too — cheap to flag.
    regex: /\b(?:pk|sk|rk)_(?:test|live)_[A-Za-z0-9]{10,}\b/g,
  },
  {
    id: "jwt",
    label: "JSON Web Token",
    severity: "medium",
    category: "SECRET",
    regex: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  },
  {
    id: "slack-token",
    label: "Slack Token",
    severity: "high",
    category: "SECRET",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    id: "github-token",
    label: "GitHub Token",
    severity: "high",
    category: "SECRET",
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
  },
  {
    id: "generic-password-assignment",
    label: "Password Assignment",
    severity: "medium",
    category: "SECRET",
    // `["']?` around the key name handles the quoted JSON form — see the
    // generic-api-key comment above for why that was a blind spot.
    // `[ \t]*` around the operator, NOT `\s*`: `\s` includes the line break, so
    // `if not email or not password:` at the end of a line let the match run on
    // and claim `return` from the statement below it. A value lives on its key's
    // own line.
    //
    // The value class excludes brackets and parens so a call or subscript ends
    // the match instead of being swallowed whole; valueFilter then rejects what
    // is left when it is a bare identifier rather than a literal.
    // Backticks count as quotes on BOTH sides. Markdown and JS template
    // literals wrap values in them constantly, and without this a value ends up
    // with a trailing ` glued on — the same over-wide span the URL rule had in
    // 1.2.8. Found by scanning this repo's own test files.
    regex: /["'`]?\b(?:password|passwd|pwd)\b["'`]?[ \t]*[:=][ \t]*['"`]?([^\s'"`;,}()[\]{}]{6,})['"`]?/gid,
    valueGroup: 1,
    valueFilter: looksLikeAssignedLiteral,
  },
  {
    id: "username-assignment",
    label: "Username Assignment",
    severity: "medium",
    category: "PII",
    // Account names in their code/config forms: USERNAME=svc_corp_uat,
    // "username": "svc_corp_uat", login = deploy_bot.
    //
    // valueFilter is looksLikeUsername rather than looksLikeAssignedLiteral,
    // because an account name has no digit or symbol to prove itself with — the
    // literal test that keeps `password: Optional[str]` out would reject every
    // real username too. The type-word denylist inside looksLikeUsername is
    // what keeps `username: string` from matching here.
    regex:
      // The capture must END on an alphanumeric. Separators are legal INSIDE an
      // account name (`kashyap.jain`, `svc_corp_uat`) but never at the end, so
      // without this `login: kashyap.jain.` swallowed the sentence's full stop
      // into the value. Same trailing-punctuation family as the URL and path
      // rules; the proximity path handles it in unquotedSpan(), this is the
      // structural half.
      /["'`]?\b(?:user[_-]?name|user[_-]?id|login|account[_-]?name)\b["'`]?[ \t]*[:=][ \t]*['"`]?([A-Za-z][A-Za-z0-9._@-]{1,62}[A-Za-z0-9])['"`]?/gid,
    valueGroup: 1,
    valueFilter: (value) => looksLikeUsername(value),
  },
  {
    id: "env-var-secret",
    label: "Environment Variable Secret Assignment",
    severity: "high",
    category: "SECRET",
    // SCREAMING_CASE variable whose NAME advertises a credential, assigned a
    // non-trivial value — `export MY_APP_SECRET=...`, `DB_TOKEN=...`. The
    // credential words must appear inside the name, which is what separates
    // this from ordinary config (`NODE_ENV=production` has none of them).
    // Bare `KEY` is deliberately excluded: PRIMARY_KEY / FOREIGN_KEY /
    // PUBLIC_KEY are common and not secrets, so only the compound forms
    // (API_KEY, ACCESS_KEY, PRIVATE_KEY) count.
    regex:
      /\b(?:export[ \t]+)?[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|CRED|KEY|AUTH)[A-Z0-9_]*[ \t]*=[ \t]*["'`]?([^\s"'`()[\]{}]{8,})["'`]?/gd,
    valueGroup: 1,
    valueFilter: looksLikeAssignedLiteral,
  },
  {
    id: "db-connection-string",
    label: "Database Connection String with Credentials",
    severity: "high",
    category: "SECRET",
    // The trailing class excludes quotes, backticks and semicolons, which are
    // never part of a connection URI but always follow one in real code:
    // `const u = "postgres://...app";` used to match through to `app";`, so the
    // redaction swallowed the closing quote and the statement terminator. Same
    // over-wide-span family as the URL rule fixed in 1.2.8 — this one was
    // missed, and the self-scan over this repo's own tests found it.
    regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s:]+:[^\s@]+@[^\s"'`;,]+/gi,
  },
  {
    id: "sqlserver-connection-string",
    label: "SQL Server Connection String with Credentials",
    severity: "high",
    category: "SECRET",
    // Semicolon-delimited ADO.NET/ODBC style, which has no URI scheme to
    // anchor on. Shape (deliberately written across several lines here so
    // this comment doesn't match its own rule):
    //   Server=…
    //   Database=…
    //   User Id=…
    //   Password=…
    // Requires BOTH a Server/Data Source key and a Password/Pwd key so an
    // ordinary `Server=localhost;` alone doesn't qualify.
    //
    // Matching the WHOLE string matters: generic-password-assignment already
    // caught the `Password=x` fragment, but that redacted only the password
    // and left Server / Database / User Id exposed. This rule starts earlier
    // in the string, so the pipeline's overlap merge keeps it and drops the
    // narrower fragment match.
    regex: /\b(?:Server|Data\s+Source)\s*=[^;\n]*;(?:[^;\n]*;)*?[^;\n]*\b(?:Password|Pwd)\s*=[^;\n]*;?/gi,
  },
  // Note: standalone IP address detection (private and public) now lives in
  // infraDetector.ts, which also handles URL-embedded hosts consistently —
  // keeping a separate rule here would double-flag the same span.
];

export function scan(text: string, rules: PatternRule[] = DEFAULT_RULES): Match[] {
  const matches: Match[] = [];

  for (const rule of rules) {
    // Reset lastIndex since these regexes are reused across calls (global flag keeps state).
    rule.regex.lastIndex = 0;
    let result: RegExpExecArray | null;
    while ((result = rule.regex.exec(text)) !== null) {
      // Narrow to the rule's value group when it declares one. `indices` is
      // only populated for a regex carrying the `d` flag, so a rule that
      // declares valueGroup but forgets `d` — or whose optional group did not
      // participate in this match — falls back to the whole match. That is the
      // safe direction to fail: over-redacting loses context, under-redacting
      // leaks the secret.
      const span = rule.valueGroup !== undefined ? result.indices?.[rule.valueGroup] : undefined;
      const value = span ? result[rule.valueGroup!] : result[0];

      if (rule.valueFilter && !rule.valueFilter(value, result[0])) {
        // Guard the same zero-length case the push path guards, since we skip
        // past it without advancing lastIndex ourselves.
        if (result[0].length === 0) rule.regex.lastIndex++;
        continue;
      }

      matches.push({
        ruleId: rule.id,
        label: rule.label,
        severity: rule.severity,
        category: rule.category,
        value,
        start: span ? span[0] : result.index,
        end: span ? span[1] : result.index + result[0].length,
      });
      // Guard against zero-length matches causing infinite loops.
      if (result[0].length === 0) {
        rule.regex.lastIndex++;
      }
    }
  }

  // Sort by position so downstream tokenization can walk the string left to right.
  return matches.sort((a, b) => a.start - b.start);
}
