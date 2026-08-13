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
export type Category = "SECRET" | "PII" | "INFRA" | "BUSINESS";

export interface PatternRule {
  id: string;
  label: string;
  severity: Severity;
  category: Category;
  regex: RegExp;
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
    regex: /\b(?:aws_secret_access_key|secret_access_key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/gi,
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
      /["']?\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|secret[_-]?key|client[_-]?secret|access[_-]?key)\b["']?\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}['"]?/gi,
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
    regex: /["']?\b(?:password|passwd|pwd)\b["']?\s*[:=]\s*['"]?[^\s'";,}]{6,}['"]?/gi,
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
      /\b(?:export\s+)?[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|AUTH)[A-Z0-9_]*\s*=\s*["']?[^\s"']{8,}["']?/g,
  },
  {
    id: "db-connection-string",
    label: "Database Connection String with Credentials",
    severity: "high",
    category: "SECRET",
    regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s:]+:[^\s@]+@[^\s]+/gi,
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
      matches.push({
        ruleId: rule.id,
        label: rule.label,
        severity: rule.severity,
        category: rule.category,
        value: result[0],
        start: result.index,
        end: result.index + result[0].length,
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
