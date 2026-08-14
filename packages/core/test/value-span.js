/**
 * Redaction-span matrix — redact the VALUE, not the whole assignment.
 *
 * A `.env` file used to come back with half its variable names destroyed:
 *
 *     EMAIL = <<EMAIL_1>>          <- kept its name
 *     <<API_KEY_1>>                <- lost "API_KEY = "
 *     <<SECRET_1>>                 <- lost "DB_PASSWORD = "
 *
 * Rules that need a key name in the pattern in order to FIND the value were
 * also redacting that key name, because scan() used the whole regex match as
 * the span. `EMAIL`/`URL` survived only because their patterns match the
 * address alone.
 *
 * Not cosmetic. The stored mapping was the whole assignment, so rehydration
 * produced broken code:
 *
 *     model writes:   os.environ["API_KEY"] = "<<API_KEY_1>>"
 *     after restore:  os.environ["API_KEY"] = "API_KEY = sk_live_..."
 *
 * The property that must NEVER regress while fixing that is coverage: every
 * case below asserts the raw secret is absent from the redacted text. Moving a
 * span is safe; shrinking it past the secret is a leak, so every case checks
 * both halves.
 */

const path = require("path");
const { scan, DEFAULT_RULES } = require(path.join(__dirname, "..", "out", "patternMatcher"));
const { scanAll } = require(path.join(__dirname, "..", "out", "detectionPipeline"));
const { tokenize, restore } = require(path.join(__dirname, "..", "out", "tokenizer"));
const { EntityStore } = require(path.join(__dirname, "..", "out", "entityStore"));
const { scanProximity } = require(path.join(__dirname, "..", "out", "nlpProximityMatcher"));
const { looksLikeSecretValue } = require(path.join(__dirname, "..", "out", "proximityUtils"));

let failures = 0;
function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

/**
 * Structural rules only — most cases here are specifically about scan()'s
 * spans. The .env case below deliberately uses the FULL pipeline instead,
 * because EMAIL/URL are detected by piiDetector and infraDetector, not by
 * DEFAULT_RULES, and those two lines are half the point of the comparison.
 */
function redact(text) {
  return tokenize(text, scan(text, DEFAULT_RULES)).redactedText;
}

async function redactFull(text) {
  const { matches } = await scanAll(text, { router: null, semanticMatcher: null });
  return tokenize(text, matches).redactedText;
}

async function envCase() {
  console.log("\n[the reported .env: every line keeps its variable name]");
  const lines = [
    ["EMAIL = alice.smith@corp.example.com", "EMAIL", "alice.smith@corp.example.com"],
    ["API_KEY = sk_live_abcd1234efgh5678", "API_KEY", "sk_live_abcd1234efgh5678"],
    ["URL = https://svc-01.corp.example.internal/api", "URL", "svc-01.corp.example.internal"],
    ["DB_PASSWORD = hunter2isnotsecure", "DB_PASSWORD", "hunter2isnotsecure"],
    ["AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
  ];
  const out = await redactFull(lines.map((l) => l[0]).join("\n"));
  for (const [, name, secret] of lines) {
    check(`${name} keeps its name`, out.includes(`${name} =`), out);
    check(`${name} value is gone`, !out.includes(secret));
  }
}

console.log("\n[each narrowed rule reports the value alone, not the assignment]");
{
  const cases = [
    ["env-var-secret", "DB_PASSWORD = hunter2isnotsecure", "hunter2isnotsecure"],
    ["generic-api-key", "api_key: abcd1234efgh5678ijkl", "abcd1234efgh5678ijkl"],
    ["generic-password-assignment", "password = hunter2isnotsecure", "hunter2isnotsecure"],
    ["aws-secret-key", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
  ];
  for (const [ruleId, text, secret] of cases) {
    const m = scan(text, DEFAULT_RULES).find((x) => x.ruleId === ruleId);
    check(`${ruleId} fires`, m !== undefined);
    if (!m) continue;
    check(`${ruleId} value is the secret alone`, m.value === secret, JSON.stringify(m.value));
    check(`${ruleId} span excludes the key name`, !text.slice(m.start, m.end).includes("="), text.slice(m.start, m.end));
    check(`${ruleId} still redacts the secret`, !redact(text).includes(secret));
  }
}

console.log("\n[quotes stay outside the token, so the line stays valid syntax]");
{
  const out = redact('"client_secret": "abcd1234efgh5678ijkl"');
  check("key name and both quotes survive", /"client_secret":\s*"<<[A-Z_]+_\d+>>"/.test(out), out);
  check("secret is gone", !out.includes("abcd1234efgh5678ijkl"));

  const single = redact("API_KEY = 'abcd1234efgh5678ijkl'");
  check("single quotes survive too", /API_KEY = '<<[A-Z_]+_\d+>>'/.test(single), single);
}

console.log("\n[restore round trip: the exact damage that motivated this]");
{
  const store = new EntityStore();
  const src = "API_KEY = sk_live_abcd1234efgh5678";
  const { redactedText } = tokenize(src, scan(src, DEFAULT_RULES), store);
  const token = /<<[A-Z_]+_\d+>>/.exec(redactedText)[0];

  const restored = restore(`os.environ["API_KEY"] = "${token}"`, store.allMappings());
  check("restored code carries the bare secret", restored.includes('"sk_live_abcd1234efgh5678"'), restored);
  check("no 'API_KEY = API_KEY' doubling", !restored.includes("API_KEY = sk_live"), restored);
}

console.log("\n[connection strings deliberately stay whole — the host is sensitive too]");
{
  const pg = "DATABASE_URL = postgres://admin:hunter2@db.internal:5432/app";
  const m = scan(pg, DEFAULT_RULES).find((x) => x.ruleId === "db-connection-string");
  check("db-connection-string matches the whole URI", m && m.value === "postgres://admin:hunter2@db.internal:5432/app", m && m.value);
  check("its host is redacted, not left behind", !redact(pg).includes("db.internal"));

  const mssql = 'conn = "Server=prod-sql-01;Database=app;User Id=sa;Password=hunter2;"';
  const s = scan(mssql, DEFAULT_RULES).find((x) => x.ruleId === "sqlserver-connection-string");
  check("sqlserver-connection-string matches the whole string", s && s.value.startsWith("Server=prod-sql-01"), s && s.value);
  check("its server name is redacted", !redact(mssql).includes("prod-sql-01"));
}

console.log("\n[coverage did not shrink: no secret survives any case]");
{
  const secrets = [
    ["AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"],
    ["token = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop", "eyJhbGciOiJIUzI1NiJ9"],
    ["export APP_SECRET=supersecretvalue123", "supersecretvalue123"],
    ["PWD = hunter2isnotsecure", "hunter2isnotsecure"],
    ["ACCESS_TOKEN = ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"],
  ];
  for (const [text, secret] of secrets) {
    check(`"${text.slice(0, 34)}…" redacts its secret`, !redact(text).includes(secret), redact(text));
  }
}

/**
 * Quotes must survive the round trip.
 *
 * The proximity and semantic matchers took the whole quoted TOKEN as the span
 * while storing the STRIPPED value, so the two disagreed and restoring dropped
 * the quotes — handing the developer back `password = hunter2isnotsecure`,
 * which is not valid syntax. The structural rules had been fixed in 1.2.7; these
 * two had not, and the proximity span starts one character earlier so it WON the
 * overlap merge. The buggy span was the one that shipped.
 */
async function quoteCases() {
  console.log("\n[quotes stay in the document, and the round trip is lossless]");
  const lines = [
    'password = "hunter2isnotsecure"',
    "password = 'hunter2isnotsecure'",
    'my password is "hunter2isnotsecure"',
    'LLM_KEY="zgfd-xhfj-lfgj-hlfhjf-gh76kd"',
    'CRED="Hunter@123"',
    'the api key is "ab12cd34ef56gh78"',
  ];

  for (const line of lines) {
    const store = new EntityStore();
    const { matches } = await scanAll(line, { router: null, semanticMatcher: null });
    const { redactedText } = tokenize(line, matches, store);
    const restored = restore(redactedText, store.allMappings());

    // Count quotes rather than pattern-match: the redaction must leave exactly
    // as many quote characters as the source had, which is precisely what
    // swallowing them into the span destroyed.
    const quotes = (t) => (t.match(/["'`]/g) ?? []).length;
    check(
      `quote count unchanged: ${line.slice(0, 30)}`,
      quotes(redactedText) === quotes(line),
      `${quotes(line)} -> ${quotes(redactedText)} in ${JSON.stringify(redactedText)}`
    );
    check(`round trip is byte-identical: ${line.slice(0, 30)}`, restored === line, `got ${JSON.stringify(restored)}`);
    check(`no quote inside any stored value: ${line.slice(0, 26)}`, store.allMappings().every((m) => !/["'`]/.test(m.originalValue)), JSON.stringify(store.allMappings().map((m) => m.originalValue)));
  }

  console.log("\n[structural and proximity rules agree on the span]");
  {
    // They disagreed, and mergeAndFinalize picks by start position — so the one
    // that included the quotes won every time.
    const line = 'password = "hunter2isnotsecure"';
    const structural = scan(line, DEFAULT_RULES).find((m) => m.ruleId === "generic-password-assignment");
    const proximity = scanProximity(line).find((m) => m.ruleId === "proximity-password");
    check("both found it", !!structural && !!proximity);
    if (structural && proximity) {
      check("identical spans", structural.start === proximity.start && structural.end === proximity.end,
        `structural ${structural.start}-${structural.end}, proximity ${proximity.start}-${proximity.end}`);
    }
  }

  console.log("\n[looksLikeSecretValue no longer accepts assignments]");
  for (const v of ['LLM_KEY="zgfd-xhfj-lfgj-hlfhjf-gh76kd"', 'CRED="Hunter@123"', "x+y=12345678", "a=1234567b"]) {
    check(`rejects ${v.slice(0, 30)}`, !looksLikeSecretValue(v));
  }
  for (const v of ["Hunter@123", "Av3Xz21@UAT", "hunter2isnotsecure", "zgfd-xhfj-lfgj-hlfhjf-gh76kd"]) {
    check(`still accepts ${v}`, looksLikeSecretValue(v));
  }
}

envCase().then(quoteCases).then(() => {
  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
});
