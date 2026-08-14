/**
 * URL and path span matrix.
 *
 * Reported against 1.2.8:
 *
 *     const url = `https://${process.env.HOST_G}:${process.env.port_G}`;
 *
 * was redacted as ``https://${process.env.HOST_G}:${process.env.port_G}`;`` —
 * closing backtick and semicolon included. Wrong twice over: the span ran past
 * the URL into surrounding syntax, and that string contains no hostname at all,
 * only `${…}` expressions, so redacting it replaced working code and protected
 * nothing.
 *
 * Probing wider found seven of nine URL shapes over-matching, plus the same flaw
 * in the unix and windows path rules: the regexes match greedily to whitespace
 * and absorb whatever ends the sentence.
 *
 * TWO opposing failure modes, so every case asserts an EXACT value: too wide
 * corrupts the surrounding text, too narrow leaks the host. The single most
 * important assertion in this file is the template literal with a REAL host —
 * a lazy "skip anything containing ${" fix would silently stop redacting
 * internal hostnames, which is precisely what this rule exists to catch.
 */

const path = require("path");
const { scanInfraStructural } = require(path.join(__dirname, "..", "out", "infraDetector"));
const { scanCurrentMessage } = require(path.join(__dirname, "..", "out", "detectionPipeline"));
const { tokenize } = require(path.join(__dirname, "..", "out", "tokenizer"));

let failures = 0;
function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

/** Values flagged by the infra rules, in document order. */
function infra(text, ruleFilter) {
  return scanInfraStructural(text)
    .filter((m) => (ruleFilter ? m.ruleId.includes(ruleFilter) : true))
    .map((m) => m.value);
}

function expectValues(label, text, want, ruleFilter) {
  const got = infra(text, ruleFilter);
  const ok = got.length === want.length && want.every((w, i) => got[i] === w);
  check(label, ok, `expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`);
}

const INTERNAL = "https://svc-01.corp.example.internal";
const HOST = "svc-01.corp.example.internal";

console.log("\n[the reported case: a URL built entirely from interpolations]");
{
  const line = "const url = `https://${process.env.HOST_G}:${process.env.port_G}`;";
  expectValues("nothing is flagged — there is no hostname to protect", line, [], "url");
}

console.log("\n[under-redaction guard: a REAL host behind an interpolation]");
{
  // The case a careless fix breaks. Truncating at `${` must keep the literal
  // prefix so the internal hostname is still caught.
  const line = "const u = `" + INTERNAL + "/${path}`;";
  expectValues("the host behind the interpolation is still redacted", line, [HOST], "url");
  check("the interpolation is NOT swallowed", !infra(line, "url")[0].includes("${"));
  check("the backtick is NOT swallowed", !infra(line, "url")[0].includes("`"));
}

console.log("\n[trailing punctuation is trimmed]");
{
  expectValues("markdown link", `See [docs](${INTERNAL}/docs) for more.`, [HOST], "url");
  expectValues("end of sentence", `Deployed to ${INTERNAL}.`, [HOST], "url");
  expectValues("wrapped in parens", `(${INTERNAL})`, [HOST], "url");
  expectValues("trailing comma", `urls = [${INTERNAL}, x]`, [HOST], "url");
  expectValues("trailing semicolon", `const u = ${INTERNAL};`, [HOST], "url");
  expectValues("trailing colon", `Host: ${INTERNAL}:`, [HOST], "url");
  expectValues("multiple trailing marks", `Really? ${INTERNAL}?!`, [HOST], "url");
}

console.log("\n[balanced punctuation is NOT trimmed]");
{
  const wiki = "https://en.wikipedia.org/wiki/Foo_(bar)";
  expectValues("wikipedia-style parens survive", wiki, ["en.wikipedia.org"], "url");
  expectValues("…and still survive inside a sentence", `See ${wiki}.`, ["en.wikipedia.org"], "url");
  const q = `${INTERNAL}/x?a=b&c=d`;
  expectValues("query string leaves only the host redacted", q, [HOST], "url");
  const trailingSlash = `${INTERNAL}/api/`;
  expectValues("trailing slash stays in the path", trailingSlash, [HOST], "url");
}

console.log("\n[loopback still suppressed, externals still classified]");
{
  expectValues("loopback emits nothing", "http://localhost:9000/health", [], "url");
  expectValues("127.0.0.1 emits nothing", "http://127.0.0.1:9000/health", [], "url");
  const pub = "https://api.github.com/repos";
  expectValues("public URL: host still flagged", pub, ["api.github.com"], "url");
}

async function asyncChecks() {
  const OPTS = { router: null, semanticMatcher: null };
  const redact = async (line) => {
    const { matches } = await scanCurrentMessage(line, OPTS);
    return { out: tokenize(line, matches).redactedText, matches };
  };

  console.log("\n[the path survives — the entire point of host-only redaction]");
  {
    const line = `const u = "${INTERNAL}/api/getToken";`;
    const { out } = await redact(line);
    check("path is still readable by the model", out.includes("/api/getToken"), out);
    check("host is gone", !out.includes(HOST), out);
    check("scheme survives", out.includes("https://"), out);
  }

  console.log("\n[a secret in the query string is caught separately]");
  {
    // Only reachable because the URL span shrank to the host: while it covered
    // the whole URL, the overlap merge discarded any match inside it.
    const line = `${INTERNAL}/reset?token=abc123def456`;
    const { out, matches } = await redact(line);
    check("query secret redacted", !out.includes("abc123def456"), out);
    check(
      "…by a rule other than the URL one",
      matches.some((m) => !m.ruleId.includes("url")),
      JSON.stringify(matches.map((m) => m.ruleId))
    );
  }

  console.log("\n[end to end: the reported line survives redaction intact]");
  {
    const line = "const url = `https://${process.env.HOST_G}:${process.env.port_G}`;";
    const { out } = await redact(line);
    check("redacted text is byte-identical to the source", out === line, JSON.stringify(out));
  }

  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

asyncChecks();
