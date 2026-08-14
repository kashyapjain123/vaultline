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
  expectValues("the literal prefix (with its host) is still redacted", line, [INTERNAL + "/"], "url");
  check("the interpolation is NOT swallowed", !infra(line, "url")[0].includes("${"));
  check("the backtick is NOT swallowed", !infra(line, "url")[0].includes("`"));
}

console.log("\n[trailing punctuation is trimmed]");
{
  expectValues("markdown link", `See [docs](${INTERNAL}/docs) for more.`, [`${INTERNAL}/docs`], "url");
  expectValues("end of sentence", `Deployed to ${INTERNAL}.`, [INTERNAL], "url");
  expectValues("wrapped in parens", `(${INTERNAL})`, [INTERNAL], "url");
  expectValues("trailing comma", `urls = [${INTERNAL}, x]`, [INTERNAL], "url");
  expectValues("trailing semicolon", `const u = ${INTERNAL};`, [INTERNAL], "url");
  expectValues("trailing colon", `Host: ${INTERNAL}:`, [INTERNAL], "url");
  expectValues("multiple trailing marks", `Really? ${INTERNAL}?!`, [INTERNAL], "url");
}

console.log("\n[balanced punctuation is NOT trimmed]");
{
  const wiki = "https://en.wikipedia.org/wiki/Foo_(bar)";
  expectValues("wikipedia-style parens survive", wiki, [wiki], "url");
  expectValues("…and still survive inside a sentence", `See ${wiki}.`, [wiki], "url");
  const q = `${INTERNAL}/x?a=b&c=d`;
  expectValues("query string untouched", q, [q], "url");
  const trailingSlash = `${INTERNAL}/api/`;
  expectValues("trailing slash is part of the path", trailingSlash, [trailingSlash], "url");
}

console.log("\n[file paths trim the same way]");
{
  expectValues("unix path, sentence end", "Config lives at /etc/nginx/nginx.conf.", ["/etc/nginx/nginx.conf"], "unix");
  expectValues("unix path in parens", "(see /etc/passwd)", ["/etc/passwd"], "unix");
  expectValues("windows path, trailing comma", "Open C:\\Users\\kash\\app.log, then retry", ["C:\\Users\\kash\\app.log"], "windows");
}

console.log("\n[loopback still suppressed, externals still classified]");
{
  expectValues("loopback emits nothing", "http://localhost:9000/health", [], "url");
  expectValues("127.0.0.1 emits nothing", "http://127.0.0.1:9000/health", [], "url");
  const pub = "https://api.github.com/repos";
  expectValues("public URL still flagged (unchanged behaviour)", pub, [pub], "url");
}

console.log("\n[end to end: the reported line survives redaction intact]");
{
  const line = "const url = `https://${process.env.HOST_G}:${process.env.port_G}`;";
  scanCurrentMessage(line, { router: null, semanticMatcher: null }).then(({ matches }) => {
    const out = tokenize(line, matches).redactedText;
    check("redacted text is byte-identical to the source", out === line, JSON.stringify(out));

    console.log("\n" + "=".repeat(80));
    console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
    process.exit(failures === 0 ? 0 : 1);
  });
}
