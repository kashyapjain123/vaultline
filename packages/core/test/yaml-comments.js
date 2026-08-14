/**
 * Comment awareness for YAML, without a working grammar.
 *
 * tree-sitter-wasms@0.1.13 ships tree-sitter-yaml built at ABI 13 while every
 * other grammar in the package is ABI 14, and parsing through it throws
 * `TypeError: _ is not a function` on ANY input — an empty string included. It
 * is the newest release, so there is nothing to upgrade to.
 *
 * The visible symptom was a stack trace on every YAML scan. The real cost was
 * quieter: commentSpans feeds comment suppression in detectionPipeline, so
 * YAML silently lost it, and ordinary prose in comments — "# the server is
 * prod-db-01" — was being redacted as live infrastructure. That is the file
 * type the Copilot CLI host exists to review.
 *
 * So YAML (and TOML, same comment rules) uses a hand-written scanner instead.
 * These checks cover the two things that scanner has to get right: finding
 * comments, and NOT mistaking a `#` inside a quoted scalar for one.
 */

const path = require("path");
const { scanCurrentMessage } = require(path.join(__dirname, "..", "out", "detectionPipeline"));
const { tokenize } = require(path.join(__dirname, "..", "out", "tokenizer"));
const { EntityStore } = require(path.join(__dirname, "..", "out", "entityStore"));
const { SyntaxAnalyzer, hashCommentSpans, grammarForFile } = require(path.join(__dirname, "..", "out", "syntax", "syntaxAnalyzer"));

let failures = 0;
function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

async function redact(text, codeLanguage) {
  const options = { router: null, semanticMatcher: null, syntaxAnalyzer: new SyntaxAnalyzer(), codeLanguage };
  const { matches } = await scanCurrentMessage(text, options);
  return tokenize(text, matches, new EntityStore()).redactedText;
}

async function main() {
  console.log("\n[the scanner itself]");
  {
    const cases = [
      ["# whole line", 1],
      ["a: 1 # trailing", 1],
      ["a: 1\n# one\n# two\n", 2],
      ["", 0],
      ["a: 1", 0],
      // The reason this cannot be a bare /#.*/ regex.
      ['url: "http://example.com/#anchor"', 0],
      ["url: 'http://example.com/#anchor'", 0],
      ["a: b#c", 0], // no whitespace before # — part of the value
      ['pass: "a\\"# still in string"', 0],
    ];
    for (const [src, want] of cases) {
      const got = hashCommentSpans(src).length;
      check(`${JSON.stringify(src)} -> ${want} span(s)`, got === want, `got ${got}`);
    }
  }

  console.log("\n[a # inside a quoted value is not a comment, end to end]");
  {
    // If the scanner got this wrong it would mark the rest of the line as a
    // comment and suppress real matches after it — under-redaction, which is
    // the failure mode that matters.
    const text = 'note: "see http://x/#anchor"\nhost: "internal-db.corp.example.com"';
    const out = await redact(text, "config.yaml");
    check("the real hostname is still caught", !out.includes("internal-db.corp.example.com"), out);
  }

  console.log("\n[low-precision rules are suppressed inside comments]");
  {
    const text = [
      "# the server is prod-db-01 and the user is deploy_bot",
      "# see internal-wiki.corp.example.com for setup",
      "database:",
      '  host: "internal-db.corp.example.com"',
    ].join("\n");

    const out = await redact(text, "config.yaml");
    check("prose hostname in a comment is left alone", out.includes("prod-db-01"), out);
    check("prose username in a comment is left alone", out.includes("deploy_bot"), out);
    check("a hostname in a comment is left alone", out.includes("internal-wiki.corp.example.com"), out);
    check("but the real config value is still redacted", !out.includes('"internal-db.corp.example.com"'), out);
  }

  console.log("\n[HIGH-precision rules keep firing in comments — commenting out a secret is not hiding it]");
  {
    // Deliberately NOT suppressed: commenting out a credential line is one of
    // the most ordinary ways a real secret sits in a config file.
    const text = ['# password: "Hunter@123"', '# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'].join("\n");
    const out = await redact(text, "config.yaml");
    check("a commented-out password is still caught", !out.includes("Hunter@123"), out);
    check("a commented-out AWS key is still caught", !out.includes("AKIAIOSFODNN7EXAMPLE"), out);
  }

  console.log("\n[no stack trace: the broken grammar is never loaded]");
  {
    // The fallback is chosen before the parser initialises, so nothing warns.
    const warn = console.warn;
    const warnings = [];
    console.warn = (...args) => warnings.push(args.join(" "));
    try {
      await redact("a: 1 # note\nhost: db.corp.internal", "config.yaml");
      await redact("[x]\n# note", "config.toml");
    } finally {
      console.warn = warn;
    }
    check("scanning YAML and TOML produces no warnings", warnings.length === 0, warnings.join(" | "));
  }

  console.log("\n[working grammars are untouched]");
  {
    check("yaml still maps to a grammar name", grammarForFile("x.yaml") === "yaml");
    const py = await redact("# the server is prod-db-01\nhost = 'internal-db.corp.example.com'", "x.py");
    check("python comment suppression still works", py.includes("prod-db-01"), py);
    check("python code value still redacted", !py.includes("'internal-db.corp.example.com'"), py);
  }

  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
