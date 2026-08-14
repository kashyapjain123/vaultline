/**
 * Code-versus-secret matrix.
 *
 * Seven reports from running 1.2.7 over real Python. The structural rules anchor
 * on a key name (`password =`, `API_KEY =`) to FIND a value, which tells you
 * something follows the operator but nothing about what — so a type annotation,
 * a function call, a subscript and a bare `return` from the next line all
 * registered as secrets:
 *
 *     password: Optional[str])            -> flagged "Optional[str])"
 *     PWD = os.environ.get("...","...")   -> flagged "os.environ.get("
 *     if not password:\n    return None   -> flagged "return"
 *     LLM_API_KEY = get_api_Key(os.environ[  -> flagged "get_api_Key(os.environ["
 *
 * In a security tool this is the expensive direction of error: a developer who
 * sees `return` highlighted as a secret stops trusting the highlights, and then
 * stops reading them — so the false positives cost more than they look.
 *
 * The same pass closed three misses (`LLM_KEY`, `CRED`, `Hunter@123`), so every
 * case here asserts BOTH halves: code is not flagged, and real secrets still
 * are. Tightening precision must never quietly cost coverage.
 */

const path = require("path");
// scanCurrentMessage, NOT scanAll: the live prompt path and the editor
// highlighting path both route contextual detectors PER LINE, precisely so a
// keyword on one line cannot claim a value from another. Testing through
// scanAll would pool the lines and measure behaviour no user ever sees.
const { scanCurrentMessage } = require(path.join(__dirname, "..", "out", "detectionPipeline"));
const { looksLikeAssignedLiteral, looksLikeSecretValue } = require(path.join(__dirname, "..", "out", "proximityUtils"));

const OPTS = { router: null, semanticMatcher: null };

let failures = 0;
function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

async function values(text) {
  const { matches } = await scanCurrentMessage(text, OPTS);
  return matches.map((m) => m.value);
}

/** Asserts the exact set of flagged values for a line — nothing extra, nothing missing. */
async function expectExactly(label, text, want) {
  const got = await values(text);
  const ok = got.length === want.length && want.every((w) => got.includes(w));
  check(label, ok, `expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`);
}

async function main() {
  console.log("\n[the seven reported cases, verbatim]");
  await expectExactly("1) subscript alone is not a secret", "os.environ['API_KEY']", []);
  await expectExactly(
    "2) call is not a secret, but its password argument is",
    'PWD = os.environ.get("OPENSEARCH_PASSWORD","Av3Xz21@UAT")',
    ["Av3Xz21@UAT"]
  );
  await expectExactly(
    "3) type annotation is not a secret",
    "def login(self, email: Optional[str], password: Optional[str])",
    []
  );
  await expectExactly("4) next-line keyword is not a secret", "if not email or not password:\n     return None", []);
  await expectExactly("5) LLM_KEY value is caught", 'LLM_KEY="zgfd-xhfj-lfgj-hlfhjf-gh76kd"', [
    "zgfd-xhfj-lfgj-hlfhjf-gh76kd",
  ]);
  await expectExactly("6) CRED value is caught", 'CRED="Hunter@123"', ["Hunter@123"]);
  await expectExactly(
    "7) call + subscript is not a secret",
    "LLM_API_KEY = get_api_Key(os.environ['API_KEYSECRET_KEY_L']",
    []
  );

  console.log("\n[looksLikeAssignedLiteral: literal vs code]");
  {
    const code = ["os.environ", "os.environ.get", "get_api_Key", "Optional", "return", "None", "default_password"];
    for (const v of code) check(`rejects code "${v}"`, !looksLikeAssignedLiteral(v, `password = ${v}`));

    const secrets = ["hunter2isnotsecure", "Av3Xz21@UAT", "Hunter@123", "zgfd-xhfj-lfgj-hlfhjf-gh76kd"];
    for (const v of secrets) check(`accepts secret "${v}"`, looksLikeAssignedLiteral(v, `password = ${v}`));

    // The accepted cost, pinned deliberately rather than left incidental.
    check("rejects unquoted letmein (accepted recall loss)", !looksLikeAssignedLiteral("letmein", "password = letmein"));
    check('accepts QUOTED "letmein"', looksLikeAssignedLiteral("letmein", 'password = "letmein"'));
    check("accepts single-quoted 'letmein'", looksLikeAssignedLiteral("letmein", "password = 'letmein'"));
    // A dotted or underscored name is code precisely BECAUSE of those characters.
    check("'.' alone is not credential evidence", !looksLikeAssignedLiteral("a.b.c.d.e", "password = a.b.c.d.e"));
    check("'_' alone is not credential evidence", !looksLikeAssignedLiteral("some_var_name", "password = some_var_name"));
  }

  console.log("\n[looksLikeSecretValue: the new symbol shape]");
  {
    check("Hunter@123", looksLikeSecretValue("Hunter@123"));
    check("Av3Xz21@UAT", looksLikeSecretValue("Av3Xz21@UAT"));
    check("still rejects prose", !looksLikeSecretValue("description"));
    check("still rejects a dotted path", !looksLikeSecretValue("os.environ.get"));
    check("rejects symbol without digit", !looksLikeSecretValue("Hunter@abc"));
    check("rejects digit without symbol or letters+digits rule", !looksLikeSecretValue("....1234"));
  }

  console.log("\n[newline containment: a value never comes from the next line]");
  for (const sep of [":", "=", ": ", " ="]) {
    await expectExactly(`"password${sep}" + newline + word`, `password${sep}\n    something_here`, []);
  }
  await expectExactly("trailing spaces before the newline", "password:   \n    return None", []);

  console.log("\n[compound identifiers]");
  {
    const got = await values('cfg = {"OPENSEARCH_PASSWORD": "Av3Xz21@UAT"}');
    check("OPENSEARCH_PASSWORD anchors its value", got.includes("Av3Xz21@UAT"), JSON.stringify(got));
    await expectExactly("but a compound name with no value stays quiet", "PASSWORD_POLICY_DOC = handbook", []);
  }

  console.log("\n[ordinary Python produces no matches at all]");
  {
    const src = [
      "import os",
      "from typing import Optional",
      "",
      "class Auth:",
      "    def login(self, email: Optional[str], password: Optional[str]) -> Optional[dict]:",
      "        if not email or not password:",
      "            return None",
      "        token = self.session.get(email)",
      "        secret = compute_secret(email)",
      "        return {'user': email, 'token': token, 'secret': secret}",
      "",
      "def get_config():",
      "    return {'api_key': os.environ.get('API_KEY'), 'url': os.environ['SERVICE_URL']}",
    ].join("\n");
    const got = await values(src);
    check("zero matches over a whole ordinary file", got.length === 0, JSON.stringify(got));
  }

  console.log("\n[real secrets in that same shape are still caught]");
  {
    const src = [
      "API_KEY = 'sk_live_abcd1234efgh5678'",
      "DB_PASSWORD = \"hunter2isnotsecure\"",
      "CRED = 'Hunter@123'",
      "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
    ].join("\n");
    const got = await values(src);
    for (const s of ["sk_live_abcd1234efgh5678", "hunter2isnotsecure", "Hunter@123", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]) {
      check(`still catches ${s.slice(0, 26)}`, got.includes(s), JSON.stringify(got));
    }
  }

  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
