/**
 * Which filesystem paths are worth redacting.
 *
 * Vaultline used to flag anything under 24 filesystem roots, so `/dev/null`,
 * `/usr/bin/python` and `/etc/nginx/nginx.conf` were all replaced with tokens.
 * Those are byte-identical on every machine on earth: redacting them cost the
 * model useful context and revealed nothing in exchange.
 *
 * What actually leaks is narrower, and splits in two:
 *   - account names   — /Users/<name>, /home/<name>, /root
 *   - org-specific names — /opt/acme-payments, /Volumes/AcmeShare
 *
 * TWO failure directions, so the suite asserts both: flagging a universal path
 * is noise that trains people to ignore highlights, and missing a home
 * directory leaks an account name. A third property matters just as much and is
 * easy to break while narrowing — a repo-relative fragment like `/src/index.ts`
 * must still not be treated as a filesystem location at all.
 */

const path = require("path");
const { scanInfraStructural } = require(path.join(__dirname, "..", "out", "infraDetector"));

let failures = 0;
function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

const pathValues = (text) =>
  scanInfraStructural(text)
    .filter((m) => m.ruleId.includes("path"))
    .map((m) => m.value);

function expectFlagged(text, expected = text) {
  const got = pathValues(text);
  check(`flags ${text}`, got.includes(expected), JSON.stringify(got));
}

function expectIgnored(text) {
  const got = pathValues(text);
  check(`ignores ${text}`, got.length === 0, JSON.stringify(got));
}

console.log("\n[identifying paths — an account, product or volume name]");
expectFlagged("/Users/kash/projects/secret-app");
expectFlagged("/home/kash/.aws/credentials");
expectFlagged("/root/.ssh/id_rsa");
expectFlagged("/opt/acme-payments/config.yml");
expectFlagged("/Volumes/AcmeShare/finance/q3.xlsx");
expectFlagged("/srv/acme-api/current/.env");
expectFlagged("/mnt/backups/customer-db.sql");

console.log("\n[universal paths — identical on every machine, nothing to protect]");
expectIgnored("/dev/null");
expectIgnored("/usr/bin/python");
expectIgnored("/usr/local/lib/node_modules/npm");
expectIgnored("/etc/nginx/nginx.conf");
expectIgnored("/var/log/syslog");
expectIgnored("/tmp/build-output");
expectIgnored("/proc/cpuinfo");
expectIgnored("/System/Library/Frameworks");
expectIgnored("/Applications/Visual Studio Code.app");

console.log("\n[bare roots identify nobody]");
// "/opt" and "/Volumes" alone name no product and no share; only a second
// segment makes them specific.
expectIgnored("/opt");
expectIgnored("/Users");
// "/root" IS an account's home directory, so isIdentifyingPath() accepts it
// without a second segment — but UNIX_PATH never offers it one, since that
// regex requires two or more segments. Pre-existing and left alone: a bare
// "/root" names a directory every Linux box has, while the case that actually
// leaks ("/root/.ssh/id_rsa") has the segments it needs and is covered above.
expectIgnored("/root");

console.log("\n[still not filesystem paths at all — the pre-existing narrowing]");
expectIgnored("/src/index.ts");
expectIgnored("/components/Button.tsx");
expectIgnored("./etc/nginx.conf");
expectIgnored("../home/config");

console.log("\n[trailing punctuation is still trimmed, not swallowed]");
{
  const got = pathValues("Config lives at /Users/kash/.zshrc.");
  check("sentence-ending period excluded", got.includes("/Users/kash/.zshrc"), JSON.stringify(got));
  const parens = pathValues("(see /Users/kash/notes)");
  check("closing paren excluded", parens.includes("/Users/kash/notes"), JSON.stringify(parens));
}

console.log("\n[windows paths]");
{
  const got = scanInfraStructural("Open C:\\Users\\kash\\app.log, then retry")
    .filter((m) => m.ruleId.includes("windows"))
    .map((m) => m.value);
  check("home path flagged, comma trimmed", got.includes("C:\\Users\\kash\\app.log"), JSON.stringify(got));
}

console.log("\n" + "=".repeat(80));
console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
