/**
 * Secrets must not be written to disk by default.
 *
 * EntityStore mirrors its token -> real value table to JSON when given a
 * persist path, and the VS Code host used to pass one unconditionally. So every
 * password, API key and AWS secret Vaultline caught was written to
 * globalStorage/sessions/<uuid>.json in clear:
 *
 *     { "token": "<<PASSWORD_1>>", "originalValue": "<the real password>", ... }
 *
 * No setting guarded it, nothing warned, and nothing ever cleaned it up — while
 * `auditLogIncludeValues` sat right beside it defaulting to false for exactly
 * this reason. It also bought nothing: the host mints a fresh session id per
 * activation, so the file was never read back.
 *
 * The assertion that matters is the second one in each case: not just "no file
 * where we expected it" but "the plaintext secret appears in NO file under the
 * storage directory". A test that only checks the known path would miss the
 * value being written somewhere else.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

const { GuardSession } = require(path.join(__dirname, "..", "out", "guardSession"));
const { AuditLog } = require(path.join(__dirname, "..", "out", "auditLog"));

const SECRET = "hunter2isnotsecure";
const PROMPT = `my password is ${SECRET}`;

let failures = 0;
function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

/** Every file under dir, recursively. */
function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

function containsSecretAnywhere(dir) {
  return walk(dir).filter((f) => {
    try {
      return fs.readFileSync(f, "utf-8").includes(SECRET);
    } catch {
      return false;
    }
  });
}

function makeSession(storageDir, persistPath) {
  const context = {
    auditLog: new AuditLog(storageDir),
    scanOptions: () => ({ router: null, semanticMatcher: null }),
    policyConfig: () => ({ blockOnHighSeverity: false, blockOnBusinessContent: false }),
    auditIncludesValues: () => false,
  };
  return new GuardSession(context, persistPath);
}

async function main() {
  console.log("\n[default: persistence off — nothing is written]");
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vaultline-nodisk-"));
    // undefined is what extension.ts now passes when persistSessionMappings is off.
    const session = makeSession(dir, undefined);
    const guarded = await session.guardPrompt(PROMPT);

    check("the secret was still detected", !guarded.redactedText.includes(SECRET), guarded.redactedText);
    check("no sessions directory created", !fs.existsSync(path.join(dir, "sessions")));

    const leaks = containsSecretAnywhere(dir);
    check("the plaintext appears in NO file under storage", leaks.length === 0, JSON.stringify(leaks));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log("\n[opt in: the setting genuinely controls it]");
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vaultline-disk-"));
    const persistPath = path.join(dir, "sessions", "session.json");
    const session = makeSession(dir, persistPath);
    await session.guardPrompt(PROMPT);

    check("mapping file written when asked", fs.existsSync(persistPath));
    const body = fs.existsSync(persistPath) ? fs.readFileSync(persistPath, "utf-8") : "";
    check("…and it does contain the plaintext, as documented", body.includes(SECRET));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log("\n[the audit log keeps its own promise]");
  {
    // auditIncludesValues() is false above, so the audit trail records WHAT was
    // redacted but never the value. Same posture, now applied in both places.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vaultline-audit-"));
    const session = makeSession(dir, undefined);
    await session.guardPrompt(PROMPT);
    const leaks = containsSecretAnywhere(dir);
    check("audit log holds no plaintext", leaks.length === 0, JSON.stringify(leaks));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
