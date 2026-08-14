/**
 * The embedding API credential belongs in the OS keychain, not settings.json.
 *
 * Vaultline shipped `vaultline.embeddingApiAuthToken` as an ordinary setting,
 * which means plain text on disk, visible in the Settings UI, copied to every
 * other machine by Settings Sync, and committed to the repository if anyone set
 * it at workspace level. That is the practice this tool exists to argue
 * against, so it now reads from the host's secure storage and keeps the setting
 * only as a deprecated fallback.
 *
 * PRECEDENCE IS THE POINT. Keychain first means anyone who migrates is really
 * using it even if a stale value is still sitting in their settings file;
 * setting second means no existing install breaks on upgrade. Getting that
 * order backwards would look fine in manual testing and quietly keep using the
 * value the user thought they had removed.
 *
 * ConsoleHost's in-memory secret store stands in for the keychain — the
 * contract the core depends on is only "somewhere that isn't the settings file".
 */

const os = require("os");
const path = require("path");
const { ConsoleHost } = require(path.join(__dirname, "..", "out", "host"));
const { VaultlineEngine } = require(path.join(__dirname, "..", "out", "engine"));

const KEY = VaultlineEngine.AUTH_TOKEN_SECRET_KEY;

let failures = 0;
function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

/** A host that records every line written to any log channel, so we can prove the token never appears. */
class RecordingHost extends ConsoleHost {
  constructor(settings) {
    super(settings, path.join(os.tmpdir(), `vaultline-secret-${Date.now()}-${Math.random()}`));
    this.logged = [];
  }
  createLogChannel() {
    return { append: (m) => this.logged.push(m), show: () => {}, dispose: () => {} };
  }
  async warn() {
    return undefined;
  }
  async info() {
    return undefined;
  }
}

/** The Authorization header the engine's embedder would actually send. */
function authHeaderOf(engine) {
  const embedder = engine.apiEmbedder ?? engine["apiEmbedder"];
  return embedder.headers?.Authorization ?? embedder["headers"]?.Authorization;
}

async function main() {
  console.log("\n[a token in secure storage reaches the request header]");
  {
    const host = new RecordingHost({ embeddingApiAuthType: "bearer", autoStartEmbeddingServer: false });
    const engine = VaultlineEngine.create(host);
    await engine.setAuthToken("from-keychain");
    check("header carries the keychain value", authHeaderOf(engine) === "Bearer from-keychain", authHeaderOf(engine));
    check("stored under the documented key", (await host.secret(KEY)) === "from-keychain");
    engine.dispose();
  }

  console.log("\n[precedence: keychain beats the deprecated setting]");
  {
    const host = new RecordingHost({
      embeddingApiAuthType: "bearer",
      embeddingApiAuthToken: "from-settings",
      autoStartEmbeddingServer: false,
    });
    await host.storeSecret(KEY, "from-keychain");
    const engine = VaultlineEngine.create(host);
    await engine["applyAuthToken"]();
    check("keychain wins", authHeaderOf(engine) === "Bearer from-keychain", authHeaderOf(engine));
    engine.dispose();
  }

  console.log("\n[the deprecated setting still works when the keychain is empty]");
  {
    const host = new RecordingHost({
      embeddingApiAuthType: "bearer",
      embeddingApiAuthToken: "from-settings",
      autoStartEmbeddingServer: false,
    });
    const engine = VaultlineEngine.create(host);
    await engine["applyAuthToken"]();
    check("existing installs keep authenticating", authHeaderOf(engine) === "Bearer from-settings", authHeaderOf(engine));
    engine.dispose();
  }

  console.log("\n[clearing really clears]");
  {
    const host = new RecordingHost({ embeddingApiAuthType: "bearer", autoStartEmbeddingServer: false });
    const engine = VaultlineEngine.create(host);
    await engine.setAuthToken("temporary");
    check("set", authHeaderOf(engine) === "Bearer temporary");

    await engine.clearAuthToken();
    // A stale header here would mean "clear the token" silently kept
    // authenticating with it.
    check("header gone", authHeaderOf(engine) === undefined, String(authHeaderOf(engine)));
    check("secret removed from storage", (await host.secret(KEY)) === undefined);
    engine.dispose();
  }

  console.log("\n[the token never appears in a log line]");
  {
    const host = new RecordingHost({ embeddingApiAuthType: "bearer", autoStartEmbeddingServer: false });
    const engine = VaultlineEngine.create(host);
    await engine.setAuthToken("super-secret-token-value");
    await engine.inspect("my password is hunter2isnotsecure");
    const leaked = host.logged.filter((line) => line.includes("super-secret-token-value"));
    check("absent from every log line", leaked.length === 0, JSON.stringify(leaked));
    engine.dispose();
  }

  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
