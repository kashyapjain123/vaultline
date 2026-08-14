/**
 * Shared plumbing for the CLI suites: a client that speaks MCP to an
 * in-process server over stream pairs.
 *
 * In-process rather than spawned, for everything except the one end-to-end
 * check in mcp-protocol.js. Spawning would drag in the user's real
 * ~/.vaultline config and their keychain, which makes the suite depend on the
 * machine it runs on. mcp-protocol.js pays that cost once, deliberately, to
 * prove the packaged binary actually starts.
 *
 * Settings pin embeddingBackend to "hashing" so no embedding server is
 * launched — the detectors under test here are the structural and proximity
 * ones, and a background server would make the suite slow and flaky for no
 * added coverage.
 */

const path = require("path");
const os = require("os");
const fs = require("fs");
const { PassThrough } = require("stream");

const CORE = path.join(__dirname, "..", "node_modules", "@vaultline", "core", "out");
const { ConsoleHost, VaultlineEngine, DEFAULT_SETTINGS } = require(path.join(CORE, "index"));
const { runMcpServer } = require(path.join(__dirname, "..", "out", "mcpServer"));

let failures = 0;

function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

function summarize(name) {
  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? `${name}: ALL CHECKS PASSED` : `${name}: ${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

/** A scratch directory that cleans itself up, for fixture files the tools will read and write. */
function tempDir(prefix = "vaultline-cli-test-") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  process.on("exit", () => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/**
 * Start a server on stream pairs and return a client with a `call` method.
 * `settings` overrides individual defaults; `persistPath` mirrors mappings to
 * disk the way `persistSessionMappings` does in the real CLI.
 */
function startServer({ cwd, settings = {}, persistPath } = {}) {
  const toServer = new PassThrough();
  const fromServer = new PassThrough();

  const host = new ConsoleHost({ ...DEFAULT_SETTINGS, embeddingBackend: "hashing", ...settings }, cwd);
  const engine = VaultlineEngine.create(host);
  const done = runMcpServer(engine, { cwd, input: toServer, output: fromServer, persistPath });

  // Responses arrive newline-delimited and in order; park them by id so a
  // caller can await one call without caring what else is in flight.
  const pending = new Map();
  let buffer = "";
  fromServer.on("data", (chunk) => {
    buffer += chunk.toString();
    let nl;
    while ((nl = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      const message = JSON.parse(line);
      const resolve = pending.get(message.id);
      if (resolve) {
        pending.delete(message.id);
        resolve(message);
      }
    }
  });

  let nextId = 1;
  const call = (method, params) =>
    new Promise((resolve) => {
      const id = nextId++;
      pending.set(id, resolve);
      toServer.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });

  const notify = (method, params) => toServer.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");

  const close = async () => {
    toServer.end();
    await done;
    engine.dispose();
  };

  return { call, notify, close };
}

/** The text of a tools/call result, which is where every assertion here actually looks. */
function textOf(response) {
  if (response.error) throw new Error(`RPC error: ${response.error.message}`);
  return response.result.content.map((c) => c.text).join("");
}

/** A fixture with one of each thing Vaultline is supposed to catch. */
const CONFIG_YAML = [
  "database:",
  '  host: "internal-db.corp.example.com"',
  "  port: 5432",
  '  username: "svc_corp_uat"',
  '  password: "Hunter@123"',
  "api:",
  '  llm_key: "sk-lf-9c8b7a6d5e4f3g2h"',
  "  endpoint: http://localhost:9000/v1/embed",
  "owner:",
  "  email: rahul.sharma@example.com",
].join("\n");

module.exports = { CONFIG_YAML, check, failures: () => failures, startServer, summarize, tempDir, textOf };
