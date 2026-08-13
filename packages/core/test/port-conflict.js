/**
 * Port-conflict matrix — the Windows failure this suite exists for:
 *
 *   Error: listen EADDRINUSE: address already in use :::9000
 *
 * Port 9000 is a popular default (Docker proxies, PHP-FPM, Portainer, various
 * corporate agents). Vaultline used to treat it as fixed: it probed the port
 * for a healthy Vaultline server, got nothing useful back from the foreign
 * process holding it, and spawned onto the occupied port anyway. The server
 * died with an uncaught EADDRINUSE and MiniLM was permanently unavailable on
 * that machine.
 *
 * The distinction that fixes it is that "is a Vaultline server here?" and "can
 * I bind here?" are different questions. A foreign process answers the first
 * one identically to an empty port — which is exactly how the old code walked
 * into the collision.
 *
 * Assertions, not description (cf. scenario-matrix.js), and a non-zero exit on
 * failure: silently starting on the wrong port, or refusing to start at all, is
 * the kind of regression nothing else would catch.
 *
 * Hermetic: ports are occupied with plain net/http servers, so nothing here
 * downloads a model or spawns the real server. Runs against a BASE_PORT well
 * away from 9000 so a developer's own busy 9000 can't make it flap.
 */

const http = require("http");
const net = require("net");
const os = require("os");
const path = require("path");

const { ConsoleHost } = require(path.join(__dirname, "..", "out", "host"));
const { EmbeddingServerManager, isPortFree } = require(path.join(__dirname, "..", "out", "embeddings", "serverManager"));

const BASE_PORT = 19000;
const SPAN = 10; // must match PORT_SCAN_SPAN in serverManager.ts

// Quiet host — the manager logs a lot, and it drowns the assertions.
class QuietHost extends ConsoleHost {
  createLogChannel() {
    return { append: () => {}, show: () => {}, dispose: () => {} };
  }
  async warn() {
    return undefined;
  }
}

function makeManager() {
  const host = new QuietHost(
    { embeddingApiUrl: `http://localhost:${BASE_PORT}` },
    path.join(os.tmpdir(), "vaultline-port-test")
  );
  return new EmbeddingServerManager(host);
}

/**
 * Occupy a port with a bare TCP listener — the "foreign process" case.
 *
 * The connection handler destroys each socket immediately, which matters for
 * more than realism: without it, probeHealth's aborted fetch leaves a half-open
 * socket, and net.Server.close() then waits on it forever (unlike http.Server,
 * net.Server has no closeAllConnections()). The suite would hang between cases
 * and node would exit 0 mid-run having reported only the cases that finished.
 * Hanging up instantly still holds the port, which is the whole point.
 */
function occupy(port) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => socket.destroy());
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server));
  });
}

/** Serve /health with a given body — used both for a believable Vaultline server and for an impostor. */
function serveHealth(port, body) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(body));
    });
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server));
  });
}

/**
 * close() alone DEADLOCKS here. It stops accepting new connections but waits
 * for existing ones to end before firing its callback — and probeHealth()
 * aborts its fetch on timeout, leaving a half-open socket against every silent
 * listener it probed. The await then never resolves, the event loop drains, and
 * node exits 0 mid-suite having reported only the cases that ran so far.
 * closeAllConnections() (node 18.2+) is what stops that.
 */
function closeAll(servers) {
  return Promise.all(
    servers.map(
      (s) =>
        new Promise((resolve) => {
          s.closeAllConnections?.();
          s.close(() => resolve());
        })
    )
  );
}

const cases = [
  {
    label: "nothing listening — takes the configured port",
    setup: async () => [],
    expect: { port: BASE_PORT, adopted: false },
  },
  {
    label: "THE WINDOWS BUG: configured port held by a foreign process — moves up one",
    setup: async () => [await occupy(BASE_PORT)],
    expect: { port: BASE_PORT + 1, adopted: false },
  },
  {
    label: "a cluster of busy neighbours — walks past all of them",
    setup: async () => [await occupy(BASE_PORT), await occupy(BASE_PORT + 1), await occupy(BASE_PORT + 2)],
    expect: { port: BASE_PORT + 3, adopted: false },
  },
  {
    label: "a healthy Vaultline server is already there — adopts it, spawns nothing",
    setup: async () => [await serveHealth(BASE_PORT, { status: "ready", model: "Xenova/all-MiniLM-L6-v2" })],
    expect: { port: BASE_PORT, adopted: true },
  },
  {
    label: "an IMPOSTOR on the port (answers /health, but not ours) — does not adopt, moves up",
    setup: async () => [await serveHealth(BASE_PORT, { message: "some other service entirely" })],
    expect: { port: BASE_PORT + 1, adopted: false },
  },
  {
    label: "a Vaultline server still LOADING — not adopted yet (embed calls would 503)",
    setup: async () => [await serveHealth(BASE_PORT, { status: "loading" })],
    expect: { port: BASE_PORT + 1, adopted: false },
  },
  {
    label: "adopts a healthy server further up rather than taking a free port below it",
    setup: async () => [
      await occupy(BASE_PORT),
      await serveHealth(BASE_PORT + 2, { status: "ready" }),
    ],
    expect: { port: BASE_PORT + 2, adopted: true },
  },
  {
    label: "entire span occupied — gives up so the caller can fall back to hashing",
    setup: async () => {
      const servers = [];
      for (let p = BASE_PORT; p <= BASE_PORT + SPAN; p++) servers.push(await occupy(p));
      return servers;
    },
    expect: null,
  },
];

async function main() {
  // Refuse to report meaningless results if the range isn't actually clear.
  for (let p = BASE_PORT; p <= BASE_PORT + SPAN; p++) {
    if (!(await isPortFree(p))) {
      console.error(`Port ${p} is already in use — this test needs ${BASE_PORT}-${BASE_PORT + SPAN} free.`);
      process.exit(1);
    }
  }

  let failures = 0;

  for (const c of cases) {
    const servers = await c.setup();
    let actual;
    try {
      // selectPort is private in TypeScript; this is compiled JS, where it
      // isn't. Testing it directly is the point — going through start() would
      // drag in npm installs and a real model load.
      actual = await makeManager().selectPort(BASE_PORT);
    } finally {
      await closeAll(servers);
    }

    const describe = (v) => (v === null ? "null (give up)" : `port ${v.port}, adopted=${v.adopted}`);
    const ok =
      c.expect === null
        ? actual === null
        : actual !== null && actual.port === c.expect.port && actual.adopted === c.expect.adopted;

    console.log(`\n[${c.label}]`);
    console.log(`  expected: ${describe(c.expect)}`);
    console.log(`  actual:   ${describe(actual)}`);
    if (ok) {
      console.log("  PASS");
    } else {
      failures++;
      console.log("  FAIL");
    }
  }

  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? `ALL ${cases.length} CHECKS PASSED` : `${failures} of ${cases.length} CHECKS FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
