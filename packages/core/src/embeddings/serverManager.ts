/**
 * Lifecycle manager for the bundled MiniLM embedding server.
 *
 * WHY THIS EXISTS: embedding-server/ is a separate Node process on purpose
 * (see its module comment — keeping model inference off the editor's own
 * thread). That's the right architecture but a terrible install story: a
 * .vsix is just a zip, VS Code runs no install hooks, so without this file
 * every user has to manually `cd embedding-server && npm install && npm
 * start` before the API backend does anything. This class closes that gap by
 * doing it at activation instead. Nothing about that problem is specific to
 * VS Code — any editor plugin shipping this server has the same one — which
 * is why it lives in the core behind VaultlineHost rather than in a host.
 *
 * WHAT IS AND ISN'T SHIPPED: the package carries embedding-server/server.js
 * and its package.json + package-lock.json — a few KB of plain JS — but
 * NOT its node_modules. That's deliberate: @xenova/transformers pulls in
 * onnxruntime-node and sharp, which are prebuilt NATIVE binaries. Shipping
 * them would add ~280MB and make the artifact platform-specific, which it
 * otherwise isn't (everything else is JS + WASM). So the deps are installed
 * per-machine, on first run, into the host's storage directory — which also
 * keeps them out of the read-only install dir, where npm has no business
 * writing.
 *
 * FAIL-OPEN, ALWAYS: every failure path here (no node, no npm, install
 * failed, model download failed, port taken by something else) is reported
 * to the log channel and surfaced once as a notification, and then
 * ignored. Nothing in this file is allowed to block activation or throw
 * into it. If the server never comes up, ApiEmbedder just fails, and
 * embeddingRouter.ts treats that as "routing unavailable" and runs every
 * contextual detector unconditionally — the same safe degradation as a
 * missing centroids file. Losing the server must never mean losing
 * detection.
 */

import * as fs from "fs";
import * as net from "net";
import * as path from "path";
import * as crypto from "crypto";
import { spawn, ChildProcess, execFile } from "child_process";
import { LogChannel, VaultlineHost } from "../host";
import { embeddingServerDir } from "../assets";

/** Files copied from the bundled embedding-server/ into host storage. package-lock.json is included so the install is reproducible (npm ci-equivalent resolution) rather than floating to whatever satisfies the ranges today. */
const SERVER_FILES = ["server.js", "package.json", "package-lock.json"];

/** How long to wait for /health to report "ready" after spawning. Generous because the FIRST run downloads ~90MB of model weights from Hugging Face before the server can serve anything; subsequent runs hit the local cache and take a couple of seconds. */
const READY_TIMEOUT_MS = 5 * 60 * 1000;
const HEALTH_POLL_INTERVAL_MS = 1000;

/** Timeout for the one-shot probe that checks whether a server is ALREADY listening (started manually, or by another editor window). Short — this is a localhost round-trip, not a model call. */
const PROBE_TIMEOUT_MS = 1500;

/**
 * How many ports past the configured one to consider before giving up.
 *
 * The configured port is a request, not a guarantee: 9000 is a popular default
 * (Docker proxies, PHP-FPM, Portainer, assorted corporate agents) and a Windows
 * user hit exactly that — the manager spawned onto an occupied port, the server
 * died with EADDRINUSE, and MiniLM was permanently unavailable on that machine
 * until they found the setting and changed it by hand.
 *
 * Ten is enough to walk past a cluster of neighbours without scanning a
 * meaningful chunk of the port space when something is badly wrong.
 */
const PORT_SCAN_SPAN = 10;

/** The one address the locally spawned server binds to — see embedding-server/server.js. */
const LOOPBACK_IP = "127.0.0.1";

export class EmbeddingServerManager {
  private child: ChildProcess | null = null;
  private output: LogChannel;
  private disposed = false;
  /** Guards against two ensureRunning() calls (e.g. activation + a settings change) racing into two spawns. */
  private starting: Promise<boolean> | null = null;
  /**
   * Where a LOCAL server actually ended up, which is not necessarily the
   * configured port — see selectPort(). Null when there is no local server to
   * talk to (remote endpoint, or nothing came up).
   */
  private resolvedBaseUrl: string | null = null;

  constructor(private host: VaultlineHost) {
    this.output = host.createLogChannel("Vaultline Embedding Server");
  }

  /**
   * Bring the server up if it should be running and isn't already.
   * Safe to call repeatedly; never throws.
   *
   * Resolves TRUE only when a server is actually answering /health with
   * "ready" — whether we started it or adopted one that was already up.
   * FALSE means routing has no MiniLM behind it, for any reason (backend
   * isn't api, auto-start is off and nothing is listening, no npm, install
   * failed, model never loaded). Callers use that to decide whether to drop
   * to the hashing fallback; see engine.ts.
   */
  async ensureRunning(): Promise<boolean> {
    if (this.starting) return this.starting;
    this.starting = this.start().finally(() => {
      this.starting = null;
    });
    return this.starting;
  }

  /** Kill our server (if we own one) and start it again. Backs the "restart embedding server" command. Same true/false contract as ensureRunning(). */
  async restart(): Promise<boolean> {
    this.stopChild();
    return this.ensureRunning();
  }

  showLog(): void {
    this.output.show();
  }

  /**
   * Where the local server actually is, once ensureRunning() has resolved —
   * e.g. "http://127.0.0.1:9002" when the configured 9000 was taken.
   *
   * Null means "nothing local to point at": either the user configured a remote
   * endpoint (which the caller must leave alone) or no server came up at all.
   * engine.ts uses this to repoint ApiEmbedder before promoting the backend;
   * without it the embedder would keep calling the configured port, which is
   * occupied by whatever displaced us.
   */
  effectiveBaseUrl(): string | null {
    return this.resolvedBaseUrl;
  }

  private async start(): Promise<boolean> {
    const settings = this.host.settings();
    this.resolvedBaseUrl = null;

    if (settings.embeddingBackend !== "api") {
      this.log("Backend is not 'api' — nothing to start.");
      return false;
    }

    const baseUrl = settings.embeddingApiUrl.replace(/\/$/, "");

    // A remote/hosted endpoint is somebody else's to run — never spawn
    // anything for it, but DO probe it, because whether it answers is
    // exactly what the caller needs to know. resolvedBaseUrl stays null so the
    // caller keeps using the configured URL untouched.
    if (!isLoopback(baseUrl)) {
      const remoteUp = await this.probeHealth(baseUrl);
      this.log(`${baseUrl} is not a local address — not starting anything. Reachable: ${remoteUp}.`);
      return remoteUp;
    }

    const preferredPort = portFromUrl(baseUrl);
    const choice = await this.selectPort(preferredPort);

    if (!choice) {
      this.fail(
        `Ports ${preferredPort}-${preferredPort + PORT_SCAN_SPAN} are all either in use by something else or ` +
          "unavailable, so the embedding server has nowhere to listen. Falling back to the built-in hashing " +
          "embedder. Set the embedding API URL to a free port to pin one explicitly."
      );
      return false;
    }

    const localUrl = `http://${LOOPBACK_IP}:${choice.port}`;

    // Adopting an existing server — a manually started one, or another editor
    // window that got here first. Checked BEFORE the auto-start setting, so
    // that turning auto-start off to manage the server by hand still reports
    // the truth about whether it's up.
    if (choice.adopted) {
      this.resolvedBaseUrl = localUrl;
      this.log(`A server is already responding at ${localUrl} — using it.`);
      return true;
    }

    if (!settings.autoStartEmbeddingServer) {
      this.log(`Auto-start is off and no server is listening on ${preferredPort}-${preferredPort + PORT_SCAN_SPAN} — not starting one.`);
      return false;
    }

    if (choice.port !== preferredPort) {
      this.log(
        `Port ${preferredPort} is in use by another process — starting on ${choice.port} instead. ` +
          "Set the embedding API URL if you'd rather pin a specific port."
      );
    }

    const sourceDir = embeddingServerDir();

    // PLATFORM-SPECIFIC BUILDS (see the host's packaging scripts) ship the
    // server's native dependencies, and the model weights, inside the
    // artifact for one target OS/arch. When that's what we're running there
    // is nothing to install and nothing to copy: no npm needed, no network
    // needed, no first-run wait. Run it straight out of the install
    // directory, which is read-only as far as we're concerned — we only
    // ever read from it, and transformers.js finds its model in the
    // bundled cache rather than fetching one.
    if (fs.existsSync(path.join(sourceDir, "node_modules"))) {
      this.log("Dependencies are bundled with this build — skipping install, starting directly.");
      const bundledTools = await this.resolveTools();
      return this.spawnServer(bundledTools.node ?? process.execPath, sourceDir, localUrl);
    }

    const installDir = path.join(this.host.storagePath(), "embedding-server");

    try {
      await this.syncServerFiles(sourceDir, installDir);
    } catch (err) {
      this.fail(`Could not stage the embedding server into ${installDir}: ${err}`);
      return false;
    }

    const tools = await this.resolveTools();
    if (!tools.node) {
      this.fail(
        "Could not find a Node.js binary to run the embedding server. Install Node 18+, or set the embedding server node path setting to its full path."
      );
      return false;
    }

    if (await this.needsInstall(installDir)) {
      if (!tools.npm) {
        this.failWithManualSteps(installDir, "Could not find npm to install the embedding server's dependencies.");
        return false;
      }
      const installed = await this.runNpmInstall(tools.npm, installDir);
      if (!installed) return false; // runNpmInstall already reported why
    }

    return this.spawnServer(tools.node, installDir, localUrl);
  }

  // ---------------------------------------------------------------------
  // Staging
  // ---------------------------------------------------------------------

  /**
   * Copy server.js/package.json/package-lock.json out of the (read-only)
   * install directory into host storage, where npm can write a node_modules
   * next to them. Copies unconditionally — these are tiny, and always
   * overwriting means an update that changed server.js takes effect without
   * any staleness logic.
   */
  private async syncServerFiles(sourceDir: string, installDir: string): Promise<void> {
    await fs.promises.mkdir(installDir, { recursive: true });
    for (const name of SERVER_FILES) {
      const from = path.join(sourceDir, name);
      // package-lock.json is nice-to-have, not required — don't fail staging over it.
      if (!fs.existsSync(from)) continue;
      await fs.promises.copyFile(from, path.join(installDir, name));
    }
    if (!fs.existsSync(path.join(installDir, "server.js"))) {
      throw new Error("server.js was not found in the installed package (check the host's packaging ignore rules).");
    }
  }

  // ---------------------------------------------------------------------
  // Dependency install
  // ---------------------------------------------------------------------

  /**
   * True when node_modules is missing, or when package.json has changed
   * since the last successful install. The stamp file records the hash of
   * the package.json we installed FOR, so an update that bumps a dependency
   * triggers a reinstall instead of silently running against the old tree.
   */
  private async needsInstall(installDir: string): Promise<boolean> {
    const stampPath = path.join(installDir, ".vaultline-install.json");
    if (!fs.existsSync(path.join(installDir, "node_modules"))) return true;
    try {
      const stamp = JSON.parse(await fs.promises.readFile(stampPath, "utf-8")) as { packageHash?: string };
      return stamp.packageHash !== (await this.hashPackageJson(installDir));
    } catch {
      return true;
    }
  }

  private async hashPackageJson(installDir: string): Promise<string> {
    const contents = await fs.promises.readFile(path.join(installDir, "package.json"));
    return crypto.createHash("sha256").update(contents).digest("hex");
  }

  private async runNpmInstall(npmPath: string, installDir: string): Promise<boolean> {
    this.log(`Installing embedding server dependencies into ${installDir} — this happens once, and needs network access.`);

    return this.host.withProgress(
      {
        location: "notification",
        title: "Vaultline: installing embedding server dependencies (one-time, ~1-3 min)",
        cancellable: true,
      },
      async (token) => {
        const ok = await new Promise<boolean>((resolve) => {
          // NOT --ignore-scripts: onnxruntime-node and sharp fetch/link their
          // prebuilt native binaries in a postinstall step, so skipping
          // scripts produces a tree that installs cleanly and then fails at
          // require() time.
          const proc = spawn(npmPath, ["install", "--omit=dev", "--no-audit", "--no-fund"], {
            cwd: installDir,
            env: { ...process.env },
            shell: process.platform === "win32",
          });

          token.onCancelled(() => {
            this.log("Install cancelled by user.");
            proc.kill();
          });

          proc.stdout?.on("data", (d) => this.log(String(d).trimEnd()));
          proc.stderr?.on("data", (d) => this.log(String(d).trimEnd()));
          proc.on("error", (err) => {
            this.log(`npm install could not be launched: ${err}`);
            resolve(false);
          });
          proc.on("close", (code) => resolve(code === 0));
        });

        if (!ok) {
          this.failWithManualSteps(installDir, "Installing the embedding server's dependencies failed.");
          return false;
        }

        await fs.promises.writeFile(
          path.join(installDir, ".vaultline-install.json"),
          JSON.stringify({ packageHash: await this.hashPackageJson(installDir), installedAt: new Date().toISOString() }, null, 2)
        );
        this.log("Dependencies installed.");
        return true;
      }
    );
  }

  // ---------------------------------------------------------------------
  // Spawn + readiness
  // ---------------------------------------------------------------------

  private async spawnServer(nodePath: string, installDir: string, baseUrl: string): Promise<boolean> {
    const port = portFromUrl(baseUrl);
    this.log(`Starting embedding server: ${nodePath} server.js (PORT=${port}, cwd=${installDir})`);

    const child = spawn(nodePath, ["server.js"], {
      cwd: installDir,
      env: {
        ...process.env,
        PORT: String(port),
        // If nodePath turned out to be the editor's own Electron binary (the
        // last-resort fallback in resolveTools), this is what makes it
        // behave as a plain Node runtime instead of trying to open a window.
        ELECTRON_RUN_AS_NODE: "1",
      },
    });
    this.child = child;

    child.stdout?.on("data", (d) => this.log(String(d).trimEnd()));
    child.stderr?.on("data", (d) => this.log(String(d).trimEnd()));
    child.on("error", (err) => this.log(`Server process error: ${err}`));
    child.on("exit", (code, signal) => {
      // 48 is server.js's deliberate "the port was taken" exit — see its
      // listen error handler. Naming it beats "exited with code 48", and it
      // means something raced us onto the port between selectPort()'s
      // bindability check and the spawn.
      this.log(
        code === 48
          ? `Server exited: port ${port} was taken by another process before it could bind.`
          : `Server exited (code=${code}, signal=${signal}).`
      );
      if (this.child === child) this.child = null;
    });

    const ready = await this.host.withProgress(
      { location: "window", title: "Vaultline: loading MiniLM embedding model…" },
      () => this.waitForReady(baseUrl)
    );

    if (ready) {
      this.resolvedBaseUrl = baseUrl;
      this.log(`Embedding server ready at ${baseUrl}.`);
    } else if (!this.disposed) {
      this.fail(
        `The embedding server did not become ready at ${baseUrl} within ${Math.round(READY_TIMEOUT_MS / 1000)}s. ` +
          "Falling back to the built-in hashing embedder."
      );
    }
    return ready;
  }

  private async waitForReady(baseUrl: string): Promise<boolean> {
    const deadline = Date.now() + READY_TIMEOUT_MS;
    while (Date.now() < deadline && !this.disposed) {
      if (await this.probeHealth(baseUrl)) return true;
      // A crashed child will never become ready — stop waiting out the full
      // five minutes for a process that's already gone.
      if (this.child === null) return false;
      await delay(HEALTH_POLL_INTERVAL_MS);
    }
    return false;
  }

  /**
   * Pick the port the local server should use.
   *
   * Walks the configured port and the PORT_SCAN_SPAN ports above it, taking the
   * first that is either (a) already serving a healthy Vaultline server, which
   * we adopt, or (b) free to bind. Returns null when the whole span is
   * unusable.
   *
   * The two checks answer genuinely different questions and neither substitutes
   * for the other. probeHealth() asks "is a VAULTLINE server here?" — a foreign
   * process holding the port answers it with a 404 or a connection reset, which
   * reads identically to "nothing is listening", which is precisely how the
   * manager used to spawn onto an occupied port. isPortFree() asks "can I
   * bind?", which is the question that was never being asked.
   *
   * Deliberately says nothing about the auto-start setting — start() decides
   * whether to actually spawn onto a free port, so that a hand-managed server
   * on a neighbouring port is still found and reported honestly either way.
   */
  private async selectPort(preferred: number): Promise<{ port: number; adopted: boolean } | null> {
    let firstFree: number | null = null;

    for (let port = preferred; port <= preferred + PORT_SCAN_SPAN; port++) {
      if (await this.probeHealth(`http://${LOOPBACK_IP}:${port}`)) {
        return { port, adopted: true };
      }
      if (firstFree === null && (await isPortFree(port))) {
        // Keep scanning rather than returning immediately: a healthy server on
        // a LATER port is a better answer than a free earlier one, since
        // adopting it avoids a second model load. Only settle for the free
        // port once the whole span has been checked for an adoptable server.
        firstFree = port;
      }
    }

    return firstFree === null ? null : { port: firstFree, adopted: false };
  }

  /**
   * True only when /health reports "ready". "loading" counts as not-yet — the
   * model is still being read in, and embed calls would 503.
   *
   * Probes by IP for loopback URLs (see toProbeUrl): the spawned server binds
   * 127.0.0.1, and on Windows "localhost" commonly resolves to ::1 first, so
   * probing by name would miss our own server and report it permanently
   * unhealthy.
   */
  private async probeHealth(baseUrl: string): Promise<boolean> {
    // The configurable path applies to SOMEBODY ELSE'S endpoint only. For a
    // loopback address this manager is choosing whether to adopt a server it
    // owns, and that decision has to be made on our own /health contract:
    // skipping the probe there would "adopt" a server that is still loading its
    // model and answer every embed call with a 503.
    const remote = !isLoopback(baseUrl);
    const configured = (this.host.settings().embeddingApiHealthPath ?? "").trim();
    const healthPath = remote ? configured : "/health";

    // EMPTY (remote only) means "don't probe" — and that is the difference
    // between a custom endpoint working and silently never being used. Hosted
    // embedding services generally have no /health route, so probing one always
    // failed, the manager reported the endpoint unreachable, and routing fell
    // back to the hashing embedder without ever calling the configured URL.
    //
    // Optimistic is safe: if the endpoint really is down, the first embed call
    // fails and EmbeddingRouter.scoreAll() already catches that and fails open,
    // so detection keeps running either way.
    if (healthPath.length === 0) return true;

    const path = healthPath.startsWith("/") ? healthPath : `/${healthPath}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
    try {
      const res = await fetch(`${toProbeUrl(baseUrl)}${path}`, { signal: controller.signal });
      if (!res.ok) return false;
      // Our own server reports {status:"ready"} and distinguishes "loading",
      // and on loopback that contract is required: anything else on the port is
      // an impostor we must not adopt. A third-party health route reports
      // whatever it likes, so there a 2xx alone counts — demanding our status
      // string would put us straight back to never using the endpoint.
      try {
        const data = (await res.json()) as { status?: string };
        if (typeof data?.status === "string") return data.status === "ready";
      } catch {
        // Not JSON.
      }
      return remote;
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  // ---------------------------------------------------------------------
  // Toolchain discovery
  // ---------------------------------------------------------------------

  /**
   * Find node and npm. This is fiddlier than it looks: an editor launched
   * from Finder/Dock inherits a minimal PATH that often has neither, and
   * version managers (nvm, fnm, asdf) put them somewhere only a login
   * shell knows about. So: explicit setting first, then ask a login shell,
   * then check the usual install prefixes, and finally — for node only —
   * fall back to the current process's own runtime (the editor's bundled
   * Electron, in Node mode), which is always present. onnxruntime-node and
   * sharp are both N-API modules, so they're ABI-compatible with that.
   */
  private async resolveTools(): Promise<{ node: string | null; npm: string | null }> {
    const configured = this.host.settings().embeddingServerNodePath.trim();
    const fromShell = await this.whichFromLoginShell(["node", "npm"]);

    const node =
      (configured && fs.existsSync(configured) ? configured : null) ??
      fromShell.node ??
      firstExisting(candidatePaths("node")) ??
      process.execPath;

    const npm = fromShell.npm ?? firstExisting(candidatePaths("npm"));

    this.log(`Using node: ${node}${node === process.execPath ? " (the editor's bundled runtime)" : ""}`);
    this.log(`Using npm:  ${npm ?? "(not found)"}`);
    return { node, npm };
  }

  /** Ask the user's login shell where these binaries live, so version-manager setups resolve. Returns nulls on any failure — every caller has fallbacks. */
  private whichFromLoginShell(names: string[]): Promise<Record<string, string | null>> {
    const empty: Record<string, string | null> = Object.fromEntries(names.map((n) => [n, null]));

    if (process.platform === "win32") {
      return new Promise((resolve) => {
        execFile("where", names, { timeout: 5000, shell: true }, (err, stdout) => {
          if (err) return resolve(empty);
          const found = { ...empty };
          for (const line of stdout.split(/\r?\n/)) {
            const hit = names.find((n) => line.toLowerCase().includes(`\\${n}.`));
            if (hit && !found[hit] && fs.existsSync(line.trim())) found[hit] = line.trim();
          }
          resolve(found);
        });
      });
    }

    return new Promise((resolve) => {
      const shell = process.env.SHELL || "/bin/zsh";
      // -l so profile files (where nvm/fnm/asdf hook themselves in) are read.
      // Each `command -v` is printed on its own line, labelled, so a shell
      // that prints extra profile noise can't scramble the mapping.
      const script = names.map((n) => `echo "${n}=$(command -v ${n} 2>/dev/null)"`).join("; ");
      execFile(shell, ["-lc", script], { timeout: 8000 }, (err, stdout) => {
        if (err && !stdout) return resolve(empty);
        const found = { ...empty };
        for (const line of stdout.split("\n")) {
          const m = /^([a-z]+)=(.+)$/.exec(line.trim());
          if (m && names.includes(m[1]) && fs.existsSync(m[2])) found[m[1]] = m[2];
        }
        resolve(found);
      });
    });
  }

  // ---------------------------------------------------------------------
  // Reporting + teardown
  // ---------------------------------------------------------------------

  private log(message: string): void {
    this.output.append(`[${new Date().toISOString()}] ${message}`);
  }

  private fail(message: string): void {
    this.log(message);
    void this.host.warn(message, "Show Log").then((choice) => {
      if (choice === "Show Log") this.output.show();
    });
  }

  /** For failures the user can fix by hand — offers the exact commands rather than making them reverse-engineer the path. */
  private failWithManualSteps(installDir: string, message: string): void {
    const manual = `cd "${installDir}" && npm install && npm start`;
    this.log(`${message} To do it manually:\n  ${manual}`);
    void this.host
      .warn(
        `${message} Routing has fallen back to the built-in hashing embedder — everything keeps working, less accurately.`,
        "Copy Command",
        "Show Log"
      )
      .then((choice) => {
        if (choice === "Copy Command") void this.host.copyToClipboard(manual);
        if (choice === "Show Log") this.output.show();
      });
  }

  private stopChild(): void {
    if (!this.child) return;
    this.log("Stopping embedding server.");
    this.child.kill();
    this.child = null;
  }

  /**
   * NOTE: this only kills a server THIS window spawned. If a second window
   * adopted it (see the probe in start()), closing this one takes the
   * server down under the other — which fails open, and the other window
   * can bring it back with the "restart embedding server" command. A proper
   * fix is a shared daemon with refcounting, which is more machinery than
   * what it needs.
   */
  dispose(): void {
    this.disposed = true;
    this.stopChild();
    this.output.dispose();
  }
}

// -----------------------------------------------------------------------
// Small helpers
// -----------------------------------------------------------------------

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Can we bind this port on loopback?
 *
 * Exported for test/port-conflict.js, which occupies ports with plain net
 * servers — testing port selection for real is otherwise impossible without
 * spawning the actual model server.
 *
 * Binds to 127.0.0.1 specifically, matching where the real server listens. A
 * foreign process holding 0.0.0.0:PORT or :::PORT still collides with that, so
 * this doesn't under-report; binding the wildcard here instead WOULD
 * over-report, by failing on ports that are only taken on some other interface.
 */
export function isPortFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const tester = net.createServer();
    tester.once("error", () => resolve(false));
    tester.once("listening", () => tester.close(() => resolve(true)));
    tester.listen(port, LOOPBACK_IP);
  });
}

/**
 * Rewrite a loopback hostname to 127.0.0.1 for probing, leaving anything else
 * alone.
 *
 * Necessary because the spawned server binds 127.0.0.1 rather than every
 * interface, and on Windows "localhost" routinely resolves to ::1 first — so
 * probing the configured "http://localhost:9000" would connect to nothing and
 * report our own healthy server as down.
 */
function toProbeUrl(baseUrl: string): string {
  try {
    const url = new URL(baseUrl);
    if (url.hostname === "localhost" || url.hostname === "::1" || url.hostname === "0.0.0.0") {
      url.hostname = LOOPBACK_IP;
      return url.toString().replace(/\/$/, "");
    }
    return baseUrl;
  } catch {
    return baseUrl;
  }
}

function isLoopback(baseUrl: string): boolean {
  try {
    const host = new URL(baseUrl).hostname;
    return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "0.0.0.0";
  } catch {
    return false;
  }
}

function portFromUrl(baseUrl: string): number {
  try {
    const url = new URL(baseUrl);
    if (url.port) return Number(url.port);
    return url.protocol === "https:" ? 443 : 80;
  } catch {
    return 9000;
  }
}

/** Usual install prefixes, in the order we'd rather find them: Homebrew (Apple silicon), Homebrew/manual (Intel + Linux), system. */
function candidatePaths(binary: string): string[] {
  if (process.platform === "win32") {
    const programFiles = process.env.ProgramFiles ?? "C:\\Program Files";
    const appData = process.env.APPDATA ?? "";
    const exe = binary === "npm" ? "npm.cmd" : `${binary}.exe`;
    return [path.join(programFiles, "nodejs", exe), appData ? path.join(appData, "npm", exe) : ""].filter(Boolean);
  }
  return ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/opt/local/bin"].map((dir) => path.join(dir, binary));
}

function firstExisting(paths: string[]): string | null {
  return paths.find((p) => fs.existsSync(p)) ?? null;
}
