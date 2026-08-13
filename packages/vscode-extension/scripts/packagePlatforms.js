#!/usr/bin/env node
/**
 * Build platform-specific VSIXs with the embedding server's dependencies
 * baked in.
 *
 * WHY: the portable VSIX (npm run package) needs npm on the target machine
 * to install onnxruntime-node and sharp on first run. Machines without
 * Node get no MiniLM, and fall back to the hashing embedder — which keeps
 * routing but loses semantic keyword matching and whole-message
 * business-content detection outright (see embeddingRouter.ts's
 * wholeMessageCapable note for the measurements behind that). If those
 * layers matter, the dependencies have to ship, and the moment they ship
 * the artifact stops being portable: onnxruntime-node and sharp are
 * prebuilt native binaries.
 *
 * So: one VSIX per OS/arch, each carrying the binaries for exactly that
 * target plus the ~23MB of cached MiniLM weights. VS Code (and the
 * Marketplace) select the matching one automatically. The core's
 * serverManager detects the bundled node_modules and skips its install path
 * entirely — no npm, no network, no first-run wait.
 *
 * WHERE THE SERVER LIVES: embedding-server/ belongs to @vaultline/core, not
 * to this extension — it's the same server whatever editor is hosting it. So
 * dependencies are installed into the core's copy, and stageCore.js then
 * materializes that whole tree (with `--with-server-deps`) inside this
 * package right before vsce runs. See that script for why the staging step
 * is unavoidable in a workspace.
 *
 * WHAT CAN'T BE PRUNED: transformers.js v2 statically imports BOTH `sharp`
 * (via utils/image.js) and `onnxruntime-web` (via backends/onnx.js), so
 * neither can be dropped even though this server only ever embeds text on
 * the Node backend — verified empirically, the process dies at import with
 * ERR_MODULE_NOT_FOUND. The one prune that does work is onnxruntime-node's
 * per-platform binaries, which ship for darwin+linux+win32 in a single
 * package (~91MB combined); only the target's are kept.
 *
 * Usage:
 *   node scripts/packagePlatforms.js                    # every target
 *   node scripts/packagePlatforms.js darwin-arm64       # just one
 *   node scripts/packagePlatforms.js --keep-model=false # smaller, downloads on first run
 */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const { stage, unstage } = require("./stageCore");

const ROOT = path.join(__dirname, "..");
/** The engine package, wherever it's installed from — source checkout or registry. */
const CORE_DIR = path.dirname(require.resolve("@vaultline/core/package.json", { paths: [ROOT] }));
const SERVER_DIR = path.join(CORE_DIR, "embedding-server");
const NODE_MODULES = path.join(SERVER_DIR, "node_modules");
const OUT_DIR = path.join(ROOT, "dist");

/** Where transformers.js caches downloaded weights, relative to the server's node_modules. */
const MODEL_CACHE = path.join(NODE_MODULES, "@xenova", "transformers", ".cache");
/** onnxruntime-node ships every platform's binaries in one package; these are the subdirectory names. */
const ONNX_BIN = path.join(NODE_MODULES, "onnxruntime-node", "bin", "napi-v3");

/**
 * `onnx` is the onnxruntime-node bin/ subdirectory to KEEP. npm's
 * --os/--cpu and the npm_config_platform/npm_config_arch pair are what
 * make sharp's prebuild-install fetch the right binary from a machine of a
 * different architecture.
 */
const TARGETS = {
  "darwin-arm64": { os: "darwin", cpu: "arm64", onnx: "darwin" },
  "darwin-x64": { os: "darwin", cpu: "x64", onnx: "darwin" },
  "win32-x64": { os: "win32", cpu: "x64", onnx: "win32" },
  "linux-x64": { os: "linux", cpu: "x64", onnx: "linux" },
};

function parseArgs() {
  const requested = [];
  let keepModel = true;
  for (const arg of process.argv.slice(2)) {
    if (arg === "--keep-model=false") keepModel = false;
    else if (arg.startsWith("--")) throw new Error(`Unknown flag "${arg}".`);
    else if (TARGETS[arg]) requested.push(arg);
    else throw new Error(`Unknown target "${arg}". Valid: ${Object.keys(TARGETS).join(", ")}`);
  }
  return { targets: requested.length ? requested : Object.keys(TARGETS), keepModel };
}

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { stdio: "inherit", cwd: ROOT, ...opts });
}

function dirSizeMb(dir) {
  if (!fs.existsSync(dir)) return 0;
  let total = 0;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true, recursive: true })) {
    if (entry.isFile()) {
      try {
        total += fs.statSync(path.join(entry.parentPath ?? entry.path, entry.name)).size;
      } catch {
        /* races with npm; size is advisory only */
      }
    }
  }
  return Math.round(total / 1e6);
}

/**
 * The model cache lives INSIDE node_modules, which every install wipes.
 * Stashing it in a temp dir and putting it back afterwards means the
 * ~23MB of weights are downloaded once for the whole build rather than
 * once per target — and, more importantly, that every VSIX ships them, so
 * installs are genuinely offline.
 */
function stashModelCache() {
  if (!fs.existsSync(MODEL_CACHE)) return null;
  const stash = path.join(ROOT, ".model-cache-stash");
  fs.rmSync(stash, { recursive: true, force: true });
  fs.cpSync(MODEL_CACHE, stash, { recursive: true });
  return stash;
}

function restoreModelCache(stash) {
  if (!stash || !fs.existsSync(stash)) return;
  fs.mkdirSync(path.dirname(MODEL_CACHE), { recursive: true });
  fs.cpSync(stash, MODEL_CACHE, { recursive: true });
}

/**
 * NOTE THE rm -rf: it is load-bearing, not tidiness. A plain `npm install`
 * over a tree that was cross-installed for another platform reports "up to
 * date" and changes NOTHING — npm tracks which packages are present, not
 * which native binaries got downloaded inside them, so sharp keeps
 * whatever sharp-<os>-<arch>.node the last install fetched. Wiping the
 * tree first is the only reliable way to make the platform actually
 * change.
 */
function installDeps(os, cpu) {
  console.log(`\n  Installing dependencies for ${os}/${cpu} ...`);
  fs.rmSync(NODE_MODULES, { recursive: true, force: true });
  run("npm", ["install", "--omit=dev", "--no-audit", "--no-fund", `--os=${os}`, `--cpu=${cpu}`], {
    cwd: SERVER_DIR,
    // sharp@0.32 resolves its prebuilt binary through prebuild-install,
    // which reads these rather than npm's --os/--cpu. Both are set so the
    // cross-download works regardless of which dependency is asking.
    env: { ...process.env, npm_config_platform: os, npm_config_arch: cpu },
  });
}

function installFor(target) {
  const { os, cpu } = TARGETS[target];
  installDeps(os, cpu);
}

/**
 * Put embedding-server/node_modules back the way a developer on THIS
 * machine needs it. Without this the repo is left holding the last
 * target's binaries — `npm start` then dies with an invalid ELF header or
 * equivalent, and (see installDeps) `npm install` won't fix it.
 */
function restoreHostInstall(stash) {
  console.log(`\n=== restoring local install (${process.platform}/${process.arch}) ===`);
  try {
    installDeps(process.platform, process.arch);
    restoreModelCache(stash);
  } catch (err) {
    console.warn(
      `  Could not restore the local install automatically: ${err.message}\n` +
        `  Run: rm -rf "${NODE_MODULES}" && (cd "${SERVER_DIR}" && npm install)`
    );
  }
}

/**
 * Drop the other platforms' onnxruntime binaries — the single largest
 * saving available. The layout is bin/napi-v3/<platform>/<arch>/, and both
 * levels are pruned: a win32-x64 package has no use for win32/arm64's
 * ~9.6MB of DLLs any more than it does for darwin's.
 */
function pruneOnnx(target) {
  if (!fs.existsSync(ONNX_BIN)) return;
  const { onnx: keepOs, cpu: keepArch } = TARGETS[target];

  for (const osDir of fs.readdirSync(ONNX_BIN)) {
    const osPath = path.join(ONNX_BIN, osDir);
    if (osDir !== keepOs) {
      fs.rmSync(osPath, { recursive: true, force: true });
      console.log(`  Pruned onnxruntime-node/bin/napi-v3/${osDir}`);
      continue;
    }
    if (!fs.statSync(osPath).isDirectory()) continue;
    for (const archDir of fs.readdirSync(osPath)) {
      if (archDir !== keepArch) {
        fs.rmSync(path.join(osPath, archDir), { recursive: true, force: true });
        console.log(`  Pruned onnxruntime-node/bin/napi-v3/${osDir}/${archDir}`);
      }
    }
  }
}

function packageFor(target) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const version = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf-8")).version;
  const out = path.join(OUT_DIR, `vaultline-${version}-${target}.vsix`);

  // Staged per target rather than once around the whole loop: each target's
  // native binaries are installed into the core in turn, so the copy has to
  // be taken after THIS target's install and thrown away before the next one.
  let staged = false;
  try {
    staged = stage({ withServerDeps: true });
    run("npx", [
      "--yes",
      "@vscode/vsce",
      "package",
      "--target", target,
      "--ignoreFile", ".vscodeignore.bundled",
      "--allow-missing-repository",
      "--out", out,
    ]);
  } finally {
    if (staged) unstage();
  }
  return out;
}

function main() {
  const { targets, keepModel } = parseArgs();
  console.log(`Building platform packages: ${targets.join(", ")}`);
  console.log(`Model weights bundled: ${keepModel ? "yes (offline install)" : "no (downloads on first run)"}`);

  const stash = keepModel ? stashModelCache() : null;
  if (keepModel && !stash) {
    console.warn(
      "\n  WARNING: no model cache found to bundle. Start the server once " +
        "(cd embedding-server && npm start) to download the weights, then re-run " +
        "this script — otherwise each install downloads ~23MB on first use."
    );
  }

  const built = [];
  for (const target of targets) {
    console.log(`\n=== ${target} ===`);
    installFor(target);
    pruneOnnx(target);
    if (keepModel) restoreModelCache(stash);
    console.log(`  Payload: ~${dirSizeMb(NODE_MODULES)}MB uncompressed`);
    built.push(packageFor(target));
  }

  restoreHostInstall(stash);
  if (stash) fs.rmSync(stash, { recursive: true, force: true });

  console.log("\nBuilt:");
  for (const file of built) {
    console.log(`  ${path.relative(ROOT, file)}  (${Math.round(fs.statSync(file).size / 1e6)}MB)`);
  }
}

main();
