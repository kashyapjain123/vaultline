#!/usr/bin/env node
/**
 * Assemble a real, self-contained node_modules for the duration of a
 * packaging run.
 *
 * WHY: this repo is an npm workspace, which is what makes developing against
 * a linked @vaultline/core pleasant — edit the core, recompile, reload the
 * dev host. It also means NOTHING the extension needs at run time actually
 * sits under packages/vscode-extension/: the core is a symlink, and its
 * dependencies (web-tree-sitter, tree-sitter-wasms) are hoisted to the
 * workspace root. `vsce package` only ever looks inside the extension
 * directory, and a .vsix is a zip with no symlinks, so packaging as-is
 * produces an extension whose every require() fails.
 *
 * So: materialize exactly the runtime tree the VSIX needs, run the packaging
 * command, and tear it back down afterwards — in a finally, so an interrupted
 * or failed package never leaves a stale copy shadowing the live workspace
 * link. Only entries this script created are removed on the way out.
 *
 * Usage:
 *   node scripts/stageCore.js --run -- npx @vscode/vsce package …
 *   node scripts/stageCore.js --run --with-server-deps -- …   (platform builds:
 *       also copies embedding-server/node_modules, i.e. the prebuilt native
 *       binaries and cached model weights — see packagePlatforms.js)
 *   node scripts/stageCore.js --stage | --unstage               (manual)
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const EXTENSION_DIR = path.join(__dirname, "..");
const NODE_MODULES = path.join(EXTENSION_DIR, "node_modules");
const CORE_PATH = path.join(NODE_MODULES, "@vaultline", "core");
const MANIFEST_PATH = path.join(EXTENSION_DIR, "package.json");
/** Records what this script created, so unstage() removes exactly that and nothing else. */
const MARKER_PATH = path.join(NODE_MODULES, ".vaultline-staged.json");

/** Only what @vaultline/core declares under "files" — a .vsix has no business carrying the core's TypeScript sources or its test matrices. */
const CORE_ENTRIES = [
  "package.json",
  "README.md",
  "out",
  "data",
  path.join("embedding-server", "server.js"),
  path.join("embedding-server", "package.json"),
  path.join("embedding-server", "package-lock.json"),
];

const SERVER_DEPS = path.join("embedding-server", "node_modules");

/**
 * Files that must not reach the .vsix even though they sit inside a staged
 * entry.
 *
 * This is filtered HERE rather than in .vscodeignore because a `!` negation
 * there re-includes unconditionally: `!node_modules/@vaultline/core/**` beats
 * any later `node_modules/@vaultline/core/**\/*.map`, regardless of order. So
 * whatever this script copies is what ships, and the ignore file's job is
 * only to say which top-level trees are eligible at all.
 *
 *  - source maps: nothing at run time reads them. Type DECLARATIONS are kept
 *    on purpose even though the run time doesn't read them either — vsce runs
 *    `vscode:prepublish`, i.e. tsc, while the staging is in place, and the
 *    extension type-checks against the core's emitted .d.ts;
 *  - categoryExamples.json: the INPUT to buildEmbeddings.js, not something
 *    the pipeline ever loads — only the centroids it precomputes are;
 *  - npm leftovers inside the bundled server tree (platform builds only):
 *    docs, tests and examples shipped by dependencies, some of them large.
 */
function shouldSkip(source) {
  const name = path.basename(source);
  if (name.endsWith(".map")) return true;
  if (name === "categoryExamples.json") return true;
  if (source.includes(`${path.sep}node_modules${path.sep}`)) {
    // Markdown inside a dependency is documentation we have no reason to
    // ship — EXCEPT when it is the licence itself. sharp vendors its libvips
    // binaries' attributions as THIRD-PARTY-NOTICES.md, and those cover
    // LGPLv3 libraries (libvips, glib, pango, librsvg, gdk-pixbuf, fribidi,
    // libexif, libheif). Stripping them would mean redistributing copyleft
    // binaries with their notices deleted, which is a licence violation, not
    // a size optimisation.
    if (name.endsWith(".md") && !LICENCE_FILE.test(name)) return true;
    if (["test", "tests", "docs", "example", "examples", ".github"].includes(name)) return true;
  }
  return false;
}

/** Filenames that carry licence/attribution text and must survive packaging, whatever their extension. */
const LICENCE_FILE = /^(licen[cs]e|notice|copying|third-party-notices|authors|patents)/i;

function exists(target) {
  try {
    fs.lstatSync(target);
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve an installed package's root directory.
 *
 * `from` matters: the core's own runtime dependencies are installed under
 * packages/core/node_modules, which is not on any resolution path starting
 * from the extension — so they're looked up from the core's directory, the
 * same way Node will look them up at run time.
 */
function packageRoot(name, from = EXTENSION_DIR) {
  return path.dirname(require.resolve(`${name}/package.json`, { paths: [from, EXTENSION_DIR, __dirname] }));
}

function copyInto(source, destination, entries) {
  for (const entry of entries) {
    const from = path.join(source, entry);
    if (!fs.existsSync(from)) continue; // package-lock and README are nice-to-have
    if (shouldSkip(from)) continue;
    const to = path.join(destination, entry);
    fs.mkdirSync(path.dirname(to), { recursive: true });
    // dereference: the point of this whole script is producing real files.
    fs.cpSync(from, to, { recursive: true, dereference: true, filter: (src) => !shouldSkip(src) });
  }
}

function stage({ withServerDeps }) {
  if (exists(MARKER_PATH)) {
    throw new Error("stageCore: a previous staging was left behind — run `node scripts/stageCore.js --unstage` first.");
  }

  const coreSource = packageRoot("@vaultline/core");
  if (!fs.existsSync(path.join(coreSource, "out"))) {
    throw new Error(`stageCore: ${coreSource}/out is missing — compile @vaultline/core before packaging.`);
  }

  /**
   * Everything undone by unstage(). Written to the marker BEFORE any of it
   * happens, so a crash or a Ctrl-C halfway through is still recoverable with
   * `--unstage` rather than leaving the package quietly broken.
   */
  const state = { created: [], coreLink: null, manifestBefore: null };
  const runtimeDeps = Object.keys(require(path.join(coreSource, "package.json")).dependencies ?? {});

  if (exists(CORE_PATH) && fs.lstatSync(CORE_PATH).isSymbolicLink()) {
    state.coreLink = fs.readlinkSync(CORE_PATH);
    state.created.push(CORE_PATH);
  }
  for (const dep of runtimeDeps) {
    if (!exists(path.join(NODE_MODULES, dep))) state.created.push(path.join(NODE_MODULES, dep));
  }
  if (String(require(MANIFEST_PATH).dependencies?.["@vaultline/core"] ?? "").startsWith("file:")) {
    state.manifestBefore = fs.readFileSync(MANIFEST_PATH, "utf-8");
  }

  fs.mkdirSync(NODE_MODULES, { recursive: true });
  fs.writeFileSync(MARKER_PATH, JSON.stringify(state, null, 2));

  try {
    // --- @vaultline/core: a partial, real copy in place of the link.
    if (state.coreLink) fs.unlinkSync(CORE_PATH);
    if (!exists(CORE_PATH)) {
      fs.mkdirSync(CORE_PATH, { recursive: true });
      copyInto(coreSource, CORE_PATH, withServerDeps ? [...CORE_ENTRIES, SERVER_DEPS] : CORE_ENTRIES);
    }

    // --- The core's own runtime dependencies, which live under the core's
    // node_modules and are therefore outside the extension directory — the
    // only place vsce looks. Read from the core's manifest rather than
    // hardcoded, so adding a dependency there can't silently produce a .vsix
    // that fails to load it.
    for (const dep of runtimeDeps) {
      const target = path.join(NODE_MODULES, dep);
      if (exists(target)) continue; // already present — leave whatever's there alone
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.cpSync(packageRoot(dep, coreSource), target, { recursive: true, dereference: true });
    }

    // --- The manifest's dependency spec, temporarily.
    //
    // vsce decides which node_modules paths to ship by running `npm list`, and
    // npm calls a `file:../core` dependency INVALID the moment the link is
    // replaced by the real copy staged above — which fails the listing, and
    // with it the whole package. Pointing the spec at the version actually
    // sitting there makes the listing agree with reality for exactly as long
    // as the staging lasts. Restored byte-for-byte in unstage().
    if (state.manifestBefore) {
      const manifest = JSON.parse(state.manifestBefore);
      manifest.dependencies["@vaultline/core"] = require(path.join(coreSource, "package.json")).version;
      fs.writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);
    }
  } catch (err) {
    unstage();
    throw err;
  }

  console.log(
    `stageCore: staged @vaultline/core${withServerDeps ? " (with server dependencies)" : ""} ` +
      `and ${runtimeDeps.length} runtime dependenc${runtimeDeps.length === 1 ? "y" : "ies"}.`
  );
  return true;
}

function unstage() {
  if (!exists(MARKER_PATH)) return;
  const { created, coreLink, manifestBefore } = JSON.parse(fs.readFileSync(MARKER_PATH, "utf-8"));

  if (manifestBefore) fs.writeFileSync(MANIFEST_PATH, manifestBefore);
  for (const target of created) fs.rmSync(target, { recursive: true, force: true });
  if (coreLink) {
    fs.mkdirSync(path.dirname(CORE_PATH), { recursive: true });
    fs.symlinkSync(coreLink, CORE_PATH, "dir");
  }

  fs.rmSync(MARKER_PATH, { force: true });
  console.log("stageCore: restored the workspace layout.");
}

function main() {
  const argv = process.argv.slice(2);
  const withServerDeps = argv.includes("--with-server-deps");

  if (argv.includes("--unstage")) return unstage();
  if (argv.includes("--stage")) return void stage({ withServerDeps });

  const separator = argv.indexOf("--");
  if (!argv.includes("--run") || separator === -1 || separator === argv.length - 1) {
    console.error("stageCore: expected --run -- <command…>, or --stage / --unstage.");
    process.exit(2);
  }

  const [command, ...args] = argv.slice(separator + 1);
  let staged = false;
  try {
    staged = stage({ withServerDeps });
    const result = spawnSync(command, args, { stdio: "inherit", cwd: EXTENSION_DIR, shell: process.platform === "win32" });
    if (result.status !== 0) process.exitCode = result.status ?? 1;
  } finally {
    if (staged) unstage();
  }
}

module.exports = { stage, unstage };

if (require.main === module) main();
