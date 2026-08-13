#!/usr/bin/env node
/**
 * First-run setup for a fresh clone.
 *
 * Both packages live in this repository, but they are installed and built
 * separately and IN ORDER — the extension type-checks against the .d.ts the
 * core emits, and resolves it through a `file:../core` dependency, so a
 * plain `npm install` at the root does neither of the things that need
 * doing. This runs them in the right order.
 *
 * The guard below exists because that `file:` dependency fails with an
 * unhelpful ENOENT if packages/core is missing (a partial checkout, or the
 * directory deleted by hand) — worth naming plainly rather than leaving
 * someone to decode a path error.
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const CORE_DIR = path.join(ROOT, "packages", "core");

function run(command, args) {
  const result = spawnSync(command, args, { stdio: "inherit", cwd: ROOT, shell: process.platform === "win32" });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

if (!fs.existsSync(path.join(CORE_DIR, "package.json"))) {
  console.error(
    "\n@vaultline/core is missing.\n\n" +
      `  Expected the detection engine at ${path.relative(process.cwd(), CORE_DIR) || "packages/core"}.\n` +
      "  It is tracked in this repository, so this usually means an incomplete\n" +
      "  checkout or a deleted directory. Restore it and re-run:\n\n" +
      "    git checkout -- packages/core\n" +
      "    npm run setup\n"
  );
  process.exit(1);
}

// Installed per package, not once at the root: this is deliberately not an
// npm workspace, because vsce's `npm list` answers for the whole repo inside
// one and it then collects files from outside the extension. See the root
// package.json.
console.log("Installing @vaultline/core dependencies…");
run("npm", ["--prefix", "packages/core", "install", "--no-audit", "--no-fund"]);

console.log("\nInstalling extension dependencies…");
run("npm", ["--prefix", "packages/vscode-extension", "install", "--no-audit", "--no-fund"]);

console.log("\nCompiling @vaultline/core and the extension…");
run("npm", ["run", "compile"]);

console.log("\nChecking the settings manifest against the core…");
run("npm", ["run", "check:settings"]);

console.log("\nReady. Press F5 in VS Code to launch an Extension Development Host.");
