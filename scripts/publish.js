#!/usr/bin/env node
/**
 * Publish @vaultline/core and @vaultline/cli to npm.
 *
 * Exists because publishing this repo by hand gets two things wrong, both
 * quietly:
 *
 * 1. `packages/cli` depends on the core as `file:../core`. That is right for
 *    development — npm symlinks it, so a core change is picked up without a
 *    reinstall — and completely wrong in a published tarball, where a consumer
 *    has no `../core` to resolve. npm packs the manifest verbatim, so the
 *    package publishes cleanly and then fails on every install. This script
 *    swaps the spec to the core's real version for the publish and puts the
 *    file: link back afterwards, in a finally, the same shape as
 *    stageCore.js's dance for vsce.
 *
 * 2. A SCOPED package defaults to `restricted`, which on a free account fails
 *    with a payment-required error that reads like an account problem rather
 *    than a missing flag. `--access public` is passed explicitly every time.
 *
 * Order matters: the core goes first, because the CLI's dependency on it must
 * be resolvable the moment the CLI is published.
 *
 * Usage:
 *   node scripts/publish.js --dry-run     # pack both, install them, publish nothing
 *   node scripts/publish.js               # the real thing
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const CORE_DIR = path.join(ROOT, "packages", "core");
const CLI_DIR = path.join(ROOT, "packages", "cli");
const CLI_MANIFEST = path.join(CLI_DIR, "package.json");

const dryRun = process.argv.includes("--dry-run");

function run(command, args, cwd = ROOT) {
  const result = spawnSync(command, args, { stdio: "inherit", cwd, shell: process.platform === "win32" });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with status ${result.status}`);
  }
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function main() {
  const coreVersion = readJson(path.join(CORE_DIR, "package.json")).version;
  const cliManifest = readJson(CLI_MANIFEST);

  if (cliManifest.version !== coreVersion) {
    throw new Error(
      `Version mismatch: core is ${coreVersion}, cli is ${cliManifest.version}.\n` +
        "  They are released in lockstep — the CLI pins the core exactly — so bump both.",
    );
  }

  // Compiled output is what actually ships; a stale `out/` publishes silently.
  for (const [name, dir] of [["core", CORE_DIR], ["cli", CLI_DIR]]) {
    if (!fs.existsSync(path.join(dir, "out"))) {
      throw new Error(`packages/${name}/out is missing — run "npm run compile" first.`);
    }
  }

  const original = fs.readFileSync(CLI_MANIFEST, "utf8");
  const publishArgs = dryRun ? ["publish", "--access", "public", "--dry-run"] : ["publish", "--access", "public"];

  try {
    // Pin exactly, not with a caret. The two are cut from one commit and the
    // CLI reaches into core internals that a minor bump could reasonably move.
    cliManifest.dependencies["@vaultline/core"] = coreVersion;
    fs.writeFileSync(CLI_MANIFEST, JSON.stringify(cliManifest, null, 2) + "\n", "utf8");

    console.log(`\n=== @vaultline/core@${coreVersion} ===`);
    run("npm", publishArgs, CORE_DIR);

    console.log(`\n=== @vaultline/cli@${coreVersion} (depends on core ${coreVersion}) ===`);
    run("npm", publishArgs, CLI_DIR);
  } finally {
    // Always — a failed publish must not leave the working tree pinned to a
    // registry version, which would break the local build with no obvious cause.
    fs.writeFileSync(CLI_MANIFEST, original, "utf8");
    console.log("\nRestored packages/cli/package.json (file:../core).");
  }

  console.log(
    dryRun
      ? "\nDry run only — nothing was published.\n"
      : `\nPublished. Users install with:\n\n    npm install -g @vaultline/cli\n\n` +
          `Then:\n\n    vaultline doctor --live\n    vaultline copilot\n`,
  );
}

try {
  main();
} catch (err) {
  console.error(`\npublish failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
