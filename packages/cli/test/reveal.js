/**
 * `vaultline reveal` — reading back an answer full of placeholders.
 *
 * The honest limitation of this integration: Copilot's reply goes straight
 * from the CLI to the terminal without passing through Vaultline, so the
 * developer reads <<PASSWORD_1>> where VS Code would have shown the real
 * value. reveal closes that after the fact.
 *
 * It needs mappings to outlive the process, which means persistSessionMappings
 * — a setting that writes every detected value to disk in plain text and is
 * off by default for exactly that reason. So the two cases that matter are
 * both here: it works when the user has opted in, and when they have not it
 * says so rather than silently producing nothing.
 */

const path = require("path");
const fs = require("fs");
const { CONFIG_YAML, check, startServer, summarize, tempDir, textOf } = require("./harness");
const { EntityStore, restore } = require(path.join(__dirname, "..", "node_modules", "@vaultline", "core", "out", "index"));

async function main() {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "config.yaml"), CONFIG_YAML);
  const persistPath = path.join(dir, "session.json");

  console.log("\n[opted in: placeholders come back]");
  {
    const server = startServer({ cwd: dir, settings: { persistSessionMappings: true }, persistPath });
    await server.call("initialize", {});
    const redacted = textOf(await server.call("tools/call", { name: "vaultline_read", arguments: { path: "config.yaml" } }));
    await server.close();

    check("mappings were mirrored to disk", fs.existsSync(persistPath));

    // Stand in for what the developer copies off their terminal: Copilot's
    // prose answer, quoting tokens it was given.
    const answer = [
      "Two problems in this config:",
      "  1. the password " + (redacted.match(/<<PASSWORD_\d+>>/) || [])[0] + " is committed in plain text",
      "  2. " + (redacted.match(/<<USERNAME_\d+>>/) || [])[0] + " should not be a shared service account",
    ].join("\n");

    const store = new EntityStore(persistPath);
    const revealed = restore(answer, store.allMappings());

    check("the password is legible again", revealed.includes("Hunter@123"), revealed);
    check("the username is legible again", revealed.includes("svc_corp_uat"), revealed);
    check("no placeholder is left standing", !/<<[A-Z_]+_\d+>>/.test(revealed), revealed);
    check("the surrounding prose is untouched", revealed.startsWith("Two problems in this config:"), revealed.slice(0, 40));
  }

  console.log("\n[not opted in: nothing is written, and reveal has nothing to work with]");
  {
    const otherDir = tempDir();
    fs.writeFileSync(path.join(otherDir, "config.yaml"), CONFIG_YAML);
    const server = startServer({ cwd: otherDir }); // persistSessionMappings defaults off
    await server.call("initialize", {});
    await server.call("tools/call", { name: "vaultline_read", arguments: { path: "config.yaml" } });
    await server.close();

    const strays = fs.readdirSync(otherDir).filter((f) => f.endsWith(".json"));
    check("no mapping file is written by default", strays.length === 0, strays.join(", "));
  }

  console.log("\n[the default really is off]");
  {
    const { DEFAULT_SETTINGS } = require(path.join(__dirname, "..", "node_modules", "@vaultline", "core", "out", "index"));
    check("persistSessionMappings defaults to false", DEFAULT_SETTINGS.persistSessionMappings === false);
  }

  console.log("\n[--reveal: usable without turning on permanent persistence]");
  {
    // The point of the flag. Restoring terminal output used to require
    // persistSessionMappings, which writes every value to disk permanently —
    // a heavy price for a convenience. --reveal instead shares the same
    // ephemeral, deleted-on-exit file the -p path already uses.
    const cliSource = fs.readFileSync(path.join(__dirname, "..", "out", "cli.js"), "utf8");

    check("the flag exists", cliSource.includes("--reveal"));
    check("it is stripped before Copilot sees it", /filter\(\s*\(a\)\s*=>\s*a\s*!==\s*"--reveal"\s*\)/.test(cliSource), "not filtered from argv");
    check("it reuses the ephemeral session, not the permanent one", cliSource.includes("createEphemeralSession(true)"));

    // reveal runs as a separate process and the temp path is random, so a
    // pointer is the only way it can find the live file.
    check("a pointer file is published for the second process", cliSource.includes("current-session"));
    check("the pointer is owner-only", cliSource.includes("0o600") || cliSource.includes("384"));
    check("the pointer is removed with the session", /rmSync\(CURRENT_SESSION_POINTER|CURRENT_SESSION_POINTER, \{ force: true \}/.test(cliSource));

    // A crash skips the exit handler, so a stale pointer must not wedge reveal.
    check("a stale pointer falls through instead of failing", cliSource.includes("existsSync(pointed)"));
  }

  console.log("\n[--reveal does NOT claim to fix the screen]");
  {
    // Worth asserting: the flag shares mappings, it does not restore the live
    // TUI. Copilot requires a TTY and rewrites its own layout, so substituting
    // a different-width value under it would corrupt the display.
    const cliSource = fs.readFileSync(path.join(__dirname, "..", "out", "cli.js"), "utf8");
    check("the banner still says answers show placeholders", /still show <<TYPE_N>> on screen/.test(cliSource), "banner overstates coverage");
  }

  summarize("reveal");
}

main();
