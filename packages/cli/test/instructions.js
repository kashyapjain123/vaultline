/**
 * What the model is told about tokens.
 *
 * Redaction working and the session being USABLE are different things. If the
 * model is handed <<PASSWORD_1>> with no explanation, the reasonable reading
 * is that information is missing — so it stops and asks the developer to paste
 * the real value, or hedges every answer with "replace this placeholder".
 * Nothing is leaked, but the tool is annoying enough to turn off, which leaks
 * everything.
 *
 * In VS Code the instruction is prepended to each request. Here we do not own
 * the prompt, so the only channel is the `instructions` field of the MCP
 * initialize result — and Copilot CLI honours that only for allowlisted
 * servers unless --allow-all-mcp-server-instructions is passed. Both halves
 * are asserted: the text is served, and the launcher passes the flag.
 */

const path = require("path");
const fs = require("fs");
const { check, startServer, summarize, tempDir } = require("./harness");
const { EXCLUDED_BUILTINS } = require(path.join(__dirname, "..", "out", "copilotTools"));

async function main() {
  const dir = tempDir();
  const server = startServer({ cwd: dir });

  console.log("\n[initialize carries the instruction]");
  const res = await server.call("initialize", {});
  const text = res.result.instructions ?? "";

  check("instructions are present at all", text.length > 0);
  check("the token format is spelled out", text.includes("<<TYPE_N>>"), text.slice(0, 80));

  console.log("\n[the half that was missing before 1.4.0]");
  {
    // Paragraph one (preserve tokens) shipped from the start. Paragraph two —
    // that the developer DOES see real values, so do not stall — is the fix,
    // and its absence is invisible until a model asks you to paste a password.
    check("says the developer is not missing the information", /developer is NOT missing/i.test(text), "(absent)");
    check("forbids asking the developer for the value", /do not ask the developer/i.test(text), "(absent)");
    check("forbids pausing or refusing to continue", /do not pause or refuse/i.test(text), "(absent)");
    check("forbids 'fill this in' warnings", /do not add notes, warnings, or TODOs/i.test(text), "(absent)");
  }

  console.log("\n[and still forbids the original failure]");
  {
    check("reproduce tokens exactly", /Reproduce every token exactly/i.test(text), "(absent)");
    check("no guessing the original", /Do not guess, infer, reconstruct, or omit/i.test(text), "(absent)");
  }

  console.log("\n[the tools are named, so the model prefers them]");
  {
    for (const name of ["vaultline_read", "vaultline_grep", "vaultline_shell", "vaultline_write", "vaultline_edit"]) {
      check(`mentions ${name}`, text.includes(name));
    }
  }

  await server.close();

  console.log("\n[the launcher actually turns the instruction on]");
  {
    // Serving instructions the CLI then discards would be a silent failure, so
    // the flag is asserted in the source of the launcher itself.
    const cliSource = fs.readFileSync(path.join(__dirname, "..", "out", "cli.js"), "utf8");
    check("passes --allow-all-mcp-server-instructions", cliSource.includes("--allow-all-mcp-server-instructions"));
    check("passes --excluded-tools", cliSource.includes("--excluded-tools"));
    check("passes --additional-mcp-config", cliSource.includes("--additional-mcp-config"));
  }

  console.log("\n[every built-in ingestion and write path is replaced]");
  {
    // If a built-in read tool is left enabled the model simply uses it and
    // never calls us — a silent bypass, not a degraded experience.
    //
    // These names come from a real request payload captured with --log-level
    // debug. An earlier version of this list came from the CLI's bundled
    // registry instead, which turned out to describe `copilot init`'s
    // capability check rather than the runtime tools: four of its nine names
    // were rejected outright, and because `shell` is not the shell tool's name
    // (`bash` is), command output was reaching the model unredacted while
    // everything appeared to be working. Hence `vaultline doctor --live`.
    for (const name of ["view", "grep", "glob", "bash", "read_bash", "edit", "create"]) {
      check(`excludes built-in ${name}`, EXCLUDED_BUILTINS.includes(name));
    }
    check("excludes the subagent launcher, which has its own toolset", EXCLUDED_BUILTINS.includes("task"));

    // The names that were wrong. Asserting their ABSENCE keeps the mistake
    // from being reintroduced by anyone reading that bundled registry.
    for (const name of ["shell", "rg", "str_replace_editor", "apply_patch"]) {
      check(`does not request the non-existent "${name}"`, !EXCLUDED_BUILTINS.includes(name));
    }
    check("the exclusion list has no duplicates", new Set(EXCLUDED_BUILTINS).size === EXCLUDED_BUILTINS.length, EXCLUDED_BUILTINS.join(","));
  }

  summarize("instructions");
}

main();
