/**
 * The `-p` round trip: typed prompt out, real values back.
 *
 * Interactive mode guards only the tool boundary, because Copilot owns the
 * terminal in both directions. With `-p` the prompt arrives in our argv and
 * the answer comes back through our stdout, so the whole loop is available —
 * the same one the VS Code host has:
 *
 *     typed prompt  -> guardPrompt()      -> Copilot -> GitHub
 *     answer        <- restoreResponse()  <- Copilot
 *
 * The subtle part is that these two halves run in DIFFERENT PROCESSES from the
 * file redaction: Copilot spawns the MCP server itself. Two EntityStores would
 * mint tokens independently, so the same secret could be <<PASSWORD_1>> in the
 * prompt and <<PASSWORD_2>> in a file read — or worse, two different secrets
 * could collide on one token and restore to the wrong value. They share one
 * store through an ephemeral file, and that sharing is what these checks are
 * really about.
 *
 * No Copilot process is started here. Spawning one would cost AI credits on
 * every test run and make the suite depend on network and authentication;
 * `vaultline doctor --live` is the command that does talk to the real CLI.
 */

const path = require("path");
const fs = require("fs");
const os = require("os");
const { check, startServer, summarize, tempDir, textOf, CONFIG_YAML } = require("./harness");

const CORE = path.join(__dirname, "..", "node_modules", "@vaultline", "core", "out");
const { ConsoleHost, VaultlineEngine, DEFAULT_SETTINGS } = require(path.join(CORE, "index"));

const SETTINGS = { ...DEFAULT_SETTINGS, embeddingBackend: "hashing" };

async function main() {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "config.yaml"), CONFIG_YAML);
  const sessionPath = path.join(dir, "session.json");

  console.log("\n[a secret typed into the prompt never leaves]");
  let promptToken;
  {
    const engine = VaultlineEngine.create(new ConsoleHost(SETTINGS, dir));
    const session = engine.createSession(sessionPath);
    const guarded = await session.guardPrompt("My database password is Hunter@123, is that strong enough?");

    check("the prompt was redacted", !guarded.redactedText.includes("Hunter@123"), guarded.redactedText);
    check("a token replaced it", /<<PASSWORD_\d+>>/.test(guarded.redactedText), guarded.redactedText);
    check("the rest of the sentence survives", guarded.redactedText.includes("is that strong enough?"), guarded.redactedText);
    promptToken = (guarded.redactedText.match(/<<PASSWORD_\d+>>/) || [])[0];
    engine.dispose();
  }

  console.log("\n[the answer is restored before the developer sees it]");
  {
    const engine = VaultlineEngine.create(new ConsoleHost(SETTINGS, dir));
    const session = engine.createSession(sessionPath);
    // What Copilot would print, quoting the token it was given.
    const answer = `No — ${promptToken} is weak. Consider a longer passphrase.`;
    const restored = session.restoreResponse(answer);

    check("the real value is legible again", restored.text.includes("Hunter@123"), restored.text);
    check("no placeholder is left standing", !/<<[A-Z_]+_\d+>>/.test(restored.text), restored.text);
    check("nothing is flagged as lost", restored.suspiciousTokens.length === 0, restored.suspiciousTokens.join(","));
    engine.dispose();
  }

  console.log("\n[THE CROSS-PROCESS PART: prompt and file agree on one token]");
  {
    // The MCP server runs as its own process against the same session file.
    // If the stores were separate, this read would mint a SECOND password
    // token for the same value.
    const server = startServer({ cwd: dir, settings: SETTINGS, persistPath: sessionPath });
    await server.call("initialize", {});
    const fileText = textOf(await server.call("tools/call", { name: "vaultline_read", arguments: { path: "config.yaml" } }));
    await server.close();

    const fileToken = (fileText.match(/<<PASSWORD_\d+>>/) || [])[0];
    check("the file read reused the prompt's token", fileToken === promptToken, `prompt ${promptToken} vs file ${fileToken}`);

    // And the reverse direction: a value first seen in the FILE must restore
    // correctly in the parent, which only learns about it by re-reading.
    const engine = VaultlineEngine.create(new ConsoleHost(SETTINGS, dir));
    const session = engine.createSession(sessionPath);
    const apiToken = (fileText.match(/<<API_KEY_\d+>>/) || [])[0];
    check("the file minted an api key token", !!apiToken, fileText.slice(0, 200));
    const restored = session.restoreResponse(`The key ${apiToken} is committed.`);
    check("the parent restores a token minted by the child", restored.text.includes("sk-lf-9c8b7a6d5e4f3g2h"), restored.text);
    engine.dispose();
  }

  console.log("\n[distinct secrets never share a token]");
  {
    const engine = VaultlineEngine.create(new ConsoleHost(SETTINGS, path.join(dir, "b")));
    const session = engine.createSession(path.join(dir, "b-session.json"));
    const a = await session.guardPrompt("my password is Hunter@123");
    const b = await session.guardPrompt("my password is Different@456");
    const tokenA = (a.redactedText.match(/<<PASSWORD_\d+>>/) || [])[0];
    const tokenB = (b.redactedText.match(/<<PASSWORD_\d+>>/) || [])[0];
    check("two values get two tokens", tokenA !== tokenB, `${tokenA} / ${tokenB}`);
    check("and each restores to its own value", session.restoreResponse(`${tokenA} ${tokenB}`).text === "Hunter@123 Different@456");
    engine.dispose();
  }

  console.log("\n[the ephemeral session file is not the permanent one]");
  {
    // persistSessionMappings writes to ~/.vaultline/sessions and stays there.
    // The -p session file lives in a private temp dir and is deleted on exit;
    // conflating them would leave real values behind after every run.
    check("default config does not persist mappings", DEFAULT_SETTINGS.persistSessionMappings === false);
    const cliSource = fs.readFileSync(path.join(__dirname, "..", "out", "cli.js"), "utf8");
    check("the ephemeral dir is created under the OS temp dir", cliSource.includes("vaultline-session-"));
    check("it is locked down to the owner", cliSource.includes("0o700") || cliSource.includes("448"));
    check("it is removed on exit", /process\.on\("exit"/.test(cliSource) && cliSource.includes("rmSync"));
    check("and on interrupt", cliSource.includes("SIGINT"));
  }

  console.log("\n[a blocked prompt is not sent at all]");
  {
    const engine = VaultlineEngine.create(new ConsoleHost({ ...SETTINGS, blockOnHighSeverity: true }, dir));
    const session = engine.createSession();
    const guarded = await session.guardPrompt("here is my key: AKIAIOSFODNN7EXAMPLE");
    if (guarded.action === "block") {
      check("blocked prompts carry no text onward", guarded.redactedText === "", JSON.stringify(guarded.redactedText));
    } else {
      check("a high-severity secret is at least redacted", !guarded.redactedText.includes("AKIAIOSFODNN7EXAMPLE"), guarded.redactedText);
    }
    engine.dispose();
  }

  console.log("\n[resuming must not silently drop protection]");
  {
    // Copilot ends every session by printing `Resume  copilot --resume=<id>`.
    // Followed literally that runs plain Copilot with its built-in file tools
    // back — no warning, and the user has only copied the command the tool
    // handed them. We cannot change what Copilot prints, so Vaultline sets the
    // session UUID itself in order to print the protected form afterwards.
    const { sessionSteeringFlags } = require(path.join(__dirname, "..", "out", "cli"));

    const fresh = sessionSteeringFlags([]);
    check("a fresh session gets an id assigned", fresh.args[0] === "--session-id" && !!fresh.args[1], JSON.stringify(fresh.args));
    check("and that id is known, so the hint can name it", fresh.id === fresh.args[1]);

    // THE BUG THIS BLOCK EXISTS FOR. The first version suppressed the hint
    // whenever the user steered the session — conflating "do not assign an id"
    // with "do not know one". Copilot prints its unprotected resume line at the
    // end of a RESUMED session too, so the footgun came back on every session
    // after the first.
    for (const argv of [["--resume=abc-123"], ["-r", "abc-123"], ["--session-id", "abc-123"]]) {
      const r = sessionSteeringFlags(argv);
      check(`${JSON.stringify(argv)} assigns no id of our own`, r.args.length === 0, JSON.stringify(r.args));
      check(`${JSON.stringify(argv)} still knows the id for the hint`, r.id === "abc-123", String(r.id));
    }

    // No id recoverable here — both pick a session interactively — but the
    // warning still has to appear, which printResumeHint handles by showing
    // <id> rather than staying silent.
    for (const argv of [["--continue"], ["--resume"]]) {
      const r = sessionSteeringFlags(argv);
      check(`${JSON.stringify(argv)} assigns nothing`, r.args.length === 0, JSON.stringify(r.args));
      check(`${JSON.stringify(argv)} has no id to report`, r.id === undefined, String(r.id));
    }

    check("--reveal is not mistaken for a session id", sessionSteeringFlags(["--resume=a", "--reveal"]).id === "a");
    check("a -p run still gets an id", !!sessionSteeringFlags(["-p", "hello"]).id);
  }
  summarize("prompt-loop");
}

main();
