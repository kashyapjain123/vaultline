#!/usr/bin/env node
/**
 * `vaultline` — the terminal front end.
 *
 *   vaultline copilot [args…]   launch Copilot CLI with its file/shell tools
 *                               swapped for Vaultline's redacting equivalents
 *   vaultline mcp               the MCP server itself (stdio; Copilot spawns this)
 *   vaultline reveal [file|-]   substitute placeholders in captured output back
 *                               to real values
 *   vaultline doctor            check the wiring and say what is and is not covered
 */

import { spawn, spawnSync } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { EntityStore, VaultlineEngine, restore } from "@vaultline/core";
import { CliHost, CONFIG_PATH, VAULTLINE_HOME, loadConfig } from "./cliHost";
import { EXCLUDED_BUILTINS, MCP_SERVER_NAME } from "./copilotTools";
import { runMcpServer } from "./mcpServer";

const SESSIONS_DIR = path.join(VAULTLINE_HOME, "sessions");

/** Points at the live `--reveal` session file. Contains a path, never a value; removed when the session ends. */
const CURRENT_SESSION_POINTER = path.join(VAULTLINE_HOME, "current-session");

function fail(message: string): never {
  process.stderr.write(`vaultline: ${message}\n`);
  process.exit(1);
}

/**
 * Where this run's entity mappings are mirrored, or undefined when
 * persistSessionMappings is off — which is the default, and deliberately so:
 * the file holds every detected value in plain text, right next to its token.
 */
function sessionMappingPath(persist: boolean): string | undefined {
  if (!persist) return undefined;
  fs.mkdirSync(SESSIONS_DIR, { recursive: true });
  return path.join(SESSIONS_DIR, `${crypto.randomUUID()}.json`);
}

// -------------------------------------------------------------------
// vaultline mcp
// -------------------------------------------------------------------

async function cmdMcp(argv: string[]): Promise<void> {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i !== -1 ? argv[i + 1] : undefined;
  };
  const cwd = flag("--cwd") ?? process.cwd();

  const { settings } = loadConfig();
  const host = new CliHost(settings);
  const engine = VaultlineEngine.create(host);

  // --session is how `vaultline copilot -p` shares ONE EntityStore across two
  // processes. Copilot spawns this server itself, so without a shared store
  // the parent (which redacts the typed prompt) and this child (which redacts
  // file contents) would mint tokens independently and collide — two different
  // values could both become <<API_KEY_1>>. It takes precedence over the
  // persistSessionMappings path because it is a scoped, deleted-on-exit file
  // rather than the permanent one.
  const persistPath = flag("--session") ?? sessionMappingPath(settings.persistSessionMappings);

  try {
    await runMcpServer(engine, { cwd, persistPath });
  } finally {
    engine.dispose();
  }
}

// -------------------------------------------------------------------
// vaultline copilot
// -------------------------------------------------------------------

/** The config Copilot CLI reads to find us. Schema matches what `copilot mcp add` writes. */
function writeMcpConfig(cwd: string, sessionPath?: string): string {
  fs.mkdirSync(VAULTLINE_HOME, { recursive: true });
  const configPath = path.join(VAULTLINE_HOME, "copilot-mcp.json");
  const args = [path.join(__dirname, "cli.js"), "mcp", "--cwd", cwd];
  if (sessionPath) args.push("--session", sessionPath);

  const config = {
    mcpServers: {
      [MCP_SERVER_NAME]: {
        tools: ["*"],
        type: "local",
        // process.execPath, not "node": the user's PATH node may differ from
        // the one this was installed under, and a version mismatch here
        // surfaces as a silent MCP handshake failure.
        command: process.execPath,
        args,
      },
    },
  };
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), "utf8");
  return configPath;
}

/**
 * Copilot ends every session by printing `Resume  copilot --resume=<id>`.
 *
 * Followed literally that is a silent downgrade: plain `copilot` has no
 * Vaultline in it, so the built-in file and shell tools come back and the
 * resumed conversation reads files straight to GitHub. The user has done
 * nothing wrong — they copied the command the tool gave them.
 *
 * We cannot change what Copilot prints, but we can make sure the right
 * command exists to print afterwards. `--session-id` lets us choose the UUID
 * rather than discover it, which we could not otherwise do with stdio
 * inherited, and then the correct line can be shown on exit.
 *
 * Skipped when the user is already steering the session themselves — passing
 * our own id on top of --resume or --continue would either be ignored or
 * start the wrong conversation.
 */
export function sessionSteeringFlags(argv: string[]): { args: string[]; id?: string } {
  const steering = ["--session-id", "--resume", "-r", "--continue", "--connect"];

  // Two separate questions, and conflating them was a bug: whether to ASSIGN
  // an id, and whether we KNOW one to show at the end. On a resumed session we
  // must not assign — but we do know the id, because the user just gave it to
  // us — and Copilot prints its unprotected resume line at the end of that
  // session too. Suppressing the hint there meant the downgrade was only
  // guarded against on the very first run of a conversation.
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const match = steering.find((s) => arg === s || arg.startsWith(`${s}=`));
    if (!match) continue;

    // `--resume=<id>` / `--session-id=<id>`, or the value in the next argv slot.
    // Both --resume and -r take an OPTIONAL value, so a bare one (pick a session
    // interactively) leaves us without an id — hence the undefined case below.
    const attached = arg.includes("=") ? arg.slice(arg.indexOf("=") + 1) : undefined;
    const separate = argv[i + 1] && !argv[i + 1].startsWith("-") ? argv[i + 1] : undefined;
    const known = attached || (match === "--session-id" || match === "--resume" || match === "-r" ? separate : undefined);

    return { args: [], id: known };
  }

  const id = crypto.randomUUID();
  return { args: ["--session-id", id], id };
}

/**
 * Tell the user how to resume WITH protection, since Copilot has just told
 * them how to resume without it.
 *
 * Printed even when we do not know the id — `--continue` and a bare `--resume`
 * leave us without one — because the warning matters more than the
 * convenience, and the id is on screen directly above.
 */
function printResumeHint(id: string | undefined, reveal: boolean): void {
  const flags = reveal ? " --reveal" : "";
  const shown = id ? `=${id}` : "=<id>";
  process.stderr.write(
    `\nvaultline: Copilot printed "copilot --resume${shown}" above — that command runs\n` +
      `vaultline: WITHOUT Vaultline, so files would reach the model unredacted.\n` +
      `vaultline: To resume protected:\n\n` +
      `    vaultline copilot${flags} --resume${shown}\n\n`,
  );
}

/** Index of the -p/--prompt VALUE in argv, or -1 when this is an interactive run. */
function promptArgIndex(argv: string[]): number {
  const i = argv.findIndex((a) => a === "-p" || a === "--prompt");
  return i !== -1 && i + 1 < argv.length ? i + 1 : -1;
}

/**
 * A mapping file only for the lifetime of one `-p` run.
 *
 * Distinct from persistSessionMappings, which is permanent and off by default.
 * This one exists solely so the parent and the MCP child agree on tokens, is
 * created 0600 inside a private directory, and is removed on the way out. It
 * still holds real values while it exists — that is unavoidable for two
 * processes to share a store — so the cleanup is registered before anything is
 * written, and runs on signals as well as normal exit.
 */
function createEphemeralSession(publish = false): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vaultline-session-"));
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, "mappings.json");

  // `publish` writes a pointer so a SECOND process — `vaultline reveal`, run
  // from another terminal while the session is live — can find this file. The
  // path is random by design, so without the pointer reveal has no way to
  // locate it. The pointer holds a path, never a value.
  if (publish) {
    fs.mkdirSync(VAULTLINE_HOME, { recursive: true });
    fs.writeFileSync(CURRENT_SESSION_POINTER, file, { encoding: "utf8", mode: 0o600 });
  }

  const cleanup = () => {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      if (publish) fs.rmSync(CURRENT_SESSION_POINTER, { force: true });
    } catch {
      /* best effort — nothing useful to do if the temp dir is already gone */
    }
  };
  process.on("exit", cleanup);
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
    process.on(sig, () => {
      cleanup();
      process.exit(130);
    });
  }
  return file;
}

async function cmdCopilot(argv: string[]): Promise<void> {
  const probe = spawnSync("copilot", ["--version"], { stdio: "ignore" });
  if (probe.error) {
    fail("GitHub Copilot CLI not found on PATH. Install it with: npm install -g @github/copilot");
  }

  const cwd = process.cwd();

  // Ours, not Copilot's — strip it before spawning or the CLI rejects it.
  const wantsReveal = argv.includes("--reveal");
  const passThrough = argv.filter((a) => a !== "--reveal");

  const promptIndex = promptArgIndex(passThrough);
  const interactive = promptIndex === -1;

  // Interactive and -p are genuinely different integrations, not one with a
  // flag. Interactive gives Copilot the terminal and we only guard the tool
  // boundary. With -p the prompt and the answer both pass through this
  // process, so the full loop is available — the same one the VS Code host has.
  if (interactive) {
    // --reveal only shares the token store so a second process can read it.
    // It does NOT restore anything on screen: Copilot renders a full-screen
    // TUI and requires a TTY, and substituting a different-width string under
    // a TUI corrupts its own cursor and layout arithmetic. See the README.
    const sessionPath = wantsReveal ? createEphemeralSession(true) : undefined;
    const configPath = writeMcpConfig(cwd, sessionPath);

    process.stderr.write(
      `vaultline: ${EXCLUDED_BUILTINS.length} built-in tools replaced. File and shell content is redacted.\n` +
        `vaultline: what you TYPE is not — it goes to GitHub as typed. Use -p for full coverage.\n` +
        (wantsReveal
          ? "vaultline: --reveal is on. Answers still show <<TYPE_N>> on screen; pipe or paste them\n" +
            "vaultline:   into `vaultline reveal` (another terminal) for real values. Mappings are\n" +
            "vaultline:   held in a private temp file for this session only and deleted on exit.\n"
          : ""),
    );

    const steering = sessionSteeringFlags(passThrough);
    const child = spawn("copilot", [...baseArgs(configPath), ...steering.args, ...passThrough], { stdio: "inherit" });
    child.on("exit", (code, signal) => {
      printResumeHint(steering.id, wantsReveal);
      if (signal) process.kill(process.pid, signal);
      else process.exit(code ?? 0);
    });
    return;
  }

  if (wantsReveal) {
    process.stderr.write("vaultline: --reveal is redundant with -p, which already restores the answer.\n");
  }
  await runGuardedPrompt(passThrough, promptIndex, cwd);
}

function baseArgs(configPath: string): string[] {
  return [
    `--excluded-tools=${EXCLUDED_BUILTINS.join(",")}`,
    "--additional-mcp-config",
    `@${configPath}`,
    // Without this the CLI drops our initialize() instructions unless the
    // server is separately allowlisted, and the model starts asking the
    // developer to paste values it believes are missing. See mcpServer.ts.
    "--allow-all-mcp-server-instructions",
  ];
}

/**
 * The full loop, for non-interactive runs.
 *
 *   typed prompt -> guardPrompt()  -> Copilot -> GitHub
 *   answer       <- restoreResponse() <- Copilot
 *
 * Both halves run here in the parent, sharing one EntityStore with the MCP
 * child through an ephemeral file, so a value redacted out of the prompt and
 * the same value redacted out of a file get the same token.
 */
async function runGuardedPrompt(argv: string[], promptIndex: number, cwd: string): Promise<void> {
  const sessionPath = createEphemeralSession();
  const { settings } = loadConfig();
  const host = new CliHost(settings);
  const engine = VaultlineEngine.create(host);

  try {
    const session = engine.createSession(sessionPath);
    const guarded = await session.guardPrompt(argv[promptIndex]);

    if (guarded.action === "block") {
      fail(`prompt blocked before it left this machine — ${guarded.reason}`);
    }
    if (guarded.mappings.length > 0) {
      process.stderr.write(`vaultline: redacted ${guarded.mappings.length} value(s) from your prompt.\n`);
    }

    const outgoing = [...argv];
    outgoing[promptIndex] = guarded.redactedText;
    const configPath = writeMcpConfig(cwd, sessionPath);

    // Piped rather than inherited, because the answer has to come back through
    // here to be restored. stderr stays inherited so Copilot's own progress and
    // warnings still reach the user live.
    const steering = sessionSteeringFlags(outgoing);
    const child = spawn("copilot", [...baseArgs(configPath), ...steering.args, ...outgoing], {
      stdio: ["inherit", "pipe", "inherit"],
    });

    let output = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (output += chunk));

    const code: number = await new Promise((resolve) => child.on("exit", (c) => resolve(c ?? 0)));

    // Re-read the store: the MCP child minted its own tokens into the shared
    // file while this process was waiting, and those are exactly the ones the
    // answer is most likely to quote.
    const finalSession = engine.createSession(sessionPath);
    const restored = finalSession.restoreResponse(output);
    process.stdout.write(restored.text);

    if (restored.suspiciousTokens.length > 0) {
      process.stderr.write(
        `vaultline: ${restored.suspiciousTokens.length} placeholder(s) could not be restored ` +
          `(${restored.suspiciousTokens.join(", ")}) — the model may have altered them, so a real value was lost.\n`,
      );
    }
    printResumeHint(steering.id, false);
    process.exit(code);
  } finally {
    engine.dispose();
  }
}

// -------------------------------------------------------------------
// vaultline reveal
// -------------------------------------------------------------------

/**
 * Where to read mappings from, in priority order:
 *
 *   1. the live `--reveal` session, via the pointer file. This is the common
 *      case and the reason --reveal exists: it lets reveal work during a
 *      session without turning on permanent persistence.
 *   2. the newest permanent file, when persistSessionMappings is on.
 *
 * The pointer can be stale — a crash or a kill -9 skips the exit handler — so
 * a path that no longer exists falls through to (2) rather than failing.
 */
function findSessionFile(): { file: string; live: boolean } | undefined {
  if (fs.existsSync(CURRENT_SESSION_POINTER)) {
    const pointed = fs.readFileSync(CURRENT_SESSION_POINTER, "utf8").trim();
    if (pointed && fs.existsSync(pointed)) return { file: pointed, live: true };
  }

  if (!fs.existsSync(SESSIONS_DIR)) return undefined;
  const newest = fs
    .readdirSync(SESSIONS_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => path.join(SESSIONS_DIR, f))
    .map((f) => ({ f, mtime: fs.statSync(f).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)[0];
  return newest ? { file: newest.f, live: false } : undefined;
}

async function cmdReveal(argv: string[]): Promise<void> {
  const source = argv[0] ?? "-";
  const text =
    source === "-" ? await new Promise<string>((resolve) => {
      let buf = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (chunk) => (buf += chunk));
      process.stdin.on("end", () => resolve(buf));
    }) : fs.readFileSync(source, "utf8");

  const found = findSessionFile();
  if (!found) {
    fail(
      "no session mappings available, so there is nothing to restore from.\n\n" +
        "  Either start the session with:\n" +
        "      vaultline copilot --reveal\n" +
        "    which keeps mappings in a private temp file for that session and deletes\n" +
        "    them on exit — nothing is left behind.\n\n" +
        `  Or set "persistSessionMappings": true in ${CONFIG_PATH} to keep them permanently.\n` +
        "    Be aware of what that turns on: every detected value is written to disk in\n" +
        "    plain text and stays there, which is why it is off by default.",
    );
  }

  const store = new EntityStore(found.file);
  const mappings = store.allMappings();
  if (mappings.length === 0) {
    process.stderr.write("vaultline: the session has not recorded any values yet.\n");
  }

  const output = restore(text, mappings);
  process.stdout.write(output);

  // Distinguish "nothing to restore" from "restored nothing" — a leftover
  // token means this text came from a different session than the mappings.
  const leftover = /<<[A-Z_]+_\d+>>/.test(output);
  if (leftover) {
    process.stderr.write(
      `vaultline: some placeholders were not recognised — they were minted by a different ` +
        `session than ${found.live ? "the live one" : found.file}.\n`,
    );
  }
}

// -------------------------------------------------------------------
// vaultline doctor
// -------------------------------------------------------------------

/**
 * Ask Copilot itself which tools it disabled.
 *
 * This is the only real verification available. The tool names are not
 * published, the CLI's bundled registry describes a different thing (see
 * copilotTools.ts), and no offline invocation validates them: `--help` and
 * `--version` exit before tool setup, and an empty `-p` exits earlier still.
 * A name that has been renamed upstream therefore cannot be caught by
 * inspection — only by starting a session and reading what Copilot says.
 *
 * It costs a small number of AI credits, which is why it is opt-in rather
 * than part of the default `doctor` run.
 */
function cmdDoctorLive(): void {
  const out = (s = "") => process.stdout.write(s + "\n");
  out("\nStarting a minimal Copilot session to verify tool exclusions (this uses a few AI credits)…\n");

  const result = spawnSync(
    "copilot",
    ["-p", "Reply with the single word OK.", `--excluded-tools=${EXCLUDED_BUILTINS.join(",")}`, "--allow-all-tools"],
    { encoding: "utf8" },
  );
  const text = `${result.stdout ?? ""}${result.stderr ?? ""}`;

  const unknown = [...text.matchAll(/Unknown tool name in the tool excluded ?list: "([^"]+)"/g)].map((m) => m[1]);
  const disabledLine = /Disabled tools:\s*(.+)/.exec(text);
  const disabled = disabledLine ? disabledLine[1].split(/,\s*/).map((s) => s.trim()) : [];

  if (unknown.length > 0) {
    out(`  FAIL  Copilot does not recognise: ${unknown.join(", ")}`);
    out("        These are NOT being excluded. If any of them is a file or shell tool,");
    out("        the model can read files past Vaultline. Update BUILTIN_READ_TOOLS in");
    out("        copilotTools.ts from a --log-level debug request payload.");
  } else {
    out("  ok    Copilot recognised every excluded tool name");
  }

  const missing = EXCLUDED_BUILTINS.filter((t) => !disabled.includes(t));
  if (disabled.length === 0) {
    out("  WARN  could not read a \"Disabled tools:\" line from Copilot's output");
  } else if (missing.length > 0) {
    out(`  FAIL  requested but not reported as disabled: ${missing.join(", ")}`);
  } else {
    out(`  ok    Copilot disabled all ${disabled.length}: ${disabled.join(", ")}`);
  }

  out("");
  process.exit(unknown.length === 0 && missing.length === 0 ? 0 : 1);
}

function cmdDoctor(argv: string[] = []): void {
  if (argv.includes("--live")) return cmdDoctorLive();
  const out = (s = "") => process.stdout.write(s + "\n");
  let problems = 0;
  const bad = (s: string) => {
    problems++;
    out(`  FAIL  ${s}`);
  };
  const ok = (s: string) => out(`  ok    ${s}`);

  out("\nVaultline for Copilot CLI\n");

  // 1. Copilot present, and at a version whose tool names we know.
  const probe = spawnSync("copilot", ["--version"], { encoding: "utf8" });
  if (probe.error) {
    bad("GitHub Copilot CLI not found on PATH (npm install -g @github/copilot)");
  } else {
    ok(`Copilot CLI found: ${(probe.stdout ?? "").trim().split("\n")[0]}`);
  }

  // 2. The tool names we exclude must still exist in this CLI. A name that has
  //    been renamed upstream is not cosmetic: the built-in tool stays enabled
  //    and the model reads files straight past Vaultline.
  const help = spawnSync("copilot", ["--help"], { encoding: "utf8" }).stdout ?? "";
  if (help.includes("--excluded-tools")) {
    ok(`--excluded-tools supported; requesting ${EXCLUDED_BUILTINS.length}: ${EXCLUDED_BUILTINS.join(", ")}`);
    // Deliberately not claimed as verified. Tool names are unpublished and
    // change between releases, and nothing offline can confirm this CLI still
    // uses them — an earlier version of this command asserted the list was
    // correct while four of the names were in fact being rejected.
    out("  NOTE  tool names cannot be verified offline. Run `vaultline doctor --live`");
    out("        to confirm against the installed CLI (uses a few AI credits).");
  } else {
    bad("this Copilot CLI has no --excluded-tools flag; built-in tools cannot be replaced");
  }
  if (help.includes("--allow-all-mcp-server-instructions")) {
    ok("--allow-all-mcp-server-instructions supported (model will be told what tokens are)");
  } else {
    bad("no --allow-all-mcp-server-instructions flag; the model may ask you to paste real values");
  }

  // 3. Settings.
  try {
    const { settings, rejected, found } = loadConfig();
    ok(found ? `config: ${CONFIG_PATH}` : `config: none, using defaults (${CONFIG_PATH} not present)`);
    if (rejected.length > 0) bad(`malformed settings ignored, defaults used instead: ${rejected.join(", ")}`);
    if (settings.persistSessionMappings) {
      out(`  WARN  persistSessionMappings is ON — detected values are written to ${SESSIONS_DIR} in plain text`);
    } else {
      ok("persistSessionMappings off (so `vaultline reveal` is unavailable — this is the safe default)");
    }
  } catch (err) {
    bad(err instanceof Error ? err.message : String(err));
  }

  // 4. Keychain.
  if (CliHost.keychainAvailable()) ok(`secrets: OS keychain (${process.platform})`);
  else out(`  WARN  no OS keychain on ${process.platform}; credentials stay in memory for the session only`);

  out("\nCoverage differs by mode, so it is worth knowing which one you are in:");
  out("");
  out("  vaultline copilot -p \"…\"   (non-interactive)");
  out("    covered      your prompt is redacted before Copilot sees it");
  out("    covered      file, search and shell content reaching the model");
  out("    covered      writes back to disk are restored to real values first");
  out("    covered      the answer is restored, so you read real values");
  out("");
  out("  vaultline copilot          (interactive)");
  out("    covered      file, search and shell content reaching the model");
  out("    covered      writes back to disk are restored to real values first");
  out("    NOT covered  what you TYPE — Copilot owns that prompt, it goes as typed");
  out("    NOT covered  the answer on screen, which shows <<TYPE_N>> placeholders");
  out("");

  process.exit(problems === 0 ? 0 : 1);
}

// -------------------------------------------------------------------

function usage(): void {
  process.stdout.write(
    [
      "vaultline — zero-trust context control for GitHub Copilot CLI",
      "",
      "Usage:",
      "  vaultline copilot [args…]   launch Copilot CLI with redacting file/shell tools",
      "    --reveal                  keep mappings for this session so `vaultline reveal` works",
      "  vaultline doctor [--live]   check the wiring; --live verifies tool names against Copilot",
      "  vaultline reveal [file|-]   restore <<TYPE_N>> placeholders to real values",
      "  vaultline mcp               run the MCP server (Copilot CLI spawns this)",
      "",
    ].join("\n"),
  );
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  switch (command) {
    case "mcp":
      return cmdMcp(rest);
    case "copilot":
      return cmdCopilot(rest);
    case "reveal":
      return cmdReveal(rest);
    case "doctor":
      return cmdDoctor(rest);
    case "--version":
    case "-v":
      process.stdout.write("1.4.0\n");
      return;
    case undefined:
    case "--help":
    case "-h":
      return usage();
    default:
      fail(`unknown command "${command}". Run "vaultline --help".`);
  }
}

// Guarded so the tests can require this module and call the exported helpers
// directly. Asserting on behaviour beats grepping the compiled source, which
// is what the argument-parsing checks used to do — and a source grep would
// happily pass on a function that was never wired up.
if (require.main === module) {
  main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
}
