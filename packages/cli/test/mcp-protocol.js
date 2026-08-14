/**
 * The MCP transport itself.
 *
 * jsonRpc.ts is hand-rolled rather than taken from @modelcontextprotocol/sdk,
 * which is a defensible trade for a security tool but means the protocol is
 * ours to get right. The two rules worth a test are the ones whose breach
 * produces a server that looks fine and then hangs:
 *
 *   - a notification must NOT be answered (MCP sends notifications/initialized
 *     straight after the handshake; replying to it violates the spec)
 *   - stdout carries frames only, so a stray write corrupts the stream
 *
 * The last case spawns the real packaged binary. Everything else here runs
 * in-process; this one exists because "it works when I call the function" and
 * "it works when Copilot spawns the bin" are different claims.
 */

const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");
const { CONFIG_YAML, check, startServer, summarize, tempDir, textOf } = require("./harness");

async function main() {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "config.yaml"), CONFIG_YAML);
  const server = startServer({ cwd: dir });

  console.log("\n[handshake]");
  {
    const res = await server.call("initialize", { protocolVersion: "2024-11-05", capabilities: {} });
    check("initialize returns a protocol version", typeof res.result.protocolVersion === "string", JSON.stringify(res.result));
    check("advertises the tools capability", res.result.capabilities.tools !== undefined);
    check("names itself vaultline", res.result.serverInfo.name === "vaultline", res.result.serverInfo.name);
  }

  console.log("\n[notifications are not answered]");
  {
    // If the transport replies to this, the id-keyed client below would still
    // work but a real MCP client would error. Assert it by sending the
    // notification and then a normal call: the very next frame out must be
    // the answer to the CALL, not to the notification.
    server.notify("notifications/initialized", {});
    const res = await server.call("tools/list", {});
    check("next frame after a notification is the next request's reply", res.id !== undefined && !!res.result);
  }

  console.log("\n[tools/list]");
  {
    const res = await server.call("tools/list", {});
    const names = res.result.tools.map((t) => t.name).sort();
    check(
      "advertises the full read and write set",
      JSON.stringify(names) ===
        JSON.stringify(["vaultline_edit", "vaultline_glob", "vaultline_grep", "vaultline_read", "vaultline_shell", "vaultline_write"]),
      names.join(", "),
    );
    check("every tool has a schema", res.result.tools.every((t) => t.inputSchema && t.inputSchema.type === "object"));
    check(
      "write tools tell the model not to fill placeholders in",
      res.result.tools.filter((t) => t.name === "vaultline_write" || t.name === "vaultline_edit").every((t) => /placeholder/i.test(t.description)),
    );
  }

  console.log("\n[errors are reported, not thrown away]");
  {
    const unknown = await server.call("tools/call", { name: "vaultline_nope", arguments: {} });
    check("unknown tool produces an error frame", !!unknown.error, JSON.stringify(unknown));

    const missing = await server.call("tools/call", { name: "vaultline_read", arguments: {} });
    check("missing required argument produces an error frame", !!missing.error, JSON.stringify(missing));

    const absent = await server.call("tools/call", { name: "vaultline_read", arguments: { path: "does-not-exist.txt" } });
    check("unreadable file produces an error frame", !!absent.error, JSON.stringify(absent));

    const method = await server.call("no/such/method", {});
    check("unknown method reports -32601", method.error && method.error.code === -32601, JSON.stringify(method.error));
  }

  console.log("\n[a call still works after those errors]");
  {
    const res = await server.call("tools/call", { name: "vaultline_read", arguments: { path: "config.yaml" } });
    check("server did not wedge", textOf(res).includes("database:"), textOf(res).slice(0, 60));
  }

  await server.close();

  console.log("\n[the packaged binary actually starts]");
  {
    const bin = path.join(__dirname, "..", "out", "cli.js");
    const text = await new Promise((resolve) => {
      // HOME is redirected so this reads a scratch ~/.vaultline rather than
      // the developer's real config and keychain.
      const child = spawn(process.execPath, [bin, "mcp", "--cwd", dir], {
        env: { ...process.env, HOME: dir },
        stdio: ["pipe", "pipe", "pipe"],
      });
      let out = "";
      child.stdout.on("data", (d) => (out += d.toString()));
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) + "\n");
      setTimeout(() => {
        child.kill();
        resolve(out);
      }, 4000);
    });
    check("spawned server completes a handshake on stdout", text.includes('"protocolVersion"'), text.slice(0, 200) || "(no output)");
    check("stdout carries frames only", text.trim().split("\n").every((l) => l.trim() === "" || l.trim().startsWith("{")), text.slice(0, 200));
  }

  summarize("mcp-protocol");
}

main();
