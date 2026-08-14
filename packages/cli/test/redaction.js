/**
 * The reproduction.
 *
 * What prompted this package: Copilot CLI was asked to review a config.yaml
 * full of real credentials. It read the file with its built-in tool, sent the
 * contents to GitHub, and answered "Critical: hardcoded secrets committed in
 * plain text" — correct, and far too late. Every value was already off the
 * machine.
 *
 * So the property under test is not "some redaction happened". It is that NO
 * original value survives in what the tool hands back, across every ingestion
 * path the model has. grep and rg matter as much as read here: `grep -r
 * password .` returns matching LINES, so a search tool is a file-content read
 * wearing a different name, and leaving it built-in would have left the most
 * obvious way to hunt for secrets wide open.
 */

const path = require("path");
const fs = require("fs");
const { CONFIG_YAML, check, startServer, summarize, tempDir, textOf } = require("./harness");

/** Every value in the fixture that must never appear in a tool result. */
const SECRETS = [
  "Hunter@123",
  "sk-lf-9c8b7a6d5e4f3g2h",
  "svc_corp_uat",
  "internal-db.corp.example.com",
  "rahul.sharma@example.com",
];

function assertClean(label, text) {
  const leaked = SECRETS.filter((s) => text.includes(s));
  check(label, leaked.length === 0, leaked.length ? `LEAKED ${leaked.join(", ")}` : "");
}

async function main() {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "config.yaml"), CONFIG_YAML);
  fs.writeFileSync(path.join(dir, "notes.md"), "The uat service account is svc_corp_uat and the password is Hunter@123.\n");

  const server = startServer({ cwd: dir });
  await server.call("initialize", {});

  console.log("\n[THE ORIGINAL REPORT: reviewing config.yaml]");
  {
    const text = textOf(await server.call("tools/call", { name: "vaultline_read", arguments: { path: "config.yaml" } }));
    assertClean("no original value survives the read", text);
    check("something was actually detected", /<<[A-Z_]+_\d+>>/.test(text), text.slice(0, 200));
    check("structure is preserved, so the model can still review it", text.includes("database:") && text.includes("api:"), text.slice(0, 120));
    // The port IS redacted, and deliberately — infraDetector treats it as
    // infrastructure detail. Asserting 5432 survived was this test being wrong
    // about the product, not the product being wrong.
    check("field names survive, so the review is still possible", /host:|username:|password:/.test(text), text.slice(0, 200));
    check("localhost is left alone (every machine has one)", text.includes("localhost"), text.slice(0, 200));
  }

  console.log("\n[grep returns matching lines, so it is a content read too]");
  {
    const text = textOf(await server.call("tools/call", { name: "vaultline_grep", arguments: { pattern: "password|username|key" } }));
    assertClean("no original value survives a grep", text);
  }

  console.log("\n[the same for shell output]");
  {
    const text = textOf(await server.call("tools/call", { name: "vaultline_shell", arguments: { command: "cat config.yaml" } }));
    assertClean("no original value survives `cat`", text);

    const env = textOf(await server.call("tools/call", { name: "vaultline_shell", arguments: { command: "echo PASSWORD=Hunter@123" } }));
    assertClean("no original value survives an echoed env assignment", env);
  }

  console.log("\n[prose, not just structured config]");
  {
    const text = textOf(await server.call("tools/call", { name: "vaultline_read", arguments: { path: "notes.md" } }));
    assertClean("no original value survives a prose file", text);
  }

  console.log("\n[tokens are stable across calls]");
  {
    // The model reads a file twice, or reads then greps. If the same secret
    // minted two different tokens the model would treat them as two different
    // values — and a later edit would rehydrate to the wrong one.
    const first = textOf(await server.call("tools/call", { name: "vaultline_read", arguments: { path: "config.yaml" } }));
    const second = textOf(await server.call("tools/call", { name: "vaultline_read", arguments: { path: "config.yaml" } }));
    check("the same file redacts identically twice", first === second, "tokens differed between reads");

    const grep = textOf(await server.call("tools/call", { name: "vaultline_grep", arguments: { pattern: "Hunter" } }));
    const tokenInRead = (first.match(/<<PASSWORD_\d+>>/) || [])[0];
    const tokenInGrep = (grep.match(/<<PASSWORD_\d+>>/) || [])[0];
    check("read and grep agree on the token for one value", !!tokenInRead && tokenInRead === tokenInGrep, `${tokenInRead} vs ${tokenInGrep}`);
  }

  console.log("\n[glob: paths leak usernames and layout]");
  {
    const text = textOf(await server.call("tools/call", { name: "vaultline_glob", arguments: { pattern: "*.yaml" } }));
    check("glob finds the fixture", text.includes("config.yaml"), text);
  }

  await server.close();
  summarize("redaction");
}

main();
