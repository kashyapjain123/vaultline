/**
 * The trap: redacting reads without rehydrating writes CORRUPTS FILES.
 *
 * The sequence is completely ordinary — it is what an agent does all day:
 *
 *   1. model reads config.yaml   -> sees password: "<<PASSWORD_1>>"
 *   2. model edits config.yaml   -> writes back what it was given
 *   3. the literal string "<<PASSWORD_1>>" is now the password on disk
 *
 * The user's real credential is gone, replaced by a placeholder, by a tool
 * whose entire promise is safety. That is strictly worse than not redacting at
 * all, so vaultline_write and vaultline_edit run guardToolInput() to put the
 * real values back before touching the filesystem.
 *
 * This is therefore the suite that must never be allowed to fail. Its central
 * assertion is byte-identity: read a file, hand the redacted text straight
 * back, and what lands on disk must equal the original exactly.
 */

const path = require("path");
const fs = require("fs");
const { CONFIG_YAML, check, startServer, summarize, tempDir, textOf } = require("./harness");

async function main() {
  const dir = tempDir();
  const configPath = path.join(dir, "config.yaml");
  fs.writeFileSync(configPath, CONFIG_YAML);

  const server = startServer({ cwd: dir });
  await server.call("initialize", {});

  console.log("\n[THE TRAP: read, then write back verbatim]");
  {
    const redacted = textOf(await server.call("tools/call", { name: "vaultline_read", arguments: { path: "config.yaml" } }));
    check("the read really was redacted", redacted.includes("<<PASSWORD_1>>"), redacted.slice(0, 120));

    // Exactly what a model does when asked to reformat or comment a file: it
    // echoes back the content it was given, tokens and all.
    await server.call("tools/call", { name: "vaultline_write", arguments: { path: "config.yaml", content: redacted } });

    const onDisk = fs.readFileSync(configPath, "utf8");
    check("file on disk is byte-identical to the original", onDisk === CONFIG_YAML, `got:\n${onDisk}`);
    check("no placeholder reached the filesystem", !/<<[A-Z_]+_\d+>>/.test(onDisk), onDisk);
  }

  console.log("\n[a real edit keeps the untouched lines intact]");
  {
    const redacted = textOf(await server.call("tools/call", { name: "vaultline_read", arguments: { path: "config.yaml" } }));
    // The model changes something it can actually see, leaving tokens
    // elsewhere untouched. Note it cannot edit the port: that is redacted too,
    // so a token is all it has there.
    const modified = redacted.replace("database:", "database: # reviewed");
    await server.call("tools/call", { name: "vaultline_write", arguments: { path: "config.yaml", content: modified } });

    const onDisk = fs.readFileSync(configPath, "utf8");
    check("the intended change landed", onDisk.includes("database: # reviewed"), onDisk);
    check("the real port came back despite never being visible", onDisk.includes("port: 5432"), onDisk);
    check("the real password survived the edit", onDisk.includes('password: "Hunter@123"'), onDisk);
    check("the real hostname survived the edit", onDisk.includes("internal-db.corp.example.com"), onDisk);
    check("no placeholder reached the filesystem", !/<<[A-Z_]+_\d+>>/.test(onDisk), onDisk);

    fs.writeFileSync(configPath, CONFIG_YAML); // reset for the next block
  }

  console.log("\n[vaultline_edit: a token may be used to MATCH redacted text]");
  {
    const redacted = textOf(await server.call("tools/call", { name: "vaultline_read", arguments: { path: "config.yaml" } }));
    const token = (redacted.match(/<<PASSWORD_\d+>>/) || [])[0];
    check("a password token was minted", !!token, redacted.slice(0, 120));

    // The model wants to change the password. It can only refer to the old one
    // by its token — so old_text has to rehydrate for the match to succeed.
    const res = await server.call("tools/call", {
      name: "vaultline_edit",
      arguments: { path: "config.yaml", old_text: token, new_text: "NewSecret@456" },
    });
    check("the edit applied", !res.error, res.error && res.error.message);

    const onDisk = fs.readFileSync(configPath, "utf8");
    check("the token matched the real value on disk", onDisk.includes("NewSecret@456"), onDisk);
    check("the old password is gone", !onDisk.includes("Hunter@123"), onDisk);
    check("nothing else changed", onDisk.includes('username: "svc_corp_uat"'), onDisk);

    fs.writeFileSync(configPath, CONFIG_YAML);
  }

  console.log("\n[a file the model never read is written unchanged]");
  {
    // Nothing to rehydrate here. The guard must be a no-op rather than
    // mangling ordinary new content that happens to look token-ish.
    const content = "# notes\nplain text, no tokens, <<NOT_A_REAL_TOKEN_9>> included\n";
    await server.call("tools/call", { name: "vaultline_write", arguments: { path: "fresh.md", content } });
    const onDisk = fs.readFileSync(path.join(dir, "fresh.md"), "utf8");
    check("unknown token-shaped text is left exactly as written", onDisk === content, JSON.stringify(onDisk));
  }

  console.log("\n[edit refuses an ambiguous match rather than guessing]");
  {
    fs.writeFileSync(path.join(dir, "dup.txt"), "alpha\nalpha\n");
    const res = await server.call("tools/call", {
      name: "vaultline_edit",
      arguments: { path: "dup.txt", old_text: "alpha", new_text: "beta" },
    });
    check("a non-unique old_text is an error", !!res.error, JSON.stringify(res.result));
    check("the file was not touched", fs.readFileSync(path.join(dir, "dup.txt"), "utf8") === "alpha\nalpha\n");
  }

  await server.close();
  summarize("rehydrate");
}

main();
