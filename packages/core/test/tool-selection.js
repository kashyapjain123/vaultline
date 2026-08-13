/**
 * Tool selection matrix — the failure this exists for:
 *
 *     Vaultline: the underlying model call failed
 *     Error: Cannot have more than 128 tools per request
 *
 * chatParticipant forwarded the whole of `vscode.lm.tools` — every built-in,
 * extension-contributed and MCP tool the user had installed — straight into
 * sendRequest. Past the provider's ceiling the request is rejected before the
 * model sees a token, so @vaultline stopped working ENTIRELY for the users with
 * the richest setups. Not a degraded answer: no answer.
 *
 * The properties worth locking down are the ones that make truncation safe
 * rather than arbitrary: the cap actually binds, VS Code's ordering survives
 * (its general-purpose built-ins come first), deny-list entries free up budget
 * instead of wasting it, and a provider that reports a *different* limit can be
 * adapted to rather than guessed at.
 */

const path = require("path");
const { selectTools, parseToolLimitFromError } = require(path.join(__dirname, "..", "out", "toolSelection"));

let failures = 0;
function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

/** Mimics vscode.lm.tools ordering: built-ins first, then extension/MCP tools. */
function registry(builtins, extras) {
  const tools = [];
  for (let i = 0; i < builtins; i++) tools.push({ name: `copilot_builtin_${i}` });
  for (let i = 0; i < extras; i++) tools.push({ name: `mcp_vendor_${i}` });
  return tools;
}

console.log("\n[the reported case: 150 tools, provider ceiling of 128]");
{
  const all = registry(20, 130); // 150 total
  const r = selectTools(all, { max: 128 });
  check("selected is exactly the cap", r.selected.length === 128, `got ${r.selected.length}`);
  check("the overflow is reported, not silently lost", r.truncated.length === 22, `got ${r.truncated.length}`);
  check("nothing is invented", r.selected.length + r.truncated.length + r.denied.length === all.length);
  check(
    "VS Code's order survives — built-ins are kept, not scattered",
    r.selected.slice(0, 20).every((t, i) => t.name === `copilot_builtin_${i}`)
  );
}

console.log("\n[under the cap: everything is offered]");
{
  const all = registry(10, 30);
  const r = selectTools(all, { max: 128 });
  check("all 40 offered", r.selected.length === 40, `got ${r.selected.length}`);
  check("nothing truncated", r.truncated.length === 0);
}

console.log("\n[deny list frees budget rather than wasting it]");
{
  // 130 noisy vendor tools would otherwise consume the whole budget and push
  // the built-ins out; denying them must give that budget back.
  const all = registry(20, 130);
  const r = selectTools(all, { max: 128, denyList: ["mcp_vendor_*"] });
  check("denied entries reported", r.denied.length === 130, `got ${r.denied.length}`);
  check("only the built-ins remain", r.selected.length === 20, `got ${r.selected.length}`);
  check("nothing truncated once the noise is gone", r.truncated.length === 0);
  check("denied tools are absent from the offer", !r.selected.some((t) => t.name.startsWith("mcp_vendor")));
}

console.log("\n[deny-list matching]");
{
  const all = [{ name: "copilot_readFile" }, { name: "MCP_Noisy_Thing" }, { name: "other" }];
  const exact = selectTools(all, { max: 10, denyList: ["other"] });
  check("exact name match", exact.denied.length === 1 && exact.denied[0].name === "other");

  const ci = selectTools(all, { max: 10, denyList: ["mcp_noisy_*"] });
  check("case-insensitive wildcard", ci.denied.length === 1 && ci.denied[0].name === "MCP_Noisy_Thing");

  const dot = selectTools([{ name: "a.b" }, { name: "axb" }], { max: 10, denyList: ["a.b"] });
  check("'.' is literal, not a regex wildcard", dot.denied.length === 1 && dot.denied[0].name === "a.b");

  const blank = selectTools(all, { max: 10, denyList: ["", "   "] });
  check("blank patterns deny nothing", blank.denied.length === 0 && blank.selected.length === 3);
}

console.log("\n[max edge cases]");
{
  const all = registry(5, 5);
  check("max 0 offers nothing", selectTools(all, { max: 0 }).selected.length === 0);
  check("negative max is treated as 0, never unlimited", selectTools(all, { max: -5 }).selected.length === 0);
  check("fractional max is floored", selectTools(all, { max: 3.9 }).selected.length === 3);
  check("empty registry is fine", selectTools([], { max: 128 }).selected.length === 0);
}

console.log("\n[reading a provider's limit out of its rejection]");
{
  check(
    "the actual Copilot message",
    parseToolLimitFromError("Error: Cannot have more than 128 tools per request") === 128
  );
  check("a smaller limit", parseToolLimitFromError("Cannot have more than 64 tools per request") === 64);
  check("singular phrasing", parseToolLimitFromError("cannot have more than 1 tool per request") === 1);
  check("alternate phrasing", parseToolLimitFromError("A maximum of 32 tools is allowed") === 32);
  check("unrelated errors are not misread", parseToolLimitFromError("429 rate limited, retry in 30 seconds") === null);
  check(
    "a number with no tool context is ignored",
    parseToolLimitFromError("Cannot have more than 128 messages per request") === null
  );
  check("empty input", parseToolLimitFromError("") === null);
}

console.log("\n" + "=".repeat(80));
console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
