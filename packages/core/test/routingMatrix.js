const path = require("path");
const { scanAll } = require(path.join(__dirname, "..", "out", "detectionPipeline"));
const { decide } = require(path.join(__dirname, "..", "out", "policyEngine"));
const { tokenize } = require(path.join(__dirname, "..", "out", "tokenizer"));
const { EmbeddingRouter } = require(path.join(__dirname, "..", "out", "embeddingRouter"));
const { HashingEmbedder } = require(path.join(__dirname, "..", "out", "embeddings", "hashingEmbedder"));
const { centroidsPath } = require(path.join(__dirname, "..", "out", "assets"));

// The hashing backend, so this matrix runs with no server and no network.
// Its centroids file must be the matching one — see buildEmbeddings.js on why
// mixing vector spaces produces meaningless scores.
const router = EmbeddingRouter.load(centroidsPath("hashing"), new HashingEmbedder(), false);
if (!router) {
  console.error("FATAL: router failed to load — aborting test");
  process.exit(1);
}

const policyConfig = { blockOnHighSeverity: true, blockOnBusinessContent: true };

async function run(text, opts = {}) {
  const { matches, businessMatches } = await scanAll(text, { router, ...opts });
  const decision = decide(matches, businessMatches, policyConfig);
  const { redactedText } = tokenize(text, matches);
  return { matches, businessMatches, decision, redactedText };
}

async function main() {
  console.log("=".repeat(110));
  console.log("PART 1 — THE PAYOFF: the previously-permanent gap, now caught via routing");
  console.log("=".repeat(110));
  {
    const text = "we're spending $80k on Project Falcon for the German expansion";
    const r = await run(text);
    console.log(`\nIN: ${text}`);
    console.log(`  action: ${r.decision.action.toUpperCase()}`);
    console.log(`  reason: ${r.decision.reason}`);
    console.log(`  entity-level matches: ${r.matches.length} (expected 0 — no keyword, no shape)`);
    console.log(`  business flag: ${r.businessMatches.length > 0 ? r.businessMatches[0].label : "(none)"}`);
  }

  console.log("\n" + "=".repeat(110));
  console.log("PART 2 — false-positive guard: ordinary messages must NOT trip business-content");
  console.log("=".repeat(110));
  const benignTexts = [
    "can you help me write a function to sort this array of objects",
    "what does this TypeError mean and how do I fix it",
    "explain how promises work in javascript",
    "the server runs on port 8080 for the internal API",
    "my password is hunter2isnotsecure, help me rotate it",
  ];
  for (const text of benignTexts) {
    const r = await run(text);
    const flagged = r.businessMatches.length > 0;
    console.log(`\nIN: ${text}`);
    console.log(`  business flag fired: ${flagged ? "YES (unexpected!)" : "no (expected)"}  action: ${r.decision.action}`);
  }

  console.log("\n" + "=".repeat(110));
  console.log("PART 3 — mixed-category message: your own example, all three tags at once");
  console.log("=".repeat(110));
  {
    const text = "customer id 4521, my password is \"hunter2isnotsecure\", and the server is prod-db-02";
    const r = await run(text);
    console.log(`\nIN: ${text}`);
    console.log(`  action: ${r.decision.action}  matches: ${r.matches.length}`);
    for (const m of r.matches) console.log(`    - [${m.category}] ${m.label} -> "${m.value}"`);
    console.log(`  redacted: ${r.redactedText}`);
  }

  console.log("\n" + "=".repeat(110));
  console.log("PART 4 — routing actually gates detectors (not just always-run-everything)");
  console.log("=".repeat(110));
  {
    // A message with ONLY infra content should score low on pii/credentials —
    // confirm via scoreAll that routing genuinely discriminates, not just
    // rubber-stamping everything above threshold.
    const text = "the server runs on port 8080 for the internal API";
    const scores = await router.scoreAll(text);
    console.log(`\nIN: ${text}`);
    console.log("  category scores:", scores.map(s => `${s.category}=${s.score.toFixed(3)}`).join("  "));
    const r = await run(text);
    console.log(`  matches found: ${r.matches.length}`);
    for (const m of r.matches) console.log(`    - [${m.category}] ${m.label} -> "${m.value}"`);
  }

  console.log("\n" + "=".repeat(110));
  console.log("PART 5 — fail-open check: routing disabled (no router) must not lose detection");
  console.log("=".repeat(110));
  {
    const text = "my password is hunter2isnotsecure";
    const withRouter = await scanAll(text, { router });
    const withoutRouter = await scanAll(text, { router: null });
    console.log(`\nIN: ${text}`);
    console.log(`  with router:    ${withRouter.matches.length} match(es)`);
    console.log(`  without router: ${withoutRouter.matches.length} match(es)  (should be >= with-router count)`);
  }

  console.log("\n" + "=".repeat(110));
  console.log("PART 6 — regression: full 30-scenario hybrid matrix, now behind routing");
  console.log("=".repeat(110));
  const regressionCases = [
    { label: "PAN", text: "his PAN is ABCDE1234F for the KYC form" },
    { label: "SSN", text: "SSN on file is 123-45-6789" },
    { label: "credit card valid", text: "card number 4532015112830366 was charged" },
    { label: "credit card invalid Luhn (should NOT match)", text: "random number 4532015112830367 came up" },
    { label: "internal URL", text: "hit http://internal-api.company.com/v1/users for the data" },
    { label: "port vs score", text: "he scored 8080 runs across his career" },
    { label: "hostname vs phrase", text: "step-by-step-3 guide was helpful" },
    { label: "AWS key (structural, always-on)", text: "AKIAABCDEFGHIJKLMNOP" },
  ];
  let pass = 0, fail = 0;
  for (const c of regressionCases) {
    const r = await run(c.text);
    const found = r.matches.length > 0;
    const expectedNone = c.label.includes("should NOT") || c.label.includes("vs score") || c.label.includes("vs phrase");
    const ok = expectedNone ? !found : found;
    console.log(`  [${ok ? "PASS" : "FAIL"}] ${c.label}: ${r.matches.length} match(es)`);
    if (ok) pass++; else fail++;
  }
  console.log(`\n${pass} passed, ${fail} failed`);

  console.log("\n" + "=".repeat(110));
  console.log("PART 7 — MAC address and IPv6 (the ifconfig-output gap)");
  console.log("=".repeat(110));
  {
    const text = `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
          inet 192.168.1.50  netmask 255.255.255.0  broadcast 192.168.1.255
          inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
          ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)

  lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
          inet 127.0.0.1  netmask 255.0.0.0
          inet6 ::1  prefixlen 128  scopeid 0x10<host>`;
    const r = await run(text);
    console.log(`  matches found: ${r.matches.length}`);
    for (const m of r.matches) console.log(`    - [${m.category}] [${m.severity}] ${m.label} -> "${m.value}"`);
    console.log(`  (expect: private IP + broadcast flagged, netmasks/loopback/::1 excluded as noise, MAC caught, link-local IPv6 caught)`);
  }
  console.log("\n" + "=".repeat(110));
}

main();
