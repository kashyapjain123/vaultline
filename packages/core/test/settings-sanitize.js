/**
 * Settings validation — the highest-stakes suite in the project.
 *
 * A VS Code host reads settings with `config.get(key)`, which returns whatever
 * is in settings.json WITHOUT validating it against the manifest schema. A
 * hand-edited file, a synced one, or a workspace `.vscode/settings.json`
 * committed to a repo can therefore put any value under any key, and before
 * sanitizeSettings() those values went straight into the pipeline. Measured on
 * the previous build:
 *
 *   routingMinSimilarity = NaN  ->  0 matches. `score >= NaN` is always false,
 *                                   so PII, infra and conversational-secret
 *                                   detection all went quiet and secrets passed
 *                                   through — no error, nothing in the log.
 *
 * That is the worst failure a detection tool has: silently not detecting. NaN
 * is the specific trap, because it satisfies `typeof x === "number"` and slips
 * past a naive type check.
 *
 * The suite therefore asserts BOTH halves everywhere: bad values fall back to a
 * default AND detection still works afterwards. Checking the fallback alone
 * would pass even if the pipeline were broken some other way.
 */

const path = require("path");
const { sanitizeSettings, DEFAULT_SETTINGS } = require(path.join(__dirname, "..", "out", "settings"));
const { scanCurrentMessage } = require(path.join(__dirname, "..", "out", "detectionPipeline"));

let failures = 0;
function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

/** A router that clears any sane threshold, so the only thing under test is the threshold value itself. */
const FAKE_ROUTER = {
  scoreAll: async () => [
    { category: "credentials", score: 0.9 },
    { category: "infrastructure", score: 0.9 },
    { category: "pii", score: 0.9 },
  ],
  supportsWholeMessageClassification: () => false,
};

const SECRET_LINE = "my password is hunter2isnotsecure and the server is prod-db-02";

async function main() {
  console.log("\n[routingMinSimilarity: every bad shape falls back AND still detects]");
  for (const bad of [NaN, "high", null, {}, [], Infinity, -Infinity, undefined]) {
    const label = `routingMinSimilarity = ${JSON.stringify(bad) ?? String(bad)}`;
    const { settings, rejected } = sanitizeSettings({ routingMinSimilarity: bad });

    // undefined means "not configured", which is normal and must stay silent.
    const shouldReject = bad !== undefined;
    check(
      `${label}: ${shouldReject ? "rejected" : "ignored quietly"}`,
      rejected.includes("routingMinSimilarity") === shouldReject,
      JSON.stringify(rejected)
    );
    check(`${label}: default restored`, settings.routingMinSimilarity === DEFAULT_SETTINGS.routingMinSimilarity);

    const { matches } = await scanCurrentMessage(SECRET_LINE, {
      router: FAKE_ROUTER,
      semanticMatcher: null,
      routingMinSimilarity: settings.routingMinSimilarity,
    });
    check(`${label}: detection still works`, matches.length >= 2, `${matches.length} match(es)`);
  }

  console.log("\n[the other two that broke]");
  {
    const a = sanitizeSettings({ crossTurnSecretTurns: NaN });
    check("crossTurnSecretTurns NaN rejected", a.rejected.includes("crossTurnSecretTurns"));
    check("…and defaults to a finite number", Number.isFinite(a.settings.crossTurnSecretTurns));

    const b = sanitizeSettings({ maxTools: NaN });
    check("maxTools NaN rejected", b.rejected.includes("maxTools"));
    check("…and defaults to 128", b.settings.maxTools === DEFAULT_SETTINGS.maxTools);
  }

  console.log("\n[type mismatches across every kind of setting]");
  {
    const r = sanitizeSettings({
      enablePiiDetection: "yes",
      toolDenyList: "mcp_*",
      embeddingApiUrl: 8080,
      embeddingBackend: 3,
    });
    for (const key of ["enablePiiDetection", "toolDenyList", "embeddingApiUrl", "embeddingBackend"]) {
      check(`${key} rejected`, r.rejected.includes(key), JSON.stringify(r.rejected));
    }
    check("array of non-strings rejected", sanitizeSettings({ toolDenyList: [1, 2] }).rejected.includes("toolDenyList"));
  }

  console.log("\n[valid values pass through — including the falsy ones]");
  {
    const { settings, rejected } = sanitizeSettings({
      routingMinSimilarity: 0,
      blockOnHighSeverity: false,
      toolDenyList: [],
      embeddingServerNodePath: "",
      maxTools: 64,
      embeddingApiUrl: "https://embeddings.corp.example.com",
    });
    check("nothing rejected", rejected.length === 0, JSON.stringify(rejected));
    check("0 kept (not treated as missing)", settings.routingMinSimilarity === 0);
    check("false kept", settings.blockOnHighSeverity === false);
    check("[] kept", Array.isArray(settings.toolDenyList) && settings.toolDenyList.length === 0);
    check('"" kept', settings.embeddingServerNodePath === "");
    check("64 kept", settings.maxTools === 64);
    check("url kept", settings.embeddingApiUrl === "https://embeddings.corp.example.com");
  }

  console.log("\n[an empty bag is the default bag]");
  {
    const { settings, rejected } = sanitizeSettings({});
    check("nothing rejected", rejected.length === 0);
    check("identical to DEFAULT_SETTINGS", JSON.stringify(settings) === JSON.stringify(DEFAULT_SETTINGS));
  }

  console.log("\n[every rejection is reported, so nothing fails silently]");
  {
    const { rejected } = sanitizeSettings({ routingMinSimilarity: NaN, maxTools: "x", toolDenyList: 5 });
    check("all three named", rejected.length === 3, JSON.stringify(rejected));
  }

  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
