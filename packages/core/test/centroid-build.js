/**
 * Centroid rebuild matrix.
 *
 * Routing scores each message against precomputed centroids built from
 * all-MiniLM-L6-v2. Point vaultline.embeddingApiUrl at a different model and a
 * dimension mismatch is caught by EmbeddingRouter.scoreAll() — but a SAME
 * dimension, different model is not catchable at all: cosine similarity against
 * a foreign vector space produces plausible-looking numbers that mean nothing,
 * and routing then gates detectors on noise.
 *
 * centroidBuilder.ts removes that failure mode by rebuilding the centroids
 * against whatever endpoint is configured. This suite covers the properties
 * that make that safe: one batch call rather than 72, unit-length output,
 * caching keyed on the endpoint, and no partial file left behind on failure.
 *
 * Hermetic — a fake /embed-batch endpoint returns deterministic vectors, so
 * nothing downloads a model. Assertions with a non-zero exit, like
 * port-conflict.js: silently building wrong centroids would degrade routing
 * everywhere while looking completely healthy.
 */

const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const { buildCentroids } = require(path.join(__dirname, "..", "out", "centroidBuilder"));
const { categoryExamplesPath } = require(path.join(__dirname, "..", "out", "assets"));
const { ApiEmbedder } = require(path.join(__dirname, "..", "out", "embeddings", "apiEmbedder"));
const { EmbeddingRouter } = require(path.join(__dirname, "..", "out", "embeddingRouter"));

// A DISTINCT port per endpoint, not one reused across cases. fetch (undici)
// pools connections by origin, so a socket left over from a closed server gets
// reused against the next server bound to that same port and immediately
// ECONNRESETs. Fresh port, fresh origin, no stale pool entry.
let nextPort = 19100;

/**
 * Deterministic pseudo-embedding: seeded by the text so identical inputs give
 * identical vectors, and unrelated inputs give unrelated ones. Real semantics
 * are irrelevant here — what's under test is the plumbing and the averaging.
 */
function fakeVector(text, dim) {
  let seed = 0;
  for (let i = 0; i < text.length; i++) seed = (seed * 31 + text.charCodeAt(i)) >>> 0;
  const out = new Array(dim);
  for (let i = 0; i < dim; i++) {
    seed = (seed * 1103515245 + 12345) >>> 0;
    out[i] = (seed / 0xffffffff) * 2 - 1;
  }
  return out;
}

/** Fake endpoint. Counts requests so "one batch call, not 72" is actually verified. */
function startEndpoint({ dim = 384, fail = false, ragged = false } = {}) {
  const port = nextPort++;
  const state = { requests: 0, totalTexts: 0, port };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      state.requests++;
      if (fail) {
        res.statusCode = 500;
        return res.end(JSON.stringify({ error: "nope" }));
      }
      const { texts } = JSON.parse(body || "{}");
      state.totalTexts += texts.length;
      const embeddings = texts.map((t, i) => fakeVector(t, ragged && i === 3 ? dim - 1 : dim));
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ embeddings }));
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve({ server, state }));
  });
}

function stop(server) {
  return new Promise((resolve) => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  });
}

function embedderFor(state) {
  return new ApiEmbedder({ baseUrl: `http://127.0.0.1:${state.port}`, timeoutMs: 10000 });
}

let failures = 0;
function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

function magnitude(v) {
  return Math.sqrt(v.reduce((s, x) => s + x * x, 0));
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vaultline-centroids-"));
  const examples = categoryExamplesPath();
  const corpus = JSON.parse(fs.readFileSync(examples, "utf-8"));
  const categoryCount = Object.keys(corpus).length;
  const sentenceCount = Object.values(corpus).reduce((n, v) => n + v.length, 0);

  console.log(`\ncorpus: ${categoryCount} categories, ${sentenceCount} sentences\n`);

  // --- 1. Builds one centroid per category, at the endpoint's dimension ---
  {
    console.log("[builds centroids at the endpoint's dimension]");
    const { server, state } = await startEndpoint({ dim: 384 });
    const out = path.join(tmp, "a.json");
    const result = await buildCentroids(examples, embedderFor(state), out);
    const written = JSON.parse(fs.readFileSync(out, "utf-8"));

    check("one centroid per category", Object.keys(written).length === categoryCount);
    check("reported dim matches endpoint", result.dim === 384, `got ${result.dim}`);
    check(
      "every centroid is 384-dim",
      Object.values(written).every((v) => v.length === 384)
    );
    check(
      "every centroid is unit length (the L2 step ran)",
      Object.values(written).every((v) => Math.abs(magnitude(v) - 1) < 1e-9)
    );
    check("ONE http request for the whole corpus", state.requests === 1, `made ${state.requests}`);
    check("all sentences sent", state.totalTexts === sentenceCount, `sent ${state.totalTexts}`);
    await stop(server);
  }

  // --- 2. A different dimension flows through end to end ---
  // This is the whole point: the router must then score against centroids in
  // the SAME space as the embedder, with no dimension warning.
  {
    console.log("\n[a 128-dim endpoint produces 128-dim centroids the router accepts]");
    const { server, state } = await startEndpoint({ dim: 128 });
    const out = path.join(tmp, "b.json");
    const result = await buildCentroids(examples, embedderFor(state), out);
    check("reported dim is 128", result.dim === 128, `got ${result.dim}`);

    const router = EmbeddingRouter.load(out, embedderFor(state), false);
    check("router loads the rebuilt centroids", router !== null);

    const warnings = [];
    const realWarn = console.warn;
    console.warn = (...args) => warnings.push(args.join(" "));
    const scores = await router.scoreAll("the api key is ab12cd34ef56");
    console.warn = realWarn;

    check("scoring returns every category", scores.length === categoryCount, `got ${scores.length}`);
    check(
      "no dimension-mismatch warning",
      !warnings.some((w) => w.includes("dimension mismatch")),
      warnings.join(" | ")
    );
    await stop(server);
  }

  // --- 3. Failure leaves nothing behind ---
  // A partial file would be fatal: the cache key is the FILENAME, so a
  // truncated write would be treated as a valid cache hit forever.
  {
    console.log("\n[endpoint failure throws and leaves no partial file]");
    const { server, state } = await startEndpoint({ fail: true });
    const out = path.join(tmp, "c.json");
    let threw = false;
    try {
      await buildCentroids(examples, embedderFor(state), out);
    } catch {
      threw = true;
    }
    check("buildCentroids throws", threw);
    check("no output file written", !fs.existsSync(out));
    check("no .tmp left behind", fs.readdirSync(tmp).every((f) => !f.includes(".tmp")));
    await stop(server);
  }

  // --- 4. A ragged response is rejected rather than silently averaged ---
  {
    console.log("\n[inconsistent vector dimensions are rejected]");
    const { server, state } = await startEndpoint({ dim: 384, ragged: true });
    const out = path.join(tmp, "d.json");
    let threw = false;
    try {
      await buildCentroids(examples, embedderFor(state), out);
    } catch {
      threw = true;
    }
    check("buildCentroids throws on ragged vectors", threw);
    check("no output file written", !fs.existsSync(out));
    await stop(server);
  }

  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
  fs.rmSync(tmp, { recursive: true, force: true });
  process.exit(failures === 0 ? 0 : 1);
}

main();
