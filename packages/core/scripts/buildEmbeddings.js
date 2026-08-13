/**
 * Offline embedding precomputation.
 *
 * Reads data/categoryExamples.json, embeds every example sentence, averages
 * them into one centroid vector per category, and writes the result to
 * data/categoryEmbeddings.json.
 *
 * CRITICAL: whichever backend computes these centroids MUST be the same
 * backend configured at runtime (vaultline.embeddingBackend), or cosine
 * similarity against them is meaningless (different vector space, usually
 * a different dimension entirely — 256 for the hashing embedder, 384 for
 * MiniLM). embeddingRouter.ts guards against a dimension mismatch and
 * fails open rather than producing garbage results, but there's no way to
 * detect a same-dimension-but-wrong-space mismatch, so this has to be kept
 * in sync deliberately.
 *
 * Each backend writes to its OWN file by default — categoryEmbeddings.json
 * for api/MiniLM (384-dim), categoryEmbeddings.hashing.json for hashing
 * (256-dim) — and BOTH ship in the VSIX. That's what lets extension.ts
 * switch backends at runtime (falling back to hashing when the MiniLM
 * server can't start) without regenerating anything on the user's machine.
 * Override the destination with --out if you need to.
 *
 * Usage:
 *   npm run build:embeddings:all                             # both files (needs the server up)
 *   node scripts/buildEmbeddings.js                          # hashing embedder (default)
 *   node scripts/buildEmbeddings.js --backend=hashing        # -> data/categoryEmbeddings.hashing.json
 *   node scripts/buildEmbeddings.js --backend=api            # -> data/categoryEmbeddings.json, hits http://localhost:9000
 *   node scripts/buildEmbeddings.js --backend=api --url=http://localhost:9000
 *   node scripts/buildEmbeddings.js --backend=hashing --out=/tmp/centroids.json
 *
 * Run via: npm run build:embeddings (after npm run compile, since this
 * requires the compiled hashingEmbedder.js when using the hashing backend).
 */

const fs = require("fs");
const path = require("path");

function parseArgs() {
  const args = { backend: "hashing", url: "http://localhost:9000", out: null };
  for (const arg of process.argv.slice(2)) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (key === "backend" && value) args.backend = value;
    if (key === "url" && value) args.url = value;
    if (key === "out" && value) args.out = value;
  }
  return args;
}

/**
 * Both backends' centroids ship in the VSIX, under different filenames, so
 * the extension can switch between them at RUNTIME without regenerating
 * anything (see extension.ts — it falls back to hashing when the MiniLM
 * server can't be brought up on a machine with no npm). --out exists to
 * write the second file; without it the default path is the api/MiniLM one,
 * which is what the extension prefers.
 */
function defaultOutputFor(backend) {
  return backend === "hashing" ? "categoryEmbeddings.hashing.json" : "categoryEmbeddings.json";
}

async function embedViaApi(text, baseUrl) {
  const res = await fetch(`${baseUrl.replace(/\/$/, "")}/embed`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) {
    throw new Error(
      `Embedding API at ${baseUrl} returned HTTP ${res.status}. Is the server running? (cd embedding-server && npm start)`
    );
  }
  const data = await res.json();
  if (!Array.isArray(data.embedding)) {
    throw new Error(`Embedding API at ${baseUrl} returned an unexpected response shape.`);
  }
  return data.embedding;
}

function averageVectorsLocal(vectors) {
  const dim = vectors[0].length;
  const avg = new Array(dim).fill(0);
  for (const v of vectors) {
    for (let i = 0; i < dim; i++) avg[i] += v[i];
  }
  for (let i = 0; i < dim; i++) avg[i] /= vectors.length;
  const norm = Math.sqrt(avg.reduce((s, v) => s + v * v, 0)) || 1;
  return avg.map((v) => v / norm);
}

async function main() {
  const args = parseArgs();
  const examplesPath = path.join(__dirname, "..", "data", "categoryExamples.json");
  const outputPath = args.out
    ? path.resolve(args.out)
    : path.join(__dirname, "..", "data", defaultOutputFor(args.backend));
  const examples = JSON.parse(fs.readFileSync(examplesPath, "utf-8"));

  let embedFn;
  if (args.backend === "api") {
    console.log(`Using API backend at ${args.url} — make sure embedding-server is running.`);
    embedFn = (text) => embedViaApi(text, args.url);
  } else if (args.backend === "hashing") {
    const { embed } = require("../out/embeddings/hashingEmbedder");
    embedFn = (text) => Promise.resolve(embed(text));
  } else {
    throw new Error(`Unknown --backend "${args.backend}". Use "hashing" or "api".`);
  }

  const centroids = {};
  for (const [category, sentences] of Object.entries(examples)) {
    if (!Array.isArray(sentences) || sentences.length === 0) {
      throw new Error(`Category "${category}" has no example sentences.`);
    }
    const vectors = [];
    for (const s of sentences) vectors.push(await embedFn(s));
    centroids[category] = averageVectorsLocal(vectors);
    console.log(`  ${category}: ${sentences.length} examples -> ${vectors[0].length}-dim centroid`);
  }

  fs.writeFileSync(outputPath, JSON.stringify(centroids), "utf-8");
  console.log(`\nWrote ${Object.keys(centroids).length} category centroids (backend="${args.backend}") to ${outputPath}`);
}

main().catch((err) => {
  console.error("build:embeddings failed:", err.message);
  process.exit(1);
});
