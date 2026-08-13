/**
 * Rebuild the category centroids in-process, against whatever embedder is
 * actually configured.
 *
 * WHY THIS EXISTS. Routing compares each message against precomputed centroids
 * (data/categoryEmbeddings.json), built from all-MiniLM-L6-v2 at 384 dims.
 * Centroids and embedder MUST share a vector space. Point
 * vaultline.embeddingApiUrl at a different model and there are two outcomes:
 *
 *  - Different dimension — caught. EmbeddingRouter.scoreAll() warns and returns
 *    [], so routing fails open and every contextual detector runs.
 *  - Same dimension, different model — NOT caught, and not catchable. Cosine
 *    similarity against centroids from a foreign vector space produces numbers
 *    that look perfectly reasonable and mean nothing. Routing then gates
 *    detectors on noise.
 *
 * The standing advice for that was "run npm run build:embeddings", which is
 * useless to anyone who installed from the Marketplace: it's a dev script, and
 * its input corpus wasn't even shipped. Rebuilding here closes that gap — the
 * centroids become correct by construction for whatever endpoint is in use.
 *
 * This is the same computation as scripts/buildEmbeddings.js, deliberately
 * sharing averageVectors() with it rather than keeping a third copy of
 * mean-then-L2-normalise. The script stays because building the SHIPPED
 * centroids is a build-time job that must not depend on a user's machine.
 *
 * THROWS on any failure — a partial or wrong centroid set is worse than none,
 * because it would silently replace a known-good one. Callers keep the bundled
 * centroids and carry on; see engine.ts.
 */

import * as fs from "fs";
import * as path from "path";
import { Embedder, embedBatchFallback } from "./embeddings/embedder";
import { averageVectors } from "./embeddings/hashingEmbedder";

export interface CentroidBuildResult {
  /** Dimension of the produced centroids — i.e. what the endpoint actually returns. */
  dim: number;
  categories: number;
}

/**
 * Embed every example sentence, average per category, write the result as JSON.
 *
 * ONE batch call for the whole corpus (72 sentences across 5 categories), not
 * one per category and certainly not one per sentence — embedBatchFallback
 * collapses to a single embedBatch() where the embedder supports it, which
 * ApiEmbedder does. Against a remote endpoint that's the difference between one
 * round trip and seventy-two.
 */
export async function buildCentroids(
  examplesPath: string,
  embedder: Embedder,
  outPath: string
): Promise<CentroidBuildResult> {
  const raw = fs.readFileSync(examplesPath, "utf-8");
  const examples = JSON.parse(raw) as Record<string, string[]>;

  const categories = Object.keys(examples);
  if (categories.length === 0) throw new Error(`${examplesPath} contains no categories.`);

  // Flatten, remembering how many sentences each category owns so the results
  // can be split back apart in order.
  const flat: string[] = [];
  const counts: number[] = [];
  for (const category of categories) {
    const sentences = examples[category];
    if (!Array.isArray(sentences) || sentences.length === 0) {
      throw new Error(`Category "${category}" has no example sentences.`);
    }
    flat.push(...sentences);
    counts.push(sentences.length);
  }

  const vectors = await embedBatchFallback(embedder, flat);
  if (vectors.length !== flat.length) {
    throw new Error(`Embedder returned ${vectors.length} vectors for ${flat.length} inputs.`);
  }

  const dim = vectors[0]?.length ?? 0;
  if (dim === 0) throw new Error("Embedder returned empty vectors.");
  // A ragged response would silently corrupt the averaging — averageVectors
  // reads vectors[0].length and indexes every other vector against it.
  for (const v of vectors) {
    if (v.length !== dim) throw new Error(`Embedder returned inconsistent dimensions (${v.length} vs ${dim}).`);
  }

  const centroids: Record<string, number[]> = {};
  let offset = 0;
  for (let i = 0; i < categories.length; i++) {
    centroids[categories[i]] = averageVectors(vectors.slice(offset, offset + counts[i]));
    offset += counts[i];
  }

  // Write via a temp file in the same directory, then rename. A crash or a
  // second window racing us mid-write would otherwise leave a truncated JSON
  // file that EmbeddingRouter.load() rejects — and since the cache key is the
  // FILENAME, that corrupt file would be treated as a valid cache hit forever.
  await fs.promises.mkdir(path.dirname(outPath), { recursive: true });
  const tmpPath = `${outPath}.${process.pid}.tmp`;
  try {
    await fs.promises.writeFile(tmpPath, JSON.stringify(centroids), "utf-8");
    await fs.promises.rename(tmpPath, outPath);
  } catch (err) {
    await fs.promises.rm(tmpPath, { force: true }).catch(() => {});
    throw err;
  }

  return { dim, categories: categories.length };
}
