/**
 * Embedding Router
 *
 * Loads the precomputed category centroids (data/categoryEmbeddings.json)
 * once, then for each input: embed it (via whichever Embedder was
 * constructed — see embeddings/embedder.ts), score cosine similarity
 * against every category centroid, return the categories that clear a
 * threshold.
 *
 * Two different thresholds are used by callers for two different-stakes
 * decisions (see detectionPipeline.ts):
 *   - A LOW threshold for "should the cheap, safe contextual detector for
 *     this category run at all" — false positives here just mean running
 *     an extra harmless regex/proximity check, so it's fine to be generous.
 *   - A HIGHER, separate threshold specifically for the business-content
 *     category, which triggers a whole-message flag rather than
 *     fine-grained redaction — a false positive there means wrongly
 *     flagging an entire ordinary message, so it needs real confidence.
 *
 * If the centroids file is missing or malformed, load() returns null
 * rather than throwing — callers should treat that as "routing
 * unavailable" and fail OPEN (run every detector), not fail closed. Same
 * treatment if the embedder itself fails at call time (e.g. the API
 * backend is down) — scoreAll() catches that and returns [] rather than
 * throwing, for the same fail-open reason.
 */

import * as fs from "fs";
import { Embedder } from "./embeddings/embedder";
import { cosineSimilarity } from "./embeddings/hashingEmbedder";

export interface RouteResult {
  category: string;
  score: number;
}

export class EmbeddingRouter {
  private centroids: Record<string, number[]>;
  private embedder: Embedder;
  private expectedDim: number | null = null;
  private wholeMessageCapable: boolean;

  private constructor(centroids: Record<string, number[]>, embedder: Embedder, wholeMessageCapable: boolean) {
    this.centroids = centroids;
    this.embedder = embedder;
    this.wholeMessageCapable = wholeMessageCapable;
    const first = Object.values(centroids)[0];
    this.expectedDim = first ? first.length : null;
  }

  /**
   * `wholeMessageCapable` — whether these centroids are trustworthy enough
   * to decide, on similarity ALONE, that an entire message is confidential
   * and should be blocked (detectionPipeline.ts's business-content flag).
   *
   * It is a separate axis from "is routing available" because the two have
   * wildly different error costs. Routing is a gate in front of cheap,
   * safe detectors: a false positive there costs one extra regex pass, so
   * a generous, imprecise embedder is perfectly good enough. The
   * whole-message flag BLOCKS the message, so a false positive there is a
   * developer being told their question about quicksort is confidential
   * business content.
   *
   * Measured on the hashing embedder, that is not a hypothetical: benign
   * developer questions reach 0.46 on the business-strategy centroid while
   * genuine business content bottoms out at 0.40 — the classes overlap, so
   * NO threshold separates them, and raising the bar just trades false
   * blocks for missed secrets. MiniLM separates them cleanly. Hence the
   * flag: the hashing fallback keeps routing and gives up the flag, rather
   * than pretending a lexical embedder can carry a blocking decision.
   */
  static load(centroidsPath: string, embedder: Embedder, wholeMessageCapable: boolean = true): EmbeddingRouter | null {
    try {
      const raw = fs.readFileSync(centroidsPath, "utf-8");
      const parsed = JSON.parse(raw);
      if (typeof parsed !== "object" || parsed === null || Object.keys(parsed).length === 0) {
        return null;
      }
      return new EmbeddingRouter(parsed, embedder, wholeMessageCapable);
    } catch {
      // Missing file, bad JSON, whatever — routing just isn't available.
      return null;
    }
  }

  /** See load()'s `wholeMessageCapable` note. Callers that BLOCK on a similarity score alone must check this first. */
  supportsWholeMessageClassification(): boolean {
    return this.wholeMessageCapable;
  }

  /**
   * Swap BOTH the centroids and the embedder that produced them, in place.
   *
   * In place, rather than constructing a new router, because this instance
   * has already been handed to the chat participant and the detection
   * pipeline — mutating it means a backend switch reaches every caller
   * without re-registering anything or plumbing a fresh reference through.
   *
   * The two always move together and that is the entire point: centroids
   * and embedder must come from the same vector space, and every existing
   * caller of this class is protected from getting that wrong only by the
   * dimension check in scoreAll(), which catches the 256-vs-384 case but
   * could not catch a same-dimension mismatch. Keeping the swap atomic here
   * means there is no window in which they disagree.
   *
   * Returns false (leaving the router untouched and still usable) if the
   * new centroids file is missing or malformed — same fail-open contract as
   * load().
   */
  useBackend(centroidsPath: string, embedder: Embedder, wholeMessageCapable: boolean = true): boolean {
    try {
      const parsed = JSON.parse(fs.readFileSync(centroidsPath, "utf-8")) as Record<string, number[]>;
      if (typeof parsed !== "object" || parsed === null || Object.keys(parsed).length === 0) {
        return false;
      }
      this.centroids = parsed;
      this.embedder = embedder;
      this.wholeMessageCapable = wholeMessageCapable;
      const first = Object.values(parsed)[0];
      this.expectedDim = first ? first.length : null;
      return true;
    } catch {
      return false;
    }
  }

  /**
   * All categories with their similarity score, sorted highest first (no
   * threshold applied). Returns [] — not a throw — if the embedder call
   * fails or if the returned vector's dimension doesn't match the loaded
   * centroids (e.g. centroids were built with a different embedder than
   * is currently configured — see scripts/buildEmbeddings.js). Both are
   * treated as "routing unavailable for this call", consistent with the
   * fail-open behavior when the centroids file itself is missing.
   */
  async scoreAll(text: string): Promise<RouteResult[]> {
    let vec: number[];
    try {
      vec = await this.embedder.embed(text);
    } catch (err) {
      console.warn("Vaultline: embedding call failed, routing unavailable for this message:", err);
      return [];
    }

    if (this.expectedDim !== null && vec.length !== this.expectedDim) {
      console.warn(
        `Vaultline: embedding dimension mismatch (got ${vec.length}, centroids are ${this.expectedDim}-dim). ` +
          `Did you switch vaultline.embeddingBackend without regenerating data/categoryEmbeddings.json? ` +
          `Run: npm run build:embeddings -- --backend=<same backend>`
      );
      return [];
    }

    const scored: RouteResult[] = Object.entries(this.centroids).map(([category, centroid]) => ({
      category,
      score: cosineSimilarity(vec, centroid),
    }));
    return scored.sort((a, b) => b.score - a.score);
  }

  /** Categories scoring at or above minSimilarity, capped at topK. */
  async route(text: string, minSimilarity: number, topK: number = 10): Promise<RouteResult[]> {
    const scored = await this.scoreAll(text);
    return scored.filter((r) => r.score >= minSimilarity).slice(0, topK);
  }
}
