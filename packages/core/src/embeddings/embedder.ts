/**
 * The seam. Everything above this interface (embeddingRouter.ts,
 * detectionPipeline.ts) only ever talks to `Embedder`, never to a specific
 * implementation — so swapping which model actually produces the vectors
 * is a matter of constructing a different Embedder at activation time in
 * extension.ts, not touching the routing/detection logic itself.
 *
 * async by design: the local hashing embedder is actually synchronous
 * (pure JS math, no I/O), but a real model — especially one served over
 * HTTP — is not. Wrapping the sync implementation in a resolved Promise
 * costs nothing and means callers never need to know or care which kind
 * they have.
 */
export interface Embedder {
  embed(text: string): Promise<number[]>;
  /**
   * Optional: embed many strings in one call. Implementations that don't
   * override this get a default (see embedBatchFallback in this file) that
   * just calls embed() once per item — fine for the local hashing embedder
   * (no I/O cost either way), but callers making many small embed() calls
   * against a network-backed Embedder (ApiEmbedder) should prefer a real
   * batched implementation to avoid one HTTP round-trip per item.
   */
  embedBatch?(texts: string[]): Promise<number[][]>;
}

/** Used by callers that want batching but the Embedder they were given didn't implement embedBatch. */
export async function embedBatchFallback(embedder: Embedder, texts: string[]): Promise<number[][]> {
  if (embedder.embedBatch) return embedder.embedBatch(texts);
  return Promise.all(texts.map((t) => embedder.embed(t)));
}
