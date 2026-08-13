/**
 * Lightweight, dependency-free "embedding".
 *
 * IMPORTANT — read this before assuming this is a neural embedding: it is
 * NOT. This is a hashed bag-of-words + character-trigram vector (the
 * "hashing trick" — the same idea behind scikit-learn's HashingVectorizer
 * or Vowpal Wabbit's feature hashing). It captures LEXICAL overlap —
 * shared words and word-fragments — not semantic meaning. "password" and
 * "credential" will NOT score highly similar to each other under this
 * embedder despite being synonymous in this domain, because they share no
 * words and few character trigrams. It works here because the category
 * examples in data/categoryExamples.json are written to lexically overlap
 * with the phrasing you'd actually expect (e.g. the "credentials" category
 * examples literally contain the word "password"), not because this
 * understands meaning.
 *
 * Why this instead of a real model: bundling an actual embedding model
 * (e.g. MiniLM via @xenova/transformers) needs downloaded weights and an
 * async load step — meaningful setup cost, and this sandbox has
 * no network to fetch either the package or the weights to prove it out.
 * This module is written as a narrow, swappable interface (embed, plus
 * cosineSimilarity/averageVectors that don't care how the vector was
 * produced) specifically so that swap is a one-file change later — see
 * README "Upgrading to a real embedding model".
 */

export const EMBEDDING_DIM = 256;

import { Embedder } from "./embedder";

/** Embedder adapter around the sync hashing implementation below — the default, zero-setup backend. */
export class HashingEmbedder implements Embedder {
  async embed(text: string): Promise<number[]> {
    return embed(text);
  }
}

function hash(token: string, dim: number): number {
  // FNV-1a — fast, deterministic, good enough distribution for this dim.
  let h = 2166136261;
  for (let i = 0; i < token.length; i++) {
    h ^= token.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h) % dim;
}

function tokensForEmbedding(text: string): string[] {
  const words = text.toLowerCase().match(/[a-z0-9]+/g) || [];
  const grams: string[] = [...words];
  // Character trigrams per word give partial credit for related word forms
  // ("creds" / "credential" share trigrams like "cre", "red") without any
  // real morphological understanding — still lexical, just more forgiving.
  for (const w of words) {
    if (w.length < 4) continue;
    for (let i = 0; i <= w.length - 3; i++) {
      grams.push("#" + w.slice(i, i + 3));
    }
  }
  return grams;
}

/** Produces an L2-normalized vector — dot product of two outputs IS cosine similarity. */
export function embed(text: string, dim: number = EMBEDDING_DIM): number[] {
  const vec = new Array(dim).fill(0);
  const grams = tokensForEmbedding(text);
  for (const g of grams) {
    vec[hash(g, dim)] += 1;
  }
  const norm = Math.sqrt(vec.reduce((s, v) => s + v * v, 0)) || 1;
  return vec.map((v) => v / norm);
}

export function cosineSimilarity(a: number[], b: number[]): number {
  let dot = 0;
  for (let i = 0; i < a.length; i++) dot += a[i] * b[i];
  return dot;
}

/** Averages a set of (already L2-normalized) vectors and re-normalizes the result — used to build one centroid per category from several example sentences. */
export function averageVectors(vectors: number[][]): number[] {
  const dim = vectors[0].length;
  const avg = new Array(dim).fill(0);
  for (const v of vectors) {
    for (let i = 0; i < dim; i++) avg[i] += v[i];
  }
  for (let i = 0; i < dim; i++) avg[i] /= vectors.length;
  const norm = Math.sqrt(avg.reduce((s, v) => s + v * v, 0)) || 1;
  return avg.map((v) => v / norm);
}
