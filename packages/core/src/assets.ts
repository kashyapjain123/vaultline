/**
 * Where the core's own data files live.
 *
 * These paths used to be computed by the extension from
 * `context.extensionUri` — which meant the host had to know the core's
 * internal directory layout, and any second host would have to know it too
 * (and get it wrong, since the layout differs between a source checkout and
 * a packaged install). The package that owns the files resolves them
 * instead, relative to its own compiled location, so a host never names
 * `data/` or `embedding-server/` at all.
 *
 * Every getter returns a path whether or not the file exists. Callers already
 * treat a missing asset as a fail-open condition (routing off, syntax
 * awareness off, server unavailable), so there is nothing useful to throw
 * here — see EmbeddingRouter.load() and SyntaxAnalyzer.
 */

import * as path from "path";

/** The package root: one level up from the compiled `out/` this file runs from. */
const PACKAGE_ROOT = path.join(__dirname, "..");

/** Precomputed category centroids, one file per embedding backend — see scripts/buildEmbeddings.js for why they can never be mixed. */
const CENTROID_FILES = {
  api: "categoryEmbeddings.json",
  hashing: "categoryEmbeddings.hashing.json",
} as const;

export function dataDir(): string {
  return path.join(PACKAGE_ROOT, "data");
}

/**
 * Centroids for one backend. BOTH files ship, which is what makes the
 * runtime fallback in VaultlineEngine possible: a machine that can't bring
 * MiniLM up still gets working (lexical) routing without regenerating
 * anything locally.
 */
export function centroidsPath(backend: keyof typeof CENTROID_FILES): string {
  return path.join(dataDir(), CENTROID_FILES[backend]);
}

export function semanticSeedsPath(): string {
  return path.join(dataDir(), "semanticKeywordSeeds.json");
}

/**
 * The example corpus the centroids are averaged from.
 *
 * Ships as of 1.2.7 — it used to be build-input only, deliberately excluded
 * from the packaged extension. centroidBuilder.ts now reads it at RUN time to
 * rebuild centroids against a custom embedding endpoint, which is impossible
 * without it (see the note in the host's scripts/stageCore.js).
 */
export function categoryExamplesPath(): string {
  return path.join(dataDir(), "categoryExamples.json");
}

/** Source directory of the bundled MiniLM server — server.js plus its manifest, staged per-machine by EmbeddingServerManager. */
export function embeddingServerDir(): string {
  return path.join(PACKAGE_ROOT, "embedding-server");
}

/**
 * Directory holding the tree-sitter `*.wasm` grammars.
 *
 * Resolved through Node's module resolution rather than a hardcoded
 * `node_modules/...` path, because where the dependency physically lands is
 * the package manager's business: npm hoists it to a workspace root during
 * development and leaves it beside the extension when packaged, and both
 * must work. Returns null when the dependency isn't installed at all, which
 * SyntaxAnalyzer treats as "no syntax awareness" — the same fail-open path as
 * an unsupported language.
 */
export function grammarDir(): string | null {
  try {
    return path.join(path.dirname(require.resolve("tree-sitter-wasms/package.json")), "out");
  } catch {
    return null;
  }
}
