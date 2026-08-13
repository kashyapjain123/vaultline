/**
 * Vaultline embedding server.
 *
 * Loads sentence-transformers/all-MiniLM-L6-v2 (via its @xenova/transformers
 * ONNX port) ONCE at startup, then serves embeddings over a tiny HTTP API.
 * This is a separate process from the VS Code extension on purpose — see
 * the extension's README for why (mainly: keeping model inference off the
 * extension host's single UI-relevant thread).
 *
 * First run downloads the model (~90MB) from Hugging Face and caches it
 * locally (under your OS cache dir, e.g. ~/.cache/huggingface on
 * macOS/Linux) — needs network access once, not on every subsequent start.
 *
 * Endpoints:
 *   GET  /health         -> { status: "loading" | "ready" | "error" }
 *   POST /embed  {text}  -> { embedding: number[] }   (384-dim, L2-normalized)
 */

import express from "express";
import { pipeline } from "@xenova/transformers";

const PORT = process.env.PORT || 9000;
const MODEL_NAME = "Xenova/all-MiniLM-L6-v2";

const app = express();
app.use(express.json());

let extractor = null;
let loadError = null;

console.log(`Loading ${MODEL_NAME} ... (first run downloads ~90MB and caches it locally)`);
pipeline("feature-extraction", MODEL_NAME)
  .then((p) => {
    extractor = p;
    console.log("Model loaded — ready to serve /embed.");
  })
  .catch((err) => {
    loadError = err;
    console.error("Failed to load model:", err);
  });

app.get("/health", (req, res) => {
  if (loadError) return res.status(500).json({ status: "error", error: String(loadError) });
  if (!extractor) return res.status(503).json({ status: "loading" });
  res.json({ status: "ready", model: MODEL_NAME });
});

app.post("/embed", async (req, res) => {
  if (loadError) {
    return res.status(500).json({ error: "Model failed to load: " + String(loadError) });
  }
  if (!extractor) {
    return res.status(503).json({ error: "Model still loading — try again shortly." });
  }

  const { text } = req.body ?? {};
  if (typeof text !== "string" || text.length === 0) {
    return res.status(400).json({ error: "Request body must be { text: string }" });
  }

  try {
    // mean pooling over token embeddings + L2 normalize -> a single
    // 384-dim sentence vector, ready for cosine similarity via dot product.
    const output = await extractor(text, { pooling: "mean", normalize: true });
    res.json({ embedding: Array.from(output.data) });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.post("/embed-batch", async (req, res) => {
  if (loadError) {
    return res.status(500).json({ error: "Model failed to load: " + String(loadError) });
  }
  if (!extractor) {
    return res.status(503).json({ error: "Model still loading — try again shortly." });
  }

  const { texts } = req.body ?? {};
  if (!Array.isArray(texts) || texts.some((t) => typeof t !== "string")) {
    return res.status(400).json({ error: "Request body must be { texts: string[] }" });
  }
  if (texts.length === 0) {
    return res.json({ embeddings: [] });
  }

  try {
    // transformers.js accepts an array of inputs directly and batches them
    // internally — one forward pass, not N. .tolist() gives back a plain
    // nested JS array (one embedding per input) instead of a flat typed
    // array + dims you'd have to reshape yourself.
    const output = await extractor(texts, { pooling: "mean", normalize: true });
    const embeddings = output.tolist();
    res.json({ embeddings });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.listen(PORT, () => {
  console.log(`Vaultline embedding server listening on http://localhost:${PORT}`);
});
