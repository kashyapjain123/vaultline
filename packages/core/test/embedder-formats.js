/**
 * Custom embedding endpoints: request shape, response shape, and the health
 * probe that silently blocked all of it.
 *
 * The root README promised "remote/OpenAI-compatible endpoint" while the code
 * only ever spoke its own shape — POST {texts} -> {embeddings} — so pointing
 * Vaultline at a real OpenAI-compatible service failed with "unexpected
 * response shape". Underneath that sat a worse problem: for any non-loopback
 * URL the manager gated on GET {baseUrl}/health, which hosted services do not
 * have, so the probe failed, routing fell back to the hashing embedder, and the
 * configured endpoint was never called at all.
 *
 * The ordering check is the subtle one. OpenAI returns `data` with an `index`
 * per row; trusting array order instead of sorting would pair each vector with
 * the wrong text, and nothing downstream could detect it — routing would just
 * quietly score every message against something else.
 *
 * Hermetic: a fake endpoint on a distinct port per case (undici pools
 * connections by origin, so reusing a port makes the next case ECONNRESET).
 */

const http = require("http");
const path = require("path");
const { ApiEmbedder, defaultEmbedPathFor, resolveVectorsPath } = require(path.join(__dirname, "..", "out", "embeddings", "apiEmbedder"));

let nextPort = 19300;

let failures = 0;
function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

/** Records what it was asked for, and answers in the requested shape. */
function startEndpoint({ format = "vaultline", dim = 8, shuffle = false, wrap = null } = {}) {
  const port = nextPort++;
  const state = { port, paths: [], bodies: [], headers: [] };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      state.paths.push(req.url);
      state.headers.push(req.headers);
      const parsed = JSON.parse(body || "{}");
      state.bodies.push(parsed);

      // Read whichever field holds the array — the custom cases send arbitrary
      // names like "sentences", and the mismatch case deliberately sends the
      // wrong shape entirely. The endpoint answers in ITS format regardless, so
      // the client is the thing that reports a mismatch.
      const texts = Object.values(parsed).find((v) => Array.isArray(v)) ?? [];
      const vector = (i) => Array.from({ length: dim }, (_, k) => i + k / 100);

      res.setHeader("Content-Type", "application/json");
      if (format === "openai") {
        const rows = texts.map((_, i) => ({ embedding: vector(i), index: i }));
        // Deliberately out of order when asked: the client must sort by index.
        res.end(JSON.stringify({ data: shuffle ? rows.slice().reverse() : rows }));
      } else if (wrap) {
        // An arbitrary nesting, for the "custom" path expression.
        res.end(JSON.stringify(wrap(texts.map((_, i) => vector(i)))));
      } else {
        res.end(JSON.stringify({ embeddings: texts.map((_, i) => vector(i)) }));
      }
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve({ server, state }));
  });
}

const stop = (server) =>
  new Promise((resolve) => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  });

async function main() {
  console.log("\n[default paths per format]");
  check('vaultline -> "/embed-batch"', defaultEmbedPathFor("vaultline") === "/embed-batch");
  check('openai -> "/v1/embeddings"', defaultEmbedPathFor("openai") === "/v1/embeddings");

  console.log("\n[vaultline format: {texts} -> {embeddings}]");
  {
    const { server, state } = await startEndpoint({ format: "vaultline" });
    const embedder = new ApiEmbedder({ baseUrl: `http://127.0.0.1:${state.port}`, format: "vaultline" });
    const out = await embedder.embedBatch(["a", "b", "c"]);
    check("three vectors back", out.length === 3);
    check("hit /embed-batch", state.paths[0] === "/embed-batch", state.paths[0]);
    check("sent {texts}", Array.isArray(state.bodies[0].texts), JSON.stringify(state.bodies[0]));
    await stop(server);
  }

  console.log("\n[openai format: {input, model} -> {data:[{embedding}]}]");
  {
    const { server, state } = await startEndpoint({ format: "openai" });
    const embedder = new ApiEmbedder({
      baseUrl: `http://127.0.0.1:${state.port}`,
      format: "openai",
      model: "text-embedding-3-small",
    });
    const out = await embedder.embedBatch(["a", "b"]);
    check("two vectors back", out.length === 2);
    check("hit /v1/embeddings", state.paths[0] === "/v1/embeddings", state.paths[0]);
    check("sent {input}", Array.isArray(state.bodies[0].input), JSON.stringify(state.bodies[0]));
    check("sent a model (OpenAI requires one)", typeof state.bodies[0].model === "string");
    await stop(server);
  }

  console.log("\n[out-of-order OpenAI rows are sorted by index]");
  {
    // Silent corruption if wrong: each vector would be attributed to the wrong
    // text and routing would score against the wrong thing forever.
    const { server, state } = await startEndpoint({ format: "openai", shuffle: true });
    const embedder = new ApiEmbedder({ baseUrl: `http://127.0.0.1:${state.port}`, format: "openai" });
    const out = await embedder.embedBatch(["a", "b", "c"]);
    check("first vector belongs to the first input", out[0][0] === 0, JSON.stringify(out[0].slice(0, 2)));
    check("last vector belongs to the last input", out[2][0] === 2, JSON.stringify(out[2].slice(0, 2)));
    await stop(server);
  }

  console.log("\n[a custom path is the path actually requested]");
  {
    const { server, state } = await startEndpoint({ format: "vaultline" });
    const embedder = new ApiEmbedder({
      baseUrl: `http://127.0.0.1:${state.port}`,
      format: "vaultline",
      embedPath: "/input/text",
    });
    await embedder.embedBatch(["a"]);
    check("hit /input/text", state.paths[0] === "/input/text", state.paths[0]);
    await stop(server);
  }

  console.log("\n[a path without a leading slash still works]");
  {
    const { server, state } = await startEndpoint({ format: "vaultline" });
    const embedder = new ApiEmbedder({ baseUrl: `http://127.0.0.1:${state.port}`, embedPath: "input/text" });
    await embedder.embedBatch(["a"]);
    check("normalised to /input/text", state.paths[0] === "/input/text", state.paths[0]);
    await stop(server);
  }

  console.log("\n[wrong format is reported, not silently mis-parsed]");
  {
    const { server, state } = await startEndpoint({ format: "openai" });
    // Ask for the vaultline shape from an OpenAI-shaped endpoint.
    const embedder = new ApiEmbedder({ baseUrl: `http://127.0.0.1:${state.port}`, format: "vaultline", embedPath: "/v1/embeddings" });
    let message = "";
    try {
      await embedder.embedBatch(["a"]);
    } catch (err) {
      message = String(err);
    }
    check("throws", message.length > 0);
    check("names the setting to fix", message.includes("embeddingApiFormat"), message);
    await stop(server);
  }

  console.log("\n[setAuthToken puts the credential on the wire]");
  {
    const { server, state } = await startEndpoint({ format: "vaultline" });
    const embedder = new ApiEmbedder({ baseUrl: `http://127.0.0.1:${state.port}` });
    embedder.setAuthToken("sekret-token", "bearer");
    await embedder.embedBatch(["a"]);
    check("Authorization header sent", state.headers[0].authorization === "Bearer sekret-token", JSON.stringify(state.headers[0].authorization));

    // Clearing must actually clear — a stale header would keep authenticating.
    embedder.setAuthToken(undefined);
    await embedder.embedBatch(["b"]);
    check("cleared token removes the header", state.headers[1].authorization === undefined, JSON.stringify(state.headers[1].authorization));
    await stop(server);
  }

  console.log("\n[custom format: the presets are not special-cased]");
  {
    // The point of "custom": describing the vaultline preset by hand must
    // behave identically, which is what shows the two built-ins are just fixed
    // points of the same mechanism rather than the only shapes supported.
    const { server, state } = await startEndpoint({ format: "vaultline" });
    const embedder = new ApiEmbedder({
      baseUrl: `http://127.0.0.1:${state.port}`,
      format: "custom",
      embedPath: "/embed-batch",
      requestField: "texts",
      responsePath: "embeddings",
    });
    const out = await embedder.embedBatch(["a", "b"]);
    check("behaves like the vaultline preset", out.length === 2);
    check("sent the configured field", Array.isArray(state.bodies[0].texts), JSON.stringify(state.bodies[0]));
    await stop(server);
  }

  {
    const { server, state } = await startEndpoint({ format: "openai" });
    const embedder = new ApiEmbedder({
      baseUrl: `http://127.0.0.1:${state.port}`,
      format: "custom",
      embedPath: "/v1/embeddings",
      requestField: "input",
      responsePath: "data[].embedding",
    });
    const out = await embedder.embedBatch(["a", "b", "c"]);
    check("describes the openai shape by hand", out.length === 3);
    await stop(server);
  }

  console.log("\n[custom format: arbitrary field names and nesting]");
  {
    const { server, state } = await startEndpoint({ wrap: (v) => ({ result: { vectors: v } }) });
    const embedder = new ApiEmbedder({
      baseUrl: `http://127.0.0.1:${state.port}`,
      format: "custom",
      embedPath: "/input/text",
      requestField: "sentences",
      responsePath: "result.vectors",
    });
    const out = await embedder.embedBatch(["a", "b"]);
    check("nested path resolves", out.length === 2);
    check("custom request field used", Array.isArray(state.bodies[0].sentences), JSON.stringify(state.bodies[0]));
    check("custom path used", state.paths[0] === "/input/text", state.paths[0]);
    await stop(server);
  }

  console.log("\n[a wrong path is reported, naming the setting to fix]");
  {
    const { server, state } = await startEndpoint({ format: "vaultline" });
    const embedder = new ApiEmbedder({
      baseUrl: `http://127.0.0.1:${state.port}`,
      format: "custom",
      responsePath: "nowhere.at.all",
    });
    let message = "";
    try {
      await embedder.embedBatch(["a"]);
    } catch (err) {
      message = String(err);
    }
    check("throws rather than returning garbage", message.length > 0);
    check("names embeddingApiResponsePath", message.includes("embeddingApiResponsePath"), message);
    await stop(server);
  }

  console.log("\n[resolveVectorsPath directly]");
  {
    check("flat", resolveVectorsPath({ embeddings: [[1, 2]] }, "embeddings")?.length === 1);
    check("array hop", resolveVectorsPath({ data: [{ embedding: [1] }, { embedding: [2] }] }, "data[].embedding")?.length === 2);
    check("nested object", resolveVectorsPath({ result: { vectors: [[1]] } }, "result.vectors")?.length === 1);
    check("bare array hop", resolveVectorsPath({ out: [[1], [2]] }, "out[]")?.length === 2);
    check("missing path -> null", resolveVectorsPath({ embeddings: [[1]] }, "nope") === null);
    check("wrong leaf -> null", resolveVectorsPath({ data: [{ x: 1 }] }, "data[].embedding") === null);
    check("non-numeric -> null", resolveVectorsPath({ embeddings: [["a"]] }, "embeddings") === null);
    check("empty path -> null", resolveVectorsPath({ embeddings: [[1]] }, "") === null);
  }

  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
