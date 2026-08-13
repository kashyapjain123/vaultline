/**
 * API-backed Embedder — calls a backend embedding server over HTTP. By
 * default this is the bundled local server (see embedding-server/, a
 * separate Node process) running all-MiniLM-L6-v2 on localhost:9000, but
 * baseUrl/auth are fully configurable so this can point at any
 * OpenAI-compatible or custom embedding API instead — see
 * ApiEmbedderOptions below and the vaultline.embeddingApi* settings in
 * package.json.
 *
 * FAIL-OPEN BY DESIGN: if the server is unreachable, slow, errors, or
 * rejects auth, embed() throws — it does NOT silently return a zero vector
 * or fall back to the hashing embedder internally. That choice is
 * deliberate: embeddingRouter.ts is what catches this and treats it as
 * "routing unavailable for this call", same as a missing centroids file,
 * which means every contextual detector just runs unconditionally. A
 * silent fallback here would hide real problems (server down, wrong URL,
 * bad credentials, model failed to load) behind what looks like normal
 * operation.
 */

import { Embedder } from "./embedder";

export type ApiAuthType = "none" | "bearer" | "apiKey" | "basic";

export interface ApiEmbedderOptions {
  baseUrl: string;
  timeoutMs?: number;

  /** Optional model name, sent as `{ model, texts }` in the request body — for backends (e.g. OpenAI-compatible endpoints) that serve more than one embedding model behind the same URL. Omit for the bundled server, which only ever serves one model and ignores this field. */
  model?: string;

  authType?: ApiAuthType;
  /** Bearer token (authType "bearer"), API key value (authType "apiKey"), or "username:password" (authType "basic"). Ignored when authType is "none"/undefined. */
  authToken?: string;
  /** Header name to send the API key under, when authType is "apiKey". Defaults to "x-api-key". */
  apiKeyHeader?: string;

  /** Arbitrary extra headers, for anything the structured authType options above don't cover. Merged in after the auth header, so these can also override it if needed. */
  extraHeaders?: Record<string, string>;
}

export class ApiEmbedder implements Embedder {
  private baseUrl: string;
  private timeoutMs: number;
  private model?: string;
  private headers: Record<string, string>;

  constructor(options: ApiEmbedderOptions) {
    // Trim a trailing slash so `${baseUrl}/embed-batch` never ends up double-slashed.
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 3000;
    this.model = options.model;
    this.headers = { "Content-Type": "application/json", ...buildAuthHeaders(options), ...(options.extraHeaders ?? {}) };
  }

  async embed(text: string): Promise<number[]> {
    const [vec] = await this.embedBatch([text]);
    return vec;
  }

  async embedBatch(texts: string[]): Promise<number[][]> {
    if (texts.length === 0) return [];

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await fetch(`${this.baseUrl}/embed-batch`, {
        method: "POST",
        headers: this.headers,
        body: JSON.stringify(this.model ? { texts, model: this.model } : { texts }),
        signal: controller.signal,
      });

      if (res.status === 401 || res.status === 403) {
        throw new Error(`Embedding API at ${this.baseUrl} rejected the request (HTTP ${res.status}) — check vaultline.embeddingApiAuthType / embeddingApiAuthToken.`);
      }
      if (!res.ok) {
        throw new Error(`Embedding API at ${this.baseUrl} returned HTTP ${res.status}`);
      }

      const data = (await res.json()) as { embeddings?: number[][] };
      if (!Array.isArray(data.embeddings) || data.embeddings.length !== texts.length) {
        throw new Error(`Embedding API at ${this.baseUrl} returned an unexpected response shape`);
      }

      return data.embeddings;
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new Error(`Embedding API at ${this.baseUrl} timed out after ${this.timeoutMs}ms`);
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }
}

function buildAuthHeaders(options: ApiEmbedderOptions): Record<string, string> {
  const type = options.authType ?? "none";
  if (type === "none" || !options.authToken) return {};

  if (type === "bearer") {
    return { Authorization: `Bearer ${options.authToken}` };
  }
  if (type === "apiKey") {
    return { [options.apiKeyHeader ?? "x-api-key"]: options.authToken };
  }
  if (type === "basic") {
    // authToken is expected as "username:password" — base64-encode it here
    // so settings.json only ever holds the plain credential, not a
    // pre-encoded one, matching how every other auth-token setting works.
    const encoded = Buffer.from(options.authToken, "utf-8").toString("base64");
    return { Authorization: `Basic ${encoded}` };
  }
  return {};
}
