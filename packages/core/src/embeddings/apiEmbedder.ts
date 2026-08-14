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

/**
 * Which request/response shape the endpoint speaks.
 *
 * "vaultline" is the bundled server's: POST {texts} -> {embeddings}.
 * "openai" is the de-facto standard every hosted provider implements:
 * POST {input, model} -> {data:[{embedding, index}]}.
 *
 * This exists because the README promised "remote/OpenAI-compatible endpoint"
 * while the code only ever spoke the first shape — so pointing at a real
 * OpenAI-compatible service failed with "unexpected response shape".
 */
export type ApiEmbedFormat = "vaultline" | "openai";

/** Where each format serves embeddings when the user hasn't overridden the path. */
export function defaultEmbedPathFor(format: ApiEmbedFormat): string {
  return format === "openai" ? "/v1/embeddings" : "/embed-batch";
}

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

  /** Request/response shape. Defaults to "vaultline" (the bundled server). */
  format?: ApiEmbedFormat;
  /** Path appended to baseUrl. Empty/omitted uses defaultEmbedPathFor(format). */
  embedPath?: string;
}

export class ApiEmbedder implements Embedder {
  private baseUrl: string;
  private timeoutMs: number;
  private model?: string;
  private headers: Record<string, string>;
  private format: ApiEmbedFormat;
  private embedPath: string;
  private authType: ApiAuthType;
  private apiKeyHeader?: string;
  private readonly extraHeaders: Record<string, string>;

  constructor(options: ApiEmbedderOptions) {
    // Trim a trailing slash so `${baseUrl}/embed-batch` never ends up double-slashed.
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 3000;
    this.model = options.model;
    this.format = options.format ?? "vaultline";
    this.embedPath = normalisePath(options.embedPath) || defaultEmbedPathFor(this.format);
    this.authType = options.authType ?? "none";
    this.apiKeyHeader = options.apiKeyHeader;
    this.extraHeaders = options.extraHeaders ?? {};
    this.headers = { "Content-Type": "application/json", ...buildAuthHeaders(options), ...this.extraHeaders };
  }

  /**
   * Swap the credential, mid-session.
   *
   * Same in-place mutation as repoint() below and for the same reason: engine.ts
   * hands this ONE instance to both EmbeddingRouter and SemanticKeywordMatcher,
   * so rebuilding would leave them holding a stale embedder.
   *
   * Needed because the token now comes from the OS keychain, which is an async
   * read — the embedder is constructed long before the value is available.
   * Passing an empty token removes the header entirely rather than sending an
   * empty one, so "clear the token" genuinely stops authenticating.
   */
  setAuthToken(authToken: string | undefined, authType?: ApiAuthType, apiKeyHeader?: string): void {
    const { "Content-Type": contentType, ...rest } = this.headers;
    void rest; // dropped deliberately: stale auth headers must not survive
    this.headers = {
      "Content-Type": contentType ?? "application/json",
      ...buildAuthHeaders({
        baseUrl: this.baseUrl,
        authType: authToken ? (authType ?? this.authType) : "none",
        authToken: authToken || undefined,
        apiKeyHeader: apiKeyHeader ?? this.apiKeyHeader,
      }),
      ...this.extraHeaders,
    };
  }

  /**
   * Repoint this embedder at a different server, mid-session.
   *
   * Exists because the local server does not always land on the configured
   * port — if something else holds it, EmbeddingServerManager picks the next
   * free one (see selectPort there) and the embedder has to follow, or it keeps
   * calling the port occupied by whatever displaced us.
   *
   * Mutating in place rather than rebuilding is the point: engine.ts hands this
   * SAME instance to both EmbeddingRouter and SemanticKeywordMatcher, so one
   * call repoints every consumer. A rebuild would leave the semantic matcher
   * holding a stale embedder aimed at a dead port.
   */
  setBaseUrl(url: string): void {
    this.baseUrl = url.replace(/\/$/, "");
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
      const res = await fetch(`${this.baseUrl}${this.embedPath}`, {
        method: "POST",
        headers: this.headers,
        body: JSON.stringify(
          this.format === "openai"
            ? // OpenAI requires `model`; there is no server-side default to fall
              // back on, so send something rather than let the request 400 with
              // a message about a field the user never knew existed.
              { input: texts, model: this.model || "text-embedding-3-small" }
            : this.model
              ? { texts, model: this.model }
              : { texts }
        ),
        signal: controller.signal,
      });

      if (res.status === 401 || res.status === 403) {
        throw new Error(`Embedding API at ${this.baseUrl} rejected the request (HTTP ${res.status}) — check vaultline.embeddingApiAuthType / embeddingApiAuthToken.`);
      }
      if (!res.ok) {
        throw new Error(`Embedding API at ${this.baseUrl} returned HTTP ${res.status}`);
      }

      const body = (await res.json()) as {
        embeddings?: number[][];
        data?: Array<{ embedding?: number[]; index?: number }>;
      };

      const vectors =
        this.format === "openai"
          ? // Sort by `index` before mapping. The API documents them in order,
            // but relying on that is a silent-corruption risk: mismatched
            // vectors would make routing score every message against the wrong
            // text, and nothing downstream could detect it.
            (body.data ?? [])
              .slice()
              .sort((a, b) => (a.index ?? 0) - (b.index ?? 0))
              .map((row) => row.embedding as number[])
          : body.embeddings;

      if (!Array.isArray(vectors) || vectors.length !== texts.length || vectors.some((v) => !Array.isArray(v))) {
        throw new Error(
          `Embedding API at ${this.baseUrl}${this.embedPath} returned an unexpected response shape for ` +
            `format "${this.format}" — check vaultline.embeddingApiFormat.`
        );
      }

      return vectors;
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

/** Normalises a configured path fragment: trims, and guarantees a single leading slash. */
function normalisePath(path?: string): string {
  const trimmed = (path ?? "").trim();
  if (trimmed.length === 0) return "";
  return trimmed.startsWith("/") ? trimmed.replace(/\/+$/, "") : `/${trimmed.replace(/\/+$/, "")}`;
}
