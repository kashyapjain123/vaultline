/**
 * Newline-delimited JSON-RPC 2.0 over stdio — the MCP transport, and the whole
 * reason this package has no runtime dependency beyond @vaultline/core.
 *
 * Two rules that are easy to get wrong and produce a server which "works"
 * until it doesn't:
 *
 *   1. stdout is the PROTOCOL. Anything else written there — a stray
 *      console.log, a warning, a progress line — corrupts the stream and the
 *      client drops the connection. Diagnostics go to stderr, which is why
 *      CliHost routes its log channel there.
 *
 *   2. A notification (a request with no `id`) MUST NOT be answered. MCP
 *      sends `notifications/initialized` immediately after the handshake;
 *      replying to it is a protocol violation.
 */

import * as readline from "readline";

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  /** Absent for notifications — see rule 2 above. */
  id?: string | number;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

/** Standard JSON-RPC codes. -32603 is what we use for a handler that threw. */
export const RPC_METHOD_NOT_FOUND = -32601;
export const RPC_INVALID_PARAMS = -32602;
export const RPC_INTERNAL_ERROR = -32603;

export type MethodHandler = (params: Record<string, unknown>) => Promise<unknown>;

export class StdioRpcServer {
  private readonly handlers = new Map<string, MethodHandler>();

  constructor(
    private readonly input: NodeJS.ReadableStream = process.stdin,
    private readonly output: NodeJS.WritableStream = process.stdout,
  ) {}

  on(method: string, handler: MethodHandler): this {
    this.handlers.set(method, handler);
    return this;
  }

  /** Resolves when the input stream closes, i.e. when the client goes away. */
  listen(): Promise<void> {
    const rl = readline.createInterface({ input: this.input, crlfDelay: Infinity });

    return new Promise((resolve) => {
      rl.on("line", (line) => {
        // Serialized deliberately: tool calls mutate a shared EntityStore, and
        // interleaving two of them can mint two different tokens for the same
        // value. Ordering costs a little latency and buys a coherent mapping.
        this.queue = this.queue.then(() => this.dispatch(line)).catch(() => {});
      });
      rl.on("close", () => resolve());
    });
  }

  private queue: Promise<void> = Promise.resolve();

  private async dispatch(line: string): Promise<void> {
    const trimmed = line.trim();
    if (!trimmed) return;

    let request: JsonRpcRequest;
    try {
      request = JSON.parse(trimmed) as JsonRpcRequest;
    } catch {
      // No id recoverable from unparseable input, so there is nobody to answer.
      return;
    }

    const isNotification = request.id === undefined || request.id === null;
    const handler = this.handlers.get(request.method);

    if (!handler) {
      if (!isNotification) {
        this.send({ jsonrpc: "2.0", id: request.id, error: { code: RPC_METHOD_NOT_FOUND, message: `Unknown method: ${request.method}` } });
      }
      return;
    }

    try {
      const result = await handler(request.params ?? {});
      if (!isNotification) this.send({ jsonrpc: "2.0", id: request.id, result });
    } catch (err) {
      if (!isNotification) {
        this.send({
          jsonrpc: "2.0",
          id: request.id,
          error: { code: RPC_INTERNAL_ERROR, message: err instanceof Error ? err.message : String(err) },
        });
      }
    }
  }

  private send(message: Record<string, unknown>): void {
    this.output.write(JSON.stringify(message) + "\n");
  }
}
