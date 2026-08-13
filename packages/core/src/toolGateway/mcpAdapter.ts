/**
 * MCP adapter — the "structured JSON" side. Input and output are both
 * JSON, unlike the shell adapter's plain strings.
 *
 * Deliberately generic: rather than depending on a specific MCP SDK/client
 * library (which I don't know your exact setup for), this takes a `caller`
 * function you provide — whatever actually sends the MCP tool-call request
 * and returns its JSON result in your environment. Wire it to your real
 * MCP client's `callTool()` (or equivalent) and the adapter — and
 * everything above it in the gateway — doesn't need to change.
 */

import { ToolAdapter } from "./toolAdapter";

export type McpCaller = (toolName: string, args: Record<string, unknown>) => Promise<unknown>;

export class McpAdapter implements ToolAdapter {
  readonly type = "mcp" as const;

  constructor(private caller: McpCaller) {}

  /** rehydratedInput is the full arguments object, already rehydrated by the gateway. */
  async execute(toolName: string, rehydratedInput: unknown): Promise<unknown> {
    const args = (rehydratedInput ?? {}) as Record<string, unknown>;
    return this.caller(toolName, args);
  }
}
