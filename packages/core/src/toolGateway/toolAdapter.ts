export type ToolType = "shell" | "mcp" | "api";

/**
 * What a specific tool type knows how to do: given a rehydrated
 * (real-values-restored) input, run it and return the raw output. The
 * gateway (toolGateway.ts) never talks to a shell or an MCP server
 * directly — only to this interface. That's what keeps redact/rehydrate
 * logic centralized instead of duplicated per tool type.
 */
export interface ToolAdapter {
  readonly type: ToolType;
  execute(toolName: string, rehydratedInput: unknown): Promise<unknown>;
}
