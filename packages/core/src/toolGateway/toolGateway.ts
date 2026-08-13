/**
 * Tool Gateway — the single entry point for "run a tool without leaking
 * redacted values into it, and without leaking real values back out of its
 * output." Agent-mode shell commands and MCP JSON calls are the same shape
 * at this level: rehydrate → execute → redact. Only the ADAPTER differs
 * (see toolAdapter.ts) — this class never branches on tool type itself.
 *
 * One EntityStore per session, passed in — see entityStore.ts. That's what
 * makes rehydration correct across multiple tool calls in a loop: a token
 * minted from a chat message earlier in the session rehydrates correctly
 * here, and any NEW sensitive values this tool's own output contains get
 * added to that same store, available for the next step.
 *
 * STATUS: nothing currently constructs this class. The live tool path is
 * chatParticipant.ts, which drives vscode.lm.invokeTool directly and shares
 * this directory's jsonRedactor.ts. This class is the entry point for the
 * OTHER case its module comment describes — a separate MCP client or shell
 * runner that bypasses vscode.lm.tools. It's kept in sync with the live path
 * deliberately, so wiring it up later doesn't silently reintroduce bugs
 * already fixed over there.
 */

import { ToolAdapter } from "./toolAdapter";
import { EntityStore } from "../entityStore";
import { redactJson, rehydrateJson } from "./jsonRedactor";
import { restore } from "../tokenizer";
import { scanCurrentMessage, ScanOptions } from "../detectionPipeline";
import { tokenize } from "../tokenizer";

export interface ToolExecutionResult {
  /** The tool's raw output, with any sensitive values found in it now redacted — this is what should go back to the LLM. */
  redactedOutput: unknown;
  /** How many new tokens were minted from this tool's output (0 if it contained nothing sensitive). */
  newTokensFromOutput: number;
}

export class ToolGateway {
  constructor(private store: EntityStore, private scanOptions: ScanOptions = {}) {}

  /**
   * input: for a shell adapter, a command-line string (may contain
   * <<TOKEN>> placeholders). For an MCP adapter, an arguments object (its
   * string values may contain <<TOKEN>> placeholders).
   */
  async executeTool(toolName: string, input: unknown, adapter: ToolAdapter): Promise<ToolExecutionResult> {
    // 1. Rehydrate — restore real values before the tool ever sees the input.
    const rehydratedInput =
      adapter.type === "mcp" ? rehydrateJson(input, this.store) : restore(String(input), this.store.allMappings());

    // 2. Execute.
    const rawOutput = await adapter.execute(toolName, rehydratedInput);

    // 3. Redact the raw output before it goes anywhere near the LLM.
    if (adapter.type === "mcp") {
      const { redacted, mappings } = await redactJson(rawOutput, this.store, this.scanOptions);
      return { redactedOutput: redacted, newTokensFromOutput: mappings.length };
    }

    // Shell adapter: output is a { stdout, stderr, exitCode } object with
    // two string fields worth scanning — same field-level idea as JSON,
    // just for this specific known shape rather than an arbitrary tree.
    // scanCurrentMessage, not scanAll: terminal output is multi-line by
    // definition, and a single pooled embedding over the whole blob dilutes
    // any one sensitive line's routing signal into the surrounding noise —
    // the same bug jsonRedactor.ts already documents for tool results.
    const shellOutput = rawOutput as { stdout: string; stderr: string; exitCode: number | null };
    const { matches: stdoutMatches } = await scanCurrentMessage(shellOutput.stdout, this.scanOptions);
    const { matches: stderrMatches } = await scanCurrentMessage(shellOutput.stderr, this.scanOptions);
    const stdoutResult = tokenize(shellOutput.stdout, stdoutMatches, this.store);
    const stderrResult = tokenize(shellOutput.stderr, stderrMatches, this.store);

    return {
      redactedOutput: {
        stdout: stdoutResult.redactedText,
        stderr: stderrResult.redactedText,
        exitCode: shellOutput.exitCode,
      },
      newTokensFromOutput: stdoutResult.mappings.length + stderrResult.mappings.length,
    };
  }
}
