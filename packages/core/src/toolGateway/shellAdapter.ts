/**
 * Shell adapter — the "agent mode" side. Input and output are both plain
 * strings (a command line in, stdout/stderr out), unlike MCP's JSON.
 *
 * This genuinely runs commands via child_process — it's real, not a stub.
 * What's NOT wired up is VS Code actually calling this for you: there's no
 * public API today to sit in front of Copilot agent mode's own shell
 * execution (same limitation noted in chatParticipant.ts from the start of
 * this project). This adapter is ready to use the moment you have a real
 * command to run through it — either standalone, or once such a hook
 * exists.
 */

import { exec } from "child_process";
import { ToolAdapter } from "./toolAdapter";

export interface ShellExecResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

export class ShellAdapter implements ToolAdapter {
  readonly type = "shell" as const;

  constructor(private timeoutMs: number = 15000) {}

  /** rehydratedInput is the full command line, e.g. "Get-User -Username rahul.sharma" (already rehydrated by the gateway before this is called). */
  async execute(_toolName: string, rehydratedInput: unknown): Promise<unknown> {
    const command = String(rehydratedInput);

    return new Promise<ShellExecResult>((resolve) => {
      exec(command, { timeout: this.timeoutMs }, (error, stdout, stderr) => {
        resolve({
          stdout: stdout ?? "",
          stderr: stderr ?? "",
          exitCode: error ? ((error as unknown as { code?: number }).code ?? null) : 0,
        });
      });
    });
  }
}
