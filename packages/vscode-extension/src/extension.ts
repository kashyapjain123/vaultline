/**
 * VS Code activation.
 *
 * This file used to be ~340 lines of embedder construction, centroid
 * loading, backend-fallback logic and settings plumbing. All of that was
 * editor-agnostic and now lives in @vaultline/core's VaultlineEngine, so what
 * remains here is only what VS Code genuinely requires: implement the host,
 * create the engine, register the chat participant, and wire three commands
 * to engine methods.
 *
 * That shrinkage is the point of the split. Anything that grows back into
 * this file should be looked at twice — if it isn't about VS Code's API
 * specifically, it belongs in the core, where a second editor integration
 * gets it for free.
 */

import { VaultlineEngine } from "@vaultline/core";
import * as crypto from "crypto";
import * as path from "path";
import * as vscode from "vscode";
import { AnonymizeCommands } from "./anonymizeCommands";
import { registerVaultlineParticipant } from "./chatParticipant";
import { AnonymizeCodeActions } from "./codeActions";
import { PiiDecorations } from "./piiDecorations";
import { VsCodeHost } from "./vscodeHost";

export function activate(context: vscode.ExtensionContext) {
  const host = new VsCodeHost(context);
  const engine = VaultlineEngine.create(host);
  context.subscriptions.push({ dispose: () => engine.dispose() }, { dispose: () => host.dispose() });

  // One JSON mapping file per activation (= per chat participant session,
  // see chatParticipant.ts) — a durable, on-disk mirror of the in-memory
  // EntityStore for this session, living alongside the audit log.
  const sessionId = crypto.randomUUID();
  const entityStorePersistPath = path.join(context.globalStorageUri.fsPath, "sessions", `${sessionId}.json`);

  registerVaultlineParticipant(context, engine, host, entityStorePersistPath);

  // The in-editor layer: highlighting + hover + ghost text, the lightbulb that
  // reads their cached matches, and the commands that actually rewrite a
  // document. All three are VS Code-API-shaped, which is why they live here
  // and not in the core.
  const decorations = new PiiDecorations(host);
  context.subscriptions.push(
    decorations,
    vscode.languages.registerCodeActionsProvider(
      [{ scheme: "file" }, { scheme: "untitled" }],
      new AnonymizeCodeActions(decorations),
      AnonymizeCodeActions.metadata
    ),
    ...new AnonymizeCommands(context, engine).register()
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      const outcome = engine.settingsChanged((setting) => event.affectsConfiguration(`vaultline.${setting}`));
      if (outcome === "reload-required") {
        void vscode.window
          .showInformationMessage("Vaultline: reload the window to apply the embedding backend change.", "Reload Window")
          .then((choice) => {
            if (choice === "Reload Window") void vscode.commands.executeCommand("workbench.action.reloadWindow");
          });
      }
    })
  );

  // Command: run the detection pipeline on the current editor selection,
  // without sending anything anywhere. Useful for demoing/tuning rules.
  const testPipelineCmd = vscode.commands.registerCommand("vaultline.testPipeline", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      void vscode.window.showWarningMessage("Vaultline: open a file and select some text first.");
      return;
    }

    const text = editor.document.getText(editor.selection);
    if (!text) {
      void vscode.window.showWarningMessage("Vaultline: no text selected.");
      return;
    }

    // The selection came from a real editor, so we know its language —
    // comment-aware suppression applies here too.
    const report = await engine.inspect(text, editor.document.languageId);

    const panel = vscode.window.createOutputChannel("Vaultline");
    panel.clear();
    panel.appendLine(`Action: ${report.decision.action}`);
    panel.appendLine(`Reason: ${report.decision.reason}`);
    panel.appendLine("");
    panel.appendLine("--- Matches ---");
    if (report.matches.length === 0 && report.businessMatches.length === 0) {
      panel.appendLine("(none)");
    } else {
      for (const m of report.matches) {
        panel.appendLine(`[${m.category}] [${m.severity.toUpperCase()}] ${m.label} — "${m.value}"`);
      }
      for (const m of report.businessMatches) {
        panel.appendLine(`[${m.category}] [${m.severity.toUpperCase()}] ${m.label}`);
      }
    }
    panel.appendLine("");
    panel.appendLine("--- Redacted text that would be sent (n/a if blocked above) ---");
    panel.appendLine(report.redactedText);
    panel.show();
  });

  // Command: dump the audit log to an output channel — same level of
  // per-match detail as "Vaultline: Test Detection Pipeline on Selection",
  // plus the source tag (prompt / tool:<name> / history / testPipelineCommand)
  // so it's clear WHERE each entry came from.
  const showAuditLogCmd = vscode.commands.registerCommand("vaultline.showAuditLog", () => {
    const entries = engine.auditLog.readAll();
    const includeValues = host.settings().auditLogIncludeValues;
    const panel = vscode.window.createOutputChannel("Vaultline Audit Log");
    panel.clear();
    if (includeValues) {
      panel.appendLine("⚠️  vaultline.auditLogIncludeValues is ON — real sensitive values appear below in plain text.\n");
    }
    if (entries.length === 0) {
      panel.appendLine("No audit entries yet.");
    } else {
      panel.appendLine(`${entries.length} entries, most recent last.\n`);
      for (const entry of entries) {
        panel.appendLine(`[${entry.timestamp}] [${entry.source}] ${entry.action.toUpperCase()}`);
        panel.appendLine(`  ${entry.reason}`);
        for (const m of entry.matchSummary) {
          const tokenPart = m.token ? ` -> ${m.token}` : "";
          const valuePart = m.value !== undefined ? ` = "${m.value}"` : "";
          panel.appendLine(`    - [${m.category}] [${m.severity.toUpperCase()}] ${m.label} (${m.ruleId})${tokenPart}${valuePart}`);
        }
        panel.appendLine("");
      }
    }
    panel.appendLine(`Log file: ${engine.auditLog.getFilePath()}`);
    panel.show();
  });

  // Command: recover from a server that died, was killed by another window
  // closing, or was started before a settings change that should apply to it.
  const restartServerCmd = vscode.commands.registerCommand("vaultline.restartEmbeddingServer", async () => {
    engine.showEmbeddingServerLog();
    const ready = await engine.restartEmbeddingServer();
    void vscode.window.showInformationMessage(
      ready
        ? "Vaultline: embedding server is ready — routing is using MiniLM."
        : "Vaultline: embedding server unavailable — routing fell back to the built-in hashing embedder."
    );
  });

  context.subscriptions.push(testPipelineCmd, showAuditLogCmd, restartServerCmd);
}

export function deactivate() {}
