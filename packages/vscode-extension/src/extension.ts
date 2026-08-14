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
import * as fs from "fs";
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

  // OPT-IN, and off by default. This mapping file holds every secret the
  // session catches next to its token, in plain text — the same thing
  // auditLogIncludeValues refuses to do unless asked. It used to be written
  // unconditionally, which meant a tool built to keep secrets off the wire was
  // quietly accumulating them on disk instead.
  //
  // Nothing is lost by defaulting it off: the session id below is fresh on
  // every activation, so the file was never read back — it only ever grew.
  const sessionsDir = path.join(context.globalStorageUri.fsPath, "sessions");
  const persistMappings = host.settings().persistSessionMappings;
  const entityStorePersistPath = persistMappings
    ? path.join(sessionsDir, `${crypto.randomUUID()}.json`)
    : undefined;

  if (persistMappings) {
    void vscode.window.showWarningMessage(
      "Vaultline: vaultline.persistSessionMappings is ON — every detected value is being written to disk in plain text."
    );
  }

  // Remove what previous versions left behind, whether or not it is on now.
  // Existing installs are carrying real secrets from every past conversation,
  // and a user who never asked for that should not have to discover it in
  // order to be rid of it.
  void purgeOldSessionMappings(sessionsDir, host);

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

  // Command: force a centroid rebuild against the configured endpoint.
  //
  // The automatic rebuild keys off embeddingApiUrl + embeddingApiModel, so it
  // cannot notice the same URL quietly starting to serve a DIFFERENT model —
  // nothing observable changes and the cached centroids stay in use, scoring
  // against a vector space that no longer exists. This is the escape hatch.
  const rebuildEmbeddingsCmd = vscode.commands.registerCommand("vaultline.rebuildCategoryEmbeddings", async () => {
    engine.showEmbeddingServerLog();
    const rebuilt = await engine.rebuildCategoryEmbeddings();
    if (rebuilt) {
      void vscode.window.showInformationMessage(
        "Vaultline: category embeddings rebuilt against your endpoint — routing is using them now."
      );
    }
    // The "nothing to rebuild" and failure cases already explain themselves,
    // via engine.rebuildCategoryEmbeddings() and the server log respectively.
  });

  // Commands: keep the embedding API credential in the OS keychain rather than
  // in settings.json. A setting is plain text, visible in the settings UI,
  // copied to every machine by Settings Sync, and committed to the repo if set
  // at workspace level — none of which is acceptable for a bearer token, least
  // of all from a tool arguing that credentials shouldn't travel.
  const setTokenCmd = vscode.commands.registerCommand("vaultline.setEmbeddingApiToken", async () => {
    const token = await vscode.window.showInputBox({
      prompt: "Embedding API token — stored in your OS keychain, not in settings.json",
      password: true,
      ignoreFocusOut: true,
    });
    if (token === undefined) return; // dismissed
    if (token.trim().length === 0) {
      void vscode.window.showWarningMessage("Vaultline: no token entered — nothing was stored.");
      return;
    }
    await engine.setAuthToken(token.trim());
    void vscode.window.showInformationMessage("Vaultline: embedding API token saved to your OS keychain.");
  });

  const clearTokenCmd = vscode.commands.registerCommand("vaultline.clearEmbeddingApiToken", async () => {
    await engine.clearAuthToken();
    void vscode.window.showInformationMessage("Vaultline: embedding API token removed from your OS keychain.");
  });

  void offerTokenMigration(context, engine);

  context.subscriptions.push(
    testPipelineCmd,
    showAuditLogCmd,
    restartServerCmd,
    rebuildEmbeddingsCmd,
    setTokenCmd,
    clearTokenCmd
  );
}

export function deactivate() {}

/**
 * Delete session mapping files left by earlier versions (and by earlier runs
 * when the setting is on).
 *
 * Every one of these is a plaintext record of the secrets caught during a past
 * conversation. Before 1.3.0 they were written unconditionally and never
 * removed, so an install that has been in use for a while is sitting on a pile
 * of them.
 *
 * A day's grace rather than deleting outright: if the setting IS on, someone is
 * using these for debugging and shouldn't have today's work swept away
 * mid-session. Best-effort throughout — failing to tidy up must never stop the
 * extension from activating.
 */
async function purgeOldSessionMappings(sessionsDir: string, host: VsCodeHost): Promise<void> {
  const DAY_MS = 24 * 60 * 60 * 1000;
  try {
    const entries = await fs.promises.readdir(sessionsDir).catch(() => [] as string[]);
    let removed = 0;
    for (const name of entries) {
      if (!name.endsWith(".json")) continue;
      const full = path.join(sessionsDir, name);
      try {
        const stat = await fs.promises.stat(full);
        if (Date.now() - stat.mtimeMs < DAY_MS) continue;
        await fs.promises.rm(full, { force: true });
        removed++;
      } catch {
        // A file we can't stat or remove is one we leave alone.
      }
    }
    if (removed > 0) {
      const log = host.createLogChannel("Vaultline");
      log.append(
        `Removed ${removed} old session mapping file(s) from ${sessionsDir}. These held detected values in plain ` +
          "text; they are no longer written unless vaultline.persistSessionMappings is enabled."
      );
    }
  } catch {
    // Best effort only.
  }
}

/**
 * Offer to move a token out of settings.json and into the keychain.
 *
 * ASKS FIRST, deliberately. 1.2.6 declined to write `embeddingApiUrl` back
 * after port selection, on the grounds that a setting is the user's stated
 * preference and overwriting it turns a transient condition into permanent
 * config. The distinction here is that the setting's continued existence IS
 * the problem — but that still doesn't make it ours to silently delete, so the
 * user confirms and can decline and keep working exactly as before.
 */
async function offerTokenMigration(context: vscode.ExtensionContext, engine: VaultlineEngine): Promise<void> {
  const config = vscode.workspace.getConfiguration("vaultline");
  const inSettings = (config.get<string>("embeddingApiAuthToken") ?? "").trim();
  if (inSettings.length === 0) return;

  const MOVE = "Move to keychain";
  const choice = await vscode.window.showWarningMessage(
    "Vaultline: your embedding API token is stored in settings.json in plain text, where Settings Sync will copy it " +
      "to your other machines. Move it to your OS keychain?",
    MOVE,
    "Not now"
  );
  if (choice !== MOVE) return;

  try {
    await engine.setAuthToken(inSettings);
    // Clear every scope that actually holds a value — a workspace-level token
    // is the worst case of all, since that one gets committed.
    const inspected = config.inspect<string>("embeddingApiAuthToken");
    if (inspected?.globalValue) {
      await config.update("embeddingApiAuthToken", undefined, vscode.ConfigurationTarget.Global);
    }
    if (inspected?.workspaceValue) {
      await config.update("embeddingApiAuthToken", undefined, vscode.ConfigurationTarget.Workspace);
    }
    void vscode.window.showInformationMessage(
      "Vaultline: token moved to your OS keychain and removed from settings.json."
    );
  } catch (err) {
    void vscode.window.showErrorMessage(`Vaultline: could not move the token (${err}). It is unchanged in settings.json.`);
  }
}
