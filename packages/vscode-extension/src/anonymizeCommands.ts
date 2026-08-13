/**
 * Anonymize and restore sensitive values directly in a document.
 *
 * Unlike the highlighting layer (piiDecorations.ts), these are explicit,
 * user-initiated actions, so they run the engine's FULL async pipeline — the
 * contextual, conversational and embedding-routed layers included. A one-off
 * wait of a few hundred milliseconds is a fine price for catching "my password
 * is hunter2", which no structural scanner can see.
 *
 * THE THREE MODES ARE NOT EQUIVALENT, and the difference is not cosmetic:
 *
 *   placeholder  <<EMAIL_1>>            reversible — the token identifies which entity it replaced
 *   hash         [EMAIL_a1b2c3d4]       reversible — the digest is stable and unique per value
 *   mask         ***                    NOT reversible — every masked value looks identical
 *
 * Mask is offered because it is what you want when the point is to strip a
 * value permanently before sharing a file. But a "restore" that silently
 * turned every `***` into whichever value happened to be first in the mapping
 * would corrupt the document, so mask writes no mapping at all and restore
 * refuses rather than guesses.
 *
 * WHY NOT EntityStore: it is the right class conceptually and is reused for
 * chat, but it mints exactly one token format (`<<TYPE_N>>`) and exposes no
 * way to record a different replacement string, which hash and mask both
 * need. DocumentMappings below persists the core's own EntityMapping shape so
 * the core's `restore()` still does the actual work.
 */

import { entityTypeFor, restore, type EntityMapping, type Match, type VaultlineEngine } from "@vaultline/core";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

export type AnonymizeMode = "placeholder" | "mask" | "hash";

export class AnonymizeCommands {
  private readonly mappingsDir: string;

  constructor(
    context: vscode.ExtensionContext,
    private readonly engine: VaultlineEngine
  ) {
    // Separate from the chat participant's per-activation session file
    // (extension.ts). Sharing one store would put chat tokens and document
    // tokens in the same numbering space, and a document's mapping would be
    // orphaned the moment the window closed.
    this.mappingsDir = path.join(context.globalStorageUri.fsPath, "documents");
  }

  register(): vscode.Disposable[] {
    return [
      vscode.commands.registerCommand("vaultline.anonymizeSelection", (range?: vscode.Range) =>
        this.anonymize(range)
      ),
      vscode.commands.registerCommand("vaultline.anonymizeDocument", () => this.anonymize(undefined, true)),
      vscode.commands.registerCommand("vaultline.restoreDocument", () => this.restoreDocument()),
    ];
  }

  /**
   * `range` comes from the code action; otherwise the current selection is
   * used, falling back to the whole document when nothing is selected (or
   * when `wholeDocument` forces it).
   */
  private async anonymize(range?: vscode.Range, wholeDocument = false): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      void vscode.window.showWarningMessage("Vaultline: open a file first.");
      return;
    }

    const target =
      wholeDocument || (!range && editor.selection.isEmpty)
        ? new vscode.Range(editor.document.positionAt(0), editor.document.positionAt(editor.document.getText().length))
        : range ?? editor.selection;

    if (editor.document.getText(target).length === 0) {
      void vscode.window.showWarningMessage("Vaultline: nothing to anonymize.");
      return;
    }

    const mode = vscode.workspace.getConfiguration("vaultline").get<AnonymizeMode>("anonymizeMode", "placeholder");
    if (mode === "mask" && !(await confirmMask())) return;

    // Scan the WHOLE LINES the target spans, then keep only the matches that
    // actually overlap the target. Scanning the bare selection would strip the
    // context the contextual rules depend on: selecting just the digits in
    // `phone: 9876543210` leaves a naked number that contextual-phone cannot
    // recognise, so the value would be silently left in the document. The
    // replacement is still confined to the target — the surrounding text is
    // read, never rewritten.
    const contextRange = new vscode.Range(
      editor.document.lineAt(target.start.line).range.start,
      editor.document.lineAt(target.end.line).range.end
    );
    const contextText = editor.document.getText(contextRange);
    const contextBase = editor.document.offsetAt(contextRange.start);
    const targetStart = editor.document.offsetAt(target.start) - contextBase;
    const targetEnd = editor.document.offsetAt(target.end) - contextBase;

    const report = await this.engine.inspect(contextText, editor.document.languageId);
    const matches = dedupe(report.matches).filter((m) => m.start < targetEnd && m.end > targetStart);
    if (matches.length === 0) {
      void vscode.window.showInformationMessage("Vaultline: no sensitive values found in that range.");
      return;
    }

    const store = new DocumentMappings(this.mappingFile(editor.document.uri));

    const edit = new vscode.WorkspaceEdit();
    for (const match of matches) {
      const replacement = store.replacementFor(match, mode);
      edit.replace(
        editor.document.uri,
        new vscode.Range(
          editor.document.positionAt(contextBase + match.start),
          editor.document.positionAt(contextBase + match.end)
        ),
        replacement
      );
    }

    if (!(await vscode.workspace.applyEdit(edit))) {
      void vscode.window.showErrorMessage("Vaultline: could not apply the anonymization edit.");
      return;
    }

    if (mode !== "mask") store.save();

    void vscode.window.showInformationMessage(
      mode === "mask"
        ? `Vaultline: masked ${matches.length} value(s). This cannot be undone.`
        : `Vaultline: anonymized ${matches.length} value(s). Use "Vaultline: Restore Document" to reverse it.`
    );
  }

  private async restoreDocument(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      void vscode.window.showWarningMessage("Vaultline: open a file first.");
      return;
    }

    const mappings = DocumentMappings.load(this.mappingFile(editor.document.uri));
    if (mappings.length === 0) {
      void vscode.window.showWarningMessage(
        "Vaultline: no saved mapping for this file. Values anonymized in 'mask' mode cannot be restored — masking is one-way by design."
      );
      return;
    }

    const original = editor.document.getText();
    const restored = restore(original, mappings);
    if (restored === original) {
      void vscode.window.showInformationMessage("Vaultline: nothing to restore — no known tokens found in this file.");
      return;
    }

    const edit = new vscode.WorkspaceEdit();
    edit.replace(
      editor.document.uri,
      new vscode.Range(editor.document.positionAt(0), editor.document.positionAt(original.length)),
      restored
    );

    if (await vscode.workspace.applyEdit(edit)) {
      void vscode.window.showInformationMessage(`Vaultline: restored ${mappings.length} value(s).`);
    } else {
      void vscode.window.showErrorMessage("Vaultline: could not apply the restore edit.");
    }
  }

  /** One mapping file per document, named by a digest of its URI so paths with any characters are safe as filenames. */
  private mappingFile(uri: vscode.Uri): string {
    const key = crypto.createHash("sha1").update(uri.toString()).digest("hex");
    return path.join(this.mappingsDir, `${key}.json`);
  }
}

/**
 * Per-document token mint and mapping file. Persists `EntityMapping[]` — the
 * core's own interface — so `restore()` consumes it directly.
 */
class DocumentMappings {
  private readonly mappings: EntityMapping[];
  private readonly counters = new Map<string, number>();
  /** Same value twice in a document gets the same token, so restore is unambiguous either way. */
  private readonly byValue = new Map<string, string>();

  constructor(private readonly filePath: string) {
    this.mappings = DocumentMappings.load(filePath);
    for (const mapping of this.mappings) {
      this.byValue.set(`${mapping.entityType}:${mapping.originalValue}`, mapping.token);
      const counter = /_(\d+)>>$/.exec(mapping.token);
      if (counter) {
        const current = this.counters.get(mapping.entityType) ?? 0;
        this.counters.set(mapping.entityType, Math.max(current, Number(counter[1])));
      }
    }
  }

  static load(filePath: string): EntityMapping[] {
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, "utf-8"));
      return Array.isArray(parsed) ? (parsed as EntityMapping[]) : [];
    } catch {
      // No mapping file, or an unreadable one — either way there is nothing
      // to restore from, which callers report rather than throwing over.
      return [];
    }
  }

  replacementFor(match: Match, mode: AnonymizeMode): string {
    const entityType = entityTypeFor(match);
    if (mode === "mask") return "***";

    const key = `${entityType}:${match.value}`;
    const existing = this.byValue.get(key);
    if (existing) return existing;

    const token =
      mode === "hash"
        ? `[${entityType}_${crypto.createHash("sha256").update(match.value).digest("hex").slice(0, 8)}]`
        : `<<${entityType}_${(this.counters.get(entityType) ?? 0) + 1}>>`;

    if (mode === "placeholder") this.counters.set(entityType, (this.counters.get(entityType) ?? 0) + 1);
    this.byValue.set(key, token);
    this.mappings.push({
      token,
      originalValue: match.value,
      entityType,
      category: match.category,
      severity: match.severity,
      ruleId: match.ruleId,
      label: match.label,
    });
    return token;
  }

  save(): void {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      fs.writeFileSync(this.filePath, JSON.stringify(this.mappings, null, 2), "utf-8");
    } catch (err) {
      void vscode.window.showErrorMessage(
        `Vaultline: anonymized the document but could not save its mapping (${err}) — restore will not work for this file.`
      );
    }
  }
}

async function confirmMask(): Promise<boolean> {
  const choice = await vscode.window.showWarningMessage(
    "Masking replaces every value with *** and cannot be undone — no mapping is saved. Continue?",
    { modal: true },
    "Mask anyway"
  );
  return choice === "Mask anyway";
}

/** Overlapping matches would produce overlapping edits, which applyEdit rejects outright. */
function dedupe(matches: Match[]): Match[] {
  return [...matches]
    .sort((a, b) => a.start - b.start)
    .filter((m, i, all) => i === 0 || m.start >= all[i - 1].end);
}
