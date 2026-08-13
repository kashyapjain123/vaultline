/**
 * The lightbulb: "Anonymize this" on a detected value.
 *
 * Deliberately NOT backed by a DiagnosticCollection. Diagnostics are the usual
 * way to drive code actions, but they also put squiggles under every match and
 * fill the Problems panel — and the files this fires on most are exactly the
 * ones where that is wrong: a .env, a fixture, a config sample. Those aren't
 * problems with the code, and burying real compiler errors under a hundred
 * "detected an email address" entries would make the extension something you
 * turn off.
 *
 * Reads the match list piiDecorations.ts already computed rather than
 * re-scanning, so opening the lightbulb menu costs nothing.
 */

import { entityTypeFor } from "@vaultline/core";
import * as vscode from "vscode";
import { PiiDecorations } from "./piiDecorations";

export class AnonymizeCodeActions implements vscode.CodeActionProvider {
  static readonly metadata: vscode.CodeActionProviderMetadata = {
    providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
  };

  constructor(private readonly decorations: PiiDecorations) {}

  provideCodeActions(document: vscode.TextDocument, range: vscode.Range | vscode.Selection): vscode.CodeAction[] {
    const matches = this.decorations.matchesFor(document.uri);
    if (matches.length === 0) return [];

    const start = document.offsetAt(range.start);
    const end = document.offsetAt(range.end);

    // A cursor (empty range) counts as touching the match it sits inside;
    // a selection counts as touching everything it overlaps.
    const touched = matches.filter((m) => (start === end ? start >= m.start && start < m.end : start < m.end && end > m.start));
    if (touched.length === 0) return [];

    const actions: vscode.CodeAction[] = [];

    // Single value under the cursor: name it, so the menu says what will
    // happen rather than making the user guess which value it means.
    if (touched.length === 1) {
      const match = touched[0];
      const action = new vscode.CodeAction(
        `Anonymize this ${entityTypeFor(match)}`,
        vscode.CodeActionKind.QuickFix
      );
      action.command = {
        command: "vaultline.anonymizeSelection",
        title: "Anonymize this",
        arguments: [new vscode.Range(document.positionAt(match.start), document.positionAt(match.end))],
      };
      actions.push(action);
    } else {
      const action = new vscode.CodeAction(
        `Anonymize ${touched.length} values in selection`,
        vscode.CodeActionKind.QuickFix
      );
      action.command = {
        command: "vaultline.anonymizeSelection",
        title: "Anonymize selection",
        arguments: [new vscode.Range(range.start, range.end)],
      };
      actions.push(action);
    }

    const all = new vscode.CodeAction("Anonymize all values in this file", vscode.CodeActionKind.QuickFix);
    all.command = { command: "vaultline.anonymizeDocument", title: "Anonymize document" };
    actions.push(all);

    return actions;
  }
}
