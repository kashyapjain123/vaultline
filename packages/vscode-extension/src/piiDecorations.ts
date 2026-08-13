/**
 * In-editor visibility for detected sensitive values: highlighting, scrollbar
 * marks, hover detail, and a ghost-text hint on the line being typed.
 *
 * WHY THIS SCANS DIFFERENTLY FROM EVERYTHING ELSE: every other entry point
 * (the chat participant, the test-pipeline command) calls the engine's full
 * async pipeline, which routes through embedding similarity and therefore
 * makes HTTP calls to the MiniLM server. That is the right trade when a
 * message is about to leave the machine. It is the wrong trade on every
 * keystroke — typing latency would depend on model inference, and a large
 * file would hammer the server with one request per edit.
 *
 * So this layer uses every scanner that is SYNCHRONOUS and network-free —
 * which is all of them except two. The structural ones (`scan`,
 * `scanPiiStructural`, `scanInfraStructural`) catch fixed shapes: vendor API
 * keys, PEM blocks, JWTs, connection strings, emails, card numbers, IPs. The
 * contextual ones (`scanPiiContextual`, `scanInfraContextual`,
 * `scanProximity`) catch values identified by their surrounding words:
 * "customer id 4521", "host prod-db-01", "my password is …". All six are
 * plain regex and proximity work costing microseconds, so all six run here.
 *
 * Only two layers are left out, both because they require an embedding call:
 * whole-message business-content classification (which has no span to
 * highlight anyway — it is a judgment about the entire text) and semantic
 * keyword matching. Those still run, in full, at the boundary that actually
 * matters.
 *
 * NOTE the remaining asymmetry: the full pipeline additionally suppresses
 * low-precision rules inside COMMENTS via tree-sitter, which is async and so
 * is not applied here. Highlighting can therefore flag a value in a comment
 * that would not actually be redacted. Over-reporting in an affordance is the
 * acceptable direction of error; under-reporting is not.
 *
 * The cached match list is also what codeActions.ts reads, so the lightbulb
 * never re-scans.
 */

import {
  entityTypeFor,
  scan,
  scanInfraContextual,
  scanInfraStructural,
  scanPiiContextual,
  scanPiiStructural,
  scanProximity,
  splitNonBlankLines,
  type Match,
  type VaultlineSettings,
} from "@vaultline/core";
import * as vscode from "vscode";
import { VsCodeHost } from "./vscodeHost";

/** Long enough that a fast typist doesn't trigger a scan per character, short enough to feel immediate. */
const DEBOUNCE_MS = 300;

export class PiiDecorations implements vscode.Disposable {
  private readonly highlight: vscode.TextEditorDecorationType;
  private readonly ghost: vscode.TextEditorDecorationType;
  private readonly disposables: vscode.Disposable[] = [];
  /** Keyed by document URI. The single source of truth for both hover and the code-action provider. */
  private readonly matchesByUri = new Map<string, Match[]>();
  private readonly timers = new Map<string, NodeJS.Timeout>();

  constructor(private readonly host: VsCodeHost) {
    // Literal rgba rather than a ThemeColor: this needs to read as "flagged"
    // against both light and dark backgrounds, and the built-in theme colors
    // that come close (error/warning backgrounds) carry the wrong meaning —
    // a detected secret is not a problem with the code.
    this.highlight = vscode.window.createTextEditorDecorationType({
      backgroundColor: "rgba(255, 150, 0, 0.28)",
      borderRadius: "2px",
      overviewRulerColor: "rgba(255, 150, 0, 0.9)",
      overviewRulerLane: vscode.OverviewRulerLane.Right,
    });

    // Ghost text as a decoration's `after`, NOT an InlineCompletionItemProvider:
    // that API is a single shared slot, so registering one would fight Copilot
    // for it and one of the two would silently stop appearing.
    this.ghost = vscode.window.createTextEditorDecorationType({
      after: { color: new vscode.ThemeColor("editorGhostText.foreground"), margin: "0 0 0 1.5em" },
    });

    this.disposables.push(
      vscode.window.onDidChangeActiveTextEditor((editor) => editor && this.schedule(editor)),
      vscode.workspace.onDidChangeTextDocument((event) => {
        const editor = vscode.window.activeTextEditor;
        if (editor && event.document === editor.document) this.schedule(editor);
      }),
      // The cursor moving changes which line gets the ghost hint, but not the
      // matches — so this repaints without re-scanning.
      vscode.window.onDidChangeTextEditorSelection((event) => this.paint(event.textEditor)),
      vscode.workspace.onDidCloseTextDocument((document) => {
        this.matchesByUri.delete(document.uri.toString());
        this.clearTimer(document.uri.toString());
      }),
      vscode.languages.registerHoverProvider(
        [{ scheme: "file" }, { scheme: "untitled" }],
        { provideHover: (document, position) => this.hover(document, position) }
      )
    );

    for (const editor of vscode.window.visibleTextEditors) this.schedule(editor);
  }

  /** Matches currently known for a document — read by codeActions.ts rather than re-scanning. */
  matchesFor(uri: vscode.Uri): Match[] {
    return this.matchesByUri.get(uri.toString()) ?? [];
  }

  /** The match containing a document offset, if any. */
  matchAt(document: vscode.TextDocument, position: vscode.Position): Match | undefined {
    const offset = document.offsetAt(position);
    return this.matchesFor(document.uri).find((m) => offset >= m.start && offset < m.end);
  }

  /** Re-scan and repaint after the debounce interval, coalescing bursts of edits. */
  private schedule(editor: vscode.TextEditor): void {
    const key = editor.document.uri.toString();
    this.clearTimer(key);
    this.timers.set(
      key,
      setTimeout(() => {
        this.timers.delete(key);
        this.rescan(editor);
      }, DEBOUNCE_MS)
    );
  }

  private clearTimer(key: string): void {
    const existing = this.timers.get(key);
    if (existing) {
      clearTimeout(existing);
      this.timers.delete(key);
    }
  }

  private rescan(editor: vscode.TextEditor): void {
    const settings = this.host.settings();
    const config = vscode.workspace.getConfiguration("vaultline");
    const text = editor.document.getText();

    const enabled = config.get<boolean>("highlightDetectedPii", true);
    const maxLength = config.get<number>("highlightMaxFileLength", 100000);

    // Above the cap, scanning every edit costs more than the feature is worth.
    // Bail loudly in the cache (empty = "nothing known here"), so the code
    // action provider doesn't offer to anonymize based on stale matches.
    if (!enabled || text.length > maxLength) {
      this.matchesByUri.set(editor.document.uri.toString(), []);
      this.paint(editor);
      return;
    }

    this.matchesByUri.set(editor.document.uri.toString(), collectStructural(text, settings));
    this.paint(editor);
  }

  private paint(editor: vscode.TextEditor): void {
    const matches = this.matchesFor(editor.document.uri);
    const document = editor.document;

    editor.setDecorations(
      this.highlight,
      matches.map((m) => new vscode.Range(document.positionAt(m.start), document.positionAt(m.end)))
    );

    const showGhost = vscode.workspace.getConfiguration("vaultline").get<boolean>("inlineWarnings", true);
    if (!showGhost || matches.length === 0) {
      editor.setDecorations(this.ghost, []);
      return;
    }

    // One hint, on the cursor's line only — a hint per flagged line would be
    // noise in a file that legitimately holds many credentials (a .env, a
    // fixture), which is exactly the kind of file this fires on most.
    const cursorLine = editor.selection.active.line;
    const onLine = matches.filter((m) => document.positionAt(m.start).line === cursorLine);
    if (onLine.length === 0) {
      editor.setDecorations(this.ghost, []);
      return;
    }

    const labels = [...new Set(onLine.map((m) => entityTypeFor(m)))].join(", ");
    const lineEnd = document.lineAt(cursorLine).range.end;
    editor.setDecorations(this.ghost, [
      {
        range: new vscode.Range(lineEnd, lineEnd),
        renderOptions: {
          after: {
            contentText: `⚠ Vaultline: ${labels} on this line — redacted before it reaches a model`,
          },
        },
      },
    ]);
  }

  private hover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | undefined {
    const match = this.matchAt(document, position);
    if (!match) return undefined;

    // Severity, not a confidence percentage: Match carries a severity band and
    // a rule id, and there is no numeric confidence anywhere in the pipeline.
    // Rendering an invented number next to a security decision would be worse
    // than rendering none.
    const markdown = new vscode.MarkdownString();
    markdown.appendMarkdown(`**Vaultline — ${entityTypeFor(match)}**\n\n`);
    markdown.appendMarkdown(`${match.label}\n\n`);
    markdown.appendMarkdown(`Severity: \`${match.severity}\` · Category: \`${match.category}\` · Rule: \`${match.ruleId}\``);
    return new vscode.Hover(markdown, new vscode.Range(document.positionAt(match.start), document.positionAt(match.end)));
  }

  dispose(): void {
    for (const timer of this.timers.values()) clearTimeout(timer);
    this.timers.clear();
    this.highlight.dispose();
    this.ghost.dispose();
    for (const disposable of this.disposables) disposable.dispose();
  }
}

/**
 * Every synchronous scanner in the pipeline, with the user's disabled-rule and
 * layer toggles applied.
 *
 * The contextual scanners are run UNCONDITIONALLY here, where the full
 * pipeline gates them behind an embedding-similarity score. That is
 * deliberate: the gate exists to save work, its threshold is deliberately
 * generous (0.15, where almost everything qualifies), and the pipeline itself
 * falls open to running all of them whenever routing is unavailable. Running
 * them all matches that fail-open behaviour without needing the network.
 *
 * Filtering afterwards rather than passing options down: these scanners take
 * no options, and reproducing the pipeline's gating here would mean a second
 * implementation of it that could drift. One filter over the results keeps
 * rule-disabling identical to what detectionPipeline.ts does.
 */
function collectStructural(text: string, settings: VaultlineSettings): Match[] {
  // STRUCTURAL over the whole text: these rules match fixed shapes, and some
  // of them span lines — a PEM block is BEGIN…END across many lines, and
  // scanning line-by-line would shred it.
  const matches: Match[] = [...scan(text)];
  if (settings.enablePiiDetection) matches.push(...scanPiiStructural(text));
  if (settings.enableInfraDetection) matches.push(...scanInfraStructural(text));

  // CONTEXTUAL per line, exactly as scanCurrentMessage does it. These rules
  // pair a keyword with a nearby value, and "nearby" has to stop at the line
  // break: run over a whole document, the `pwrd` keyword on one line happily
  // claims a hostname from the line above, which both misses the real secret
  // and mislabels something innocent as a password.
  for (const line of splitNonBlankLines(text)) {
    const found: Match[] = [];
    if (settings.enablePiiDetection) found.push(...scanPiiContextual(line.text));
    if (settings.enableInfraDetection) found.push(...scanInfraContextual(line.text));
    if (settings.enableConversationalSecretDetection) found.push(...scanProximity(line.text));
    // Line-relative spans back to document coordinates.
    for (const match of found) {
      matches.push({ ...match, start: match.start + line.start, end: match.end + line.start });
    }
  }

  const disabled = new Set<string>([
    ...settings.disabledSecretRules,
    ...settings.disabledPiiRules,
    ...settings.disabledInfraRules,
    ...settings.disabledConversationalSecretRules,
  ]);

  return matches
    .filter((m) => !disabled.has(m.ruleId))
    .sort((a, b) => a.start - b.start)
    // Two rules can claim overlapping spans; a decoration range per claim
    // would double-paint the overlap and make the highlight look corrupted.
    .filter((m, i, all) => i === 0 || m.start >= all[i - 1].end);
}
