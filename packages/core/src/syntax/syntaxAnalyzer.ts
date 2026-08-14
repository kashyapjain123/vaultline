/**
 * Syntax-aware suppression (tree-sitter).
 *
 * WHY THIS EXISTS
 *
 * Every other layer in this pipeline reads text as a flat character stream.
 * That is the right model for chat prose, and the wrong one for source code,
 * where the SAME characters mean completely different things depending on
 * where they sit. The failure this fixes was observed, not theorized: asked
 * to find bugs in this repo, a model read a file whose doc comment had been
 * redacted, and reported the resulting hole as its top finding — a
 * "corrupted comment" that never existed. A false positive there does not
 * merely add noise; it corrupts the model's picture of the code and makes it
 * do wrong work.
 *
 * Comments are where that class of false positive lives, because a comment
 * is prose ABOUT code: it names credentials, shows example values, documents
 * regexes. Detecting that a span is a comment needs a real parser — a regex
 * "comment stripper" trips over `"http://x"` (a string, not a comment) and
 * over `//` inside string literals.
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 *
 * It does NOT suppress everything found in a comment. A commented-out
 * credential is a completely normal way to leak one, and `AKIA…` inside a
 * `//` line is still a live AWS key. Only the LOW-PRECISION, contextual
 * rules are suppressed there — see COMMENT_SUPPRESSED_RULE_PREFIXES in
 * detectionPipeline.ts for the exact split and its reasoning. Unambiguous,
 * format-specific secret rules keep firing everywhere.
 *
 * FAIL-OPEN, like the rest of the pipeline. No grammar for the language,
 * parser fails to initialise, text too large, unknown language, any thrown
 * error — every one of those results in "no comment spans known", which
 * means no suppression and therefore exactly today's behavior. Losing
 * syntax awareness must never mean losing detection.
 */

import * as fs from "fs";
import * as path from "path";
import { grammarDir as defaultGrammarDir } from "../assets";

/** Half-open [start, end) character offsets. */
export type Span = [number, number];

// Parsing is for interactive redaction, not batch analysis. A file past this
// size is almost certainly a bundle/minified artifact or a data blob, where
// the parse cost isn't worth it and "comment" is not a meaningful concept.
const MAX_PARSE_LENGTH = 512 * 1024;

/**
 * File extension -> grammar name, limited to grammars that actually ship in
 * tree-sitter-wasms. Anything not listed here simply gets no syntax
 * awareness (fail-open), which is why the map can stay small and honest
 * rather than guessing at aliases.
 */
const EXTENSION_TO_GRAMMAR: Record<string, string> = {
  ts: "typescript", mts: "typescript", cts: "typescript",
  tsx: "tsx",
  js: "javascript", mjs: "javascript", cjs: "javascript", jsx: "javascript",
  json: "json", jsonc: "json",
  py: "python", pyi: "python",
  rb: "ruby",
  go: "go",
  rs: "rust",
  java: "java",
  kt: "kotlin", kts: "kotlin",
  c: "c", h: "c",
  cpp: "cpp", cc: "cpp", cxx: "cpp", hpp: "cpp", hh: "cpp",
  cs: "c_sharp",
  php: "php",
  swift: "swift",
  scala: "scala",
  lua: "lua",
  sh: "bash", bash: "bash", zsh: "bash",
  yaml: "yaml", yml: "yaml",
  toml: "toml",
  css: "css",
  html: "html", htm: "html",
  vue: "vue",
  dart: "dart",
  ex: "elixir", exs: "elixir",
  elm: "elm",
  zig: "zig",
  sol: "solidity",
};

/**
 * Editor language identifier -> grammar name, for callers that have a
 * language id rather than a path. The keys are VS Code's languageIds because
 * that's the first host, but they're just lowercase language names — any host
 * can map its own identifiers onto them, or pass a file path instead and let
 * the extension table above do the work.
 */
const LANGUAGE_ID_TO_GRAMMAR: Record<string, string> = {
  typescript: "typescript", typescriptreact: "tsx",
  javascript: "javascript", javascriptreact: "javascript",
  json: "json", jsonc: "json",
  python: "python", ruby: "ruby", go: "go", rust: "rust", java: "java",
  kotlin: "kotlin", c: "c", cpp: "cpp", csharp: "c_sharp", php: "php",
  swift: "swift", scala: "scala", lua: "lua", shellscript: "bash",
  yaml: "yaml", toml: "toml", css: "css", html: "html", vue: "vue",
  dart: "dart", elixir: "elixir", elm: "elm", zig: "zig", solidity: "solidity",
};

/**
 * Grammars that ship broken, and the hash-comment scanner used instead.
 *
 * tree-sitter-wasms@0.1.13 builds tree-sitter-yaml at ABI 13 while everything
 * else is ABI 14, and every parse through it throws `TypeError: _ is not a
 * function` — even on an empty string, so it is the grammar rather than any
 * particular input. 0.1.13 is the newest release, so there is nothing to
 * upgrade to.
 *
 * That mattered more than a noisy warning. commentSpans feeds comment
 * suppression in detectionPipeline, so with YAML failing, a commented-out
 * example like `# password: example123` was being redacted as a live
 * credential — in the file type the Copilot CLI host exists to review.
 *
 * YAML's comment rule is small enough to implement exactly: `#` starts a
 * comment when it is at the start of a line or preceded by whitespace, it runs
 * to end of line, and it does not apply inside a quoted scalar. TOML and shell
 * share those rules, so they are handled by the same scanner — bash has a
 * working grammar today and stays with it, but the fallback is here if that
 * changes.
 */
const HASH_COMMENT_FALLBACK = new Set(["yaml", "toml"]);

/**
 * Comment spans for `#`-comment languages, without a grammar.
 *
 * Quote tracking is the only subtlety: `url: "http://x/#anchor"` contains a
 * `#` that is not a comment. YAML has no escape processing inside single
 * quotes ('' is a literal quote) and standard backslash escapes inside double
 * quotes, which is what the escape branch below covers.
 */
export function hashCommentSpans(text: string): Span[] {
  const spans: Span[] = [];
  let quote: '"' | "'" | null = null;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (ch === "\n") {
      quote = null; // an unterminated scalar cannot span a line here
      continue;
    }

    if (quote) {
      if (ch === "\\" && quote === '"') i++; // skip the escaped character
      else if (ch === quote) quote = null;
      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }

    // Start of line, or preceded by whitespace — `a#b` is a value, not a comment.
    if (ch === "#" && (i === 0 || /\s/.test(text[i - 1]))) {
      const end = text.indexOf("\n", i);
      const stop = end === -1 ? text.length : end;
      spans.push([i, stop]);
      i = stop;
    }
  }

  return spans;
}

/** Resolves a file path or editor language id to a grammar name, or null if we have no grammar for it. */
export function grammarForFile(filePathOrLanguageId: string): string | null {
  const direct = LANGUAGE_ID_TO_GRAMMAR[filePathOrLanguageId.toLowerCase()];
  if (direct) return direct;
  const ext = path.extname(filePathOrLanguageId).replace(/^\./, "").toLowerCase();
  return EXTENSION_TO_GRAMMAR[ext] ?? null;
}

/**
 * The WASM runtime is process-global and may only be initialised once, so
 * this is deliberately module-level rather than per-instance: a second
 * SyntaxAnalyzer would otherwise fail to start (init() is not re-entrant)
 * and silently lose syntax awareness. Shared as a promise so concurrent
 * first-calls await the same initialisation instead of racing it.
 */
let runtimeInit: Promise<any | null> | null = null;

function ensureRuntime(): Promise<any | null> {
  if (runtimeInit) return runtimeInit;
  runtimeInit = (async () => {
    try {
      // Required lazily so that merely importing this module never pulls a
      // WASM runtime into the extension host — if syntax awareness is off or
      // unused, nothing here is loaded at all.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const TreeSitter = require("web-tree-sitter");
      await TreeSitter.init();
      return TreeSitter;
    } catch (err) {
      console.warn("Vaultline: tree-sitter unavailable, syntax-aware redaction disabled for this session:", err);
      return null;
    }
  })();
  return runtimeInit;
}

export class SyntaxAnalyzer {
  private parser: unknown = null;
  private TreeSitter: any = null;
  private languages = new Map<string, unknown>();
  private unavailable = new Set<string>();

  private readonly grammarDir: string | null;

  /**
   * `grammarDir` is the directory holding tree-sitter-<name>.wasm files.
   * Omit it and the package finds its own bundled grammars (see assets.ts) —
   * a host only needs to pass one if it ships them somewhere else. Null (no
   * grammars installed at all) is a supported state: every lookup misses and
   * the pipeline runs exactly as it does without tree-sitter.
   */
  constructor(grammarDir?: string | null) {
    this.grammarDir = grammarDir === undefined ? defaultGrammarDir() : grammarDir;
  }

  private async ensureParser(): Promise<boolean> {
    if (this.parser) return true;
    const TreeSitter = await ensureRuntime();
    if (!TreeSitter) return false;
    try {
      this.TreeSitter = TreeSitter;
      this.parser = new TreeSitter();
      return true;
    } catch (err) {
      console.warn("Vaultline: could not create a tree-sitter parser:", err);
      return false;
    }
  }

  private async ensureLanguage(grammar: string): Promise<unknown | null> {
    if (this.languages.has(grammar)) return this.languages.get(grammar)!;
    if (this.unavailable.has(grammar)) return null;
    if (!this.grammarDir) return null;

    const wasmPath = path.join(this.grammarDir, `tree-sitter-${grammar}.wasm`);
    try {
      if (!fs.existsSync(wasmPath)) {
        this.unavailable.add(grammar);
        return null;
      }
      const language = await this.TreeSitter.Language.load(fs.readFileSync(wasmPath));
      this.languages.set(grammar, language);
      return language;
    } catch (err) {
      console.warn(`Vaultline: failed to load tree-sitter grammar "${grammar}", skipping syntax awareness for it:`, err);
      this.unavailable.add(grammar);
      return null;
    }
  }

  /**
   * Character spans of every comment in `text`, or [] if the language is
   * unknown/unsupported or anything at all goes wrong (fail-open).
   *
   * Node-type matching is deliberately substring-based: grammars disagree on
   * naming — "comment" in TS/JS/Python, "line_comment"/"block_comment" in
   * Rust, "doc_comment" elsewhere — but every one of them contains
   * "comment", and no non-comment node type does.
   */
  async commentSpans(text: string, filePathOrLanguageId: string): Promise<Span[]> {
    if (text.length === 0 || text.length > MAX_PARSE_LENGTH) return [];

    const grammar = grammarForFile(filePathOrLanguageId);
    if (!grammar) return [];

    // Checked before the parser is even initialised: these grammars are known
    // broken, so loading one only produces a warning and an empty result.
    if (HASH_COMMENT_FALLBACK.has(grammar)) return hashCommentSpans(text);

    if (!(await this.ensureParser())) return [];

    const language = await this.ensureLanguage(grammar);
    if (!language) return [];

    try {
      const parser = this.parser as any;
      parser.setLanguage(language);
      const tree = parser.parse(text);
      const spans: Span[] = [];

      // Iterative walk — a deeply nested file could blow a recursive stack,
      // and this runs on whatever a tool happens to read.
      const stack: any[] = [tree.rootNode];
      while (stack.length > 0) {
        const node = stack.pop();
        if (!node) continue;
        if (typeof node.type === "string" && node.type.includes("comment")) {
          spans.push([node.startIndex, node.endIndex]);
          continue; // no useful structure inside a comment
        }
        for (let i = node.childCount - 1; i >= 0; i--) stack.push(node.child(i));
      }

      tree.delete?.();
      return spans;
    } catch (err) {
      // Retire this grammar for the session rather than retrying it on every
      // scan. A parse failure here is almost always a grammar/runtime ABI
      // mismatch (the shipped grammars are built against a specific
      // tree-sitter version), which is permanent — retrying would just repeat
      // the same warning on every file of that language.
      console.warn(
        `Vaultline: tree-sitter parse failed for grammar "${grammar}", disabling it for this session ` +
          `(syntax-aware suppression will not apply to that language):`,
        err
      );
      this.unavailable.add(grammar);
      return [];
    }
  }
}

/** True if [start, end) lies entirely within one of `spans`. */
export function isWithinSpans(start: number, end: number, spans: Span[]): boolean {
  return spans.some(([s, e]) => start >= s && end <= e);
}
