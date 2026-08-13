/**
 * The guard, as a sequence of host-neutral steps.
 *
 * This is the orchestration that used to live inline in the VS Code chat
 * participant: scan the prompt, decide, tokenize, re-redact replayed history,
 * rehydrate tool arguments, redact tool results, restore the answer. None of
 * it is actually about VS Code — every step takes and returns plain strings
 * or plain JSON. What WAS about VS Code (turning `chatContext.history` into
 * turns, calling `vscode.lm.invokeTool`, streaming markdown) stays in the
 * host, which is a much thinner job than the ordering rules below.
 *
 * The ordering rules are the part worth not reimplementing per editor, and
 * each one was a bug once:
 *
 *  - businessMatches must NEVER reach tokenize(). Their span is the whole
 *    message by definition, so tokenizing them replaces the prompt with one
 *    opaque token. They inform the policy decision only.
 *  - History is re-redacted from KNOWN values, not re-scanned — except on a
 *    cold store, where trusting that would leak (see redactHistory).
 *  - Tool arguments are rehydrated before the tool runs; tool results are
 *    redacted before they go back to the model. Both against the same store,
 *    or a token minted in turn 1 stops resolving in turn 5.
 *  - A leftover placeholder in the final answer is only worth warning about
 *    when its TYPE was actually issued this session (see restoreResponse).
 *
 * ONE STORE PER SESSION. Not per request — cross-turn token consistency and
 * history re-redaction are impossible without it. A value seen in turn 1 gets
 * the same token in turn 5.
 */

import { AuditLog, mappingsToDetail, matchesToDetail } from "./auditLog";
import { ScanOptions, scanAll, scanCurrentMessage } from "./detectionPipeline";
import { EntityStore } from "./entityStore";
import { Match } from "./patternMatcher";
import { Action, PolicyConfig, decide } from "./policyEngine";
import { grammarForFile } from "./syntax/syntaxAnalyzer";
import { TokenMapping, findUnrestoredTokens, redactKnownValues, restore, tokenize } from "./tokenizer";
import { redactJson, rehydrateJson } from "./toolGateway/jsonRedactor";

/**
 * What a GuardSession needs from whoever owns the configuration. Supplied as
 * functions rather than values because every one of them is re-read per
 * message: a user can change any setting mid-session and must not have to
 * reload for it to take effect. VaultlineEngine implements this.
 */
export interface GuardContext {
  auditLog: AuditLog;
  scanOptions(): ScanOptions;
  policyConfig(): PolicyConfig;
  /** vaultline.auditLogIncludeValues — whether real values may be written to the audit log. */
  auditIncludesValues(): boolean;
}

export interface PromptGuardResult {
  action: Action;
  reason: string;
  /** The text safe to send onward. Empty string when `action` is "block" — nothing should be sent at all. */
  redactedText: string;
  /** Redactions performed on this message, for display ("redacted N item(s): …"). */
  mappings: TokenMapping[];
  matches: Match[];
  businessMatches: Match[];
}

export interface ConversationTurn {
  role: "user" | "assistant";
  text: string;
}

export interface HistoryGuardResult {
  turns: ConversationTurn[];
  mappings: TokenMapping[];
}

export interface ToolResultGuardResult {
  redacted: unknown;
  mappings: TokenMapping[];
}

export interface RestoreGuardResult {
  /** The answer with every token this session minted swapped back to its real value. */
  text: string;
  /**
   * Placeholders still standing afterwards whose entity TYPE was issued this
   * session — i.e. probably a corrupted real token, and therefore a lost
   * value. See restoreResponse() for why the type check matters.
   */
  suspiciousTokens: string[];
}

export class GuardSession {
  private readonly store: EntityStore;

  /** `persistPath`, when given, mirrors every mapping minted this session to a JSON file — one file per session, so the mapping table survives inspection after the fact. */
  constructor(private readonly context: GuardContext, persistPath?: string) {
    this.store = new EntityStore(persistPath);
  }

  /** The session's mapping table. Exposed for hosts that want to show or export it; callers should not mutate it. */
  entityStore(): EntityStore {
    return this.store;
  }

  // -------------------------------------------------------------------
  // The developer's live message
  // -------------------------------------------------------------------

  /**
   * Scan, decide, and (unless blocked) tokenize the message the developer
   * just typed. Audits either way.
   *
   * scanCurrentMessage, NOT scanAll: routes pii/infra/conversational-secret
   * detection per line rather than on one pooled whole-message embedding —
   * see detectionPipeline.ts's module comment. This is deliberately only
   * applied to the LIVE message; history is handled by redactHistory below.
   */
  async guardPrompt(text: string, source = "prompt"): Promise<PromptGuardResult> {
    const includeValues = this.context.auditIncludesValues();
    const { matches, businessMatches } = await scanCurrentMessage(text, this.context.scanOptions());
    const decision = decide(matches, businessMatches, this.context.policyConfig());

    if (decision.action === "block") {
      this.context.auditLog.record({
        source,
        action: decision.action,
        reason: decision.reason,
        details: matchesToDetail([...matches, ...businessMatches], includeValues),
      });
      return { action: "block", reason: decision.reason, redactedText: "", mappings: [], matches, businessMatches };
    }

    // NOTE: `matches` only — businessMatches must never flow into span-based
    // redaction. See the module comment.
    const { redactedText, mappings } = tokenize(text, matches, this.store);
    this.context.auditLog.record({
      source,
      action: decision.action,
      reason: decision.reason,
      details: mappingsToDetail(mappings, includeValues),
    });

    return { action: decision.action, reason: decision.reason, redactedText, mappings, matches, businessMatches };
  }

  // -------------------------------------------------------------------
  // Replayed conversation history
  // -------------------------------------------------------------------

  /**
   * Re-redact prior turns before replaying them as context.
   *
   * Neither side of a chat history is safe as-is. A past user turn is what
   * the person literally typed — never redacted. A past assistant turn is
   * what the host rendered to them, which is deliberately the REHYDRATED,
   * real-value text (the developer is supposed to see their own data back).
   *
   * The normal path is redactKnownValues, NOT a rescan: every past turn went
   * through full detection once, back when it WAS the live message, so every
   * sensitive value in it is already in `store`. Re-running detection (and
   * another embedding call per turn per message) would be redundant work for
   * an identical result.
   *
   * THAT ASSUMPTION BREAKS after a host restart (window reload, plugin
   * reload, editor update): `store` is recreated empty at activation, but
   * the host's history is its OWN persisted state and can still hand back
   * turns from BEFORE the restart — turns this fresh store has never seen.
   * Trusting redactKnownValues there would silently redact NOTHING (empty
   * store = no known values), leaking prior sensitive content into the model
   * context. So: store empty but history non-empty means run full detection
   * over every turn just this once, rebuilding the mapping table before
   * trusting the cheap path again.
   */
  async redactHistory(turns: ConversationTurn[]): Promise<HistoryGuardResult> {
    const bootstrapping = this.store.size() === 0 && turns.length > 0;
    const scanOptions = this.context.scanOptions();

    const out: ConversationTurn[] = [];
    const allMappings: TokenMapping[] = [];

    for (const turn of turns) {
      const { redactedText, mappings } = bootstrapping
        ? // scanCurrentMessage, not scanAll — a historical turn can just as
          // easily be a long, multi-topic message subject to the same
          // whole-message routing dilution (see detectionPipeline.ts).
          tokenize(turn.text, (await scanCurrentMessage(turn.text, scanOptions)).matches, this.store)
        : redactKnownValues(turn.text, this.store);
      allMappings.push(...mappings);
      out.push({ role: turn.role, text: redactedText });
    }

    if (allMappings.length > 0) {
      this.context.auditLog.record({
        source: "history",
        action: "redact",
        reason: `Re-redacted ${allMappings.length} item(s) across ${turns.length} prior conversation turn(s) before replaying them as context.`,
        details: mappingsToDetail(allMappings, this.context.auditIncludesValues()),
      });
    }

    return { turns: out, mappings: allMappings };
  }

  // -------------------------------------------------------------------
  // Ambient context (open file, attachments)
  // -------------------------------------------------------------------

  /**
   * Redact a short piece of ambient context — typically a file path for the
   * editor's open document or an attachment.
   *
   * File PATHS are themselves sensitive (a username or project codename in
   * the path), so they go through the same pipeline and the SAME store: if
   * the model later calls a read-file tool with a tokenized path,
   * guardToolInput() restores the real path automatically before the tool
   * runs. scanAll rather than scanCurrentMessage — a path is a single short
   * string, with no lines to dilute anything.
   */
  async guardContext(text: string, source = "editorContext"): Promise<{ redactedText: string; mappings: TokenMapping[] }> {
    const { matches } = await scanAll(text, this.context.scanOptions());
    const result = tokenize(text, matches, this.store);
    if (result.mappings.length > 0) {
      this.context.auditLog.record({
        source,
        action: "redact",
        reason: `Redacted ${result.mappings.length} item(s) in ${source}.`,
        details: mappingsToDetail(result.mappings, this.context.auditIncludesValues()),
      });
    }
    return result;
  }

  // -------------------------------------------------------------------
  // Tool calls
  // -------------------------------------------------------------------

  /**
   * Put real values back into a tool call's arguments, so the tool operates
   * on reality rather than on placeholders. Restores against every token
   * minted so far this session, not just the last call — multi-step tool
   * loops depend on that.
   */
  guardToolInput(input: unknown): unknown {
    return rehydrateJson(input, this.store);
  }

  /**
   * Redact a tool's output before it goes back to the model.
   *
   * `codeLanguage` enables comment-aware suppression for this result. A
   * file-reading tool names its file in the INPUT, never in the result, so
   * languageForToolInput() below is the only way to associate the two —
   * null simply means no syntax awareness for this result.
   */
  async guardToolResult(content: unknown, codeLanguage: string | null, toolName: string): Promise<ToolResultGuardResult> {
    const scanOptions: ScanOptions = { ...this.context.scanOptions(), codeLanguage };
    const { redacted, mappings } = await redactJson(content, this.store, scanOptions);

    if (mappings.length > 0) {
      this.context.auditLog.record({
        source: `tool:${toolName}`,
        action: "redact",
        reason: `Redacted ${mappings.length} match(es) from tool "${toolName}" output.`,
        details: mappingsToDetail(mappings, this.context.auditIncludesValues()),
      });
    }
    return { redacted, mappings };
  }

  /**
   * Best-effort: find a file path anywhere in a tool call's arguments, so the
   * tool's OUTPUT can be parsed with the right grammar. Returns null whenever
   * nothing recognizable is found, which just means no syntax awareness for
   * that result.
   */
  languageForToolInput(input: unknown): string | null {
    const seen = new Set<unknown>();
    const visit = (node: unknown, depth: number): string | null => {
      if (node === null || depth > 4) return null;
      if (typeof node === "string") return grammarForFile(node) ? node : null;
      if (typeof node !== "object" || seen.has(node)) return null;
      seen.add(node);
      for (const value of Object.values(node as Record<string, unknown>)) {
        const found = visit(value, depth + 1);
        if (found) return found;
      }
      return null;
    };
    return visit(input, 0);
  }

  // -------------------------------------------------------------------
  // The model's answer, on its way back to the developer
  // -------------------------------------------------------------------

  /**
   * Reverse-substitute before the developer ever sees the answer.
   *
   * Any placeholder still standing after restore() was never issued this
   * session — but that alone is NOT evidence of a problem, and warning on it
   * alone produced immediate false alarms. A model asked about redaction (or
   * reading a codebase whose comments explain the token format) will happily
   * write "<<PASSWORD_1>>" as an ILLUSTRATION. No value was lost there.
   *
   * The case actually worth flagging is a CORRUPTED token: the model altered
   * a real one badly enough that the tolerant pass in restore() couldn't
   * recover it, so a real value silently vanished. Those almost always keep
   * the entity TYPE and damage the counter. So only warn when the leftover's
   * type is one this session actually issued — an invented <<HOSTNAME_1>> in
   * a session that never produced a HOSTNAME token is the model talking about
   * the format, not losing data.
   */
  restoreResponse(text: string): RestoreGuardResult {
    const mappings = this.store.allMappings();
    const restored = restore(text, mappings);

    const issuedTypes = new Set(mappings.map((m) => m.entityType.toUpperCase()));
    const suspiciousTokens = findUnrestoredTokens(restored).filter((tok) => {
      const parsed = /<<\s*([A-Za-z][A-Za-z0-9_]*?)_\d+\s*>>/.exec(tok);
      return parsed ? issuedTypes.has(parsed[1].toUpperCase()) : false;
    });

    if (suspiciousTokens.length > 0) {
      this.context.auditLog.record({
        source: "rehydration",
        action: "warn",
        reason: `Model returned ${suspiciousTokens.length} placeholder(s) of an issued type that could not be restored: ${suspiciousTokens.join(", ")}.`,
        details: [],
      });
    }

    return { text: restored, suspiciousTokens };
  }
}
