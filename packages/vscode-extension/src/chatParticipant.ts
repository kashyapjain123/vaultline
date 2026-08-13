/**
 * Layer 1: Interceptor — the VS Code half.
 *
 * IMPORTANT NOTE: VS Code does not (as of writing) expose a public API
 * to transparently intercept Copilot's own agent-mode traffic — that's a
 * closed pipeline. What VS Code *does* expose is the Chat Participant API
 * (`vscode.chat.createChatParticipant`) plus the Language Model API
 * (`vscode.lm`), which together let an extension register its own chat
 * identity (here, "@vaultline") that a developer talks to directly.
 *
 * WHAT'S LEFT IN THIS FILE, now that the guard logic lives in
 * @vaultline/core's GuardSession: turning VS Code's chat types into plain
 * strings and plain JSON, and back. Every ordering decision that actually
 * matters — what gets scanned versus re-redacted, what must never reach the
 * tokenizer, when a leftover placeholder is worth warning about — is in
 * GuardSession, so a second editor gets it for free instead of
 * reimplementing it. Read that file for the reasoning; read this one for the
 * VS Code mechanics.
 *
 * TOOL CALLING: @vaultline has the same tool access agent mode does —
 * `vscode.lm.tools` is the shared registry of built-in tools (file read,
 * terminal, etc.), extension-contributed tools, and MCP tools, and any
 * chat participant can pass that list into sendRequest() and implement the
 * tool-calling loop itself. Every tool call's arguments are rehydrated
 * before the tool runs, and every result is redacted before it goes back
 * to the model.
 *
 * MCP COVERAGE: MCP tools registered via VS Code's native MCP support
 * appear in `vscode.lm.tools` alongside everything else — no special-casing
 * by tool origin anywhere in this file. If you have a separate MCP client
 * that talks to a server directly (bypassing vscode.lm.tools), route those
 * calls through the core's ToolGateway + McpAdapter instead.
 *
 * CONVERSATION HISTORY: `chatContext.history` is VS Code's own record of
 * this chat session's previous turns. Two things about it matter here:
 *   1. A previous user turn's `.prompt` is whatever the person ACTUALLY
 *      typed — never redacted at the VS Code layer, that's just their raw
 *      input.
 *   2. A previous assistant turn's rendered response is exactly what we
 *      called stream.markdown() with — which, on purpose (see the end of
 *      the handler below), is the REHYDRATED, real-value text, since the
 *      developer is supposed to see their own real data back.
 * So neither side of history is safe to feed to the model as-is. Both are
 * flattened to plain text here and handed to GuardSession.redactHistory(),
 * which re-redacts them against the same session store as the current turn.
 */

import {
  ConversationTurn,
  GuardSession,
  TOKEN_PRESERVATION_INSTRUCTION,
  VaultlineEngine,
  VaultlineHost,
  parseToolLimitFromError,
  selectTools,
} from "@vaultline/core";
import * as vscode from "vscode";

const MAX_TOOL_ROUNDS = 8;

export function registerVaultlineParticipant(
  context: vscode.ExtensionContext,
  engine: VaultlineEngine,
  host: VaultlineHost,
  entityStorePersistPath?: string
): void {
  // One GuardSession — and therefore one EntityStore — for the whole life of
  // this participant registration (i.e. this VS Code window session), NOT per
  // request. That lifetime is what makes cross-turn token consistency and
  // history re-redaction possible at all; see GuardSession.
  const session: GuardSession = engine.createSession(entityStorePersistPath);

  const handler: vscode.ChatRequestHandler = async (request, chatContext, stream, token) => {
    // --- Conversation history, flattened to plain turns for the core ---
    //
    // ORDER MATTERS, and it used to be wrong: this ran AFTER guardPrompt.
    // GuardSession.redactHistory() decides whether to bootstrap (full rescan
    // of every prior turn) by checking whether the entity store is still
    // empty — so running the live prompt first meant that any message
    // containing a secret populated the store, redactHistory then took the
    // cheap known-values path, and prior turns from before a window reload
    // were replayed to the model with nothing redacted in them.
    //
    // Replaying history first also rebuilds the cross-turn credential
    // expectation in turn order, so a reload in the middle of a credential
    // exchange doesn't drop it (see core/conversationContext.ts).
    const priorTurns: ConversationTurn[] = [];
    for (const turn of chatContext.history) {
      if (turn instanceof vscode.ChatRequestTurn) {
        priorTurns.push({ role: "user", text: turn.prompt });
      } else if (turn instanceof vscode.ChatResponseTurn) {
        let responseText = "";
        for (const part of turn.response) {
          if (part instanceof vscode.ChatResponseMarkdownPart) responseText += part.value.value;
        }
        priorTurns.push({ role: "assistant", text: responseText });
      }
    }
    const history = await session.redactHistory(priorTurns);

    // --- Detection on the developer's prompt ---
    const guarded = await session.guardPrompt(request.prompt);

    if (guarded.action === "block") {
      stream.markdown(
        `🛑 **Vaultline blocked this request.**\n\n${guarded.reason}\n\n` +
          `Nothing was sent to the model. Remove or rephrase the flagged content and try again.`
      );
      return;
    }

    if (guarded.action === "redact") {
      stream.markdown(
        `🔒 *Vaultline redacted ${guarded.mappings.length} item(s) before sending this prompt: ` +
          `${guarded.mappings.map((m) => m.label).join(", ")}.*\n\n`
      );
    }

    if (!request.model) {
      stream.markdown("_No language model is available for this request._");
      return;
    }

    // --- Tool access: same registry agent mode uses ---
    // Read per request, not once at registration, so toggling the setting
    // takes effect on the next message rather than on the next reload.
    //
    // CAPPED, and that cap is load-bearing. `vscode.lm.tools` is every built-in,
    // extension-contributed and MCP tool the user has installed, and providers
    // refuse an over-long list outright — Copilot answers "Cannot have more than
    // 128 tools per request" and the call dies before the model sees anything.
    // Forwarding the registry blindly therefore broke @vaultline completely for
    // users with a lot of extensions. See core/toolSelection.ts.
    const settings = host.settings();
    const selection = settings.enableToolCalling
      ? selectTools(vscode.lm.tools, { max: settings.maxTools, denyList: settings.toolDenyList })
      : { selected: [], denied: [], truncated: [] };

    let tools: vscode.LanguageModelChatTool[] = selection.selected.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    }));

    if (selection.truncated.length > 0) {
      // Worth saying out loud: the user didn't ask for this, and it changes what
      // the model can do for them. Silently dropping tools would look like the
      // model simply choosing not to use one.
      stream.markdown(
        `ℹ️ *Vaultline offered the model ${tools.length} of ${tools.length + selection.truncated.length} available tools ` +
          `(provider limit). ${selection.truncated.length} were left out — set \`vaultline.toolDenyList\` to choose which, ` +
          `or raise \`vaultline.maxTools\` if your model allows more.*\n\n`
      );
    }

    const historyMessages = history.turns.map((turn) =>
      turn.role === "user"
        ? vscode.LanguageModelChatMessage.User(turn.text)
        : vscode.LanguageModelChatMessage.Assistant(turn.text)
    );

    // --- Editor / attached-file context. Plain Copilot chat implicitly
    // knows the active editor and any #-attached files; @vaultline doesn't
    // get that for free — without this, the model has no idea what "the
    // file" refers to and has to ask, which is exactly the bug this fixes.
    // File PATHS can themselves be sensitive, so each one goes through
    // GuardSession.guardContext() against the SAME store — if the model
    // later calls a read-file tool with a tokenized path, the rehydration
    // step in the tool loop below restores the real path before the tool
    // runs.
    const contextMessages: vscode.LanguageModelChatMessage[] = [];
    const addFileContext = async (label: string, filePath: string) => {
      const { redactedText } = await session.guardContext(filePath);
      contextMessages.push(
        vscode.LanguageModelChatMessage.User(
          `Context: ${label}: ${redactedText}. If the developer's request doesn't name a specific file, assume they mean this one — use your file-reading tool to read it rather than asking which file they mean.`
        )
      );
    };

    const activeEditor = vscode.window.activeTextEditor;
    if (activeEditor) {
      await addFileContext("the developer currently has this file open in the editor", activeEditor.document.uri.fsPath);
    }
    for (const ref of request.references ?? []) {
      const refValue = ref.value;
      if (refValue instanceof vscode.Uri) {
        await addFileContext("the developer attached this file as context", refValue.fsPath);
      } else if (refValue && typeof refValue === "object" && "uri" in refValue) {
        const maybeUri = (refValue as { uri: unknown }).uri;
        if (maybeUri instanceof vscode.Uri) {
          await addFileContext("the developer attached this location as context", maybeUri.fsPath);
        }
      }
    }

    const messages: vscode.LanguageModelChatMessage[] = [
      vscode.LanguageModelChatMessage.User(TOKEN_PRESERVATION_INSTRUCTION),
      ...historyMessages,
      ...contextMessages,
      vscode.LanguageModelChatMessage.User(guarded.redactedText),
    ];

    try {
      let finalText = "";

      for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
        let chatResponse: vscode.LanguageModelChatResponse;
        try {
          chatResponse = await request.model.sendRequest(messages, { tools }, token);
        } catch (err) {
          // The configured cap is a DEFAULT, not a contract — a different model
          // may allow fewer tools than Copilot's 128. Rather than hardcoding a
          // guess per provider, read the limit out of the rejection and retry
          // against it once; if it isn't parseable, drop tools entirely so the
          // developer still gets an answer instead of a raw error.
          const limit = parseToolLimitFromError(String(err));
          if (tools.length === 0 || !/tool/i.test(String(err))) throw err;

          const retryMax = limit ?? 0;
          const before = tools.length;
          tools = tools.slice(0, retryMax);
          stream.markdown(
            `ℹ️ *The model rejected ${before} tools${limit ? ` (its limit is ${limit})` : ""} — retrying with ` +
              `${tools.length}. Set \`vaultline.maxTools\` to ${retryMax} to avoid this round trip.*\n\n`
          );
          chatResponse = await request.model.sendRequest(messages, { tools }, token);
        }

        const toolCalls: vscode.LanguageModelToolCallPart[] = [];
        let roundText = "";

        for await (const part of chatResponse.stream) {
          if (part instanceof vscode.LanguageModelTextPart) {
            roundText += part.value;
          } else if (part instanceof vscode.LanguageModelToolCallPart) {
            toolCalls.push(part);
          }
        }

        if (toolCalls.length === 0) {
          finalText = roundText;
          break;
        }

        stream.markdown(
          `\n\n🔧 *Vaultline: running ${toolCalls.length} tool call(s) — ${toolCalls.map((c) => c.name).join(", ")}*\n\n`
        );

        messages.push(vscode.LanguageModelChatMessage.Assistant(toolCalls));

        const resultParts: vscode.LanguageModelToolResultPart[] = [];
        for (const call of toolCalls) {
          try {
            // 1. REHYDRATE — the tool must operate on real values.
            const rehydratedInput = session.guardToolInput(call.input);

            // A file-reading tool names its file in the INPUT, never in the
            // result, so this is the only point where the two can be tied
            // together — which is what lets the result be parsed with the
            // right grammar for comment-aware suppression.
            const codeLanguage = session.languageForToolInput(rehydratedInput);

            const toolResult = await vscode.lm.invokeTool(
              call.name,
              { input: rehydratedInput as object, toolInvocationToken: request.toolInvocationToken },
              token
            );

            // 2. REDACT — every part, not just recognized text parts.
            //
            // Built-in tools like copilot_readFile commonly return a
            // LanguageModelPromptTsxPart, not a LanguageModelTextPart — its
            // `.value` is a real (`@vscode/prompt-tsx`) PromptElementJSON
            // object tree, not a string. JSON.stringify-ing the WHOLE part
            // turns every real embedded newline inside that tree's string
            // leaves into a literal two-character "\n" escape, which both
            // (a) can bleed a stray "\n" into the tail of a regex match that
            // doesn't exclude backslash, and (b) collapses per-line detection
            // back into one pooled blob, since there are no real newlines
            // left for line-splitting to find — silently undoing the per-line
            // routing in detectionPipeline.ts. Passing the real `.value` tree
            // into the core lets its recursive walk reach each ACTUAL string
            // leaf (real newlines intact, real JSON keys intact for
            // field-level masking too) instead of one flattened, re-escaped
            // blob.
            const redactedContent: vscode.LanguageModelTextPart[] = [];
            let redactedCount = 0;

            for (const part of toolResult.content) {
              const contentForRedaction: unknown =
                part instanceof vscode.LanguageModelTextPart || part instanceof vscode.LanguageModelPromptTsxPart
                  ? part.value
                  : part; // unrecognized/future part type — best-effort fallback

              const { redacted, mappings } = await session.guardToolResult(contentForRedaction, codeLanguage, call.name);
              redactedCount += mappings.length;
              redactedContent.push(
                new vscode.LanguageModelTextPart(typeof redacted === "string" ? redacted : JSON.stringify(redacted))
              );
            }

            if (redactedCount > 0) {
              stream.markdown(`🔒 *Vaultline redacted ${redactedCount} item(s) from "${call.name}" output.*\n\n`);
            }

            resultParts.push(new vscode.LanguageModelToolResultPart(call.callId, redactedContent));
          } catch (toolErr) {
            resultParts.push(
              new vscode.LanguageModelToolResultPart(call.callId, [
                new vscode.LanguageModelTextPart(`Tool call failed: ${String(toolErr)}`),
              ])
            );
          }
        }

        messages.push(vscode.LanguageModelChatMessage.User(resultParts));
      }

      // --- Reverse-substitute before the developer ever sees the answer ---
      const { text: restored, suspiciousTokens } = session.restoreResponse(finalText);

      if (suspiciousTokens.length > 0) {
        stream.markdown(
          `⚠️ *Vaultline: ${suspiciousTokens.length} placeholder(s) in this answer (${suspiciousTokens.join(", ")}) ` +
            `don't match any token issued this session, but their type does — so a real value may have ` +
            `been altered and lost rather than restored. Double-check any code or command using them.*\n\n`
        );
      }

      stream.markdown(restored);
    } catch (err) {
      stream.markdown(`_Vaultline: the underlying model call failed: ${String(err)}_`);
    }
  };

  const participant = vscode.chat.createChatParticipant("vaultline.guard", handler);
  participant.iconPath = new vscode.ThemeIcon("shield");
  context.subscriptions.push(participant);
}
