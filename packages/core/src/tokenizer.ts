/**
 * Tokenization / reverse-substitution.
 *
 * Sensitive values are swapped for TYPED placeholder tokens like
 * <<PASSWORD_1>>, <<PERSON_1>>, <<AMOUNT_INR_1>> before the prompt ever
 * leaves the machine — see entityTypes.ts for the type taxonomy and
 * entityStore.ts for why these are double-angle-bracket tokens rather than
 * the earlier generic [SEC-N] format:
 *
 *  - [SEC-1] carries no information, so a model is more likely to "fix"
 *    it away (drop it, replace it with a plain word) rather than treat it
 *    as an opaque placeholder to echo back verbatim.
 *  - <<PASSWORD_1>> looks unmistakably machine-generated (nothing in
 *    normal prose looks like that), and keeps enough type information
 *    for the model to reason correctly around the redacted value without
 *    ever seeing it — "the balance is <<AMOUNT_INR_1>>" still tells the
 *    model this is a currency amount, not just "a number".
 *
 * Pass an EntityStore to get cross-call consistency (the same value always
 * gets the same token across multiple tokenize() calls in one session —
 * needed for multi-step tool-execution loops); omit it and an ephemeral
 * one is used, matching the old per-call-only behavior.
 */

import { Match } from "./patternMatcher";
import { EntityStore, EntityMapping } from "./entityStore";

export type TokenMapping = EntityMapping;

export interface TokenizeResult {
  redactedText: string;
  mappings: TokenMapping[];
}

export function tokenize(text: string, matches: Match[], store: EntityStore = new EntityStore()): TokenizeResult {
  const mappings: TokenMapping[] = [];
  let result = "";
  let cursor = 0;

  for (const match of matches) {
    // Matches are pre-sorted by start position from patternMatcher.scan().
    if (match.start < cursor) {
      // Overlapping match (two rules caught the same span) — skip it.
      continue;
    }

    const token = store.tokenFor(match);

    result += text.slice(cursor, match.start);
    result += token;
    cursor = match.end;

    mappings.push(store.lookup(token)!);
  }

  result += text.slice(cursor);

  return { redactedText: result, mappings };
}

/**
 * Redacts `text` using ONLY values already known to `store` — no detector,
 * no embedding call, runs against nothing but the in-memory mapping table.
 *
 * Used for replaying PRIOR conversation turns as context (see
 * chatParticipant.ts): every past turn was already the live message once,
 * and got the full detection pipeline (scanCurrentMessage) at that time —
 * so by the time it's history, every sensitive value in it is already in
 * `store`. Re-running full detection on it again on every subsequent turn
 * is both wasted work (a fresh embedding call per history turn per
 * message) and a second source of inconsistency (routing/thresholds could
 * in principle score the same text differently call to call). A plain
 * substring swap against the known mapping table is cheaper and exactly as
 * correct, given that assumption holds.
 *
 * Longest values first: if one already-tokenized value happens to be a
 * substring of another (e.g. "sk-123" inside a longer "sk-123-prod" that
 * was tokenized as a single value), replacing the longer one first avoids
 * corrupting it by partially matching inside it first.
 */
export function redactKnownValues(text: string, store: EntityStore): TokenizeResult {
  const mappings: TokenMapping[] = [];
  let result = text;

  const known = [...store.allMappings()]
    .filter((m) => m.originalValue.length > 0)
    .sort((a, b) => b.originalValue.length - a.originalValue.length);

  for (const mapping of known) {
    if (!result.includes(mapping.originalValue)) continue;
    result = result.split(mapping.originalValue).join(mapping.token);
    mappings.push(mapping);
  }

  return { redactedText: result, mappings };
}

/**
 * Anything SHAPED like one of our placeholders, however the model may have
 * reformatted it — `<<PASSWORD_1>>`, `<< PASSWORD_1 >>`, `<<password_1>>`.
 * Used both to restore mangled tokens and to detect leftovers afterwards.
 */
const TOKEN_SHAPE = /<<\s*([A-Za-z][A-Za-z0-9_]*?)_(\d+)\s*>>/g;

function normalizeTokenKey(entityType: string, counter: string): string {
  return `${entityType.toUpperCase()}_${counter}`;
}

/**
 * Reverses tokenization on a model's response. Accepts either the mapping
 * list from a single tokenize() call, or store.allMappings() to restore
 * against every token minted so far this session (needed when a tool-loop
 * response references a token created several turns earlier).
 *
 * TWO PASSES, because exact-match alone is a real failure mode for coding
 * agents rather than a theoretical one. A model asked to reformat or
 * refactor code containing a placeholder will quite reasonably re-case or
 * re-space it, and an exact-match restore then silently fails — leaving a
 * literal `<<PASSWORD_1>>` in what the developer receives, with the real
 * value gone. So: exact replacement first (fast, and safe for values
 * containing regex metacharacters), then a tolerant shape-based pass that
 * catches whitespace/case variants.
 *
 * The tolerant pass can only ever restore a token this session actually
 * minted — an unknown `<<FOO_9>>` is left untouched rather than guessed at.
 */
export function restore(text: string, mappings: TokenMapping[]): string {
  let result = text;
  for (const mapping of mappings) {
    // Split/join instead of a regex replace to avoid special-character
    // headaches in original values that might contain regex metacharacters.
    result = result.split(mapping.token).join(mapping.originalValue);
  }

  const byKey = new Map<string, string>();
  for (const mapping of mappings) {
    const shape = TOKEN_SHAPE.exec(mapping.token);
    TOKEN_SHAPE.lastIndex = 0;
    if (shape) byKey.set(normalizeTokenKey(shape[1], shape[2]), mapping.originalValue);
  }

  return result.replace(TOKEN_SHAPE, (whole, entityType: string, counter: string) => {
    const value = byKey.get(normalizeTokenKey(entityType, counter));
    return value !== undefined ? value : whole;
  });
}

/**
 * Placeholder-shaped strings still present AFTER restore() — i.e. tokens
 * this session never minted, which means the model invented or corrupted
 * one. Callers should surface these rather than hand them to the developer
 * silently: a literal `<<PASSWORD_7>>` in an answer (or worse, written into
 * a file) is a visible defect, and it means whatever real value belonged
 * there was lost.
 */
export function findUnrestoredTokens(text: string): string[] {
  const found = new Set<string>();
  TOKEN_SHAPE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TOKEN_SHAPE.exec(text)) !== null) found.add(m[0]);
  return [...found];
}

/**
 * System-instruction fragment telling the model to leave tokens untouched.
 * Calls out the <<TYPE_N>> format specifically, since that shape (not
 * [SEC-N]) is what's actually being sent now.
 *
 * The second paragraph exists because the first one, on its own, was
 * incomplete in a way that showed up in use. It tells the model what a token
 * IS but not what happens to it afterwards, so a model that has correctly
 * understood "a real value you cannot see" draws the sensible conclusion that
 * the DEVELOPER cannot see it either — and stops to ask for it, or answers
 * around it, or appends "replace <<PASSWORD_1>> with your real password". None
 * of that is wrong given what it was told; it just doesn't know that
 * restoreResponse() swaps every token back before the answer is displayed.
 *
 * So the instruction has to cover both directions: don't reveal the value
 * upward (paragraph one), and don't withhold the ANSWER downward on account of
 * a value that the developer is, in fact, about to see (paragraph two).
 *
 * Hosts should prepend this per request rather than once per conversation.
 * Chat APIs are stateless — the whole message array is resent every turn — and
 * this synthetic message is not part of the host's own chat history, so
 * sending it only on the first turn leaves every later turn with no
 * instruction at all.
 */
export const TOKEN_PRESERVATION_INSTRUCTION =
  "Some values in this conversation have been replaced with placeholder " +
  "tokens in the exact format <<TYPE_N>>, e.g. <<PASSWORD_1>>, " +
  "<<PERSON_1>>, <<AMOUNT_INR_1>>. Treat each token as an opaque, " +
  "machine-generated stand-in for a real value you cannot see — never a " +
  "word to translate, summarize, or replace with a description. " +
  "Reproduce every token exactly, character for character including the " +
  "double angle brackets, wherever it would logically appear in your " +
  "response. Do not guess, infer, reconstruct, or omit the original value.\n\n" +
  "The developer is NOT missing this information. Every token is " +
  "automatically substituted back to its real value before the response " +
  "reaches them, so they will read your answer with the real values in " +
  "place. Answer exactly as you would if the real values were visible to " +
  "you: do not ask the developer to supply, confirm, or paste the " +
  "underlying value; do not pause or refuse to continue until you have it; " +
  "and do not add notes, warnings, or TODOs saying that a placeholder needs " +
  "to be filled in. The substitution is handled for you in both directions.";
