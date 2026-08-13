/**
 * Entity Store — session-level, bidirectional, typed.
 *
 * Previously each tokenize() call started a fresh counter from [SEC-1],
 * meaning the same secret got a different token every message and mapped
 * back only within that one call. For multi-step agent/tool loops, you
 * need the OPPOSITE: "rahul.sharma" should become <<PERSON_1>> once, and
 * every subsequent reference to it — across multiple tool calls in the
 * same session — reuses that exact token. That's what makes rehydration
 * before tool execution possible (see toolGateway/toolGateway.ts).
 *
 * One EntityStore per session (e.g. per chat conversation, or per
 * agent-loop run) — construct it once at session start, reuse it for
 * every redact/rehydrate call in that session, discard it when the
 * session ends.
 *
 * BUG FIX (wrong placeholder type reuse): the reuse cache used to be keyed
 * on `match.value` alone. Two different detectors can flag the exact same
 * literal string in two different roles within a session — e.g. a value
 * caught once near "password" (-> PASSWORD) and, elsewhere, the identical
 * string caught near "server" (-> HOSTNAME). Keying purely on the raw
 * value meant the second occurrence silently reused the FIRST occurrence's
 * token/type via store.lookup(), so a hostname could come back labeled
 * <<PASSWORD_N>>. Keying on `entityType::value` instead keeps the "same
 * value -> same token" consistency guarantee scoped to a single type, so
 * unrelated roles for the same literal string get their own, correctly
 * typed token.
 *
 * Optionally persisted to a per-session JSON file on disk (see
 * persistPath) — a durable mirror of the in-memory mappings for
 * inspection/debugging, not a substitute for the in-memory store, which
 * remains the source of truth for the lifetime of the session.
 */

import * as fs from "fs";
import * as path from "path";
import { Match } from "./patternMatcher";
import { entityTypeFor } from "./entityTypes";

export interface EntityMapping {
  token: string;
  originalValue: string;
  entityType: string;
  category: Match["category"];
  severity: Match["severity"];
  ruleId: string;
  label: string;
}

export class EntityStore {
  private valueToToken = new Map<string, string>();
  private tokenToMapping = new Map<string, EntityMapping>();
  private countersByType = new Map<string, number>();
  private persistPath: string | null;

  /** `persistPath`, if given, is a JSON file this store's mappings get mirrored to on every new mint (and loaded back from, if it already exists). */
  constructor(persistPath?: string) {
    this.persistPath = persistPath ?? null;
    if (this.persistPath) this.loadFromDisk(this.persistPath);
  }

  private loadFromDisk(filePath: string): void {
    if (!fs.existsSync(filePath)) return;
    try {
      const raw = fs.readFileSync(filePath, "utf-8");
      const mappings: EntityMapping[] = JSON.parse(raw);
      for (const mapping of mappings) {
        const key = `${mapping.entityType}::${mapping.originalValue}`;
        this.valueToToken.set(key, mapping.token);
        this.tokenToMapping.set(mapping.token, mapping);

        // Resume the per-type counter from the highest suffix seen, so a
        // freshly reloaded store never re-mints a token number already on disk.
        const suffix = /_(\d+)>>$/.exec(mapping.token);
        if (suffix) {
          const n = parseInt(suffix[1], 10);
          if (n > (this.countersByType.get(mapping.entityType) ?? 0)) {
            this.countersByType.set(mapping.entityType, n);
          }
        }
      }
    } catch (err) {
      console.warn("Vaultline: failed to load persisted entity mappings, starting fresh:", err);
    }
  }

  /** Rewrites the whole persisted file from the current in-memory state. Simpler and safer than a raw fs.appendFileSync of JSON fragments, which wouldn't parse back as a single JSON document. */
  private persist(): void {
    if (!this.persistPath) return;
    try {
      fs.mkdirSync(path.dirname(this.persistPath), { recursive: true });
      fs.writeFileSync(this.persistPath, JSON.stringify(this.allMappings(), null, 2), "utf-8");
    } catch (err) {
      console.warn("Vaultline: failed to persist entity mappings to disk:", err);
    }
  }

  /** Returns the existing token for this exact (type, value) pair if one was already issued this session, otherwise mints a new typed one. */
  tokenFor(match: Match): string {
    const entityType = entityTypeFor(match);
    const key = `${entityType}::${match.value}`;
    const existing = this.valueToToken.get(key);
    if (existing) return existing;

    const next = (this.countersByType.get(entityType) ?? 0) + 1;
    this.countersByType.set(entityType, next);

    const token = `<<${entityType}_${next}>>`;
    this.valueToToken.set(key, token);
    this.tokenToMapping.set(token, {
      token,
      originalValue: match.value,
      entityType,
      category: match.category,
      severity: match.severity,
      ruleId: match.ruleId,
      label: match.label,
    });
    this.persist();
    return token;
  }

  lookup(token: string): EntityMapping | undefined {
    return this.tokenToMapping.get(token);
  }

  /** All tokens minted so far this session — used by the JSON/text rehydrators to know what to look for. */
  allMappings(): EntityMapping[] {
    return [...this.tokenToMapping.values()];
  }

  size(): number {
    return this.tokenToMapping.size;
  }
}
