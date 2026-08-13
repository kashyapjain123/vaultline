/**
 * Layer 5 (logging half): Audit Log
 *
 * Every decision gets appended to a local JSON-lines file. By DEFAULT,
 * nothing here stores the original sensitive value — only which rule
 * fired, its category/severity, and the action taken. Set
 * vaultline.auditLogIncludeValues to also record the real value and the
 * placeholder token assigned to it for every redaction — see that
 * setting's description in package.json for why this is off by default:
 * enabling it turns this log file itself into a plaintext record of every
 * secret it ever caught.
 *
 * `source` tags WHERE a decision came from — "prompt", "tool:<name>",
 * "history", "testPipelineCommand" — since this gets called from multiple
 * places. Every record() call is wrapped in its own try/catch with a
 * console.error fallback: a failed audit write should never crash or
 * silently swallow a chat turn, but it also shouldn't fail completely
 * silently either — if writes are failing, check the extension host's
 * Output/Debug console for "Vaultline: audit log write failed".
 */

import * as fs from "fs";
import * as path from "path";
import { Match } from "./patternMatcher";
import { EntityMapping } from "./entityStore";

export interface AuditMatchDetail {
  ruleId: string;
  label: string;
  category: string;
  severity: string;
  /** The placeholder token assigned, e.g. "<<PASSWORD_1>>" — present when this match was actually redacted into a token (not present for a blocked match, since blocking means nothing gets tokenized). */
  token?: string;
  /** The real sensitive value. ONLY populated by the mappingsToDetail/matchesToDetail helpers below when includeValues is true — see vaultline.auditLogIncludeValues. */
  value?: string;
}

export interface AuditEntry {
  timestamp: string;
  source: string;
  action: string;
  reason: string;
  matchSummary: AuditMatchDetail[];
}

/** Build audit detail from Match[] — used where there's no token yet (e.g. a blocked message: nothing was tokenized, since the whole thing was stopped). */
export function matchesToDetail(matches: Match[], includeValues: boolean): AuditMatchDetail[] {
  return matches.map((m) => ({
    ruleId: m.ruleId,
    label: m.label,
    category: m.category,
    severity: m.severity,
    value: includeValues ? m.value : undefined,
  }));
}

/** Build audit detail from EntityMapping[] (i.e. tokenizer.ts's TokenMapping) — used wherever an actual redaction happened, since these carry both the token AND the original value. */
export function mappingsToDetail(mappings: EntityMapping[], includeValues: boolean): AuditMatchDetail[] {
  return mappings.map((m) => ({
    ruleId: m.ruleId,
    label: m.label,
    category: m.category,
    severity: m.severity,
    token: m.token,
    value: includeValues ? m.originalValue : undefined,
  }));
}

export interface AuditRecordInput {
  source: string;
  action: string;
  reason: string;
  details: AuditMatchDetail[];
}

export class AuditLog {
  private filePath: string;

  constructor(storageDir: string) {
    if (!fs.existsSync(storageDir)) {
      fs.mkdirSync(storageDir, { recursive: true });
    }
    this.filePath = path.join(storageDir, "vaultline-audit.log.jsonl");
  }

  record(input: AuditRecordInput): AuditEntry | null {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      source: input.source,
      action: input.action,
      reason: input.reason,
      matchSummary: input.details,
    };

    try {
      fs.appendFileSync(this.filePath, JSON.stringify(entry) + "\n", "utf-8");
      return entry;
    } catch (err) {
      console.error("Vaultline: audit log write failed:", err, "-- entry was:", entry);
      return null;
    }
  }

  readAll(): AuditEntry[] {
    if (!fs.existsSync(this.filePath)) {
      return [];
    }
    try {
      const raw = fs.readFileSync(this.filePath, "utf-8");
      return raw
        .split("\n")
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as AuditEntry);
    } catch (err) {
      console.error("Vaultline: audit log read failed:", err);
      return [];
    }
  }

  getFilePath(): string {
    return this.filePath;
  }
}
