/**
 * MCP tool calls/results are JSON, not prose — {"username": "rahul.sharma"}
 * rather than "the username is rahul.sharma". A bare value string has none
 * of the context (a nearby keyword, an assignment operator) that the
 * content-based detectors in detectionPipeline.ts rely on — "hunter2isnot
 * secure" on its own, with no "password" keyword next to it, doesn't look
 * like anything in particular. The field's KEY carries that context
 * instead, so field-level masking has to check the key name directly, not
 * just run content detection on the value in isolation.
 *
 * So this does BOTH: if the key name matches a known sensitive field name,
 * the entire value is treated as sensitive regardless of its shape
 * (field-level masking, matching how most MCP schemas actually name their
 * fields). Separately, every string value ALSO still goes through the
 * normal content-based pipeline, so something sensitive can still be
 * caught even under an innocuous key name (e.g. a "notes" field that
 * happens to contain a credit card number).
 */

import { scanCurrentMessage, ScanOptions } from "../detectionPipeline";
import { tokenize, restore, TokenMapping } from "../tokenizer";
import { EntityStore } from "../entityStore";
import { Match } from "../patternMatcher";

// Key name -> entity type + category, checked case-insensitively with
// underscores/hyphens normalized away ("api_key", "api-key", "apiKey" all
// match "apikey"). Grow this list the same way the other keyword lists in
// this codebase grow — via the audit-log feedback loop.
const SENSITIVE_FIELD_NAMES: Record<string, { entityType: string; category: Match["category"]; severity: Match["severity"] }> = {
  password: { entityType: "PASSWORD", category: "SECRET", severity: "high" },
  passwd: { entityType: "PASSWORD", category: "SECRET", severity: "high" },
  pwd: { entityType: "PASSWORD", category: "SECRET", severity: "high" },
  secret: { entityType: "SECRET", category: "SECRET", severity: "high" },
  apikey: { entityType: "API_KEY", category: "SECRET", severity: "high" },
  accesstoken: { entityType: "TOKEN", category: "SECRET", severity: "high" },
  authtoken: { entityType: "TOKEN", category: "SECRET", severity: "high" },
  token: { entityType: "TOKEN", category: "SECRET", severity: "medium" },
  privatekey: { entityType: "PRIVATE_KEY", category: "SECRET", severity: "high" },
  clientsecret: { entityType: "SECRET", category: "SECRET", severity: "high" },
  ssn: { entityType: "SSN", category: "PII", severity: "high" },
  aadhaar: { entityType: "AADHAAR", category: "PII", severity: "high" },
  pan: { entityType: "PAN", category: "PII", severity: "high" },
  accountnumber: { entityType: "ACCOUNT_NUMBER", category: "PII", severity: "high" },
  cardnumber: { entityType: "CARD_NUMBER", category: "PII", severity: "high" },
  creditcard: { entityType: "CARD_NUMBER", category: "PII", severity: "high" },
  email: { entityType: "EMAIL", category: "PII", severity: "low" },
  phone: { entityType: "PHONE", category: "PII", severity: "medium" },
  phonenumber: { entityType: "PHONE", category: "PII", severity: "medium" },
  username: { entityType: "PERSON", category: "PII", severity: "medium" },
  ipaddress: { entityType: "IP_ADDRESS", category: "INFRA", severity: "medium" },
  hostname: { entityType: "HOSTNAME", category: "INFRA", severity: "medium" },
  host: { entityType: "HOSTNAME", category: "INFRA", severity: "medium" },
};

function normalizeFieldName(key: string): string {
  return key.toLowerCase().replace(/[_\-\s]/g, "");
}

export interface JsonRedactResult {
  redacted: unknown;
  mappings: TokenMapping[];
}

export async function redactJson(value: unknown, store: EntityStore, scanOptions: ScanOptions = {}): Promise<JsonRedactResult> {
  const allMappings: TokenMapping[] = [];

  async function walkString(str: string, fieldKey: string | null): Promise<string> {
    // Field-level: does the KEY itself name a known sensitive field?
    const fieldRule = fieldKey ? SENSITIVE_FIELD_NAMES[normalizeFieldName(fieldKey)] : undefined;

    if (fieldRule && str.length > 0) {
      const match: Match = {
        ruleId: `mcp-field-${normalizeFieldName(fieldKey!)}`,
        label: `${fieldKey} field (MCP field-level match)`,
        severity: fieldRule.severity,
        category: fieldRule.category,
        value: str,
        start: 0,
        end: str.length,
      };
      const { redactedText, mappings } = tokenize(str, [match], store);
      allMappings.push(...mappings);
      return redactedText;
    }

    // Content-level fallback: run the normal pipeline even when the key
    // name itself gave no hint (e.g. "notes", "description", "message").
    // scanCurrentMessage, NOT scanAll: a tool result string is very often
    // an entire multi-line file (e.g. a file-read tool) with several
    // unrelated topics/categories spread across different lines — pooling
    // the whole thing into one embedding for routing dilutes every
    // category's score the same way a long chat message does (see
    // detectionPipeline.ts's module comment). Structural regex isn't
    // gated by routing at all, so it always still fires regardless; this
    // only affects the routing-gated contextual detectors (PII/infra
    // context, conversational secrets).
    const { matches } = await scanCurrentMessage(str, scanOptions);
    if (matches.length === 0) return str;
    const { redactedText, mappings } = tokenize(str, matches, store);
    allMappings.push(...mappings);
    return redactedText;
  }

  async function walk(node: unknown, fieldKey: string | null): Promise<unknown> {
    if (typeof node === "string") {
      return walkString(node, fieldKey);
    }
    if (Array.isArray(node)) {
      const out = [];
      for (const item of node) out.push(await walk(item, fieldKey)); // array items inherit the parent field's key context
      return out;
    }
    if (node !== null && typeof node === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        out[k] = await walk(v, k);
      }
      return out;
    }
    return node; // number, boolean, null, undefined
  }

  const redacted = await walk(value, null);
  return { redacted, mappings: allMappings };
}

/** Reverses redactJson — walks the same shape, restoring tokens in every string leaf. Uses store.allMappings() by default so it can restore tokens minted in EARLIER calls too, not just the immediately preceding one (needed for multi-step tool loops). */
export function rehydrateJson(value: unknown, store: EntityStore): unknown {
  const mappings = store.allMappings();

  function walk(node: unknown): unknown {
    if (typeof node === "string") return restore(node, mappings);
    if (Array.isArray(node)) return node.map(walk);
    if (node !== null && typeof node === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) out[k] = walk(v);
      return out;
    }
    return node;
  }

  return walk(value);
}
