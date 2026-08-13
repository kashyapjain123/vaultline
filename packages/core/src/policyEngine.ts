/**
 * Layer 5 (decision half): Policy Engine
 *
 * Takes raw matches from the detection layers and decides what actually
 * happens: let it through, redact just the sensitive spans, or block the
 * whole request. logic is intentionally simple — severity-threshold
 * based — real policy config would be per-organization and rule-overridable.
 *
 * businessMatches (see businessContentDetector.ts) are handled as a special
 * case: a business-content flag's span is the ENTIRE message by definition,
 * so there's no sensible "redact" outcome for it — only block or ignore. It
 * is intentionally never mixed into the caller's tokenize() input, only
 * used here to decide whether to block outright.
 */

import { Match, Severity, SEVERITY_RANK } from "./patternMatcher";

export type Action = "allow" | "redact" | "block";

export interface PolicyConfig {
  blockOnHighSeverity: boolean;
  /** Default true — a whole-message business-content flag always blocks rather than "redacts" (there's nothing sensible to redact-in-place for a whole-message concern). Set false to only log/report it without blocking. */
  blockOnBusinessContent?: boolean;
}

export interface PolicyDecision {
  action: Action;
  reason: string;
  /** Everything found, entity-level AND business-level, for audit/display. NOT what should be passed to tokenize() — callers should use the entity-level `matches` array they already have for that. */
  matches: Match[];
}

export function decide(matches: Match[], businessMatches: Match[], config: PolicyConfig): PolicyDecision {
  const allForReporting = [...matches, ...businessMatches];

  if (businessMatches.length > 0 && (config.blockOnBusinessContent ?? true)) {
    return {
      action: "block",
      reason: `Blocked: ${businessMatches[0].label}. This looks like it may reference confidential business content — rephrase without specific figures, project names, or internal plans, or request an exception.`,
      matches: allForReporting,
    };
  }

  if (matches.length === 0) {
    return { action: "allow", reason: "No sensitive content detected.", matches: allForReporting };
  }

  const highestSeverity = matches.reduce<Severity>(
    (max, m) => (SEVERITY_RANK[m.severity] > SEVERITY_RANK[max] ? m.severity : max),
    "low"
  );

  if (highestSeverity === "high" && config.blockOnHighSeverity) {
    return {
      action: "block",
      reason: `Blocked: ${matches.filter((m) => m.severity === "high").length} high-severity match(es) found (e.g. ${matches.find((m) => m.severity === "high")?.label}).`,
      matches: allForReporting,
    };
  }

  return {
    action: "redact",
    reason: `Redacted ${matches.length} match(es) before sending to the model.`,
    matches: allForReporting,
  };
}
