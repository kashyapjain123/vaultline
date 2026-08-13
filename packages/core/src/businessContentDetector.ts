/**
 * Business Content Detector
 *
 * Every other detector in this pipeline finds a specific SPAN to redact —
 * a key, an email, an IP. This category is different on purpose: "we're
 * spending a budget figure on Project Falcon" has no fixed format, no anchor
 * keyword. There's nothing token-shaped to replace with [SEC-N]; the
 * sentence is only sensitive as a whole, because of what it means, and
 * that's a genuinely different job than the regex/proximity techniques
 * everywhere else in this pipeline can do.
 *
 * So this detector doesn't extract an entity — it flags the ENTIRE
 * message and lets the policy engine decide what to do with a
 * message-level match (in practice: block or warn, not redact-and-forward,
 * since there's no way to redact "this whole sentence" and still leave
 * anything useful for the model to work with).
 *
 * This only runs when the embedding router's business-strategy score
 * clears a deliberately high, separate threshold — see embeddingRouter.ts
 * for why this category needs stricter gating than the others.
 */

import { Match, Category } from "./patternMatcher";

const CATEGORY: Category = "BUSINESS";

export function scanBusinessContent(text: string, similarityScore: number): Match[] {
  const severity = similarityScore >= 0.55 ? "high" : similarityScore >= 0.45 ? "medium" : "low";

  const preview = text.length > 80 ? text.slice(0, 80) + "…" : text;

  return [
    {
      ruleId: "business-strategy-contextual",
      label: `Possible confidential business content (embedding similarity ${similarityScore.toFixed(2)})`,
      severity,
      category: CATEGORY,
      value: preview,
      start: 0,
      end: text.length,
    },
  ];
}
