/**
 * Choosing which tools to offer the model.
 *
 * WHY THIS EXISTS: a chat participant that forwards its editor's whole tool
 * registry hits a hard provider limit. VS Code's `vscode.lm.tools` includes
 * every built-in tool, every extension-contributed tool and every MCP tool the
 * user has configured — and once that crosses the provider's ceiling the model
 * call fails outright:
 *
 *     Cannot have more than 128 tools per request
 *
 * That is not a degraded answer, it is no answer: the request dies before the
 * model sees a single token, so @vaultline stops working entirely for exactly
 * the users who have invested most in their setup. A cap is not an optimisation
 * here, it is the difference between working and not.
 *
 * WHY IT LIVES IN THE CORE: the rule is host-neutral (a list of named tools, a
 * ceiling, a deny list) and worth testing without booting an editor. The host
 * keeps only the part that is genuinely about VS Code — reading
 * `vscode.lm.tools` and passing the result to sendRequest.
 *
 * ORDER IS PRESERVED, deliberately. `vscode.lm.tools` is not arbitrary — the
 * editor's own built-ins (file read, search, terminal) come first, with
 * extension and MCP tools after, so "keep the first N" keeps the general-purpose
 * tools a request like "review this codebase" actually needs and drops the long
 * tail of niche integrations. Re-sorting by name would scatter that ordering and
 * make which tools survive depend on their spelling.
 */

/** The minimum this module needs to know about a tool — a structural subset of VS Code's LanguageModelToolInformation. */
export interface ToolDescriptor {
  name: string;
}

export interface ToolSelectionOptions {
  /** Hard ceiling on how many tools may be offered. */
  max: number;
  /** Tool-name patterns to exclude entirely. `*` matches any run of characters; matching is case-insensitive. */
  denyList?: readonly string[];
}

export interface ToolSelectionResult<T extends ToolDescriptor> {
  selected: T[];
  /** Excluded by the deny list — the user asked for these to be gone. */
  denied: T[];
  /** Excluded only because of `max`. Worth telling the user about: they didn't ask for it, and it changes what the model can do. */
  truncated: T[];
}

/** Compile one deny-list pattern into a regex, treating `*` as a wildcard and escaping everything else. */
function patternToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`, "i");
}

/**
 * Apply the deny list, then the ceiling.
 *
 * Deny first so a user who prunes noisy integrations gets that budget back for
 * the tools they actually want, rather than having the ceiling spend it on
 * tools they already said they didn't want.
 */
export function selectTools<T extends ToolDescriptor>(
  all: readonly T[],
  options: ToolSelectionOptions
): ToolSelectionResult<T> {
  const patterns = (options.denyList ?? []).filter((p) => p.trim().length > 0).map(patternToRegExp);

  const denied: T[] = [];
  const kept: T[] = [];
  for (const tool of all) {
    if (patterns.some((re) => re.test(tool.name))) denied.push(tool);
    else kept.push(tool);
  }

  // A non-positive max means "no tools", not "unlimited" — an unlimited option
  // would just reintroduce the failure this module exists to prevent.
  const max = Math.max(0, Math.floor(options.max));
  return { selected: kept.slice(0, max), denied, truncated: kept.slice(max) };
}

/**
 * Pull a tool ceiling out of a provider's error message.
 *
 * The 128 limit is Copilot's today, but it is a provider detail, not a contract
 * — another model may allow fewer. Rather than hardcoding a guess for every
 * backend, read the number the provider just told us and retry against it. A
 * failed parse returns null and the caller falls back to dropping tools
 * entirely, which still answers the question.
 */
export function parseToolLimitFromError(message: string): number | null {
  if (!/tool/i.test(message)) return null;
  const match = /more than (\d+)\s+tools?/i.exec(message) ?? /maximum of (\d+)\s+tools?/i.exec(message);
  if (!match) return null;
  const limit = Number(match[1]);
  return Number.isFinite(limit) && limit > 0 ? limit : null;
}
