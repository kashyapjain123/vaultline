/**
 * GitHub Copilot CLI's built-in tool names.
 *
 * These are not published anywhere, and getting them from the obvious place
 * was wrong in a way worth recording.
 *
 * The CLI's bundle contains a registry that looks authoritative:
 *
 *     [{name:"view",categories:["read"]},{name:"glob",...},{name:"grep",...},
 *      {name:"rg",...},{name:"edit",...},{name:"create",...},
 *      {name:"str_replace_editor",...},{name:"apply_patch",...}]
 *
 * It is not the runtime tool list. It is the capability check behind
 * `copilot init`, which is why it names tools the CLI does not actually
 * offer. Excluding those produced:
 *
 *     ● Disabled tools: create, edit, glob, grep, view
 *     ● Unknown tool name in the tool excludedlist: "rg"
 *     ● Unknown tool name in the tool excludedlist: "shell"
 *     ● Unknown tool name in the tool excludedlist: "str_replace_editor"
 *     ● Unknown tool name in the tool excludedlist: "apply_patch"
 *
 * — and, far worse than the four noisy warnings, `shell` is not the shell
 * tool's name, so the real one (`bash`) stayed enabled and command output
 * reached the model unredacted while the setup looked like it was working.
 *
 * The names below are taken from the tool array in an actual request payload,
 * captured with `--log-level debug`, which is the only ground truth. Verified
 * against CLI 1.0.80. `vaultline doctor --live` re-verifies against whatever
 * version is installed; nothing offline can, which is why that command exists.
 */

/**
 * Tools that bring content INTO the model. Each must be excluded and replaced,
 * or Vaultline never sees the bytes.
 *
 * `grep` earns its place: it returns matching LINES, so `grep -r password .`
 * is a file-content read wearing a different name. `glob` returns paths only,
 * which still discloses usernames, home directories and project layout.
 *
 * The bash family is one unit. `bash` runs the command and `read_bash` returns
 * output from a backgrounded one, so excluding only the first would leave a
 * second, quieter path to the same bytes.
 */
export const BUILTIN_READ_TOOLS = ["view", "grep", "glob", "bash", "read_bash", "list_bash", "stop_bash"] as const;

/**
 * Tools that write model-authored content BACK to disk. These matter for the
 * opposite reason: after a redacted read the model holds `<<PASSWORD_1>>`, and
 * a built-in write would put that placeholder into the user's file in place of
 * their real credential.
 */
export const BUILTIN_WRITE_TOOLS = ["edit", "create"] as const;

/**
 * Subagent launcher, excluded on purpose and separately from the two lists
 * above because the reasoning is different — and because it is the one
 * exclusion a user might reasonably want back.
 *
 * `task` spawns an agent with its own toolset, described by the CLI itself as
 * "grep/glob/view/bash". If those exclusions do not propagate into the
 * subagent, it is a complete bypass: the subagent reads the file with a
 * built-in tool and Vaultline never sees it. Whether they propagate is not
 * documented, and a security boundary resting on undocumented inheritance is
 * not a boundary. Excluded until that can be demonstrated either way.
 */
export const BUILTIN_DELEGATION_TOOLS = ["task"] as const;

/** Every built-in tool Vaultline replaces or suppresses, for `--excluded-tools`. */
export const EXCLUDED_BUILTINS: string[] = [
  ...new Set<string>([...BUILTIN_READ_TOOLS, ...BUILTIN_WRITE_TOOLS, ...BUILTIN_DELEGATION_TOOLS]),
];

/**
 * Names that are NOT excluded, recorded so the decision is visible rather than
 * looking like an oversight:
 *
 *   web_fetch                       brings in remote pages, not the user's files
 *   sql, session_store_sql          query the CLI's own session store
 *   skill, list_agents, read_agent, write_agent, fetch_copilot_cli_documentation
 *                                   no filesystem read path
 */
export const DELIBERATELY_ALLOWED = ["web_fetch", "sql", "session_store_sql", "skill"] as const;

/** The MCP server name Copilot CLI knows us by. Tools appear to the model as `vaultline-vaultline_read` and to permissions as `vaultline(vaultline_read)`. */
export const MCP_SERVER_NAME = "vaultline";
