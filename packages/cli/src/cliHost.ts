/**
 * VaultlineHost for a terminal.
 *
 * ConsoleHost in @vaultline/core already satisfies the whole interface, so
 * this exists only for the three things a real CLI installation needs beyond
 * a test double: settings from a file, a durable storage directory, and
 * secrets in the OS keychain rather than in memory.
 *
 * The one non-obvious constraint is logging. When this process is running as
 * an MCP server, stdout carries JSON-RPC frames, so ConsoleHost's
 * console.log-based log channel would corrupt the protocol stream. Everything
 * diagnostic goes to stderr instead.
 */

import { execFile } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { promisify } from "util";
import { ConsoleHost, DEFAULT_SETTINGS, LogChannel, VaultlineSettings, sanitizeSettings } from "@vaultline/core";

const execFileAsync = promisify(execFile);

export const VAULTLINE_HOME = path.join(os.homedir(), ".vaultline");
export const CONFIG_PATH = path.join(VAULTLINE_HOME, "config.json");

/** Keychain service name. Kept distinct from the VS Code extension's entries so uninstalling one does not disturb the other. */
const KEYCHAIN_SERVICE = "vaultline-cli";

export interface LoadedConfig {
  settings: VaultlineSettings;
  /** Keys the file supplied that were malformed and fell back to defaults. Surfaced by `doctor`. */
  rejected: string[];
  /** False when no config file exists — a normal first run, not an error. */
  found: boolean;
}

/**
 * Read ~/.vaultline/config.json through the core's own sanitizer.
 *
 * Going through sanitizeSettings matters more here than it looks: a malformed
 * routingMinSimilarity silently disabled ALL contextual detection once before,
 * and a hand-edited JSON file is a far likelier source of that than a settings
 * UI. Rejections are reported rather than swallowed.
 */
export function loadConfig(configPath = CONFIG_PATH): LoadedConfig {
  if (!fs.existsSync(configPath)) {
    return { settings: { ...DEFAULT_SETTINGS }, rejected: [], found: false };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch (err) {
    throw new Error(`${configPath} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  const { settings, rejected } = sanitizeSettings(raw as Record<string, unknown>);
  return { settings, rejected, found: true };
}

export class CliHost extends ConsoleHost {
  private readonly resolvedSettings: VaultlineSettings;
  private readonly homeDir: string;
  /** Fallback when no OS keychain is usable. Not persisted — the contract is only "not the settings file". */
  private readonly memorySecrets = new Map<string, string>();

  constructor(settings: VaultlineSettings, homeDir = VAULTLINE_HOME) {
    super(settings, homeDir);
    this.resolvedSettings = settings;
    this.homeDir = homeDir;
    fs.mkdirSync(homeDir, { recursive: true });
  }

  settings(): VaultlineSettings {
    return this.resolvedSettings;
  }

  storagePath(): string {
    return this.homeDir;
  }

  /** stderr, never stdout — see the file header. */
  createLogChannel(name: string): LogChannel {
    return {
      append: (message) => process.stderr.write(`[${name}] ${message}\n`),
      show: () => {},
      dispose: () => {},
    };
  }

  async warn(message: string): Promise<string | undefined> {
    process.stderr.write(`Vaultline: ${message}\n`);
    return undefined;
  }

  async info(message: string): Promise<string | undefined> {
    process.stderr.write(`Vaultline: ${message}\n`);
    return undefined;
  }

  // ---------------------------------------------------------------
  // Secrets
  //
  // macOS `security` and Linux `secret-tool` are shelled out to rather than
  // pulled in as native bindings: this package ships as plain JS with no
  // build step, and a keytar-style dependency would reintroduce exactly the
  // supply-chain surface package.json explains we are avoiding. Where
  // neither binary exists we degrade to memory and say so, rather than
  // quietly writing a credential to disk.
  // ---------------------------------------------------------------

  async secret(key: string): Promise<string | undefined> {
    try {
      if (process.platform === "darwin") {
        const { stdout } = await execFileAsync("security", ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", key, "-w"]);
        return stdout.trimEnd() || undefined;
      }
      if (process.platform === "linux") {
        const { stdout } = await execFileAsync("secret-tool", ["lookup", "service", KEYCHAIN_SERVICE, "account", key]);
        return stdout || undefined;
      }
    } catch {
      // Not found, or no keychain tool on this machine. Both mean "ask memory".
    }
    return this.memorySecrets.get(key);
  }

  async storeSecret(key: string, value: string): Promise<void> {
    try {
      if (process.platform === "darwin") {
        // -U updates in place; without it a second store fails with a duplicate error.
        await execFileAsync("security", ["add-generic-password", "-s", KEYCHAIN_SERVICE, "-a", key, "-w", value, "-U"]);
        return;
      }
      if (process.platform === "linux") {
        await execFileAsync("secret-tool", ["store", "--label", `Vaultline ${key}`, "service", KEYCHAIN_SERVICE, "account", key], {
          env: { ...process.env },
        });
        return;
      }
    } catch {
      /* fall through to memory */
    }
    this.memorySecrets.set(key, value);
  }

  async deleteSecret(key: string): Promise<void> {
    try {
      if (process.platform === "darwin") {
        await execFileAsync("security", ["delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", key]);
      } else if (process.platform === "linux") {
        await execFileAsync("secret-tool", ["clear", "service", KEYCHAIN_SERVICE, "account", key]);
      }
    } catch {
      /* not there to delete */
    }
    this.memorySecrets.delete(key);
  }

  /** True when credentials would only live in memory, so `doctor` can say so out loud. */
  static keychainAvailable(): boolean {
    return process.platform === "darwin" || process.platform === "linux";
  }
}
