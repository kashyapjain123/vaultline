/**
 * The host boundary.
 *
 * Everything else in this package is pure: rules, pipeline, tokenizer,
 * entity store, embedders. This file is the ONE place that describes what
 * the core needs FROM an editor, so that a second editor integration is a
 * matter of implementing this interface rather than reimplementing the
 * engine.
 *
 * The methods here were not invented up front — each one is a VS Code call
 * that used to sit inline in the engine and had to come out for it to be
 * host-neutral:
 *
 *   settings()          <- vscode.workspace.getConfiguration("vaultline")
 *   storagePath()       <- context.globalStorageUri.fsPath
 *   createLogChannel()  <- vscode.window.createOutputChannel
 *   warn()/info()       <- vscode.window.showWarningMessage (+ actions)
 *   withProgress()      <- vscode.window.withProgress
 *   copyToClipboard()   <- vscode.env.clipboard.writeText
 *
 * Deliberately NOT in here: anything about chat, language models, tools, or
 * documents. Those differ far too much between editors to abstract usefully,
 * and the core doesn't need them — GuardSession takes and returns plain
 * strings and plain JSON, and the host adapts its own chat API to that.
 *
 * ConsoleHost at the bottom means the core is usable with no editor at all
 * (tests, CLI, the embedding build script), which is the real proof that
 * the boundary holds.
 */

import * as os from "os";
import * as path from "path";
import { DEFAULT_SETTINGS, VaultlineSettings } from "./settings";

/** A named, append-only log destination — VS Code's OutputChannel, IntelliJ's ConsoleView, or stderr. */
export interface LogChannel {
  append(message: string): void;
  show(): void;
  dispose(): void;
}

export interface ProgressOptions {
  title: string;
  /**
   * "notification" — a prominent, optionally cancellable toast; used for the
   * one-time multi-minute dependency install.
   * "window" — a quiet status-bar-level indicator; used for model loading.
   * A host with only one progress affordance can treat both the same.
   */
  location: "notification" | "window";
  cancellable?: boolean;
}

/** Handed to a progress task so long work can react to the user cancelling it. */
export interface ProgressToken {
  onCancelled(listener: () => void): void;
}

export interface VaultlineHost {
  /**
   * Current settings. Called fresh at each decision point rather than
   * captured once, because a user can change any of these mid-session and
   * the engine is expected to pick that up without a reload (the two
   * exceptions, which genuinely do need a reload, are reported by
   * VaultlineEngine.settingsChanged()).
   */
  settings(): VaultlineSettings;

  /** A writable directory this installation owns: audit log, session entity mappings, and the embedding server's per-machine dependency install all live under it. */
  storagePath(): string;

  createLogChannel(name: string): LogChannel;

  /** Surface a warning. `actions` are button labels; resolves to the chosen label, or undefined if dismissed. A host with no action affordance may ignore them and resolve undefined. */
  warn(message: string, ...actions: string[]): Promise<string | undefined>;

  /** As warn(), at informational severity. */
  info(message: string, ...actions: string[]): Promise<string | undefined>;

  withProgress<T>(options: ProgressOptions, task: (token: ProgressToken) => Promise<T>): Promise<T>;

  copyToClipboard(text: string): Promise<void>;
}

/** A ProgressToken that is never cancelled — for hosts without cancellation. */
export const NEVER_CANCELLED: ProgressToken = { onCancelled: () => {} };

/**
 * Headless VaultlineHost: logs to the console, never prompts, runs progress
 * tasks straight through. Everything the engine does works under this — which
 * is exactly the point of the interface. Pass partial settings to override
 * individual defaults.
 */
export class ConsoleHost implements VaultlineHost {
  private readonly resolved: VaultlineSettings;

  constructor(settings: Partial<VaultlineSettings> = {}, private readonly storageDir = path.join(os.tmpdir(), "vaultline")) {
    this.resolved = { ...DEFAULT_SETTINGS, ...settings };
  }

  settings(): VaultlineSettings {
    return this.resolved;
  }

  storagePath(): string {
    return this.storageDir;
  }

  createLogChannel(name: string): LogChannel {
    return {
      append: (message) => console.log(`[${name}] ${message}`),
      show: () => {},
      dispose: () => {},
    };
  }

  async warn(message: string): Promise<string | undefined> {
    console.warn(`Vaultline: ${message}`);
    return undefined;
  }

  async info(message: string): Promise<string | undefined> {
    console.log(`Vaultline: ${message}`);
    return undefined;
  }

  withProgress<T>(options: ProgressOptions, task: (token: ProgressToken) => Promise<T>): Promise<T> {
    console.log(`Vaultline: ${options.title}`);
    return task(NEVER_CANCELLED);
  }

  async copyToClipboard(): Promise<void> {
    /* nothing to copy to */
  }
}
