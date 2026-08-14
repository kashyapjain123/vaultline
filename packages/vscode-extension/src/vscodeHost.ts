/**
 * VS Code's implementation of the core's host boundary.
 *
 * This is the entire VS Code-specific half of the engine — settings,
 * storage, logging, notifications, progress, clipboard. It is deliberately
 * mechanical: every method is a direct translation, with no logic of its
 * own, because any logic that ends up here is logic a second host would have
 * to reimplement. If something looks like it wants a decision made in this
 * file, it belongs in @vaultline/core instead.
 *
 * The equivalent file for another editor (an IntelliJ plugin, say) is the
 * only thing that has to be written from scratch to port Vaultline: this,
 * plus an adapter for that editor's chat API (see chatParticipant.ts).
 */

import {
  DEFAULT_SETTINGS,
  LogChannel,
  ProgressOptions,
  ProgressToken,
  VaultlineHost,
  VaultlineSettings,
  sanitizeSettings,
} from "@vaultline/core";
import * as vscode from "vscode";

export class VsCodeHost implements VaultlineHost {
  private readonly channels: vscode.OutputChannel[] = [];
  /** Last set of rejected setting keys, so a bad value is reported once rather than on every scan. */
  private lastRejectedSignature = "";
  private settingsLog: LogChannel | null = null;

  constructor(private readonly context: vscode.ExtensionContext) {}

  /**
   * Read every setting the core declares, in one pass keyed off
   * DEFAULT_SETTINGS.
   *
   * Iterating the core's own key set — rather than writing one `config.get`
   * call per setting with inline fallbacks — is what stops the two from
   * drifting: a setting added to the core is read here automatically, and one missing
   * from package.json falls back to the core's default instead of
   * `undefined`. scripts/checkSettings.js turns the remaining gap (a setting
   * the manifest never declares, so the UI never offers it) into a build
   * error.
   */
  settings(): VaultlineSettings {
    const config = vscode.workspace.getConfiguration("vaultline");
    const raw: Record<string, unknown> = {};
    for (const key of Object.keys(DEFAULT_SETTINGS)) raw[key] = config.get(key);

    // Through sanitizeSettings rather than trusting config.get() directly.
    // VS Code does NOT validate settings.json against the manifest schema, so
    // a hand-edited, synced, or repo-committed workspace file can put anything
    // under any key — and the values that got through unchecked broke detection
    // silently: routingMinSimilarity as NaN made `score >= NaN` always false,
    // skipping every contextual detector with no error anywhere.
    const { settings, rejected } = sanitizeSettings(raw);

    // Reported once per distinct set of bad keys, not once per message: this is
    // called for every scan, and a per-message warning would be noise. Silence
    // was the actual problem, though — the whole point is that a typo becomes
    // visible instead of quietly turning detection off.
    if (rejected.length > 0) {
      const signature = rejected.join(",");
      if (signature !== this.lastRejectedSignature) {
        this.lastRejectedSignature = signature;
        // Lazily created: the overwhelmingly common case is that nothing is
        // ever rejected, and an always-present empty channel is clutter.
        this.settingsLog ??= this.createLogChannel("Vaultline Settings");
        this.settingsLog.append(
          `Ignoring ${rejected.length} setting(s) whose value doesn't match the expected type, using defaults ` +
            `instead: ${rejected.join(", ")}. Check these in settings.json.`
        );
      }
    } else {
      this.lastRejectedSignature = "";
    }

    return settings;
  }

  // Backed by the OS keychain (Keychain / Credential Manager / libsecret) and
  // deliberately NOT synced, unlike a setting. See VaultlineHost.secret().
  async secret(key: string): Promise<string | undefined> {
    return this.context.secrets.get(key);
  }

  async storeSecret(key: string, value: string): Promise<void> {
    await this.context.secrets.store(key, value);
  }

  async deleteSecret(key: string): Promise<void> {
    await this.context.secrets.delete(key);
  }

  storagePath(): string {
    return this.context.globalStorageUri.fsPath;
  }

  createLogChannel(name: string): LogChannel {
    const channel = vscode.window.createOutputChannel(name);
    this.channels.push(channel);
    return {
      append: (message) => channel.appendLine(message),
      show: () => channel.show(),
      dispose: () => channel.dispose(),
    };
  }

  async warn(message: string, ...actions: string[]): Promise<string | undefined> {
    return vscode.window.showWarningMessage(`Vaultline: ${message}`, ...actions);
  }

  async info(message: string, ...actions: string[]): Promise<string | undefined> {
    return vscode.window.showInformationMessage(`Vaultline: ${message}`, ...actions);
  }

  withProgress<T>(options: ProgressOptions, task: (token: ProgressToken) => Promise<T>): Promise<T> {
    // Promise.resolve() because withProgress returns a Thenable, and the core
    // asks for a real Promise (it chains .finally on some of these).
    return Promise.resolve(
      vscode.window.withProgress(
        {
          location:
            options.location === "notification" ? vscode.ProgressLocation.Notification : vscode.ProgressLocation.Window,
          title: options.title,
          cancellable: options.cancellable ?? false,
        },
        (_progress, cancellation) =>
          task({ onCancelled: (listener) => cancellation.onCancellationRequested(() => listener()) })
      )
    );
  }

  async copyToClipboard(text: string): Promise<void> {
    await vscode.env.clipboard.writeText(text);
  }

  dispose(): void {
    for (const channel of this.channels) channel.dispose();
  }
}
