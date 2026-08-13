# Vaultline

**Zero-trust context control for AI coding agents.** Talk to your model through
`@vaultline` and secrets, PII and internal infrastructure details are replaced
with typed placeholders *before* the request leaves your machine — then
substituted back in the answer, so you still read your own real values.

Detection runs entirely locally. No telemetry, no accounts, nothing phoned home.

---

## How it works

You type this:

```
@vaultline write a python client for https://svc-01.corp.example.internal/api/getToken,
the password is hunter1isnotsecure
```

The model receives this:

```
write a python client for <<URL_1>>, the password is <<PASSWORD_1>>
```

and you get the answer back with the real URL and password already restored in
the code. The model reasons perfectly well about `<<PASSWORD_1>>` — it just
never learns what it stands for.

Placeholders are **typed and stable**: the same value gets the same token for
the whole session, so multi-step tool loops keep working. Tool arguments are
rehydrated before the tool runs, and every tool result is redacted before it
goes back to the model.

### Credentials mentioned across turns

Real conversations split a credential over two messages:

```
you:  ...and the password is
you:  can you replace it with hunter1isnotsecure
```

The second message has no keyword to anchor on. Vaultline carries the credential
context forward for a couple of turns, so the value is still caught. Tune with
`crossTurnSecretTurns`, or switch it off entirely.

---

## What it catches

- **Secrets** — AWS keys, GitHub/Slack tokens, JWTs, private-key blocks,
  connection strings, `.env`-style assignments, and conversational phrasings
  like "my api key is …".
- **PII** — emails, phone numbers, government IDs (SSN, Aadhaar, PAN,
  passport, driver's licence), card numbers (Luhn-checked), account numbers,
  currency amounts.
- **Infrastructure** — internal URLs and hostnames, private/public IPs, IPv6,
  MAC addresses, ports, file paths.
- **Business content** — a whole-message judgment (strategy, financials) that
  blocks rather than redacts, since there's no single span to replace.

Structural rules (regex) always run. Contextual detectors are gated by a local
embedding model so they only run where they're plausibly relevant — and if that
model is unavailable, detection **fails open**: every detector runs instead of
being skipped.

Syntax-aware suppression parses code with tree-sitter so low-precision rules
stop firing inside comments, while unambiguous secret rules keep firing there —
because commenting out a config line is one of the most ordinary ways a
credential ends up in a file.

---

## In the editor

Independently of chat, Vaultline marks up what it finds in open files:

- **Highlighting** with hover detail — entity type, severity, category, and the
  rule that fired.
- **Ghost text** on the cursor's line when it holds something sensitive.
- **Lightbulb** actions to anonymize one value, a selection, or the whole file.

Highlighting is an **affordance, not the enforcement point** — it skips the two
detectors that need an embedding call, so an unhighlighted value may still be
redacted on its way out.

### Anonymize and restore

| Mode | Looks like | Reversible |
|---|---|---|
| `placeholder` (default) | `<<EMAIL_1>>` | Yes |
| `hash` | `[EMAIL_a1b2c3d4]` | Yes — same value always yields the same token |
| `mask` | `***` | **No** — no mapping is saved |

Mask asks for confirmation first, and restore refuses on a masked document
rather than guessing.

---

## Commands

| Command | What it does |
|---|---|
| **Test Detection Pipeline on Selection** | Runs the full pipeline over the selection without sending it anywhere, and without minting tokens a real conversation would have to resolve |
| **Show Audit Log** | The local JSON-lines audit trail, tagged by source (`prompt` / `tool:<name>` / `history`) |
| **Restart Embedding Server** | Recovers a wedged local model server, promoting routing back from the hashing fallback with no reload |
| **Anonymize Selection / Document** | Rewrite detected values in place |
| **Restore Document** | Put the original values back from the saved mapping |

The anonymize/restore commands are also in the editor's right-click menu.

---

## Scope: what `@vaultline` can and can't see

Built on two public, model-agnostic VS Code APIs —
`vscode.chat.createChatParticipant` and `vscode.lm`. Nothing here is
Copilot-specific.

**It sees** any model that plugs into `vscode.lm`, and any tool contributed via
`languageModelTools` or native MCP support — *as long as the conversation goes
through `@vaultline`*.

**It does not see** another extension's own chat UI that never touches
`vscode.lm`. Assistants that ship a custom webview and make their own network
calls have nothing for Vaultline to intercept, and the same is true of
standalone CLI tools that talk to their provider directly. GitHub Copilot's own
agent mode is not interceptable today either — VS Code exposes no public API
for it.

This is a deliberate, checkable boundary rather than a claim of universal
coverage: if a request doesn't go through `@vaultline`, Vaultline never saw it.

---

## First run

The platform-specific builds bundle everything, including the embedding model —
they work offline with no setup.

The portable build downloads the model (~23MB) and installs the server's
dependencies the first time the embedding server starts. Until it's ready,
routing falls back to a local hashing embedder, and detection still runs.

Set `embeddingBackend` to `"hashing"` to skip the model server entirely.

---

## Configuration

35 settings under `vaultline.*`. The ones most worth knowing:

| Setting | Default | Purpose |
|---|---|---|
| `enablePiiDetection` / `enableInfraDetection` / `enableConversationalSecretDetection` / `enableBusinessContentDetection` | `true` | Toggle each detection layer |
| `enableCrossTurnSecretCarryover` / `crossTurnSecretTurns` | `true` / `2` | Keep detecting credentials for N turns after one is mentioned. Lower to `1` if unrelated value-shaped strings (commit hashes, build IDs) get redacted |
| `blockOnHighSeverity` | `false` | Block instead of redact on a high-severity match. Off by default: inside a tool loop one false positive aborts the whole task, and redaction already keeps the value from leaving |
| `enableToolCalling` | `true` | Whether `@vaultline` exposes `vscode.lm.tools` to the model |
| `enableSyntaxAwareRedaction` | `true` | Stop low-precision rules firing inside code comments |
| `embeddingBackend` | `"api"` | `"api"` (local model server, auto-managed) or `"hashing"` (zero-setup, no server) |
| `auditLogIncludeValues` | `false` | Off by default — turning it on makes the audit log itself a plaintext record of every secret caught |
| `anonymizeMode` | `"placeholder"` | `placeholder` / `hash` (reversible) or `mask` (not) |
| `disabled*Rules` | `[]` | Per-category checkbox lists for excluding individual rules |

---

## Privacy

Everything runs locally. The embedding server defaults to `http://localhost:9000`
and is started and stopped by the extension itself. There is no telemetry and no
account. The audit log is a local file that, by default, records *what type* of
thing was redacted and never the value.

Pointing `embeddingApiUrl` at a remote endpoint is the one way to change that,
and it is opt-in.

---

## Licensing

Apache-2.0. Bundled third-party components — including `sharp` (LGPL-3.0) and
its vendored libraries — are listed with their licences in
`THIRD-PARTY-NOTICES.md` inside the extension.

Source: [github.com/kashyapjain123/vaultline](https://github.com/kashyapjain123/vaultline)
