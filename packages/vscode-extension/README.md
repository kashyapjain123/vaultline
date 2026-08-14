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
write a python client for https://<<HOSTNAME_1>>/api/getToken, the password is <<PASSWORD_1>>
```

and you get the answer back with the real host and password already restored in
the code. The model reasons perfectly well about `<<PASSWORD_1>>` — it just
never learns what it stands for.

Note the path survives. Only the **host** identifies your infrastructure;
`/api/getToken` is generic REST vocabulary and is exactly what the model needs to
write a working client, so redacting it would cost you a correct answer and
protect nothing.

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
  currency amounts, and usernames / service accounts (`svc_corp_uat`).
- **Infrastructure** — URL hosts, internal hostnames, private/public IPs, IPv6,
  MAC addresses, ports, and file paths that identify an account or an
  organisation (`/Users/you/…`, `/opt/acme-payments/…`). Universal paths like
  `/usr/bin/python` and `/etc/nginx/nginx.conf` are left alone: they are
  identical on every machine and reveal nothing.
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
| **Set / Clear Embedding API Token** | Keeps the embedding API credential in your OS keychain instead of settings.json |
| **Rebuild Category Embeddings** | Only for custom endpoints. Rebuilds routing centroids against your model — needed when the same URL starts serving a *different* model, which nothing can detect automatically |
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

45 settings under `vaultline.*`. The ones most worth knowing:

| Setting | Default | Purpose |
|---|---|---|
| `enablePiiDetection` / `enableInfraDetection` / `enableConversationalSecretDetection` / `enableBusinessContentDetection` | `true` | Toggle each detection layer |
| `enableCrossTurnSecretCarryover` / `crossTurnSecretTurns` | `true` / `2` | Keep detecting credentials for N turns after one is mentioned. Lower to `1` if unrelated value-shaped strings (commit hashes, build IDs) get redacted |
| `blockOnHighSeverity` | `false` | Block instead of redact on a high-severity match. Off by default: inside a tool loop one false positive aborts the whole task, and redaction already keeps the value from leaving |
| `enableToolCalling` | `true` | Whether `@vaultline` exposes `vscode.lm.tools` to the model |
| `maxToolRounds` | `25` | How many model round trips one request may take while the model keeps calling tools. On reaching it, Vaultline says so and asks the model — with no tools available — to summarise what it found, so you get a partial answer rather than silence. Raise it for long agentic work; the Stop button cancels a run at any point |
| `maxTools` / `toolDenyList` | `128` / `[]` | Cap on tools offered per request, and names to exclude. Providers reject an over-long list outright, and VS Code's registry counts every built-in, extension and MCP tool you have installed |
| `enableSyntaxAwareRedaction` | `true` | Stop low-precision rules firing inside code comments |
| `embeddingBackend` | `"api"` | `"api"` (local model server, auto-managed) or `"hashing"` (zero-setup, no server) |
| `embeddingApiUrl` | local | Point at your own embedding service instead of the bundled one. Routing centroids are then **rebuilt against your model automatically**, once, and cached — see below |
| `trustCustomEmbeddingsForBlocking` | `false` | Whether rebuilt centroids may block a whole message as confidential business content. Off until you've validated your model |
| `embeddingApiFormat` / `embeddingApiEmbedPath` / `embeddingApiHealthPath` | `"vaultline"` / `""` / `"/health"` | Shape, path and health route of a custom endpoint. `"custom"` describes any shape via `embeddingApiRequestField` / `embeddingApiResponsePath`. Set the health path to `""` if yours has no health route — most hosted services don't |
| `persistSessionMappings` | `false` | Write this session's token-to-value table to disk. Off: that file holds every detected secret in plain text |
| `auditLogIncludeValues` | `false` | Off by default — turning it on makes the audit log itself a plaintext record of every secret caught |
| `anonymizeMode` | `"placeholder"` | `placeholder` / `hash` (reversible) or `mask` (not) |
| `disabled*Rules` | `[]` | Per-category checkbox lists for excluding individual rules |

---

## Using your own embedding endpoint

Set `embeddingApiUrl`, and run **Vaultline: Set Embedding API Token** if it needs
a credential — that keeps the token in your OS keychain rather than in
settings.json.

`embeddingApiFormat` has two presets and an escape hatch:

```
"vaultline"  POST {baseUrl}/embed-batch     { "texts": [...] }
                                         -> { "embeddings": [[...], ...] }

"openai"     POST {baseUrl}/v1/embeddings   { "input": [...], "model": "..." }
                                         -> { "data": [{ "embedding": [...], "index": 0 }] }

"custom"     describe your own shape with embeddingApiRequestField and
             embeddingApiResponsePath
```

Nothing here is OpenAI-specific — the presets are just two fixed points of what
`"custom"` expresses, and either can be written out by hand:

```jsonc
// the vaultline preset, spelled out
"embeddingApiFormat": "custom",
"embeddingApiRequestField": "texts",
"embeddingApiResponsePath": "embeddings",

// your own service
"embeddingApiEmbedPath": "/input/text",
"embeddingApiRequestField": "sentences",
"embeddingApiResponsePath": "result.vectors",   // nesting and arrays supported
```

The response path understands nesting and arrays: `embeddings`,
`data[].embedding`, `result.vectors`.

Override the path with `embeddingApiEmbedPath` if yours differs (`/input/text`,
say). **If your endpoint has no health route, set `embeddingApiHealthPath` to
`""`** — Vaultline otherwise probes `GET {baseUrl}/health` before using the
endpoint, and a missing route means it silently falls back to the built-in
hashing embedder and never calls your service.

Routing works by comparing your message against precomputed **category
centroids**, and those only mean anything if they came from the same model doing
the comparing. So the first time Vaultline sees a new endpoint it rebuilds them
against your model — 72 sentences, one batched call, cached per endpoint. Nothing
happens for the default local setup.

Two things worth knowing:

- **Rebuilt centroids don't block by default.** They gate detection, but the
  whole-message business-content *block* stays off until you set
  `trustCustomEmbeddingsForBlocking`. An unvalidated model getting that wrong
  tells a developer their ordinary question is confidential.
- **Routing embeds your prompt before redaction.** It has to, in order to decide
  which detectors to run. Self-hosted inside your network, that's fine; a
  third-party embedding API would see unredacted text, which inverts the point of
  the tool. Use `"embeddingBackend": "hashing"` to keep everything local instead —
  you lose semantic keyword matching and business-content detection, and all
  other detection is unaffected.

`semanticMatchThreshold` (default `0.5`) was calibrated against MiniLM, so a
different model may want a different value.

## Privacy

Everything runs locally. The embedding server binds **loopback only**
(`127.0.0.1`), starting at port 9000 and moving to the next free port if
something else already holds it. It is started and stopped by the extension
itself. There is no telemetry and no account. The audit log is a local file
that, by default, records *what type* of thing was redacted and never the
value.

Pointing `embeddingApiUrl` at a remote endpoint is the one way to change that,
and it is opt-in.

---

## Licensing

Apache-2.0. Bundled third-party components — including `sharp` (LGPL-3.0) and
its vendored libraries — are listed with their licences in
`THIRD-PARTY-NOTICES.md` inside the extension.

Source: [github.com/kashyapjain123/vaultline](https://github.com/kashyapjain123/vaultline)
