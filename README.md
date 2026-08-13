# Vaultline for VS Code

Zero-trust context control for AI coding agents. This repository holds two
packages: the **detection engine** and the **VS Code host** that embeds it.

The engine — every rule, the pipeline, the tokenizer, the policy decision, the
embedding routing — is **`@vaultline/core`** (`packages/core`), and it has no
dependency on VS Code or any other editor. The host
(`packages/vscode-extension`) is the chat participant, the settings manifest,
the commands and the packaging. Porting Vaultline to another editor means
writing that editor's equivalent of the files in
`packages/vscode-extension/src/`, not forking the engine.

They live together because there is one host today and a `file:` dependency
between them; the seam is enforced by the code, not by the repository
boundary. If a second host ever needs the engine on its own, `git subtree
split --prefix=packages/core` extracts it with its history intact.

## Repository layout

```
LICENSE                      — Apache-2.0
.vscode/                     — F5 launch + build task for the dev host
scripts/setup.js             — first-run check/install/build
packages/
  core/                      — @vaultline/core: the whole detection engine,
                               with no dependency on any editor. See its own
                               README for how detection works.
  vscode-extension/
    src/
      extension.ts           — activation: host + engine + commands
      chatParticipant.ts     — the @vaultline chat identity, adapting VS Code's
                               chat/LM/tool APIs to the core's GuardSession
      vscodeHost.ts          — VaultlineHost implemented against the VS Code API
      piiDecorations.ts      — highlighting, scrollbar marks, hover, ghost text
      anonymizeCommands.ts   — anonymize/restore a document, and its mappings
      codeActions.ts         — the "Anonymize this" lightbulb
    scripts/
      checkSettings.js       — asserts package.json agrees with the core's defaults
      stageCore.js           — assembles a real node_modules for packaging
      packagePlatforms.js    — platform-specific VSIX builds
    package.json             — the extension manifest (commands, settings schema)
    .vscodeignore(.bundled)  — what ships in each build
    THIRD-PARTY-NOTICES.md   — ships inside every .vsix; see Licensing below
```

Every file under `vscode-extension/src/` is VS Code-specific, and that is the
point of the split: they are adapters over an engine that knows nothing about
editors. If something that isn't about the VS Code API starts growing in
them, it probably belongs in the core.

## Setup

Requires Node.js 18+ and VS Code 1.90+.

```bash
git clone <this-repo> vaultline
cd vaultline
npm run setup
```

The two packages are installed and built separately and in order — the
extension type-checks against the `.d.ts` the core emits — so `npm run setup`
is the entry point rather than a plain `npm install`. From then on:

```bash
npm run compile           # both packages
npm run watch             # the extension, in watch mode
npm run check:settings    # package.json vs. the core's DEFAULT_SETTINGS
```

Then press **F5** with the repository root open as the workspace (see
`.vscode/launch.json`, which points the dev host at
`packages/vscode-extension` and maps source for both packages) to launch an
Extension Development Host with Vaultline loaded. In the new window, open the
Chat view and start a message with `@vaultline`.

**After any source change**, run `npm run compile` again AND reload/restart
the Extension Development Host — VS Code loads an extension's compiled
`out/*.js` into memory once at activation and does not hot-reload it when
files change on disk; recompiling alone has no effect on an already-running
dev host process. Note that this applies to core changes too: the extension
loads the core's compiled output, not its sources.

## Try it

In the Extension Development Host's Chat view:

```
@vaultline Rahul Sharma from HDFC Bank has account number 1234567890, can you help me write a script to validate it?
```

You should see Vaultline announce a redaction (the account number, tagged
PII), then the model's answer with the real number substituted back in.

Then open any file containing secrets — `packages/core/test/test_detection.txt`
is a ready-made one — to see the editor half described next.

## In the editor

Independently of chat, Vaultline marks up what it finds in open documents and
can rewrite it in place.

- **Highlighting** — detected values get an orange background and a mark in
  the scrollbar. Hovering one names the entity type, severity, category and
  the rule that fired.
- **Ghost text** — a hint at the end of the line the cursor is on, when that
  line holds something sensitive. Current line only, because the files this
  fires on hardest (a `.env`, a fixture) would otherwise be unreadable.
- **Lightbulb** — "Anonymize this EMAIL" on a detected value, or "Anonymize
  *n* values in selection", plus "Anonymize all values in this file".

Highlighting runs every detector that works offline, structural and
contextual alike. The two it leaves out both need an embedding call:
whole-message business-content classification, which has no span to highlight
anyway, and semantic keyword matching. Both still run in full on anything
actually sent to a model — so **highlighting is an affordance, not the
enforcement point**, and an unhighlighted value may still be redacted on its
way out. It also skips documents past `highlightMaxFileLength`.

One asymmetry worth knowing: the full pipeline uses tree-sitter to stop
low-precision rules firing inside comments, which is async and so is not
applied to highlighting. Highlighting can therefore flag something in a
comment that would not actually be redacted. Over-reporting in an affordance
is the acceptable direction of error; under-reporting is not.

### Anonymize and restore

`anonymizeMode` picks the replacement, and the three are **not** equivalent:

| Mode | Looks like | Reversible |
|---|---|---|
| `placeholder` (default) | `<<EMAIL_1>>` | Yes — the token identifies which entity it replaced |
| `hash` | `[EMAIL_a1b2c3d4]` | Yes — stable digest, same value always yields the same token |
| `mask` | `***` | **No** — every masked value looks identical, so no mapping is saved |

Mask asks for confirmation first, and restore refuses on a masked document
rather than guessing. Mappings are stored per document under the extension's
storage directory, separate from the chat session's, so document tokens and
chat tokens never share a numbering space.

## Commands

| Command | What it does |
|---|---|
| **Vaultline: Test Detection Pipeline on Selection** | Runs the full pipeline over the current editor selection without sending it anywhere, and without minting any tokens a real conversation would then have to resolve. The fastest way to demo or tune rules. |
| **Vaultline: Show Audit Log** | Dumps the local JSON-lines audit trail, tagged by source (`prompt` / `tool:<name>` / `history` / `testPipelineCommand`), and prints the log file's path. |
| **Vaultline: Restart Embedding Server** | Recovers a wedged or killed MiniLM server. A successful restart promotes routing back from the hashing fallback to MiniLM in place, with no window reload. |
| **Vaultline: Rebuild Category Embeddings** | Only meaningful when `embeddingApiUrl` points at your own endpoint: rebuilds the routing centroids against that model. The automatic rebuild keys off URL + model name, so this is the escape hatch for the same URL quietly starting to serve a different model. |
| **Vaultline: Anonymize Selection** | Replaces detected values in the selection (or the whole file, if nothing is selected). Runs the full pipeline, and scans the whole lines the selection spans so contextual rules keep the surrounding words they depend on. |
| **Vaultline: Anonymize Document** | The same over the entire file. |
| **Vaultline: Restore Document** | Puts the original values back from this document's saved mapping. |

The last three are also in the editor's right-click menu.

## Scope: what `@vaultline` can and can't see

This is built entirely on two *public, model-agnostic* VS Code APIs:
`vscode.chat.createChatParticipant` (registers `@vaultline` as its own
chat identity) and `vscode.lm` (whichever model is selected in the picker,
plus `vscode.lm.tools` for extension/MCP tools). Nothing here is
Copilot-specific.

That means:

- **What it sees**: any model that plugs into `vscode.lm` as a provider,
  and any tool contributed via VS Code's `languageModelTools` point or
  native MCP support — *as long as the conversation goes through
  `@vaultline`*.
- **What it doesn't see**: a different extension's own chat UI/agent loop
  that never touches `vscode.lm`. Most third-party AI assistants (Blackbox
  and similar) ship their own custom webview panel and make their own
  outbound network calls without registering through `vscode.lm`, so
  there's nothing for vaultline to intercept. The same is true of
  standalone tools like Claude Code, which talk to their model provider
  directly rather than through VS Code's chat/LM registry. Even GitHub
  Copilot's own **agent mode** (the default Copilot Chat panel) isn't
  interceptable today — see "True agent-mode interception" below.

To cover another tool, it would either need to register itself as a
`vscode.lm` model provider (at which point it shows up in `request.model`
automatically, no vaultline changes needed), or you'd need a materially
different, tool-specific interception strategy (proxying its network
layer, wrapping its CLI, etc.) — outside the current scope.

## Configuration

All settings live under `vaultline.*` in VS Code settings:

| Setting | Default | Purpose |
|---|---|---|
| `enablePiiDetection` / `enableInfraDetection` / `enableConversationalSecretDetection` / `enableBusinessContentDetection` | `true` | Toggle each detection layer wholesale |
| `enableCrossTurnSecretCarryover` / `crossTurnSecretTurns` | `true` / `2` | Keep detecting credentials for N turns after one is mentioned, so a value supplied in a follow-up (`and password is` … `replace it with X`) is still caught. Without it the keyword and the value must appear in the same message. Lower the turn count to `1` if unrelated value-shaped strings (commit hashes, build IDs) get redacted after a credential comes up |
| `enableHeuristicNameDetection` | `false` | Opt-in, high-false-positive-rate person-name heuristic |
| `enableSemanticKeywordMatching` | `true` | Last-line-of-defense layer; only meaningful with `embeddingBackend: "api"` |
| `enableToolCalling` | `true` | Whether `@vaultline` exposes `vscode.lm.tools` to the model at all |
| `maxTools` / `toolDenyList` | `128` / `[]` | Ceiling on how many tools go into one `sendRequest`, and name patterns (`*` wildcard) to exclude. `vscode.lm.tools` is every built-in, extension-contributed and MCP tool installed, and a provider rejects an over-long list outright — Copilot answers "Cannot have more than 128 tools per request" and the call dies before the model sees anything. Tools keep VS Code's own order, so its general-purpose built-ins survive truncation; the deny list is how you spend the budget deliberately. See `toolSelection.ts` |
| `enableSyntaxAwareRedaction` | `true` | Parse code with tree-sitter so low-precision rules stop firing inside comments — see "Syntax-aware suppression" in the core README. Unambiguous secret rules keep firing there regardless |
| `blockOnHighSeverity` | `false` | When `true`, a high-severity match (private key, PAN, SSN) **blocks** the request instead of redacting it. Off by default: inside an agent tool loop a single false high-severity hit aborts the whole task, and redaction already keeps the value from leaving |
| `blockOnBusinessContent` | `true` | Business content is a whole-*message* judgment, so there's no sensible span to redact — it's block-or-nothing |
| `routingMinSimilarity` | `0.15` | **Low-stakes, generous** gate for whether a contextual detector runs at all. Don't confuse this with `businessContentThreshold` below — setting it as high as 0.4 will silently starve PII/infra/credentials detection on realistic mixed-content text |
| `businessContentThreshold` | `0.4` | Deliberately much stricter — whole-message block, not a redact |
| `semanticMatchThreshold` | `0.5` | Gate for the last-line-of-defense semantic keyword layer. Empirically calibrated — see "Tuning the semantic threshold" in the core README. Scores above the gate are banded into low/medium/high confidence |
| `alwaysRunAllDetectors` | `false` | Bypass routing entirely — debugging / safety fallback |
| `embeddingBackend` | `"api"` | `"api"` (real model, self-managed server) or `"hashing"` (zero-setup, no server) — see "Embedding backends" in the core README |
| `autoStartEmbeddingServer` | `true` | Let the extension install, start and stop the local MiniLM server itself. Only applies when the backend is `"api"` and the API URL points at localhost |
| `embeddingServerNodePath` | `""` | Node binary for the embedding server. Blank = auto-detect (login shell → usual install paths → VS Code's bundled Node). Set it if auto-detection picks the wrong version, e.g. under nvm/fnm/asdf |
| `embeddingApiUrl` / `embeddingApiTimeoutMs` / `embeddingApiModel` / `embeddingApiAuthType` / `embeddingApiAuthToken` / `embeddingApiKeyHeader` | — | Only relevant when `embeddingBackend` is `"api"`. Point the URL at a remote/OpenAI-compatible endpoint to use one instead of the bundled server (which also disables auto-start). For a **local** URL the port is a preference, not a promise: if something else holds it, the server takes the next free port within 10 and the extension follows it (see `selectPort` in `serverManager.ts`). It binds loopback only. Pointing at a **custom** endpoint (non-loopback, or any explicit `embeddingApiModel`) triggers a one-time centroid rebuild against that model — see `centroidBuilder.ts`; the result is cached under the storage dir, keyed on a hash of URL + model |
| `trustCustomEmbeddingsForBlocking` | `false` | Whether centroids rebuilt against a CUSTOM endpoint may carry the whole-message business-content block. Off by default for the same measured reason the hashing fallback keeps routing but gives up the block — see `wholeMessageCapable` in `embeddingRouter.ts`. An arbitrary endpoint is uncalibrated by definition, and a wrong block tells a developer their ordinary question is confidential |
| `auditLogIncludeValues` | `false` | Include real values + assigned tokens in the audit log — off by default since turning it on makes the log itself a plaintext record of every secret caught |
| `disabledSecretRules` / `disabledPiiRules` / `disabledInfraRules` / `disabledConversationalSecretRules` / `disabledSemanticRules` | `[]` | Per-category checkbox lists of individual rule IDs to exclude |
| `highlightDetectedPii` | `true` | Editor highlighting, scrollbar marks and hover |
| `inlineWarnings` | `true` | Ghost-text hint on the cursor's line. Requires `highlightDetectedPii` |
| `anonymizeMode` | `"placeholder"` | `placeholder` / `hash` (both reversible) or `mask` (not) — see "In the editor" above |
| `highlightMaxFileLength` | `100000` | Skip live highlighting past this many characters. The explicit anonymize commands still work on files of any size |

The last four are **host-only**: they describe VS Code's editor surface, not
detection, so a JetBrains or CLI host would answer them completely
differently and the core has no concept of them. They are exempted by name in
`checkSettings.js`. Anything that affects *detection* belongs in the core
instead.

Settings are declared in `packages/vscode-extension/package.json` but their
**defaults are owned by the core** (`DEFAULT_SETTINGS` in
`@vaultline/core`'s `src/settings.ts`). VS Code always applies the manifest's
declared default, so a manifest that disagrees with the core silently wins —
which is how `semanticMatchThreshold` once shipped at `0.4` while the
measurements that produced `0.5` sat in a comment beside the constant.
`npm run check:settings` fails the build on any such disagreement, including a
rule ID the core knows about that the manifest's checkbox list doesn't offer.
It runs automatically as part of `npm run package`.

## Packaging

```bash
npm run package             # one portable .vsix for every OS/arch
npm run package:platforms   # one .vsix per platform, MiniLM baked in
```

The portable build needs npm on the target machine to install the embedding
server's native dependencies on first run; machines without it fall back to
the hashing embedder, which keeps routing but gives up semantic keyword
matching and whole-message business-content detection. The platform builds
trade one artifact for four in exchange for a zero-setup install — no npm, no
network, no first-run wait. See `scripts/packagePlatforms.js`.

**Seed the model cache before building platform packages**, or their whole
reason for existing is silently lost:

```bash
cd packages/core/embedding-server && npm install && npm start   # ~23MB, then Ctrl+C
```

`packagePlatforms.js` bundles whatever is in
`packages/core/embedding-server/node_modules/@xenova/transformers/.cache`. With
an empty cache it prints `Model weights bundled: no` and carries on — the VSIXs
still build, still install, and then download the model on first run like the
portable build does. Check for `Model weights bundled: yes (offline install)` in
the build output, and confirm afterwards:

```bash
unzip -l packages/vscode-extension/dist/vaultline-<v>-darwin-arm64.vsix | grep model_quantized
```

Publishing all five as one Marketplace listing (VS Code serves each machine its
matching build and falls back to the portable one):

```bash
export VSCE_PAT=<token>   # Marketplace → Manage, All accessible organizations
npx @vscode/vsce publish --packagePath packages/vscode-extension/dist/vaultline-<v>*.vsix
```

Both go through `scripts/stageCore.js` first. At rest `@vaultline/core` is a
symlink created by its `file:../core` dependency, and its own dependencies
live in `packages/core/node_modules` — meaning *nothing the extension needs
at run time actually sits inside the extension directory*, which is the only
place `vsce` looks. The staging step materializes exactly the required tree,
packages, and tears it down again in a `finally`. If a build is interrupted
badly enough to leave one behind, `node scripts/stageCore.js --unstage`
restores the layout.

(This deliberately is **not** an npm workspace. `vsce` resolves an
extension's shippable files by running `npm list` in the extension directory,
and inside a workspace npm answers for the whole repo, so `vsce` walks the
entire tree and collects files from outside the package. Each package
installs its own `node_modules` instead; `npm run setup` does both.)

## Porting to another editor

Three files here are VS Code-specific: `vscodeHost.ts` (the host boundary),
`chatParticipant.ts` (chat/model/tool adapter), and `extension.ts`
(activation and command registration). Everything else that Vaultline does is
in `@vaultline/core` and is reusable as-is.

A new host implements `VaultlineHost` — settings, storage directory, logging,
notifications, progress, clipboard — creates a `VaultlineEngine`, and calls
`GuardSession` around its own model calls. See the core's README for the
integration walkthrough and `src/guardSession.ts` for the ordering rules that
are the reason not to reimplement any of it.

## Licensing

Vaultline is **Apache-2.0** ([LICENSE](LICENSE)) — permissive, with an
explicit patent grant. For a tool that reads every secret you type before it
reaches a model, being auditable is part of the point.

Third-party attributions live in
[`packages/vscode-extension/THIRD-PARTY-NOTICES.md`](packages/vscode-extension/THIRD-PARTY-NOTICES.md),
which ships **inside every `.vsix`** rather than only in this repository,
because the obligations travel with the artifact.

The one thing to know before changing the packaging: **platform-specific
builds redistribute LGPLv3 shared libraries.** `sharp` — which Vaultline
never calls, but which transformers.js statically imports and so cannot be
pruned — bundles `libvips`, `glib`, `pango`, `librsvg` and others. That is
fine because they are unmodified, dynamically linked, and shipped with their
notices; the third of those depends on `stageCore.js` continuing to exempt
licence files from the markdown stripping it applies to dependencies. The
portable build is unaffected, since it installs those on the user's machine
rather than redistributing them.

## Engine documentation

Everything about *how detection actually works* — the layer table, why
contextual proximity rather than more regex, the value heuristic, what's
deliberately not NER, embedding backends and threshold calibration,
syntax-aware suppression, tool/MCP redaction, the test matrices, and the known
limits — is documented in `@vaultline/core`'s README, next to the code it
describes.
