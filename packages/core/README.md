# @vaultline/core

The engine behind Vaultline — zero-trust context control for AI coding
agents — as an editor-agnostic library.

Everything here is about *detecting sensitive content and deciding what to do
with it*: a hybrid detection pipeline (structural regex, contextual proximity
search, embedding-based routing, syntax-aware suppression via tree-sitter, an
optional semantic-similarity last line of defense, and optionally a rough
NER-style heuristic), plus the tokenize/redact/rehydrate machinery, the policy
decision, and the audit trail.

Nothing here imports an editor API. The VS Code extension in this monorepo is
one consumer; an IntelliJ plugin (or a CLI, or a proxy) is meant to be
another, and needs to supply only two things: an implementation of
`VaultlineHost`, and an adapter between its own chat/model API and
`GuardSession`.

Runtime dependencies are `web-tree-sitter` + `tree-sitter-wasms` (syntax
awareness) and, for the default embedding backend, a self-managed local MiniLM
server whose dependencies install on first run. Everything else is
dependency-free by design.

## Integrating a new host

```ts
import { VaultlineEngine, VaultlineHost } from "@vaultline/core";

class MyEditorHost implements VaultlineHost { /* see src/host.ts */ }

const engine = VaultlineEngine.create(new MyEditorHost());
const session = engine.createSession("/path/to/session-mappings.json");
```

Then wrap your editor's model call with the session:

```ts
// 1. The developer's message, on its way out
const guarded = await session.guardPrompt(userText);
if (guarded.action === "block") return showBlocked(guarded.reason);
// guarded.redactedText is what's safe to send

// 2. Prior turns, re-redacted before being replayed as context
const { turns } = await session.redactHistory(priorTurns);

// 3. Around every tool call the model makes
const realInput = session.guardToolInput(call.input);
const language = session.languageForToolInput(realInput);
const result = await runTool(call.name, realInput);
const { redacted } = await session.guardToolResult(result, language, call.name);

// 4. The answer, on its way back to the developer
const { text, suspiciousTokens } = session.restoreResponse(modelAnswer);
```

That's the whole integration surface. The ordering rules those calls encode —
what gets re-scanned versus substituted, what must never reach the tokenizer,
when a leftover placeholder is worth warning about — are documented in
`src/guardSession.ts`, and are the main reason this is a library rather than
something each host reimplements.

### What the host owns

| Piece | Where |
|---|---|
| Settings storage + UI | Host. The core defines the contract and every default in `src/settings.ts`; the host reads its own config system into a `VaultlineSettings`. |
| Storage directory | Host (`VaultlineHost.storagePath`) — audit log, session mappings, and the embedding server's per-machine install all live under it. |
| Logging, notifications, progress, clipboard | Host (`VaultlineHost`), so the core can report a failed dependency install without knowing what an OutputChannel is. |
| Chat/model/tool APIs | Host. Convert its types to plain strings and plain JSON at the boundary. |
| Everything else | Core. |

`ConsoleHost` is a working headless implementation — useful for tests and
scripts, and the check that the boundary actually holds.

## What it actually does

A host registers its own chat identity (in VS Code, the `@vaultline` chat
participant) and routes every message through `GuardSession`. Each prompt goes
through `src/detectionPipeline.ts`, which runs several detection layers and
merges them into one deduplicated match list:

| Layer | File | Catches | Technique |
|---|---|---|---|
| Structural secrets | `patternMatcher.ts` | AWS / OpenAI (`sk-…`) / Stripe (`pk_live_…`) keys, private key blocks, JWTs, Slack/GitHub tokens, DB + SQL Server connection strings, `password=X` assignments (bare, quoted-JSON, and YAML forms), `EXPORT_SECRET=…` env vars | Regex, fixed shape — always on, never gated |
| PII | `piiDetector.ts` | Email, PAN, IFSC, SSN, Aadhaar, credit cards (Luhn-checked), phone/account/customer numbers, US passport + driver's license | Regex + contextual proximity |
| Infrastructure | `infraDetector.ts` | IPs, internal URLs, real filesystem paths (see note below), internal hostnames, ports | Regex + contextual proximity |
| Conversational secrets | `nlpProximityMatcher.ts` | "my password is X", "the api key was X" — same categories as layer 1, phrased as prose instead of code, with typo tolerance (see below) | Windowed proximity, no ML |
| Business content | `businessContentDetector.ts` | "we're spending $80k on Project Falcon" — no fixed format, no anchor keyword, whole-message judgment | Embedding similarity vs. category centroids |
| Semantic keyword (last line of defense) | `semanticKeywordMatcher.ts` | Org-specific synonyms for password/secret/token nobody hardcoded, once every other layer has had its pass | Real embedding similarity, API backend only |

Every match carries a **category** tag — `SECRET`, `PII`, `INFRA`, or
`BUSINESS` — so downstream policy/audit/UI can reason about *what kind* of
thing was caught, not just that something was.

**Routing.** `embeddingRouter.ts` decides which CONTEXTUAL detectors (PII,
infra, conversational-secret) bother running on a given piece of text —
structural regex always runs regardless. Two different entry points exist
in `detectionPipeline.ts` for this, deliberately different granularity:

- `scanAll(text)` — routes on one embedding of the whole `text`. Used for
  anything that isn't the live user message: editor/file-path context,
  and (normally) already-known conversation history.
- `scanCurrentMessage(text)` — routes **per line** instead. A pooled
  sentence embedding of a long message dilutes a single sensitive line's
  signal into the surrounding unrelated context, which can drop routing
  below threshold and silently skip detection on that line even though it
  would clear easily on its own. Scoring each line independently avoids
  that. This is what's used for the developer's live prompt, the "Test
  Detection Pipeline on Selection" command, and tool-call output — see
  below for the tool-output subtlety that made this non-obvious to wire up
  correctly.

If routing is unavailable at all (missing/corrupt
`data/categoryEmbeddings.json`, or a failed embed call) it fails **open**
— every contextual detector just runs unconditionally rather than being
silently skipped.

Based on severity, the policy engine (`policyEngine.ts`) either lets the
prompt through, redacts the sensitive spans and replaces them with typed
placeholder tokens (`<<PASSWORD_1>>`, `<<PERSON_1>>`, `<<AMOUNT_INR_1>>`,
...) before forwarding, or blocks the request outright. A typed token
carries enough shape for the model to keep reasoning correctly around it
without ever seeing the real value, and looks unmistakably
machine-generated rather than a word a model might paraphrase away — see
`entityTypes.ts` / `tokenizer.ts` for the full rationale. If redacted, the
model's response is scanned for those same tokens and they're swapped back
to the real values before you see the answer. Every decision (never the
sensitive values themselves, unless `auditLogIncludeValues` is explicitly
turned on) is appended to a local JSON-lines audit log (`AuditLog`). Two
engine methods exist for hosts to expose as commands: `engine.inspect(text)`
runs the whole pipeline over a piece of text without sending it anywhere or
minting any tokens, and `engine.restartEmbeddingServer()` recovers a wedged
MiniLM server and promotes routing back to it in place.

### Cross-turn consistency and per-session persistence

`entityStore.ts` holds one bidirectional, typed mapping table
(`(entityType, value) -> token`) for the whole life of a chat participant
session — so the same value gets the same token everywhere in that
session, which is what makes rehydration work correctly across multi-step
tool loops and across conversation turns. It's keyed on `entityType::value`,
not just `value`, so the same literal string playing two different roles
(e.g. a value that's a password in one line and a hostname in another)
gets two distinct, correctly-typed tokens instead of the second occurrence
silently inheriting the first's type.

Mappings are also mirrored to a JSON file per session
(`globalStorage/sessions/<uuid>.json`), generated fresh at each activation
— a durable, inspectable record of what's been tokenized, not a substitute
for the in-memory store.

**Conversation history** is re-redacted before being replayed as context
on every turn (both sides — a previous user turn is raw, unredacted text;
a previous assistant turn is the real, rehydrated answer you saw — see
`guardSession.ts`'s module comment). Normally this is cheap: every
past turn already went through full detection once, back when it *was*
the live message, so history redaction just does a direct substring swap
against the already-known mapping table (`tokenizer.redactKnownValues`)
rather than re-running detection and another embedding call on the same
text. The one exception: if the store is still empty but the host's own
conversation history already has turns in it — the signature of a host
restart (window reload, plugin reload, editor update) landing
mid-conversation — it falls back to running full detection on history
once, to rebuild the mapping table from scratch, rather than trusting an
empty store and silently redacting nothing.

## Why contextual proximity, not just regex, for PII/infra

A plain digit run means nothing on its own — `8080` is a port number in
"the server runs on port 8080" and a cricket statistic in "he scored 8080
runs." Rather than write one omniscient regex, the PII and infra
detectors borrow the same technique full-text search engines use
(OpenSearch/Elasticsearch's `span_near`/slop matching): tokenize the
text, and only flag a bare number/word as sensitive if a relevant keyword
(`port`, `account`, `phone`, `server`, `db`, ...) appears within a small
token window of it. This is what correctly separates "port 8080" from a
sports score, and "prod-db-01" (near "server") from an unrelated
hyphenated phrase like "step-by-step-3" — see `test/hybrid-matrix.js` for
both cases side by side.

The same conversational-secret matcher also tolerates typos — "passowrd",
"creditial", "credentails" — via a bounded Damerau-Levenshtein edit
distance (handles the common adjacent-letter-transposition typo shape, not
just plain substitutions), restricted to keywords of **8+ characters**.

That floor is deliberately high. At 5, a 1-edit budget reached ordinary
English words that are everywhere in coding conversation: `passed`→`passwd`,
`taken`→`token`, and `crews`→`creds` are all edit-distance 1, so "the
screenshot was taken at 1280x720" flagged `1280x720` as a token value.
Short keywords (`pass`/`pwd`/`key`/`token`/`creds`/`secret`/`apikey`) are
therefore exact-only, and plurals — the recall a low floor was really
buying — are handled by exact stemming instead, which is more precise and
can't reach unrelated words. Accepted cost: `toekn`-class typos on *short*
keywords are no longer caught — so vowel-dropped abbreviations that the
edit-distance budget can no longer bridge (`pwd`, `pd`, `pwrd`, `pass`,
`tokn`) are listed explicitly as keywords instead. That's the intended
escape hatch: if a short form matters to you, add it to
`SENSITIVE_KEYWORDS` rather than lowering the fuzzy floor.

## What counts as a value

Finding a keyword is only half the job — something nearby has to look like
an actual secret. That judgment lives in one shared place,
`proximityUtils.looksLikeSecretValue()`, used by both the conversational
matcher and the semantic layer.

**Quoting grants no leniency.** The rule this replaced accepted any quoted
span of 4+ characters, on the theory that a human putting something in
quotes is pointing at a value. In prose that's often true; in the code,
JSON and documentation that flows through tool output it was catastrophic —
reading this project's own `package.json` redacted the word
`"description"`, the string `"username:password"`, and whole sentences of
prose, purely because the words "secret"/"password"/"token" appear nearby
in that file's setting descriptions. A value now has to be 8+ characters,
contain no whitespace, and either mix letters with digits or carry real
base64 padding evidence.

**Accepted recall loss:** a quoted all-lowercase, no-digit password
(`"letmein"`) is no longer detected — it's structurally indistinguishable
from an ordinary quoted English word, and guessing wrong on that class was
the single largest false-positive source in the pipeline. Anything with a
digit still gets caught.

Relatedly, both tokenizers treat a backslash-escaped quote as *not* a
string delimiter. Without that, one `\"` in JSON-escaped tool output flips
quote parity for the rest of the text, and the tokenizer starts pairing the
closing quote of one string with the opening quote of the next — emitting
"values" that straddle two unrelated strings.

## What's genuinely NOT NER, and why

The strategy behind this pipeline was explicitly to avoid needing a
bundled ML model for identifiers. That trade-off is honest and holds up
well for *identifiers* (PAN, SSN, account numbers, IPs, hostnames) — those
have a checkable shape or a reliable keyword anchor. It does **not** hold
up for detecting person or organization *names* on their own — "Rahul
Sharma" is structurally indistinguishable from "Empire State" or "Great
Expectations" without an actual language model that understands what a
name is.

`piiDetector.ts` includes `scanPersonNamesHeuristic()` — a Capitalized-Word
-pair heuristic — but it's **off by default** (`enableHeuristicNameDetection`) precisely because it's not real NER and
will false-positive on ordinary capitalized phrases. If name/org detection
becomes a real requirement, the honest next step is integrating an actual
NER model (spaCy's small English pipeline, or Presidio's default
recognizers, which wrap spaCy) rather than growing this heuristic further.

## File paths: only *real* ones

This extension targets **coding** agents, and normal coding conversation is
saturated with path-shaped text that reveals nothing —
`./scripts/build.sh`, `/src/index.ts`, `/api/v1/getToken`. Flagging all of
it was pure noise, and noise trains people to ignore the redaction notice
entirely.

The problem is that a repo-relative path and a real filesystem path are
syntactically identical (`/src/index.ts` vs `/etc/passwd`), so shape alone
can't separate them — but the **root segment** can: there is no `/src` or
`/components` on a real machine, while `/Users`, `/etc`, and `/opt` always
exist. So `infraDetector.ts` flags a Unix path only when its first segment
is a real top-level directory (`REAL_FS_ROOTS`), and never when the path is
explicitly relative (`./…`, `../…`).

What still gets caught is what actually leaks: `/Users/<name>/…` and
`C:\Users\<name>\…` (exposes the OS account name — labeled specifically as
such), `/home/<user>/…`, `/root/…`, and deployment layout like
`/opt/acme-internal/…` or `/var/log/prod-api/…`. This is the same principle
as `NON_SENSITIVE_IPV4` elsewhere in that file — flag what reveals
something about *this* machine, not everything matching the shape.

Windows paths need no such narrowing: a drive letter (`C:\…`) is inherently
a real absolute location, with no relative-fragment ambiguity. (Known
pre-existing limitation, unrelated to this narrowing: `WIN_PATH` stops at
whitespace, so `C:\Program Files\…` matches only `C:\Program`.)

## Embedding backends

Routing and business-content detection need *some* embedding. Two backends
are supported, switchable via `embeddingBackend`:

- **`api`** (default) — a local server (`embedding-server/`) running a real
  model (`sentence-transformers/all-MiniLM-L6-v2` via
  `@xenova/transformers`) for genuine semantic similarity. Required for
  `semanticKeywordMatcher.ts` (the last-line-of-defense layer) to be
  meaningful at all, which is why that layer is only constructed under this
  backend — and since this is the default, that layer is on by default too.
- **`hashing`** — a dependency-free, zero-setup lexical embedder
  (`embeddings/hashingEmbedder.ts`): no server, no model download. Good
  enough to route whole-message categories apart, but it measures character
  shape more than meaning — which is why the conversational-secrets keyword
  list is a maintained exact/fuzzy list rather than embedding similarity
  (see `nlpProximityMatcher.ts`'s module comment: "pass" and "bypass" are
  nearly identical strings and unrelated concepts at this resolution).

### The server starts itself

You do **not** run `npm install` in `embedding-server/` by hand.
`embeddings/serverManager.ts` manages the whole lifecycle from engine
construction, because editor plugin formats are typically just zips with no
install hooks — without it, every user would have to set the server up
manually before the default backend did anything.

On first run it copies `server.js` + its lockfile into the host's storage
directory (`VaultlineHost.storagePath`), installs dependencies there (~1-3
min, needs network), and downloads the ~90MB model. Subsequent starts hit the
local cache and take a couple of seconds. Dependencies are installed
per-machine rather than shipped because `@xenova/transformers` pulls in
`onnxruntime-node` and `sharp` — ~280MB of prebuilt *native* binaries, which
would make the shipped artifact platform-specific when nothing else in it is.

It is **fail-open throughout**: no node, no npm, install failure, model
download failure, port already taken — each is logged and surfaced once,
then ignored. Nothing there can block activation. If the server never comes
up, `ApiEmbedder` simply fails, `embeddingRouter.ts` treats that as "routing
unavailable", and every contextual detector runs unconditionally — the same
safe degradation as a missing centroids file.

Relevant controls: `autoStartEmbeddingServer` (default `true`; only applies
when the API URL points at localhost), `embeddingServerNodePath` (set this if
auto-detection picks the wrong Node — common with nvm/fnm/asdf), and
`engine.restartEmbeddingServer()`, which hosts should expose as a command so a
wedged server can be recovered without a reload.

**Whichever backend you pick, `data/categoryEmbeddings.json` (the
precomputed category centroids) must be regenerated with the same
backend** — mixing vector spaces produces meaningless similarity scores.
`embeddingRouter.ts` catches an obvious dimension mismatch and fails open,
but a same-dimension wrong-space mismatch wouldn't be caught, so keep this
in sync deliberately:

```bash
npm run compile
npm run build:embeddings -- --backend=api   # matches the default backend; needs the server running
npm run build:embeddings                    # hashing backend
```

## Tuning the semantic threshold

`semanticMatchThreshold` is the **gate** for the last-line-of-defense
layer, calibrated against `all-MiniLM-L6-v2` rather than guessed. Embedding
every seed in `data/semanticKeywordSeeds.json` against wanted synonyms and
unwanted ordinary/coding words gives a clean separation:

| | score |
|---|---|
| Unwanted words, highest | `passed` **0.476**, `enabled` 0.393, `taken` 0.363, `bypass` 0.362, `required` 0.356, `class` 0.339 |
| Wanted synonyms, lowest | `mobile number` **0.598**, `secret word` 0.632, `masterkey` 0.648, `passport` 0.711 |
| Wanted synonyms, highest | `passcode`/`otp`/`dob` 1.000, `apikey` 0.916, `upi` 0.857, `credentials` 0.841, `aadhaar` 0.825, `ifsc` 0.805 |

`0.5` separates these cleanly (0.476 below, 0.598 above). The previously
declared default of `0.4` was *below three ordinary English words*, so
`passed`, `license` and `string` registered as credential keywords.

**Two things make that gap wide.** First, region-specific identifiers
(`aadhaar`, `pan card`, `ifsc`, `upi`) and abbreviations (`otp`, `dob`) score
as pure noise out of the box — MiniLM has no concept of them — so they're
explicit seeds now. Add a seed for any term the model doesn't know; never
lower the gate to reach it.

Second, and less obvious: a **candidate is always a single word**, but many
**seeds are phrases**, and MiniLM puts a phrase and its head noun almost on
top of each other. `"port"` scores **0.810** against the seed `"port
number"`, `"connection"` 0.677 against `"database connection"`, `"key"` 0.615
against `"signing key"`. Left alone, every phrase seed silently promotes its
generic head noun into a keyword. Those head nouns are therefore listed in
`STOPWORDS` in `semanticKeywordMatcher.ts` — which is correct rather than
merely convenient, since each one (`port`, `key`, `account`, `phone`, …) is
already handled by an earlier deterministic layer, and this layer exists for
the synonyms those layers *don't* know.

Above the gate, the score is **banded** into confidence tiers (≥0.75
exact-synonym cluster, 0.60–0.75 paraphrases, below that the weak tail),
mirroring what `businessContentDetector.ts` already does. Banding is capped
at each seed group's declared severity so it can only ever *de-escalate* —
`policyEngine.ts` blocks on `high`, and an unvalidated embedding guess from
the least precise layer must never be able to block a message on its own.

**Deliberately not implemented:** retrying with a progressively lower
threshold until something matches. That guarantees a non-empty result, which
makes "this text contains nothing sensitive" unrepresentable and
manufactures a redaction on every clean message. Confidence has to be
measured, not searched for. The useful iterative mechanism is a *feedback*
loop instead — log near-misses and re-calibrate from real traffic.

Re-run the calibration any time (needs `embedding-server` running):

```bash
node -e 'const s=require("./data/semanticKeywordSeeds.json");
const W=["passcode","masterkey","login key","pin","otp"], U=["passed","license","string","enabled","bypass","description"];
(async()=>{const all=[...Object.values(s).flatMap(g=>g.seeds),...W,...U];
const V=(await(await fetch("http://localhost:9000/embed-batch",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({texts:all})})).json()).embeddings;
const i=t=>all.indexOf(t), cos=(a,b)=>a.reduce((x,v,k)=>x+v*b[k],0);
const best=t=>Math.max(...Object.values(s).flatMap(g=>g.seeds).map(sd=>cos(V[i(t)],V[i(sd)])));
console.log("wanted min:",Math.min(...W.map(best)).toFixed(3),"unwanted max:",Math.max(...U.map(best)).toFixed(3));})()'
```

Note `aadhaar`/`pan`/`dob` score as noise (0.28–0.32) because MiniLM has no
concept of them — the fix there is adding them as **seeds**, never lowering
the gate.

## Not degrading the agent

A redaction tool for coding agents lives or dies on **precision, not recall**.
Redacting a real secret is nearly free — a typed `<<PASSWORD_1>>` keeps the
shape the model needs to reason, and rehydration restores the real value
before any tool runs. A *false* positive is not merely noise: it silently
corrupts the model's view of your code and makes it do wrong work.

That isn't hypothetical. Asked to find bugs in this repo, a model read a
source file whose comment had been redacted, and reported the resulting hole
as its **top finding** — a "corrupted comment" that never existed. It burned
a tool call and a reasoning slot on a defect the redaction layer invented.

Measured on this repo's own source (22 files), false positives went **11 → 0**
while true positives held at 11/11 on the detection fixture. What caused
those 11:

| cause | example | fix |
|---|---|---|
| `::` scope operators read as IPv6 | `std::vector` → `d::`, `Foo::bar()` → `::ba` | require ≥2 groups, a digit, and no adjacent identifier char |
| loopback URLs | `http://localhost:9000` | `LOOPBACK_HOSTS` skip, mirroring `NON_SENSITIVE_IPV4` |
| currency regexes truncating | `$1234.56` → `$123`, `INR 543000` → `INR 54` | handle ungrouped digits + k/m/b suffixes |
| doc comments containing live examples | a comment *about* the SQL Server rule matching that rule | examples rewritten so they no longer match |

That last row generalizes: any file that *discusses* secrets — docs, tests,
detector source — is a false-positive magnet. Test fixtures with fake
credentials are the common real-world case. That class is what the
syntax-aware layer below addresses structurally.

### Syntax-aware suppression (tree-sitter)

`syntax/syntaxAnalyzer.ts` parses source with **tree-sitter** and reports
comment spans, so low-precision rules stop firing inside comments — where
they match documentation *about* credentials rather than credentials.

A parser is required rather than a regex comment-stripper, because the
distinction is genuinely syntactic: `"http://x"` is a string, `// http://x`
is a comment, and `//` inside a string literal is neither.

**It deliberately does not suppress everything in comments.** Commenting out
a config line is one of the most ordinary ways a credential ends up in a
file. So the split is by precision:

| in comments | rules |
|---|---|
| **still fire** | vendor API keys (AWS/OpenAI/Stripe/Slack/GitHub), PEM blocks, JWTs, DB + SQL Server connection strings, `name=value` credential assignments, env-var secrets |
| **suppressed** | currency amounts, IP/IPv6 literals, hostnames, ports, URLs, file paths, contextual PII, conversational proximity matching, the semantic layer |

Verified both directions: an `AKIA…` key, a commented-out `DB_PASSWORD=`,
and a JWT inside `//` lines are all still caught, while example amounts,
addresses and prose credentials in comments are not.

**Fails open, everywhere.** Unknown language, missing grammar, oversized
input, parse error, tree-sitter unavailable — each yields "no comment spans
known", i.e. exactly the pre-tree-sitter behavior. Losing syntax awareness
never means losing detection. A grammar that fails to parse is retired for
the session rather than retried per file.

It only engages when the language is known: a file read through a tool (the
path is taken from the tool's *input*, since results don't carry it) or the
active editor's `languageId`. Chat prose gets no syntax awareness, which is
correct — it isn't code.

Grammars ship via `tree-sitter-wasms` (23 of the mapped languages verified
working; `yaml`, `dart` and `elm` have an ABI mismatch with the pinned
runtime and self-disable). Note this adds ~49MB to a packaged VSIX — see
`.vscodeignore` for how to ship a subset. Toggle with
`enableSyntaxAwareRedaction`.

**Rehydration is hardened** for the same reason. `restore()` runs an exact
pass, then a tolerant shape-based pass that also catches `<< PASSWORD_1 >>`
and `<<password_1>>` — because a model asked to reformat code containing a
placeholder will reasonably re-case or re-space it, and an exact-only restore
then fails silently, handing the developer a literal token with the real value
gone. Anything still placeholder-shaped afterwards was never issued this
session, so it's surfaced as a warning rather than passed along quietly.

Writes are already safe: tool **inputs** are rehydrated before the tool
executes, so an agent editing a file with `<<PASSWORD_1>>` in its content
writes the real value, not the placeholder.

## Tool output and MCP redaction

When a host gives the model tool access, every tool call's arguments are
rehydrated before the tool runs (`session.guardToolInput`, backed by
`toolGateway/jsonRedactor.ts`'s `rehydrateJson`), and every result is redacted
before it goes back to the model (`session.guardToolResult` / `redactJson`).
In the VS Code host this covers built-in tools, extension-contributed tools,
and MCP tools registered via VS Code's native MCP support, since all three
share one registry. For a host whose tools DON'T come through a shared
registry, `toolGateway/toolGateway.ts` plus an adapter (`mcpAdapter.ts`,
`shellAdapter.ts`) provides the same guarantees around a direct call.

Tool results aren't always plain strings. Built-in tools frequently return
a `LanguageModelPromptTsxPart` — a real `@vscode/prompt-tsx` object tree,
not a string — rather than a `LanguageModelTextPart`. Redaction walks that
real tree directly (`redactJson` already knows how to recurse through
objects/arrays/strings) instead of `JSON.stringify`-ing the whole part
first: doing the latter would turn every real embedded newline inside the
tool's actual text content into a literal two-character `\n` escape,
which both defeats per-line routing (nothing left to split lines on) and
can leak a stray `\n` into the tail of a match that doesn't exclude
backslash from its character class (this is also why the URL regex in
`infraDetector.ts` excludes backslash explicitly).

`jsonRedactor.ts` also does field-level masking: if a JSON key name
matches a known sensitive field (`password`, `apikey`, `ssn`, `hostname`,
...), the entire value is treated as sensitive regardless of its shape —
on top of, not instead of, the normal content-based pipeline running on
every string value too.

## Running the test matrices

Standalone Node scripts against the compiled output — no VS Code needed:

```bash
npm run compile
node test/scenario-matrix.js   # conversational-secrets layer, in depth
node test/hybrid-matrix.js     # PII + infra + cross-category + regressions
```

`hybrid-matrix.js` covers: the Rahul-Sharma-style multi-entity example,
every structural PII rule (PAN/IFSC/SSN/Aadhaar/credit-card, including a
deliberately Luhn-invalid card number that should NOT match), contextual
PII numbers (phone/account/customer-id) with matching "should NOT match
without a keyword" negatives, infra detection (internal vs. public URL,
IP-embedded URLs, standalone IPs, file paths), the port-vs-sports-score
and hostname-vs-ordinary-phrase context tests, a regression check that the
original conversational-secrets layer still works untouched, and a
multi-category message that exercises all three tags (`PII`, `SECRET`,
`INFRA`) at once.

**One category still gets through even with every layer, on purpose, as a
demonstration of where this whole approach genuinely ends:** sensitivity
with no trigger keyword and no checkable shape at all — e.g. "we're
spending $80k on Project Falcon for the German expansion" *without* it
being the clear top-ranked, high-confidence business-strategy signal
`businessContentDetector.ts` requires. That's real semantic understanding
of intent, and it's a genuinely harder problem than routing/proximity
matching closes.

## What's stubbed out, and known limits

- **Real NER for names/orgs** — see above. Deliberately a heuristic,
  deliberately off by default.
- **True agent-mode interception** — this engine can only guard traffic a
  host actually routes through it. Whether that covers an editor's *own*
  built-in agent is a per-host question; for VS Code, it currently does not
  (see that package's README, "Scope").
- **Reverse substitution is exact-match only.** If a model paraphrases or
  drops a `<<TYPE_N>>` token instead of echoing it verbatim, that value
  won't get restored.
- **Aadhaar/PAN/SSN are pattern-only, not checksum-validated** (unlike
  credit cards, which get a real Luhn check). Aadhaar in particular has a
  real checksum (Verhoeff algorithm) that would meaningfully cut false
  positives further — worth adding before relying on those rules in anger.
- **`businessContentThreshold` is still a reasonable guess**, not
  empirically validated. (`semanticMatchThreshold` no longer is — see
  "Tuning the semantic threshold" above for its calibration; run the same
  exercise for the business-content category before trusting `0.4`.)
- **Two silent recall gaps in the value heuristic**, both deliberate trades
  against false positives, neither covered by the test matrices: quoted
  all-lowercase no-digit passwords (`"letmein"`), and `toekn`-class typos on
  short keywords. See "What counts as a value" above.

## Configuration

Every setting, its type and its default are declared once in
`src/settings.ts` (`VaultlineSettings` / `DEFAULT_SETTINGS`), and a host reads
its own config system into that shape. See the VS Code extension's README for
the user-facing table and per-setting descriptions.

Two things are worth knowing when adding a setting:

- **Defaults live here, not in the host.** A host that declares its own
  defaults will silently win over these — which is exactly how
  `semanticMatchThreshold` once shipped at `0.4` while the calibration that
  produced `0.5` sat in a comment beside the constant. The VS Code package
  has `scripts/checkSettings.js` to catch that at build time; a new host
  should do the equivalent.
- **`RULE_IDS`** enumerates every individually-disableable rule, grouped by
  the setting that disables it. Build a host's checkbox UI from it rather
  than transcribing the list.

## Project layout

```
src/
  index.ts                   — the public surface (start here)
  host.ts                    — VaultlineHost: the entire editor boundary + ConsoleHost
  engine.ts                  — VaultlineEngine: embedder/router wiring, backend fallback
  guardSession.ts            — GuardSession: the guard, as host-neutral steps
  settings.ts                — VaultlineSettings, DEFAULT_SETTINGS, RULE_IDS
  assets.ts                  — resolves this package's own data/ and grammars

  patternMatcher.ts          — structural regex: secrets. A rule whose pattern
                               needs a key name to FIND the value (API_KEY = x)
                               sets `valueGroup` + the `d` flag so only the
                               value is redacted, leaving the name visible.
  piiDetector.ts             — structural regex + contextual proximity: PII
  infraDetector.ts           — structural regex + contextual proximity: infra
  nlpProximityMatcher.ts     — contextual proximity + fuzzy matching: conversational secrets
  proximityUtils.ts          — shared tokenizer/heuristics for pii + infra
  businessContentDetector.ts — whole-message business-content flag
  embeddingRouter.ts         — category centroid similarity / routing gate
  semanticKeywordMatcher.ts  — last-line-of-defense semantic keyword layer (API backend only)
  detectionPipeline.ts       — merges & dedupes every layer; scanAll vs. scanCurrentMessage
  entityTypes.ts             — Match -> typed placeholder name (PASSWORD, PERSON, ...)
  entityStore.ts             — session-level typed token mapping table + disk persistence
  tokenizer.ts               — tokenize / reverse-substitute / known-value-only redaction
  policyEngine.ts            — allow/redact/block decision logic
  auditLog.ts                — local JSON-lines audit trail
  syntax/
    syntaxAnalyzer.ts        — tree-sitter comment spans for syntax-aware suppression
  embeddings/
    embedder.ts              — Embedder interface + batching fallback
    hashingEmbedder.ts       — dependency-free lexical embedder (no server needed)
    apiEmbedder.ts           — calls embedding-server/ for real semantic embeddings
    serverManager.ts         — installs/starts/stops that server, via VaultlineHost
  toolGateway/
    jsonRedactor.ts          — recursive JSON/tool-result redact + rehydrate, field-level masking
    toolGateway.ts, toolAdapter.ts, mcpAdapter.ts, shellAdapter.ts — tool-call plumbing
data/
  categoryExamples.json      — INPUT to buildEmbeddings.js (not shipped at run time)
  categoryEmbeddings.json    — precomputed centroids, api/MiniLM backend (384-dim)
  categoryEmbeddings.hashing.json — the same, hashing backend (256-dim)
  semanticKeywordSeeds.json  — seed keywords for the semantic matcher
embedding-server/
  server.js                  — the local MiniLM embedding server (api backend)
scripts/
  buildEmbeddings.js         — precomputes the category centroids
test/
  scenario-matrix.js         — conversational-secrets layer, in depth
  hybrid-matrix.js           — PII + infra + cross-category + regressions
  routingMatrix.js           — routing gate behavior
  test_detection.txt         — sample multi-category fixture for manual/tool-read testing
```
