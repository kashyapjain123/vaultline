# Vaultline for GitHub Copilot CLI

Zero-trust context control for [GitHub Copilot CLI](https://github.com/github/copilot-cli).

Copilot CLI reads your files and sends them to GitHub. If one of those files holds a
password, an API key, an internal hostname or a customer's email address, that value
leaves your machine — and it leaves whether or not the model then helpfully points
out that you have committed secrets in plain text.

Vaultline sits in the middle. It replaces Copilot's file and shell tools with its own,
redacts sensitive values out of everything on the way to the model, and puts the real
values back before anything is written to disk.

```
  config.yaml on disk                what GitHub receives
  ───────────────────                ────────────────────
  password: "Hunter@123"       →     password: "<<PASSWORD_1>>"
  host: "db.corp.internal"     →     host: "<<HOSTNAME_1>>"
  email: rahul@example.com     →     email: <<EMAIL_1>>
```

## Install

```bash
npm install -g @vaultline/cli
vaultline doctor
```

`doctor` checks that Copilot CLI is present, that the tool names Vaultline replaces
still exist in your version of it, and prints exactly what is and is not covered.

## Use

```bash
vaultline copilot            # instead of: copilot
vaultline copilot --resume   # any Copilot CLI argument still works
```

That launches Copilot with its built-in `view`, `grep`, `rg`, `glob`, `shell`,
`edit`, `create`, `apply_patch` and `str_replace_editor` tools switched off and
Vaultline's redacting equivalents in their place.

## What is and is not covered

Read this part. Coverage **differs between the two modes**, and a tool like this is
worse than useless if you assume it covers more than it does.

| | `-p` (non-interactive) | interactive |
|---|---|---|
| Your typed prompt | **redacted** | **not covered** |
| File / search / shell content | redacted | redacted |
| Writes back to disk | rehydrated | rehydrated |
| Answer on screen | **real values restored** | placeholders (`--reveal` decodes on demand) |

```bash
# full coverage — prompt in, answer out
vaultline copilot -p "does config.yaml use a weak password?"

# tool coverage only — what you type goes to GitHub as typed
vaultline copilot

# same, but `vaultline reveal` can decode the placeholders you see
vaultline copilot --reveal
```

With `-p`, both ends pass through Vaultline, so it matches the VS Code extension.
Interactively, Copilot owns the terminal in both directions and nothing outside that
process can reach it — that half needs the BYOK proxy under *Limitations* below.

**Never covered, in either mode**: anything Copilot does outside its tools, including
its own MCP servers.

### Resuming a session

Copilot ends every session by printing its own resume command:

```
Resume     copilot --resume=93d3b684-…
```

**Do not run that.** Plain `copilot` has no Vaultline in it, so the built-in file and
shell tools come back and the resumed conversation reads files straight to the model.
Vaultline prints the protected form on exit — use that instead:

```bash
vaultline copilot --resume=93d3b684-…
```

Nothing about copying the wrong line is your fault; it is the command Copilot offers.
We cannot change what it prints, so Vaultline sets the session UUID itself in order to
be able to show you the right one afterwards.

Rehydration on write is always on and needs no configuration — without it, redaction
would corrupt your config the first time the model edited a file it had read.

### Reading placeholders in an interactive session

`vaultline copilot --reveal` keeps this session's mappings in a private temp file, so
you can decode anything Copilot prints:

```bash
# terminal 1
vaultline copilot --reveal

# terminal 2 — paste or pipe the output you want to read
pbpaste | vaultline reveal
```

The file is `0600` in a private directory and deleted when the session ends, including
on Ctrl-C. It does **not** require `persistSessionMappings`, which is permanent.

It does not change what is on screen. Copilot requires a real TTY and draws a
full-screen interface it redraws continuously; substituting a value of a different
width underneath it (`<<PASSWORD_1>>` is 15 columns, `Hunter@123` is 10) corrupts its
own cursor and layout arithmetic. So the placeholders stay, and `reveal` decodes them
on demand.

## Configuration

`~/.vaultline/config.json`, using the same setting names as the VS Code extension:

```json
{
  "enableSemanticKeywordMatching": true,
  "embeddingBackend": "hashing",
  "persistSessionMappings": false
}
```

`vaultline doctor` reports any malformed setting rather than silently falling back —
a bad value in one numeric setting could otherwise disable contextual detection
entirely.

### `persistSessionMappings`

Off by default, and worth understanding before turning it on. It mirrors every
detected value, next to its placeholder, to `~/.vaultline/sessions/*.json` **in plain
text**. That file is what makes `vaultline reveal` possible — and it is also a file
full of your secrets. Off is the right default; turn it on deliberately or not at all.

It is **not** required for redaction, rehydration, or the `-p` round trip. Those all
work with it off.

`-p` runs do briefly need a mapping file of their own, for a different reason: the MCP
server is a separate process that Copilot spawns, so it and the parent must share one
token store or the same secret would get two different placeholders. That file is
created `0600` in a private temp directory and deleted when the run ends, including on
Ctrl-C. It holds real values while it exists, which is unavoidable for two processes
to agree, but it does not outlive the command.

## How it works

Vaultline registers itself as an MCP server and Copilot calls into it:

```
model wants config.yaml
  → Copilot calls vaultline_read
  → Vaultline reads the real bytes
  → the detection engine redacts them
  → "password: <<PASSWORD_1>>" is what reaches GitHub

model edits config.yaml, holding <<PASSWORD_1>>
  → Copilot calls vaultline_write
  → Vaultline substitutes the real value
  → the real password is what reaches disk
```

Detection is [`@vaultline/core`](../core), the same engine as the VS Code extension:
structural rules, contextual PII and infrastructure detection, proximity matching over
conversational phrasing, and optional embedding-based routing.

## Limitations of the approach

This works by replacing Copilot's tools, which is the only interception point that
keeps your GitHub authentication and Copilot subscription intact.

`-p` gets the prompt as well, because it arrives in our own argv and the answer comes
back through our stdout. **Interactive typing does not**: Copilot draws that prompt
and sends it itself, and no external process can reach it without sitting between you
and the terminal as a PTY — which was already the wrong answer for file content, since
a PTY sees only what is displayed rather than what is sent.

Closing that last gap means putting Vaultline in front of the model rather than in
front of its tools. Copilot CLI supports it through `COPILOT_PROVIDER_BASE_URL`, but
BYOK bypasses GitHub's model routing and needs your own provider key. That is the
planned second mode, not this one.

## License

Apache-2.0
