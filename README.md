# secret-filter

A Claude Code mod that masks API keys, tokens, passwords and `.env` values in tool
output **before Claude reads it**. Masked values become placeholders,
`[REDACTED:<id>]` with an 8-hex-digit id. When Claude copies a placeholder into an
edit, the mod writes the real value back to the file, so editing config files keeps
working.

## Install

At the prompt of a Claude Code terminal session:

```
/plugin install secret-filter --marketplace emretfn/claude-secret-filter
```

From a shell:

```
claude plugin install secret-filter --marketplace emretfn/claude-secret-filter
```

In the desktop app (where `/plugin` does not run): click **+** next to the prompt
box, then **Plugins**, **Add marketplace** with `emretfn/claude-secret-filter`, then
**Add plugin**.

Nothing else needs to be installed: gitleaks' rules ship converted, as a file.

> **Disclaimer.** secret-filter is best-effort defense in depth, provided "as is" under
> the MIT license, without warranty of any kind. It reduces the chance that a secret
> reaches the model; it does not guarantee that none will, and it is not a substitute
> for keeping secrets out of reach (a secrets manager, least-privilege credentials,
> rotating anything that may have been exposed). You are responsible for how you use
> it and for the secrets in your environment. See [Disclaimer](#disclaimer) below.

> **Requirements.** The mod uses Claude Code's *function hooks* API, which is in
> early access and may change between releases. It was built and tested on Claude
> Code 2.1.332. Classic `PostToolUse` hooks cannot do some of what it does (see below).

## How it works

![How secret-filter sits between Claude and its tools: tool output goes through the read hook and the redaction engine, so Claude only sees placeholders; real values stay in an in-memory vault, seeded from .env files, and the write hook puts them back when Claude edits a file.](docs/architecture.png)

- **Reading.** Every call to `Bash`, `Read`, `WebFetch`, `WebSearch` or an MCP tool runs as usual. Its text output goes through the redaction engine before Claude sees it, failed calls included (images and PDFs pass as they are: see [Limits](#limits)). Claude reads placeholders where the secrets were.
- **Everything else.** Every other row the conversation keeps (other tools such as `Monitor`, background task and subagent results, notifications, attachments) goes through the same engine before the model reads it. Only your own prompt and Claude's own reply are left as written. Some raw output reaches disk before this point: see [Limits](#limits).
- **The vault.** Each masked value is kept in the mod's memory under its placeholder id, with the files it was read from. Values from the project's git-ignored `.env`-style files are learned at session start.
- **Writing.** When Claude edits a file and copies a placeholder into `Edit` or `Write`, the write hook swaps the real value back in before the write, **only in the file the value was read from, and only on a line kept exactly as it was**. What the tool returns is masked again.

The diagram sources are in [`docs/`](docs/) (HTML with inline SVG).

## What it masks

![The redaction engine, layer by layer: known values, known formats, secret-named fields, entropy and env mode, in that order.](docs/layers.png)


Every text string in the output of `Bash`, `Read`, `WebFetch`, `WebSearch` and all MCP
tools goes through these layers, in order:

| Layer | What | Example |
|---|---|---|
| Known values | A distinctive value (8+ characters, not a plain word) masked by a confident layer, or found in the project's secret files at session start, is masked wherever it shows up again, also base64 and URL-encoded. Entropy guesses and short or letters-only values are not learned, so they are masked only where a layer catches them again | a DB password in a stack trace |
| Known formats | About 30 rules of our own, plus all 221 rules of [gitleaks](https://github.com/gitleaks/gitleaks) (keyword pre-filter, entropy, allowlists) | `ghp_…`, `sk-ant-…`, Azure DevOps PATs, JWTs, private keys |
| Secret-named fields | Values of fields whose name ends in `password`, `secret`, `token`, `apiKey`, … Also in escaped JSON, XML elements and `key="…" value="…"` attributes, `--flags`, `curl -u`/`-H`, `mysql -p`, SQL `IDENTIFIED BY`/`WITH PASSWORD` and PHP `define()`. Code is told apart from data: `token: CancellationToken` and `x = compute()` stay | `"clientSecret": "…"`, `Password=…;`, `user:pass@host` |
| Entropy | Long, random-looking tokens of no known format and with no label | an unlabeled 40-char token |
| Env mode | For `.env`, `.env.local` and other `.env.*` (not the templates `.example`, `.sample`, `.template`, `.dist`, `.defaults`), `.envrc`, `.npmrc`, `.netrc`, `.pgpass`, `credentials`, `secrets.json`, … and for `env`/`printenv` (also under `sudo` or `docker exec`), every value except booleans, numbers and a few safe names (`PATH`, `NODE_ENV`, `PORT`, …) | `DATABASE_HOST=` followed by a placeholder |

Failed commands (non-zero exit) are masked too, and so are `grep` lines that come
from env files.

## Placeholders and edits

- The same value always gets the same placeholder within a session, and real values
  are kept in the mod's memory only: never written to disk, never sent to the model.
  Ids are a keyed hash with a random per-session key, so a placeholder that ends up
  somewhere public cannot be checked against guessed passwords.
- For `Edit` and `Write`, placeholders in the input are turned back into the real
  values just before the write. The tool's result is masked again,
  and a restored value of 3 characters or more stays masked in later outputs
  whatever it looks like (one under 8 characters only as a whole word), until the
  mod reloads.
- **A value is only restored into the file it was read from with `Read`, and only
  on a line kept exactly as it was**: the mod compares the whole file before and
  after the write, and every line that holds a restored value must be a line of the
  file as it is, unchanged, no more often than there. Claude can edit the lines
  around a secret, or delete its line; editing, splitting or copying the line itself
  is refused, so a value is never moved into a new line, another file, a script or a
  URL. Nothing is restored under `.git/` or into a notebook (`NotebookEdit`).
  Command output (`cat a b`) names no file for sure, so its placeholders are
  restored nowhere. To change a line that holds a secret, edit it yourself.
- In auto mode, a write that restores real values is put to you instead of to the
  classifier, which would read its input.
- A placeholder the mod does not know (after a reload) makes the write refuse
  instead of writing a placeholder into a file. Reading the file again fixes it.
- A `Bash` command that holds a placeholder is refused: `sed` or a heredoc would
  write the placeholder itself into a file, or send it somewhere.
- The same check means the literal text of a placeholder cannot be written. To
  write one (in a test or docs), build it at run time, `'[REDACTED' + ':deadbeef]'`,
  or write `<id>` in place of the hex digits.

## False positives

The mod is tuned against real codebases (.NET, TypeScript/React/Expo, Python) so
code stays readable: git SHAs, UUIDs, migration names, code identifiers, URL slugs,
package hashes (`integrity`, `contentHash`, Go `h1:`), templates (`${VAR}`,
`{{ x }}`, `${{ secrets.X }}`, `%VAR%`), placeholder values (`changeme`, `<your-key>`,
`xxxx`) and `.env.example` files are left alone. Guesses from the entropy layer are
never learned as known values, so a false positive does not spread.

## Limits

This is defense in depth, not a guarantee. It does not:

- stop a command from **sending** a secret somewhere (`curl -d "$TOKEN" …`,
  `curl -d @.env …`): it only filters what Claude reads. It is not a sandbox: a
  command can read any file the session can.
- keep raw output off your disk. Claude Code writes some output to its own files
  before any hook sees it: the full output of a large `Bash` result (`tool-results/`
  in the session folder), the output files of background tasks and `Monitor`
  (`tasks/`), and the transcript of a subagent that ran `Monitor`. What Claude reads
  from those is masked, the files themselves are not. Treat the session folder under
  `~/.claude/projects/` as holding secrets.
- mask what you type or paste into the prompt yourself, or the output of a `!`
  command you run: those are yours, kept as written. An `@`-mention of a secret
  file is refused (Claude can `Read` it, masked); other mentions are masked.
- keep a determined or hostile model from a secret: `curl -d @.env …`, `base64 .env`
  or `rev` in a command get around any output filter. It guards against accidental
  exposure.
- hide a restored value from what runs beneath the write: the permission dialog
  shows it to you, and your own classic `PreToolUse` hooks receive it.
- catch every short random token: the entropy layer misses about 20% of 24-char
  tokens and 1–5% of 32+ char tokens. Known formats are always caught.
- catch secrets that are split, reversed or hex-encoded.
- look inside images and PDFs: a screenshot or a scanned document that shows a
  token reaches Claude as it is.
- filter text piped into a non-interactive prompt (`cat .env | claude -p`, the SDK):
  that is your own prompt.
- forget less than it learned: the vault lives in memory, so a reload of the mod (or
  of the engine's hook worker) empties it. Placeholders from before are refused on
  write, and values learned while working are masked again only when a layer
  catches them again.

Seeding runs in the background at session start (the first tool calls may come
before it ends) and reads up to 50 secret files, 4 directory levels deep from the session's
directory, nearest first. In a git repository it reads only files git ignores: a
secret file committed to a cloned repository is not yours, and could plant "decoys"
that hide ordinary code. Plain words, code identifiers, plain URLs and values that
read like code are not learned, and seeds have a budget of their own (500 values, 100
per file), so they cannot crowd out what is learned while working.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied,
as the [MIT license](LICENSE) states in full. In particular:

- It is a best-effort filter. Detection is heuristic: secrets in unknown formats,
  short values, split or encoded secrets, or output shapes the mod does not see may
  pass through unmasked. Do not rely on it as your only safeguard.
- It runs on an early-access Claude Code API that may change and break it without
  notice.
- If a secret may have reached the model, a transcript, a log or a third party,
  treat it as exposed and rotate it.
- The authors and contributors are not liable for any claim, damages, data loss,
  credential exposure or other liability arising from its use or inability to use it.
- It is an independent project, not made, endorsed or supported by Anthropic.
  "Claude" and "Claude Code" are names of Anthropic's products, used here only to say
  what the plugin works with.

By installing or using it you accept these terms and the license.

## Development

```
claude plugin validate .   # what the engine would load or refuse
claude plugin test .       # unit tests (tests/redact.test.ts) and engine integration tests (tests/hooks.test.ts)
```

Tests generate their secrets at run time, so no real-looking token is committed.
Before changing the mod, read [AGENTS.md](AGENTS.md): it covers the no-egress rule,
version bumps and releases, and how to add detection rules and tests.

To update the gitleaks rules:

```
python3 scripts/gen-gitleaks-rules.py --tag v8.30.1   # or a newer release tag
claude plugin test .
```

## Credits

- Detection rules: [gitleaks](https://github.com/gitleaks/gitleaks) (MIT), see
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- Ideas: seeding from secret files and encoded variants from
  [securikey](https://github.com/CodeAndCanvas728/securikey); ANSI stripping and value
  heuristics from [redact-hook](https://github.com/SilentAutomaton/redact-hook);
  placeholder filters from [gitleaks-redact](https://github.com/Lingnik/claude-code-plugins);
  false-positive heuristics from [detect-secrets](https://github.com/Yelp/detect-secrets).

## License

MIT, see [LICENSE](LICENSE).
