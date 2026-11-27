# secret-filter

A Claude Code mod (function hooks, early access) that masks secrets in tool output.
`README.md` covers what it does and the commands; this file covers how to change it.

## The invariant: zero egress

The mod sees every secret it masks, so its code only ever reads tool results, reads
the project's secret files, and shows toasts. Real values stay in module memory.

- The engine calls the mod may make are the allowlist in `scripts/check-no-egress.py`.
  A new `$` call, import or file under `hooks/` means editing that allowlist in the
  same pull request, so a reviewer sees it next to the code that needs it.
- Persisting the vault is out of scope: no disk writes, no `$.store`, no `$.state`.
- A real value is restored only into a file it was read from with `Read` (its
  sources in the vault), only on a line of that file kept unchanged (`movedValues`,
  on the whole file before and after the write), never under `.git/`, never by
  `NotebookEdit`. Three audits found a way around every looser rule (substring
  spans, trimmed lines, an `old_string` that is part of a line): keep it this strict. Restoring is the one place the mod puts
  a secret back into the world: a change that widens it needs a test showing a
  placeholder cannot reach another file, a new line, a command or a URL.
- Redaction is bounded in time (`withBudget`): past it the hook throws and its
  `.catch` withholds the output. A hook that runs past the engine's budget loses its
  worker: the engine starts a fresh one (the vault is gone) and its `.catch` answers.
  A single regex call cannot be interrupted, so every pattern stays linear: time new
  ones on 1 MB of hostile text (a line full of the keyword) before merging.

## Shipped files and versions

**Shipped files** are every file except docs, tests, scripts, CI and the repository's
notes (the list is `NOT_SHIPPED` in `scripts/check-version-bump.py`): the marketplace
installs the whole repository. A new top-level entry must be added to `TOP_LEVEL` in
`scripts/check-no-egress.py`. Installed copies update by version, so every pull
request that changes a shipped file raises `version` in `.claude-plugin/plugin.json`:

- PATCH: a fix, a false-positive fix, a rule tweak.
- MINOR: a new layer, a new rule set, a new tool covered.
- MAJOR: a breaking change, such as the placeholder format or the restore behaviour.

Docs, tests, scripts and CI keep the version. CI enforces the bump
(`scripts/check-version-bump.py`).

After the pull request merges, tag the merge commit `vX.Y.Z` with the new version and
push the tag. Release tags are protected: a tag points at one commit forever, so tag
only a merged `main` commit.

## Changing detection

Every detection change comes with two tests in `tests/redact.test.ts`: one that the
secret is masked, one that nearby ordinary code stays readable. A false positive
costs the user as much as a miss: it hides code Claude needs.

- `hooks/gitleaks-rules.ts` is generated. Change `scripts/gen-gitleaks-rules.py` and
  regenerate it; CI fails when the file differs from the generator's output.
- Only high-confidence layers feed the known-values layer (`mask(value)`); a guess
  passes `learn = false`, so one false positive never spreads.
- Binary content (images, PDFs, MCP image blocks) passes through untouched.

## Writing tests

- Generate secrets at run time and split their prefixes (`'gh' + 'p_' + rnd(36)`), so
  no real-format token is committed: GitHub push protection and secret scanners
  would flag it.
- Build placeholder literals at run time too (`'[REDACTED' + ':deadbeef]'`).
- Keep fixtures generic: no names, hosts or vocabulary from a real project or company.

## Working on this repo with the mod running

When the mod is active in your own session, it masks this repo's source as you read
it: regex literals and test fixtures show up as placeholders. Edit through them, as
`Edit`/`Write` restore the real text, or re-read the file after the mod reloads
(placeholders from before a reload are unknown and the write is refused).

## Guard scripts

On a pull request, CI runs `scripts/check-no-egress.py`, `scripts/check-version-bump.py`
and `scripts/gen-gitleaks-rules.py` from the base branch, so editing them does not
loosen the checks a pull request is judged by. The workflow file itself runs as the
pull request has it, so a change under `.github/` is reviewed by hand. Change a
guard script (or its allowlists) in a pull request of its own, merged before the
change that needs it.

## Pull requests

`main` is protected: every change is a pull request, and the `guard` and `test`
checks must pass. A pull request is ready when, locally:

```
claude plugin validate --strict .
claude plugin test .
python3 scripts/check-no-egress.py
python3 scripts/check-version-bump.py origin/main
```

Commit messages follow Conventional Commits (`fix(redact): ...`, `feat: ...`, `docs: ...`).
