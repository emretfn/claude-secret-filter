# Security

secret-filter sees every secret it masks, so the code it runs is guarded:

- `main` is protected: no direct pushes, no force pushes, no deletion. Every change
  goes through a pull request, and the CI checks below must pass first. The rule has
  no bypass, the maintainer included.
- Release tags (`v*`) cannot be moved or deleted, so a published version cannot be
  swapped for different code.
- CI fails on the ways the mod's code could reach out that a check can see. The
  main gate is the engine's own report of the module (`claude plugin validate
  --json`), which resolves every `$` call and refuses `$` used as a value: only
  `$.fs.list`, `$.fs.read` and `$.ui.toast` are allowed, and the events the module
  hooks are pinned. A static check (`scripts/check-no-egress.py`) adds a second
  layer: network APIs, dynamic imports, `eval`, `Function` and runtime globals are
  refused, and every input the module passes on rewritten (`next({ ... })`) must be
  one of the reviewed rewrites.
- What no check can prove is what an allowed hook does with a tool call's input: a
  hook could still put a value into a `WebFetch` URL or a command it passes on
  without a new rewrite site, for instance by changing what `restore` returns. The
  guard is that every change is a reviewed pull request; read `hooks/register.ts`
  in the diff before you update.
- The marketplace installs the whole repository, so CI pins its layout: a new
  top-level file or folder, or a manifest key that could declare hooks, servers or
  commands, fails until it is added to the allowlist in review.
- The gitleaks rules file must be plain JSON data and exactly what
  `scripts/gen-gitleaks-rules.py` produces from the pinned gitleaks release.
- CI runs with a read-only token, actions are pinned by commit SHA, and workflows
  from outside contributors' pull requests wait for the maintainer's approval.

If you want to review before updating, check the diff between release tags, and the
CI result on the commit you install.

## Reporting a vulnerability

Please report a vulnerability privately through GitHub's
[security advisories](https://github.com/emretfn/claude-secret-filter/security/advisories/new),
not in a public issue.
