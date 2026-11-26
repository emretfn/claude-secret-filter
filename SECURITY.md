# Security

secret-filter sees every secret it masks, so the code it runs is guarded:

- `main` is protected: no direct pushes, no force pushes, no deletion. Every change
  goes through a pull request, and the CI checks below must pass first. The rule has
  no bypass, the maintainer included.
- Release tags (`v*`) cannot be moved or deleted, so a published version cannot be
  swapped for different code.
- CI (`scripts/check-no-egress.py`) fails when the mod's code could send data
  anywhere: network APIs, dynamic imports, `eval`, or any engine call besides
  `$.fs.list`, `$.fs.read` and `$.ui.toast`. The same check reads the engine's own
  report of what the module calls (`claude plugin validate --json`).
- The gitleaks rules file must be exactly what `scripts/gen-gitleaks-rules.py`
  produces from the pinned gitleaks release, so it cannot hide code.
- CI runs with a read-only token, actions are pinned by commit SHA, and workflows
  from outside contributors' pull requests wait for the maintainer's approval.

If you want to review before updating, check the diff between release tags, and the
CI result on the commit you install.

## Reporting a vulnerability

Please report a vulnerability privately through GitHub's
[security advisories](https://github.com/emretfn/claude-secret-filter/security/advisories/new),
not in a public issue.
