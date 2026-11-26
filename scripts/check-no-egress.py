#!/usr/bin/env python3
"""Fails when the mod's code could send data anywhere.

The mod sees every secret it masks, so its code must never reach the network, other
processes, the model, or disk writes. CI runs this on every pull request and push;
`main` cannot be merged into while it fails.

  python3 scripts/check-no-egress.py                          # static check of hooks/
  python3 scripts/check-no-egress.py --validate report.json   # also check `claude plugin validate --json`

Adding a file under hooks/ or a new $ call means changing the allowlists below, in
the same pull request, where a reviewer sees it.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / "hooks"

# The only engine calls the mod may make: list and read files (seeding), show a toast.
ALLOWED_CALLS = {"$.fs.list", "$.fs.read", "$.ui.toast"}
# The only files under hooks/, and the one module the engine loads.
ALLOWED_FILES = {"hooks.json", "register.ts", "redact.ts", "gitleaks-rules.ts"}
MODULES = ["./register.ts"]
# Generated data: checked by regenerating it (see the CI workflow), not by these patterns.
DATA_FILES = {"gitleaks-rules.ts"}

FORBIDDEN = {
    r"\bfetch\s*\(": "network: fetch",
    r"\bXMLHttpRequest\b": "network: XMLHttpRequest",
    r"\bWebSocket\b": "network: WebSocket",
    r"\bEventSource\b": "network: EventSource",
    r"\bsendBeacon\b": "network: sendBeacon",
    r"\bimport\s*\(": "dynamic import",
    r"\brequire\s*\(": "require",
    r"\beval\s*\(": "eval",
    r"\bnew\s+Function\b": "new Function",
    r"\bglobalThis\b": "globalThis",
    r"\bReflect\b": "Reflect",
    r"(?<![\\\w])\$\s*\[": "$ accessed by index",  # not an escaped \$ inside a regex
}
IMPORT = re.compile(r"""^\s*import\b[^'"]*['"]([^'"]+)['"]""", re.M)
ALLOWED_IMPORTS = {"claude-code", "./redact", "./gitleaks-rules"}
DOLLAR_CALL = re.compile(r"\$\.([A-Za-z_]\w*)\.([A-Za-z_]\w*)")


def fail(errors: list[str]) -> None:
    for e in errors:
        print(f"::error::{e}")
    sys.exit(1)


def static_check() -> list[str]:
    errors = []
    names = {p.name for p in HOOKS.iterdir()}
    for extra in sorted(names - ALLOWED_FILES):
        errors.append(f"hooks/{extra}: unexpected file (add it to ALLOWED_FILES in this script, in review)")
    modules = json.loads((HOOKS / "hooks.json").read_text()).get("modules")
    if modules != MODULES:
        errors.append(f"hooks/hooks.json: modules must be {MODULES}, found {modules}")
    for p in sorted(HOOKS.glob("*.ts")):
        if p.name in DATA_FILES:
            continue
        src = p.read_text()
        for pattern, what in FORBIDDEN.items():
            for m in re.finditer(pattern, src):
                line = src.count("\n", 0, m.start()) + 1
                errors.append(f"hooks/{p.name}:{line}: forbidden ({what})")
        for spec in IMPORT.findall(src):
            if spec not in ALLOWED_IMPORTS:
                errors.append(f"hooks/{p.name}: forbidden import {spec!r}")
        for noun, method in DOLLAR_CALL.findall(src):
            call = f"$.{noun}.{method}"
            if call not in ALLOWED_CALLS:
                errors.append(f"hooks/{p.name}: forbidden engine call {call}")
    return errors


def validate_check(report_path: str) -> list[str]:
    report = json.loads(Path(report_path).read_text())
    notes = [n for c in report.get("contents", []) for n in c.get("notes", [])]
    calls_notes = [n for n in notes if " calls: " in n]
    if not calls_notes:
        return []  # no engine calls at all
    errors = []
    for n in calls_notes:
        for call in (c.strip() for c in n.split(" calls: ", 1)[1].split(",")):
            if call and call not in ALLOWED_CALLS:
                errors.append(f"claude plugin validate: the module calls {call}, which is not allowed")
    return errors


def main() -> None:
    errors = static_check()
    if sys.argv[1:2] == ["--validate"]:
        errors += validate_check(sys.argv[2])
    if errors:
        fail(errors)
    print(f"ok: no egress; engine calls limited to {', '.join(sorted(ALLOWED_CALLS))}")


if __name__ == "__main__":
    main()
