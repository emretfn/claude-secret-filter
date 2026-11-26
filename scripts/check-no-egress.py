#!/usr/bin/env python3
"""Fails when the mod's code could send data anywhere.

The mod sees every secret it masks, so its code must never reach the network, other
processes, the model, or disk writes. CI runs this on every pull request and push;
`main` cannot be merged into while it fails.

  python3 scripts/check-no-egress.py                          # static check of the repository
  python3 scripts/check-no-egress.py --validate report.json   # also check `claude plugin validate --json`

The engine's own report (`--validate`) is the main gate: the engine resolves every
`$` call, whatever the hook's parameter is named, and refuses `$` used as a value.
The static check is a second, independent layer. It also pins what the plugin ships:
the marketplace installs the whole repository, so a new top-level file or folder
(skills/, commands/, .mcp.json, ...) could add a component nobody reviewed.

Adding a file under hooks/, a top-level entry, or a new $ call means changing the
allowlists below, in the same pull request, where a reviewer sees it.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / "hooks"

# The only engine calls the mod may make: list and read files (seeding), show a toast.
ALLOWED_CALLS = {"$.fs.list", "$.fs.read", "$.ui.toast"}
# The only files under hooks/, and the one module the engine loads.
ALLOWED_FILES = {"hooks.json", "register.ts", "redact.ts", "gitleaks-rules.ts"}
MODULES = ["./register.ts"]
# Generated data: must be data only (checked by `data_check`), and is regenerated in CI.
DATA_FILES = {"gitleaks-rules.ts"}

# Every tracked path, by top-level entry. Anything else is refused.
TOP_LEVEL = {
    ".claude-plugin", ".claude", ".github", "docs", "hooks", "scripts", "tests",
    ".gitignore", "AGENTS.md", "LICENSE", "README.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md", "tsconfig.json",
}
FIXED_FILES = {
    ".claude-plugin": {"plugin.json", "marketplace.json"},
    ".claude": {"CLAUDE.md"},
}
PLUGIN_KEYS = {"name", "version", "description", "license", "keywords", "author", "homepage", "repository"}
MARKETPLACE = {"name", "owner", "plugins", "description"}

FORBIDDEN = {
    r"\bfetch\b": "network: fetch",
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
    r"\bconstructor\b": "constructor (reaches Function)",
    r"\b(?:Bun|Deno|process|window|self)\b": "runtime global",
    r"\bsetTimeout\s*\(\s*['\"`]": "setTimeout with a string",
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


def data_check() -> list[str]:
    """gitleaks-rules.ts holds three type aliases and JSON values, nothing that runs."""
    errors = []
    src = (HOOKS / "gitleaks-rules.ts").read_text()
    body = "\n".join(l for l in src.splitlines() if not l.startswith("//"))
    types = re.findall(r"^export type \w+ = .*$", body, re.M)
    if len(types) != 3 or any(re.search(r"[()=]>|\bfunction\b|\bnew\b|\bimport\b", t) for t in types):
        errors.append("hooks/gitleaks-rules.ts: unexpected type declarations")
    rest = re.sub(r"^export type \w+ = .*$", "", body, flags=re.M)
    decls = re.split(r"^export const (\w+)(?:: [^=\n]+)? = ", rest, flags=re.M)
    if decls[0].strip():
        errors.append("hooks/gitleaks-rules.ts: code outside the data declarations")
    names = decls[1::2]
    if names != ["GITLEAKS_VERSION", "GITLEAKS_RULES", "GITLEAKS_GLOBAL_ALLOW"]:
        errors.append(f"hooks/gitleaks-rules.ts: unexpected declarations {names}")
    for name, value in zip(names, decls[2::2]):
        try:
            json.loads(value)
        except ValueError as e:
            errors.append(f"hooks/gitleaks-rules.ts: {name} is not plain JSON data ({e})")
    return errors


def layout_check() -> list[str]:
    errors = []
    try:
        tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        return ["git ls-files failed: the layout check needs a git checkout"]
    for path in tracked:
        top, _, rest = path.partition("/")
        if top not in TOP_LEVEL:
            errors.append(f"{path}: unexpected top-level entry (the marketplace ships the whole repository; add it to TOP_LEVEL, in review)")
        elif top in FIXED_FILES and rest not in FIXED_FILES[top]:
            errors.append(f"{path}: unexpected file in {top}/")
    plugin = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())
    for k in sorted(set(plugin) - PLUGIN_KEYS):
        errors.append(f".claude-plugin/plugin.json: unexpected key {k!r} (it could declare hooks, servers or commands)")
    market = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
    for k in sorted(set(market) - MARKETPLACE):
        errors.append(f".claude-plugin/marketplace.json: unexpected key {k!r}")
    if market.get("plugins") != [{"name": plugin.get("name"), "source": "./"}]:
        errors.append(".claude-plugin/marketplace.json: plugins must be exactly this plugin, from ./")
    return errors


def validate_check(report_path: str) -> list[str]:
    report = json.loads(Path(report_path).read_text())
    errors = []
    if report.get("success") is not True:
        errors.append("claude plugin validate: did not succeed")
    for c in [report.get("manifest", {}), *report.get("contents", [])]:
        for x in [*c.get("errors", []), *c.get("warnings", [])]:
            errors.append(f"claude plugin validate: {x.get('message', x)}")
    notes = [n for c in report.get("contents", []) for n in c.get("notes", [])]
    calls_notes = [n for n in notes if " calls: " in n]
    if not calls_notes:
        # the module does call $.fs and $.ui: a report without that note was not read right
        return errors + ["claude plugin validate: no 'calls:' note in the report; cannot check the engine calls"]
    for n in calls_notes:
        for call in (c.strip() for c in n.split(" calls: ", 1)[1].split(",")):
            if call and call not in ALLOWED_CALLS:
                errors.append(f"claude plugin validate: the module calls {call}, which is not allowed")
    return errors


def main() -> None:
    errors = static_check() + data_check() + layout_check()
    if sys.argv[1:2] == ["--validate"]:
        errors += validate_check(sys.argv[2])
    if errors:
        fail(errors)
    print(f"ok: no egress; engine calls limited to {', '.join(sorted(ALLOWED_CALLS))}")


if __name__ == "__main__":
    main()
