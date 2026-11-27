#!/usr/bin/env python3
"""Fails when the mod's code could send data anywhere.

The mod sees every secret it masks, so its code must never reach the network, other
processes, the model, or disk writes. CI runs this on every pull request and push;
`main` cannot be merged into while it fails.

  python3 scripts/check-no-egress.py                          # static check of the repository
  python3 scripts/check-no-egress.py --validate report.json   # also check `claude plugin validate --json`
  python3 check-no-egress.py --root <checkout> [...]           # check another checkout (CI runs main's copy on a PR)

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

ROOT = Path(sys.argv[sys.argv.index("--root") + 1]).resolve() if "--root" in sys.argv else Path(__file__).resolve().parent.parent
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
    r"\b(?:getPrototypeOf|setPrototypeOf|__proto__|prototype|defineProperty|getOwnPropertyDescriptors?)\b": "prototype access",
    r"\[\s*['\"`][^\]\n]*['\"`]\s*\+": "computed member name built from strings",
    r"\bwasm\b|\bWebAssembly\b": "WebAssembly",
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
    hooks_json = json.loads((HOOKS / "hooks.json").read_text())
    if hooks_json != {"modules": MODULES}:
        # anything else there (a "hooks" block of command hooks) would run outside the module
        errors.append(f"hooks/hooks.json: must be exactly {{\"modules\": {MODULES}}}")
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
        errors += next_check(p.name, src)
    return errors


# What a hook passes down with next(...): the event as it came, or one of these
# rewrites, each as often as listed. A hook that rewrites its input (a WebFetch URL, a
# command) can carry a secret out through a tool, so a new rewrite is reviewed here.
NEXT_REWRITES = {
    "register.ts": {
        "{ ...e, ...rewritten } as typeof e": 1,  # Edit/Write: placeholders restored
        "{ ...e, message: { ...e.message, content } }": 2,  # session.append: masked row
    },
}
NEXT_CALL = re.compile(r"\bnext\(([^()]*)\)")
NEXT_OTHER = re.compile(r"\bnext\b(?!\(|\.called\b)")
NEXT_PARAM = re.compile(r"\(\s*_?\$\s*,\s*_?e\s*,\s*next\s*\)")


def next_check(name: str, src: str) -> list[str]:
    errors = []
    found: dict[str, int] = {}
    for m in NEXT_CALL.finditer(src):
        arg = " ".join(m.group(1).split())
        if arg != "e":
            found[arg] = found.get(arg, 0) + 1
    expected = NEXT_REWRITES.get(name, {})
    if found != expected:
        errors.append(f"hooks/{name}: next(...) rewrites {found} differ from {expected} (a new input rewrite: allow it here, in review)")
    # next only as a hook parameter, called, or asked `.called`: never passed on or renamed
    # (single-quoted string literals are not code; comments are, so they avoid the word)
    rest = re.sub(r"'(?:[^'\\\n]|\\.)*'", "", src)
    rest = NEXT_PARAM.sub("", rest)
    for m in NEXT_OTHER.finditer(rest):
        line = rest.count("\n", 0, m.start()) + 1
        errors.append(f"hooks/{name}: next used other than called (near line {line})")
    return errors


EXPECTED_TYPES = [
    "export type Src = { src: string; flags: string; fb?: { src: string; flags: string } }",
    "export type Allow = { target: string; regexes?: Src[]; stopwords?: string[] }",
    "export type GitleaksRule = Src & { id: string; keywords?: string[]; entropy?: number; secretGroup?: number; path?: Src; allow?: Allow[] }",
]
VALIDATE_NOTES = re.compile(r"^\./register\.ts (?:hooks: |gating hook with \.catch: |calls: )")
# The events the module hooks, as the engine reports them: a new event is a new
# capability (an `http.fetch` or `prompt.compose` hook could carry data out).
EXPECTED_HOOKS = ("./register.ts hooks: prompt.mention, session.start, tool.call{tool=?}, tool.call{tool=?}, "
                  "tool.run{tool=?|?}, tool.judge{tool=?}, session.append")


def data_check() -> list[str]:
    """gitleaks-rules.ts holds three type aliases and JSON values, nothing that runs."""
    errors = []
    src = (HOOKS / "gitleaks-rules.ts").read_text()
    body = "\n".join(l for l in src.splitlines() if not l.startswith("//"))
    types = re.findall(r"^export type \w+ = .*$", body, re.M)
    if types != EXPECTED_TYPES:
        # a type line can hold statements after a `;`: only these exact lines are allowed
        errors.append("hooks/gitleaks-rules.ts: the type declarations differ from the generator's")
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
    for n in notes:
        if not VALIDATE_NOTES.match(n):
            errors.append(f"claude plugin validate: unexpected note {n!r} (a new capability: allow it here, in review)")
    hooks_notes = [n for n in notes if " hooks: " in n]
    if hooks_notes != [EXPECTED_HOOKS]:
        errors.append(f"claude plugin validate: the module hooks {hooks_notes!r}, expected [{EXPECTED_HOOKS!r}] (allow a new hook here, in review)")
    for c in [report.get("manifest", {}), *report.get("contents", [])]:
        if c.get("wasm"):
            errors.append("claude plugin validate: the plugin declares WebAssembly")
    provides = report.get("provides") or {}
    for kind, items in provides.items():
        expected = [{"path": "hooks/register.ts"}] if kind == "modules" else []
        if items != expected:
            errors.append(f"claude plugin validate: the plugin provides {kind} {items!r} (only the one hooks module is allowed)")
    hosts = report.get("hosts") or {}
    if hosts.get("named") or hosts.get("unread") or (hosts.get("declared") or {}).get("plugin") or (hosts.get("declared") or {}).get("servers"):
        errors.append(f"claude plugin validate: the plugin declares hosts {hosts!r}")
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
    if "--validate" in sys.argv:
        errors += validate_check(sys.argv[sys.argv.index("--validate") + 1])
    if errors:
        fail(errors)
    print(f"ok: no egress; engine calls limited to {', '.join(sorted(ALLOWED_CALLS))}")


if __name__ == "__main__":
    main()
