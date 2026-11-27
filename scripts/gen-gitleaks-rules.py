#!/usr/bin/env python3
"""Generate hooks/gitleaks-rules.ts from gitleaks' default ruleset.

Usage:
  python3 scripts/gen-gitleaks-rules.py               # fetch the pinned release
  python3 scripts/gen-gitleaks-rules.py --tag v8.31.0 # fetch another release
  python3 scripts/gen-gitleaks-rules.py --tag v8.30.1 path/to/gitleaks.toml  # a local copy of that release

gitleaks is not needed at runtime: its rules are converted once, here, from
Go RE2 syntax into JavaScript regular expressions and committed.
gitleaks is MIT licensed, see THIRD_PARTY_NOTICES.md.

RE2 -> JS conversion:
  - a leading (?i) becomes the `i` flag
  - a (?i) in the middle becomes a (?i:...) modifier group around the rest of
    its enclosing group; inline groups such as (?-i:...) or (?s:...) are kept.
    Each rule also gets a fallback without modifier groups (their flags applied
    to the whole pattern), used where the JS engine lacks regexp modifiers:
    slightly broader, never narrower.
  - \\z -> $, \\A -> ^, (?P<name> -> (?<name>, [[:alnum:]] and similar -> ranges
Allowlist entries that are literal tokens (gitleaks lists some public example keys)
are dropped, so the generated file holds no real-format key.
A rule scoped to file paths (`path`) runs only when the output's file is known and matches
(the Read tool's file, or a file named in a Bash command); rules that are a path alone
(no regex) are skipped.
"""
import hashlib
import json
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

PINNED_TAG = "v8.30.1"
# SHA-256 of that release's config/gitleaks.toml: a tag can be moved, the bytes cannot.
# Updating the tag means updating this hash in the same pull request.
PINNED_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/{tag}/config/gitleaks.toml"
# --root: write into another checkout (CI runs main's copy of this script on a pull request)
ROOT = Path(sys.argv[sys.argv.index("--root") + 1]).resolve() if "--root" in sys.argv else Path(__file__).resolve().parent.parent
OUT = ROOT / "hooks" / "gitleaks-rules.ts"

POSIX = {
    "[:alnum:]": "a-zA-Z0-9", "[:alpha:]": "a-zA-Z", "[:digit:]": "0-9", "[:lower:]": "a-z",
    "[:upper:]": "A-Z", "[:space:]": r"\s", "[:xdigit:]": "0-9a-fA-F", "[:word:]": r"\w",
    "[:punct:]": r"!-\/:-@\[-`{-~",
}


def group_end(rx: str, start: int) -> int:
    """Index of the ')' that closes the group enclosing position `start` (or len(rx))."""
    depth, i, in_class = 0, start, False
    while i < len(rx):
        c = rx[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            if depth == 0:
                return i
            depth -= 1
        i += 1
    return len(rx)


def convert(rx: str) -> dict:
    flags = ""
    for k, v in POSIX.items():
        rx = rx.replace(k, v)
    rx = rx.replace("(?P<", "(?<").replace(r"\z", "$").replace(r"\A", "^")
    m = re.match(r"^\(\?([is]+)\)", rx)
    if m:
        flags += m.group(1)
        rx = rx[m.end():]
    # mid-pattern (?i) / (?s): wrap the rest of the enclosing group in a modifier group
    while True:
        m = re.search(r"(?<!\\)\(\?([is]+)\)", rx)
        if not m:
            break
        end = group_end(rx, m.end())
        rx = rx[: m.start()] + f"(?{m.group(1)}:" + rx[m.end(): end] + ")" + rx[end:]
    native = {"src": rx, "flags": flags}
    mods = re.findall(r"(?<!\\)\(\?(-?[is]+):", rx)
    if not mods:
        return native
    fb_flags = set(flags)
    for mod in mods:
        if not mod.startswith("-"):
            fb_flags |= set(mod)
    fallback = re.sub(r"(?<!\\)\(\?-?[is]+:", "(?:", rx)
    native["fb"] = {"src": fallback, "flags": "".join(sorted(fb_flags))}
    return native


def is_literal_secret(rx: str) -> bool:
    """An allowlist entry that is a literal token (a public example key), not a pattern.
    Dropped: committing it would trip secret scanners, and masking it is harmless."""
    return len(rx) >= 20 and not re.search(r"[\[\](){}*+?|^$\\]", rx)


def allowlist(a: dict) -> dict:
    out = {"target": a.get("regexTarget", "secret")}
    regexes = [x for x in a.get("regexes", []) if not is_literal_secret(x)]
    if regexes:
        out["regexes"] = [convert(x) for x in regexes]
    if a.get("stopwords"):
        out["stopwords"] = [s.lower() for s in a["stopwords"]]
    if a.get("paths"):
        # paths are unknown for tool output: an AND condition with paths never holds
        out["needsPath"] = a.get("condition", "OR").upper() == "AND"
    return out


def main() -> None:
    args = [a for i, a in enumerate(sys.argv[1:], 1) if a != "--root" and sys.argv[i - 1] != "--root"]
    tag = PINNED_TAG
    if args[:1] == ["--tag"]:
        tag, args = args[1], args[2:]
    # the header names the public source only, never a local path
    source = URL.format(tag=tag)
    if args:
        raw = Path(args[0]).read_bytes()
    else:
        with urllib.request.urlopen(source) as r:
            raw = r.read()
    if tag == PINNED_TAG and hashlib.sha256(raw).hexdigest() != PINNED_SHA256:
        sys.exit(f"gitleaks.toml for {tag} does not match PINNED_SHA256: refusing to generate")
    cfg = tomllib.loads(raw.decode())

    rules, skipped = [], []
    for r in cfg["rules"]:
        if "regex" not in r:
            skipped.append(r["id"])
            continue
        rule = {"id": r["id"], **convert(r["regex"])}
        if r.get("keywords"):
            rule["keywords"] = [k.lower() for k in r["keywords"]]
        if r.get("entropy"):
            rule["entropy"] = r["entropy"]
        if r.get("path"):
            rule["path"] = convert(r["path"])
        if r.get("secretGroup"):
            rule["secretGroup"] = r["secretGroup"]
        allows = [allowlist(a) for a in r.get("allowlists", [])]
        allows = [a for a in allows if not a.get("needsPath") and (a.get("regexes") or a.get("stopwords"))]
        if allows:
            rule["allow"] = allows
        rules.append(rule)

    g = cfg.get("allowlist", {})
    glob = {"regexes": [convert(x) for x in g.get("regexes", []) if not is_literal_secret(x)], "stopwords": [s.lower() for s in g.get("stopwords", [])]}

    body = (
        "// GENERATED by scripts/gen-gitleaks-rules.py. Do not edit by hand.\n"
        f"// Source: gitleaks {tag} config/gitleaks.toml ({source})\n"
        "// gitleaks is Copyright (c) 2019 Zachary Rice, MIT License; see THIRD_PARTY_NOTICES.md.\n"
        f"// {len(rules)} rules converted; skipped (path-only, no regex): {', '.join(skipped)}\n\n"
        "export type Src = { src: string; flags: string; fb?: { src: string; flags: string } }\n"
        "export type Allow = { target: string; regexes?: Src[]; stopwords?: string[] }\n"
        "export type GitleaksRule = Src & { id: string; keywords?: string[]; entropy?: number; secretGroup?: number; path?: Src; allow?: Allow[] }\n\n"
        f"export const GITLEAKS_VERSION = {json.dumps(tag)}\n\n"
        f"export const GITLEAKS_RULES: GitleaksRule[] = {json.dumps(rules, indent=1)}\n\n"
        f"export const GITLEAKS_GLOBAL_ALLOW: {{ regexes: Src[]; stopwords: string[] }} = {json.dumps(glob, indent=1)}\n"
    )
    OUT.write_text(body)
    print(f"wrote {OUT} ({len(rules)} rules, skipped {len(skipped)}: {', '.join(skipped)})")


if __name__ == "__main__":
    main()
