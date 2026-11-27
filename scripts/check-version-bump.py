#!/usr/bin/env python3
"""Fails a pull request that changes what the plugin ships without raising its version.

Installed copies update by version: a change to shipped files with the same version
may never reach anyone. The marketplace installs the whole repository, so every file
is shipped except docs, tests, scripts, CI and the repository's own notes, which
change nothing an installed copy runs.

  python3 scripts/check-version-bump.py origin/main   # compare HEAD with the PR's base
"""
import json
import re
import subprocess
import sys

NOT_SHIPPED = ("docs/", "tests/", "scripts/", ".github/", ".claude/", ".gitignore", "AGENTS.md", "README.md",
               "SECURITY.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "tsconfig.json")
MANIFEST = ".claude-plugin/plugin.json"


ROOT = sys.argv[sys.argv.index("--root") + 1] if "--root" in sys.argv else "."


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", ROOT, *args], check=True, capture_output=True, text=True).stdout


def version_at(ref: str) -> tuple[int, int, int]:
    raw = json.loads(git("show", f"{ref}:{MANIFEST}"))["version"]
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", raw)
    if not m:
        sys.exit(f"::error::{MANIFEST}: version {raw!r} at {ref} is not MAJOR.MINOR.PATCH")
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


def main() -> None:
    args = [a for i, a in enumerate(sys.argv[1:], 1) if a != "--root" and sys.argv[i - 1] != "--root"]
    base = args[0] if args else "origin/main"
    merge_base = git("merge-base", base, "HEAD").strip()
    changed = [p for p in git("diff", "--name-only", merge_base, "HEAD").splitlines() if p]
    shipped = [p for p in changed if not p.startswith(NOT_SHIPPED)]
    before, after = version_at(merge_base), version_at("HEAD")
    fmt = lambda v: ".".join(map(str, v))

    if after < before:
        sys.exit(f"::error::{MANIFEST}: version went down, {fmt(before)} -> {fmt(after)}")
    if not shipped:
        print(f"ok: no shipped file changed (version {fmt(after)})")
        return
    if after == before:
        print(f"::error::{MANIFEST}: shipped files changed but the version is still {fmt(before)}.")
        print("Bump it in this pull request: PATCH for a fix, MINOR for a feature or new rules, MAJOR for a breaking change.")
        for p in shipped:
            print(f"  changed: {p}")
        sys.exit(1)
    print(f"ok: version {fmt(before)} -> {fmt(after)} for {len(shipped)} shipped file(s)")


if __name__ == "__main__":
    main()
