#!/usr/bin/env python3
"""Fails a pull request that changes what the plugin ships without raising its version.

Installed copies update by version: a change to shipped files with the same version
may never reach anyone. Shipped files are everything under hooks/ and the manifests
in .claude-plugin/. Docs, tests, scripts and CI change nothing installed, so they
need no bump.

  python3 scripts/check-version-bump.py origin/main   # compare HEAD with the PR's base
"""
import json
import re
import subprocess
import sys

SHIPPED = ("hooks/", ".claude-plugin/")
MANIFEST = ".claude-plugin/plugin.json"


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def version_at(ref: str) -> tuple[int, int, int]:
    raw = json.loads(git("show", f"{ref}:{MANIFEST}"))["version"]
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", raw)
    if not m:
        sys.exit(f"::error::{MANIFEST}: version {raw!r} at {ref} is not MAJOR.MINOR.PATCH")
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


def main() -> None:
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/main"
    merge_base = git("merge-base", base, "HEAD").strip()
    changed = [p for p in git("diff", "--name-only", merge_base, "HEAD").splitlines() if p]
    shipped = [p for p in changed if p.startswith(SHIPPED)]
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
