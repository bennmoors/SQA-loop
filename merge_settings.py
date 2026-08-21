#!/usr/bin/env python3
"""merge_settings.py -- additively merge the SQA Bash allowlist into a settings.json.

    python merge_settings.py <settings.json> <settings.snippet.json>

Exit 0 = merged (or already complete). Exit 1 = refused, and settings.json is untouched.

WHY THIS IS ADDITIVE AND NOTHING ELSE. settings.json is the user's own configuration and, per
fixer-scope-guard.ps1, one of the two files "that decide what every later run is allowed to do".
An installer that rewrites it is an installer that can quietly widen permissions. So this script:

  * only ever APPENDS to permissions.allow, never removes, reorders or rewrites an entry;
  * never touches permissions.deny, permissions.ask, env, hooks, or any other key;
  * refuses outright if the existing file is not valid JSON, rather than "repairing" it;
  * is idempotent -- running it twice adds nothing the second time.

BOM. Claude Code writes settings.json as UTF-8, sometimes with a BOM. `json.load` chokes on one
("Unexpected UTF-8 BOM"), so it is read as utf-8-sig and written back without a BOM. Same defect
class as the PowerShell `>` redirect trap recorded in the QA protocol.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def fail(msg: str) -> None:
    print(f"merge_settings: {msg}", file=sys.stderr)
    raise SystemExit(1)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        fail("usage: merge_settings.py <settings.json> <settings.snippet.json>")

    settings_path, snippet_path = Path(argv[1]), Path(argv[2])

    if not snippet_path.is_file():
        fail(f"snippet not found: {snippet_path}")
    try:
        snippet = json.loads(snippet_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as e:
        fail(f"snippet is not valid JSON ({e}) -- refusing")

    wanted = snippet.get("permissions", {}).get("allow", [])
    if not wanted:
        fail("snippet declares no permissions.allow entries -- nothing to do, and that is "
             "surprising enough to be worth stopping over")

    if settings_path.is_file():
        raw = settings_path.read_text(encoding="utf-8-sig")
        if raw.strip():
            try:
                settings = json.loads(raw)
            except json.JSONDecodeError as e:
                fail(f"{settings_path} is not valid JSON ({e}). Refusing to touch it -- fix the "
                     f"file by hand, or merge the snippet yourself.")
        else:
            settings = {}
    else:
        settings = {}

    if not isinstance(settings, dict):
        fail(f"{settings_path} does not contain a JSON object -- refusing")

    perms = settings.setdefault("permissions", {})
    if not isinstance(perms, dict):
        fail("permissions is present but is not an object -- refusing")
    allow = perms.setdefault("allow", [])
    if not isinstance(allow, list):
        fail("permissions.allow is present but is not an array -- refusing")

    existing = set(allow)
    added = [e for e in wanted if e not in existing]
    allow.extend(added)

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(
        json.dumps(settings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if added:
        print(f"merge_settings: added {len(added)} permission(s):")
        for e in added:
            print(f"  + {e}")
    else:
        print("merge_settings: all SQA permissions already present; nothing added.")
    print(f"merge_settings: {len(allow)} total entries in permissions.allow.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
