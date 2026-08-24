#!/usr/bin/env python3
"""run_shape_corpus.py -- two-sided corpus for perf_probe.check_run_shape().

WHY THIS EXISTS. `perf_probe.py` had NO dedicated test. Its correctness was asserted only
indirectly, through guard_corpus reaching it via reapply_guard -- which tests the GUARD, not the
shape check. That was survivable while `check_run_shape` was one function with one language in it.
It stopped being survivable the moment it became a three-way dispatch, because a per-language
dispatch is exactly the shape where one branch silently loses a check and every other branch keeps
passing.

The `py` branch is the one to watch. It is supposed to be byte-for-byte unchanged, and a corpus is
the only thing that can say so after the next edit.

NO SUBPROCESS. Cases are fed to check_run_shape() directly, so this runs in well under a second
and can be a pre-commit gate rather than a ceremony. It deliberately does NOT exercise
reapply_guard -- that is guard_corpus's job, and duplicating it here would mean two files failing
for one cause.

Exit codes follow the harness convention: 0 = all hold, 1 = at least one case failed,
2 = the target could not be exercised at all (perf_probe not importable).

    python run_shape_corpus.py [--probe <path to perf_probe.py>] [--quiet|--score|--json]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

ACCEPT, REFUSE = "accept", "refuse"


def load_probe(path: Path):
    spec = importlib.util.spec_from_file_location("perf_probe_under_test", str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_cases(tmp: Path, repo_file: Path):
    """(id, expectation, lang, argv, why).

    Real files are needed because check_run_shape resolves and stat()s its target -- a corpus of
    imaginary paths would pass the shape check and never reach the existence or sandbox rules,
    which are half of what this file is for.
    """
    py = tmp / "w.py"; py.write_text("x = 1\n", encoding="utf-8")
    ps = tmp / "w.ps1"; ps.write_text("Write-Output 1\n", encoding="utf-8")
    sh = tmp / "w.sh"; sh.write_text("#!/bin/bash\necho 1\n", encoding="utf-8")
    nope = tmp / "missing.ps1"

    P, S, H = str(py), str(ps), str(sh)
    R = str(repo_file)  # a real file OUTSIDE any temp directory

    return [
        # ---------------------------------------------------------------- py, unchanged
        ("py-script", ACCEPT, "py", ["python", P], "the ordinary case"),
        ("py-script-args", ACCEPT, "py", ["python", P, "--n", "5"], "target args are carried"),
        ("py-flag-u", ACCEPT, "py", ["python", "-u", P], "-u is the one allowed interpreter flag"),
        ("py-module", ACCEPT, "py", ["python", "-m", "pytest", "-q"], "an allowlisted -m module"),
        ("py-default-lang", ACCEPT, None, ["python", P],
         "lang defaults to py, so every pre-existing invocation still resolves"),
        ("py-outside-temp", ACCEPT, "py", ["python", R],
         "PY IS NOT SANDBOX-CONSTRAINED. It was already able to run the target's own code before "
         "this change, and narrowing it would be an unrelated behavioural break"),
        ("py-bad-interpreter", REFUSE, "py", ["node", P], "not a Python interpreter"),
        ("py-bad-flag", REFUSE, "py", ["python", "-c", P], "-c is an inline-code channel"),
        ("py-module-not-allowed", REFUSE, "py", ["python", "-m", "http.server"],
         "-m is allowlisted; http.server is not on it"),
        ("py-not-a-py-file", REFUSE, "py", ["python", H], ".sh is not a .py target"),
        ("py-empty", REFUSE, "py", [], "--run given no command"),
        ("py-no-target", REFUSE, "py", ["python"], "interpreter but no target"),

        # ---------------------------------------------------------------- ps1
        ("ps1-ok", ACCEPT, "ps1",
         ["pwsh", "-NoProfile", "-NonInteractive", "-File", S], "the ordinary case"),
        ("ps1-powershell-exe", ACCEPT, "ps1",
         ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", S],
         "Windows PowerShell spells it differently and is equally valid"),
        ("ps1-args", ACCEPT, "ps1",
         ["pwsh", "-NoProfile", "-NonInteractive", "-File", S, "-Count", "3"],
         "target args are carried"),
        ("ps1-missing-prefix", REFUSE, "ps1", ["pwsh", "-File", S],
         "the EXACT prefix is required; a partial one is refused rather than completed for the "
         "caller, because injecting flags would desync prepare_run's token arithmetic"),
        ("ps1-command-channel", REFUSE, "ps1", ["pwsh", "-Command", "Get-Date"],
         "-Command is inline code. This is the line that does not move"),
        ("ps1-encoded", REFUSE, "ps1",
         ["pwsh", "-NoProfile", "-NonInteractive", "-EncodedCommand", "ZQ=="],
         "-EncodedCommand is inline code wearing base64"),
        ("ps1-outside-sandbox", REFUSE, "ps1",
         ["pwsh", "-NoProfile", "-NonInteractive", "-File", R],
         "ps1 EXECUTES, so it is Tier 2 and confined to a staged copy in temp"),
        ("ps1-missing-file", REFUSE, "ps1",
         ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(nope)],
         "a missing entry point is [Needs-info], never an invocation to invent"),
        ("ps1-wrong-interpreter", REFUSE, "ps1",
         ["python", "-NoProfile", "-NonInteractive", "-File", S], "not a PowerShell host"),
        ("ps1-py-target", REFUSE, "ps1",
         ["pwsh", "-NoProfile", "-NonInteractive", "-File", P], ".py is not a .ps1 target"),

        # ---------------------------------------------------------------- sh
        ("sh-bash-ok", ACCEPT, "sh", ["bash", H], "the ordinary case"),
        ("sh-sh-ok", ACCEPT, "sh", ["sh", H], "POSIX host spelling"),
        ("sh-args", ACCEPT, "sh", ["bash", H, "5"], "target args are carried"),
        ("sh-dash-c", REFUSE, "sh", ["bash", "-c", "echo hi"],
         "-c is an inline-code channel; --lang sh permits NO interpreter flags at all"),
        ("sh-any-flag", REFUSE, "sh", ["bash", "-x", H],
         "not a denylist of dangerous flags -- the grammar permits none, so a novel flag fails "
         "for the same reason -c does"),
        ("sh-outside-sandbox", REFUSE, "sh", ["bash", R],
         "sh EXECUTES, so it is Tier 2 and confined to a staged copy in temp"),
        ("sh-wrong-interpreter", REFUSE, "sh", ["zsh", H], "only bash and sh are recognised"),
        ("sh-ps1-target", REFUSE, "sh", ["bash", S], ".ps1 is not a .sh target"),
    ]


# The gate: a two-sided subset, disjoint from --score's set, so the metric cannot be climbed by
# satisfying the gate. Same rationale as guard_corpus.GATE_IDS.
GATE_IDS = {
    "py-script", "py-module", "py-default-lang",       # py must keep working
    "ps1-ok", "sh-bash-ok",                            # the new languages must work
    "ps1-command-channel", "sh-dash-c",                # inline code must stay refused
    "ps1-outside-sandbox", "sh-outside-sandbox",       # Tier 2 containment must hold
}


def run(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Two-sided corpus for perf_probe.check_run_shape().")
    default_probe = Path(__file__).resolve().parent.parent / "tools" / "perf_probe.py"
    ap.add_argument("--probe", default=str(default_probe))
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    probe_path = Path(args.probe)
    if not probe_path.is_file():
        if args.score:
            print("0.0")
            return 0
        print(f"UNUSABLE: no perf_probe.py at {probe_path}", file=sys.stderr)
        return 2
    try:
        probe = load_probe(probe_path)
    except Exception as exc:  # noqa: BLE001
        if args.score:
            print("0.0")
            return 0
        print(f"UNUSABLE: {probe_path} did not import: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 2

    # A real file guaranteed NOT under a temp directory: this corpus file itself.
    repo_file = Path(__file__).resolve()

    with tempfile.TemporaryDirectory(prefix="run-shape-") as td:
        tmp = Path(td)
        cases = build_cases(tmp, repo_file)
        if args.gate:
            cases = [c for c in cases if c[0] in GATE_IDS]
        elif args.score:
            cases = [c for c in cases if c[0] not in GATE_IDS]

        rows, bad = [], []
        for cid, expect, lang, argv_in, why in cases:
            try:
                if lang is None:
                    probe.check_run_shape(argv_in)
                else:
                    probe.check_run_shape(argv_in, lang)
                got = ACCEPT
                detail = ""
            except probe.Refusal as r:
                got = REFUSE
                detail = f"{r.control}: {r.reason[:70]}"
            except Exception as exc:  # noqa: BLE001 -- an unexpected type IS a failure
                got = f"error({type(exc).__name__})"
                detail = str(exc)[:70]
            ok = got == expect
            rows.append({"id": cid, "expected": expect, "got": got, "ok": ok,
                         "lang": lang or "py", "why": why, "detail": detail})
            if not ok:
                bad.append(cid)

    if args.json:
        print(json.dumps({"total": len(rows), "failed": len(bad), "rows": rows}, indent=2))
        return 1 if bad else 0

    score = (100.0 * (len(rows) - len(bad)) / len(rows)) if rows else 0.0
    if args.score:
        print(f"{score:.1f}")
        return 0

    if not args.quiet:
        for r in rows:
            mark = "pass" if r["ok"] else "FAIL"
            print(f"  {mark}  {r['id']:<24} lang={r['lang']:<4} "
                  f"expected={r['expected']:<6} got={r['got']}"
                  + (f"  [{r['detail']}]" if not r["ok"] and r["detail"] else ""))

    acc = [r for r in rows if r["expected"] == ACCEPT]
    ref = [r for r in rows if r["expected"] == REFUSE]
    print(f"  must-accept: {sum(1 for r in acc if r['ok'])}/{len(acc)} correct")
    print(f"  must-refuse: {sum(1 for r in ref if r['ok'])}/{len(ref)} correct")
    label = "GATE" if args.gate else "RUN SHAPE CORPUS"
    if args.gate:
        print(f"  {label}: {len(rows) - len(bad)}/{len(rows)} — "
              + ("PASS" if not bad else "FAIL"))
    else:
        print(f"  {label}: {len(rows) - len(bad)}/{len(rows)} = {score:.1f}%")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(run())
