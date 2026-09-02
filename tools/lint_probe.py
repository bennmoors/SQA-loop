#!/usr/bin/env python3
"""lint_probe.py -- static analysis for PowerShell and shell targets. PARSES, NEVER RUNS.

THE LOAD-BEARING PROPERTY, and the one sentence to keep if everything else is cut:
**lint_probe PARSES, perf_probe RUNS.** There is no --run here and there never will be. Its whole
value is that it provably never executes the target, which is what lets it be pointed at a hostile
or unknown script with no sandbox, no guard re-application and no shape check.

WHY A WRAPPER AT ALL, rather than allowlisting the tools directly.
`Invoke-ScriptAnalyzer` is a cmdlet, not an exe, so reaching it from the Bash tool means
`pwsh -Command "..."`. Measured 2026-08-24 against the live guard, that is a general interpreter
escape with NOTHING behind it: the denylist's payload rules are Python/Node only, so
`Start-Process`, `Invoke-Expression`, `iex`, `Import-Module` and `New-Object` all pass inside an
already-allowed form -- and the denylist cannot see inside quotes at command position at all
(`echo '<destructive> build/'` -> ALLOW, the same command bare -> BLOCK). Routing through here
means the guard sees `python .../lint_probe.py`, which sqa-guard-bash.ps1 already permits, and the
PowerShell backend is invoked against a MODULE-CONSTANT script path.

It also solves the triage problem, which is the other half of the job. Raw linter output is not a
report. Measured on this repo's own files before any policy was applied:

    install.ps1             34 findings -- 30 of them PSAvoidUsingWriteHost
    sqa-guard-bash.ps1       1 finding
    fixer-scope-guard.ps1    0 findings -- on a file with a PROVEN write bypass

Piping that into a VERDICT floods the counts with style opinions about an installer legitimately
printing to a console, and says nothing about a security guard with a real hole. Severity mapping
and domain tagging are therefore DETERMINISTIC AND IN CODE, not re-decided by each agent.

Envelope and refusal vocabulary are perf_probe.py's, deliberately duplicated rather than imported:
the two tools are independently installable and an import would make a missing sibling a hard
failure. Agents parse ONE shape.

USAGE
    python lint_probe.py --files <paths...> [--lang ps1|sh|auto] [--timeout N]
    python lint_probe.py --mode env          # backend availability; runs nothing at all
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"

# The PowerShell backend. A MODULE CONSTANT derived from this file's own location -- never from a
# caller argument. Same trust shape as perf_probe.reapply_guard(), which spawns
# `powershell.exe -File <constant>`. Both files sit in tools/, which fixer-scope-guard.ps1
# protects, so neither can be rewritten by the process being reviewed.
PS_SCAN = Path(__file__).resolve().parent / "ps_lint.ps1"

# ---------------------------------------------------------------------------- shellcheck policy
#
# THE HIGHEST-VALUE SHELL CHECKS ARE OFF BY DEFAULT. Measured on the installed ShellCheck 0.11.0:
# `cat file | grep foo` produces NO output bare, and only reports SC2002 under
# `--enable=useless-use-of-cat`. 0.11.0 demoted SC2002 to opt-in and made several others optional.
#
# So a bare run silently loses UUOC from the efficiency axis and BOTH `set -e` checks from the
# functional axis, and the resulting clean report is indistinguishable from a real one. The enabled
# set is therefore curated here AND reported in the JSON, so a run's coverage is visible rather
# than assumed.
OPTIONAL_RULES = [
    "useless-use-of-cat",           # efficiency -- UUOC; the fork-count axis loses this entirely
    "check-set-e-suppressed",       # functional -- `set -e` suppressed during function invocation
    "check-extra-masked-returns",   # functional -- masked exit codes, e.g. rm -r "$(get_dir)/home"
    "check-unassigned-uppercase",   # security   -- the `rm -rf "$VAR/"` unset-variable class
]

# DELIBERATELY NOT ENABLED, and this is a correctness decision rather than taste:
# `require-double-brackets` demands `[[ ]]`, which is a BASHISM. Enabling it globally would emit a
# finding on every POSIX target telling the author to introduce the exact defect `-s sh` exists to
# catch. `avoid-negated-conditions` and `require-variable-braces` are pure style and would only
# add Suggestion noise.
OPTIONAL_RULES_REJECTED = {
    "require-double-brackets": "demands a bashism; wrong on any -s sh target",
    "avoid-negated-conditions": "style only",
    "require-variable-braces": "style only",
    "quote-safe-variables": "style only; the unsafe cases are already SC2086",
    "deprecate-which": "style only",
    "add-default-case": "style only",
}

# shellcheck severity -> our vocabulary. A policy, not a passthrough.
SC_SEVERITY = {"error": "Critical", "warning": "Warning", "info": "Suggestion", "style": "Suggestion"}

# Domain routing. This is the ANTI-DOUBLE-BILLING mechanism: without it SC2086 is claimed by both
# sqa-functional and sqa-security and sqa-lead's dedup step has to guess which one meant it.
#
# The honest limit, stated rather than hidden: the plan's rule is "a quoting bug whose value is a
# filename is functional; one whose value crosses a network or user boundary is security", and
# STATIC ANALYSIS CANNOT SEE WHERE A VALUE CAME FROM. So the table below routes by the code's
# characteristic use, defaults to functional, and sqa-security is expected to re-attribute a
# finding it can show reaches a trust boundary. A wrong default is a triage cost; a wrong claim of
# security relevance is a false positive with a CWE number attached, which is worse.
SC_DOMAIN = {
    "SC2002": "efficiency",   # useless use of cat -- a fork per invocation
    "SC2196": "efficiency", "SC2197": "efficiency",
    "SC2115": "security",    # rm -rf "$VAR/" with VAR possibly unset
    "SC2064": "security",    # trap expands now, not on signal
    "SC2059": "security",    # variable in a printf format string
    "SC2154": "security",    # referenced but not assigned -- the unset-variable class
    "SC2029": "security",    # client-side expansion in ssh
}

# Style-only shellcheck codes, capped at Suggestion whatever shellcheck calls them, so a formatting
# opinion can never gate a verdict.
SC_STYLE_ONLY = {"SC2034", "SC2086_style", "SC2035", "SC2012", "SC2010"}


# ---------------------------------------------------------------------------- envelope
# Copied from perf_probe.py rather than imported -- see the module docstring.


class Refusal(Exception):
    """A control refused. Carries the control name so the JSON can say which one."""

    def __init__(self, control: str, reason: str, guard_stderr: str = ""):
        super().__init__(reason)
        self.control = control
        self.reason = reason
        self.guard_stderr = guard_stderr


def emit(mode: str, ok: bool, result=None, refusal=None, disclosures=None, notes=None):
    """The single JSON object. Nothing else is ever written to stdout."""
    doc = {
        "tool": "lint_probe.py",
        "version": VERSION,
        "mode": mode,
        "ok": ok,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": {
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "executable": sys.executable,
        },
        "refusal": refusal,
        "result": result if result is not None else {},
        "disclosures": disclosures or [],
        "notes": notes or [],
    }
    sys.stdout.write(json.dumps(doc, indent=2, default=str) + "\n")
    sys.stdout.flush()
    return 0 if ok else 3


# ---------------------------------------------------------------------------- language + dialect


def detect_lang(path: Path) -> str:
    """ps1 | sh | unknown, from extension then shebang. Extension wins; it is unambiguous."""
    ext = path.suffix.lower()
    if ext in (".ps1", ".psm1", ".psd1"):
        return "ps1"
    if ext in (".sh", ".bash", ".bats", ".ksh"):
        return "sh"
    try:
        first = path.open("r", encoding="utf-8", errors="replace").readline()
    except OSError:
        return "unknown"
    if first.startswith("#!"):
        if re.search(r"\b(?:ba|da|k|z)?sh\b", first):
            return "sh"
        if re.search(r"\bpwsh|powershell\b", first, re.I):
            return "ps1"
    return "unknown"


def shell_dialect(path: Path) -> str:
    """The `-s` value for shellcheck, from the shebang.

    DIALECT DECIDES WHICH FINDINGS ARE REAL, which is why this is not merely cosmetic. `[[ ]]`,
    `local`, arrays and `echo -e` are defects under `#!/bin/sh` and perfectly fine under
    `#!/bin/bash`, and only `-s sh` proves it. Measured 2026-08-24: on a `#!/bin/sh` script using
    `[[ -n "$1" ]]` and `local x=1`, `sh -n` exits **0** and reports nothing, while
    `shellcheck -s sh` returns SC3010 and SC3043. Never let a green `sh -n` stand in for this.
    """
    try:
        first = path.open("r", encoding="utf-8", errors="replace").readline().strip()
    except OSError:
        return "bash"
    if path.suffix.lower() == ".bats":
        return "bats"
    m = re.search(r"\b(bash|dash|ksh|zsh|sh)\b", first)
    if not m:
        return "bash"
    d = m.group(1)
    if d in ("sh", "dash"):
        return "sh"
    if d == "ksh":
        return "ksh"
    return "bash"


# ---------------------------------------------------------------------------- backends


def _which(name: str):
    return shutil.which(name)


def _wsl_available() -> bool:
    if not _which("wsl"):
        return False
    try:
        r = subprocess.run(["wsl", "--", "true"], capture_output=True, timeout=20)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def shellcheck_backend() -> dict:
    """Prefer the native binary; fall back to WSL. ALWAYS report which answered.

    Not cosmetic: until the PATH refresh landed, the native binary existed on the machine and was
    absent from the session, so a run that silently used WSL looked identical to one that used the
    native tool. A degraded route must be visible.
    """
    native = _which("shellcheck")
    if native:
        try:
            out = subprocess.run([native, "--version"], capture_output=True, text=True, timeout=30)
            ver = ""
            for line in (out.stdout or "").splitlines():
                if line.lower().startswith("version:"):
                    ver = line.split(":", 1)[1].strip()
            return {"available": True, "route": "native", "path": native, "version": ver}
        except (OSError, subprocess.SubprocessError):
            pass
    if _wsl_available():
        try:
            out = subprocess.run(["wsl", "--", "shellcheck", "--version"],
                                 capture_output=True, text=True, timeout=45)
            if out.returncode == 0:
                ver = ""
                for line in (out.stdout or "").splitlines():
                    if line.lower().startswith("version:"):
                        ver = line.split(":", 1)[1].strip()
                return {"available": True, "route": "wsl", "path": "wsl shellcheck", "version": ver}
        except (OSError, subprocess.SubprocessError):
            pass
    return {"available": False, "route": "none", "path": "", "version": ""}


def win_to_wsl(p: Path) -> str:
    """C:\\x\\y -> /mnt/c/x/y. Only used when the shellcheck route is WSL."""
    r = p.resolve()
    drive = r.drive.rstrip(":").lower()
    rest = str(r)[len(r.drive):].replace("\\", "/")
    return f"/mnt/{drive}{rest}"


def run_shellcheck(files, backend: dict, timeout: int) -> tuple:
    """Returns (findings, errors). Uses --format=json1 and the curated optional set."""
    findings, errors = [], []
    if not backend["available"] or not files:
        return findings, errors

    by_dialect = {}
    for f in files:
        by_dialect.setdefault(shell_dialect(f), []).append(f)

    for dialect, group in by_dialect.items():
        enable = ",".join(OPTIONAL_RULES)
        if backend["route"] == "native":
            argv = [backend["path"], "--format=json1", "-s", dialect, f"--enable={enable}"]
            argv += [str(p.resolve()) for p in group]
        else:
            argv = ["wsl", "--", "shellcheck", "--format=json1", "-s", dialect, f"--enable={enable}"]
            argv += [win_to_wsl(p) for p in group]
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                               errors="replace")
        except subprocess.TimeoutExpired:
            errors.append(f"shellcheck timed out after {timeout}s on dialect {dialect}")
            continue
        except OSError as exc:
            errors.append(f"shellcheck could not be launched: {exc}")
            continue

        # shellcheck exits 1 when it HAS findings; that is success, not failure.
        raw = (r.stdout or "").strip()
        if not raw:
            if r.returncode not in (0, 1):
                errors.append(f"shellcheck exit {r.returncode}: {(r.stderr or '')[-300:]}")
            continue
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"shellcheck emitted unparseable JSON: {exc}")
            continue
        for c in doc.get("comments", []):
            code = f"SC{c.get('code')}"
            sev = SC_SEVERITY.get(c.get("level", "style"), "Suggestion")
            if code in SC_STYLE_ONLY:
                sev = "Suggestion"
            findings.append({
                "rule": code,
                "file": c.get("file", ""),
                "line": c.get("line", 0),
                "col": c.get("column", 0),
                "severity": sev,
                "domain": SC_DOMAIN.get(code, "functional"),
                "backend": f"shellcheck/{backend['route']}",
                "message": c.get("message", ""),
                "dialect": dialect,
            })
    return findings, errors


def run_syntax_check(files, timeout: int) -> tuple:
    """`bash -n` per file. A parse failure is a [Proven] Critical with no dependencies.

    NOT a dialect check. `sh -n` parses `[[` and `local` as ordinary command words and exits 0 on
    a POSIX script full of bashisms (measured). It is kept because it catches genuine syntax errors
    with zero setup, and because it is the shell analogue of the mutant compile-check
    `code-reviewer` is required to run. Dialect is shellcheck's job.
    """
    findings, errors = [], []
    bash = _which("bash")
    if not bash:
        return findings, ["bash not found; syntax check skipped"]
    for f in files:
        try:
            r = subprocess.run([bash, "-n", str(f.resolve())], capture_output=True, text=True,
                               timeout=timeout, errors="replace")
        except subprocess.TimeoutExpired:
            errors.append(f"bash -n timed out on {f}")
            continue
        except OSError as exc:
            errors.append(f"bash -n could not be launched: {exc}")
            continue
        if r.returncode != 0:
            for line in (r.stderr or "").strip().splitlines():
                m = re.search(r":\s*line\s+(\d+):", line)
                findings.append({
                    "rule": "BashSyntaxError",
                    "file": str(f),
                    "line": int(m.group(1)) if m else 0,
                    "col": 0,
                    "severity": "Critical",
                    "domain": "functional",
                    "backend": "bash -n",
                    "message": line.strip(),
                    "dialect": shell_dialect(f),
                })
    return findings, errors


def run_ps_lint(files, timeout: int) -> tuple:
    """Spawn the bundled PowerShell backend against a module-constant script path."""
    findings, errors, backends = [], [], {}
    if not files:
        return findings, errors, backends
    if not PS_SCAN.is_file():
        return findings, [f"ps_lint.ps1 missing at {PS_SCAN}"], backends
    ps = _which("powershell") or _which("powershell.exe")
    if not ps:
        return findings, ["powershell.exe not found"], backends

    argv = [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(PS_SCAN)] + [str(p.resolve()) for p in files]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired:
        return findings, [f"ps_lint.ps1 timed out after {timeout}s"], backends
    except OSError as exc:
        return findings, [f"ps_lint.ps1 could not be launched: {exc}"], backends

    raw = (r.stdout or "").strip()
    if not raw:
        return findings, [f"ps_lint.ps1 produced no output (exit {r.returncode}): "
                          f"{(r.stderr or '')[-300:]}"], backends
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return findings, [f"ps_lint.ps1 emitted unparseable JSON: {exc}"], backends

    backends = doc.get("backends", {})
    got = doc.get("findings", [])
    # ConvertTo-Json collapses a one-element array to an object in Windows PowerShell 5.1.
    if isinstance(got, dict):
        got = [got]
    findings.extend(got or [])
    if (r.stderr or "").strip():
        errors.append((r.stderr or "").strip()[-300:])
    return findings, errors, backends


# ---------------------------------------------------------------------------- modes


def mode_env(args) -> int:
    """Reports what is reachable. Runs nothing against any target."""
    sc = shellcheck_backend()
    ps_backends, ps_errors = {}, []
    if PS_SCAN.is_file():
        ps = _which("powershell") or _which("powershell.exe")
        if ps:
            try:
                # Probe with a real invocation against this script's own directory marker file,
                # so an available-but-broken backend reports broken rather than available.
                r = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                                    "Bypass", "-File", str(PS_SCAN), str(PS_SCAN)],
                                   capture_output=True, text=True, timeout=180, errors="replace")
                if (r.stdout or "").strip():
                    ps_backends = json.loads(r.stdout).get("backends", {})
                else:
                    ps_errors.append(f"probe produced no output (exit {r.returncode})")
            except Exception as exc:  # noqa: BLE001 -- env mode never raises
                ps_errors.append(f"{type(exc).__name__}: {exc}")
        else:
            ps_errors.append("powershell.exe not found")
    else:
        ps_errors.append(f"ps_lint.ps1 missing at {PS_SCAN}")

    result = {
        "shell": {
            "shellcheck": sc,
            "bash": _which("bash") or "",
            "wsl": _wsl_available(),
            "optional_rules_enabled": OPTIONAL_RULES,
            "optional_rules_rejected": OPTIONAL_RULES_REJECTED,
        },
        "powershell": {
            "ps_lint": str(PS_SCAN),
            "ps_lint_present": PS_SCAN.is_file(),
            "backends": ps_backends,
            "errors": ps_errors,
        },
    }
    notes = [
        "lint_probe PARSES; it never executes a target. There is no --run.",
        "shellcheck 0.11.0 has SC2002 and the set -e checks OFF by default. The enabled set is "
        "listed above; if it is empty, a clean shell report is not evidence of no findings.",
        "sh -n is NOT a dialect check: it exits 0 on [[ and local in a #!/bin/sh script. "
        "shellcheck -s sh (SC3010/SC3043) is what proves dialect.",
    ]
    disclosures = []
    if sc["available"] and sc["route"] == "wsl":
        disclosures.append("shellcheck answered via WSL, not the native binary.")
    if not sc["available"]:
        disclosures.append("shellcheck is NOT available; no shell linting can run.")
    if not ps_backends.get("pssa", {}).get("available"):
        disclosures.append("PSScriptAnalyzer is NOT available; PowerShell coverage is AST-only.")
    if not ps_backends.get("injectionhunter", {}).get("available"):
        disclosures.append("InjectionHunter is NOT available; no PowerShell injection rules ran. "
                           "A clean PSSA run is not a security result.")
    return emit("env", True, result=result, disclosures=disclosures, notes=notes)


def mode_lint(args) -> int:
    paths = []
    for raw in args.files:
        p = Path(raw)
        if not p.exists():
            raise Refusal("argument", f"{raw!r} does not exist.")
        if p.is_dir():
            raise Refusal("argument",
                          f"{raw!r} is a directory. Pass explicit file paths -- walking a tree "
                          "would silently decide what counts as a target.")
        paths.append(p)
    if not paths:
        raise Refusal("argument", "--files was given no paths.")

    buckets = {"ps1": [], "sh": [], "unknown": []}
    for p in paths:
        lang = args.lang if args.lang != "auto" else detect_lang(p)
        if lang not in buckets:
            lang = "unknown"
        buckets[lang].append(p)

    findings, errors, disclosures = [], [], []

    sc_backend = shellcheck_backend()
    if buckets["sh"]:
        f, e = run_shellcheck(buckets["sh"], sc_backend, args.timeout)
        findings += f
        errors += e
        f, e = run_syntax_check(buckets["sh"], args.timeout)
        findings += f
        errors += e
        if not sc_backend["available"]:
            disclosures.append("shellcheck unavailable: shell targets got `bash -n` only, which "
                               "catches syntax errors and NO dialect or quoting defects.")
        elif sc_backend["route"] == "wsl":
            disclosures.append("shellcheck answered via WSL, not the native binary.")

    ps_backends = {}
    if buckets["ps1"]:
        f, e, ps_backends = run_ps_lint(buckets["ps1"], args.timeout)
        findings += f
        errors += e
        if not ps_backends.get("pssa", {}).get("available"):
            disclosures.append("PSScriptAnalyzer unavailable: PowerShell coverage is AST-only.")
        if not ps_backends.get("injectionhunter", {}).get("available"):
            disclosures.append("InjectionHunter did not run. PSSA's default rules carry no "
                               "injection checks, so a clean result here says nothing about "
                               "injection risk.")

    if buckets["unknown"]:
        disclosures.append(
            "Not analysed (language undetermined; pass --lang to force): "
            + ", ".join(str(p) for p in buckets["unknown"]))

    counts = {"Critical": 0, "Warning": 0, "Suggestion": 0}
    for f in findings:
        counts[f.get("severity", "Suggestion")] = counts.get(f.get("severity", "Suggestion"), 0) + 1
    by_domain = {}
    for f in findings:
        by_domain[f.get("domain", "functional")] = by_domain.get(f.get("domain", "functional"), 0) + 1

    result = {
        "files": {k: [str(p) for p in v] for k, v in buckets.items() if v},
        "counts": counts,
        "by_domain": by_domain,
        "findings": findings,
        "errors": errors,
        "backends": {
            "shellcheck": sc_backend,
            "powershell": ps_backends,
            "optional_rules_enabled": OPTIONAL_RULES if buckets["sh"] else [],
        },
    }
    notes = [
        "Severity is a POLICY mapping, not a linter passthrough. Style rules are capped at "
        "Suggestion so they cannot gate a verdict.",
        "`domain` prevents double-billing across specialists. Static analysis cannot see where a "
        "value came from, so a quoting finding defaults to functional; sqa-security re-attributes "
        "one it can show reaches a trust boundary.",
        "These counts are NOT a VERDICT. They are inputs to triage.",
    ]
    if buckets["sh"] and sc_backend["available"]:
        notes.append("shellcheck optional rules enabled: " + ", ".join(OPTIONAL_RULES)
                     + ". Without these, UUOC and both set -e checks are silently absent.")
    return emit("lint", True, result=result, disclosures=disclosures, notes=notes)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Static analysis for PowerShell and shell. Parses; never runs.")
    p.add_argument("--mode", choices=("lint", "env"), default="lint")
    p.add_argument("--lang", choices=("ps1", "sh", "auto"), default="auto")
    p.add_argument("--files", nargs="*", default=[])
    p.add_argument("--timeout", type=int, default=180)
    args = p.parse_args()

    try:
        if args.mode == "env":
            return mode_env(args)
        if not args.files:
            raise Refusal("argument", "--files is required for --mode lint.")
        return mode_lint(args)
    except Refusal as r:
        return emit(args.mode, False,
                    refusal={"control": r.control, "reason": r.reason,
                             "guard_stderr": r.guard_stderr})
    except Exception as exc:  # noqa: BLE001
        return emit(args.mode, False,
                    refusal={"control": "internal-error",
                             "reason": f"{type(exc).__name__}: {exc}", "guard_stderr": ""})


if __name__ == "__main__":
    sys.exit(main())
