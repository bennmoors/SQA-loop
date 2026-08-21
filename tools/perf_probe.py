#!/usr/bin/env python3
"""
perf_probe.py -- the SQA suite's read-only measurement instrument.

ONE JSON object on stdout, always, success or failure. Never writes outside the system
temp directory. Never edits a target. It measures; it does not fix.

    python ~/.claude/tools/perf_probe.py --mode <MODE> [opts] [--run <argv...>]

MODES
    env       Report what is measurable on this machine right now. Runs nothing.
    profile   Native-Windows CPU + memory attribution (cProfile + tracemalloc, stdlib).
    scalene   Line-level CPU + memory attribution. RUNS UNDER WSL -- see WHY below.
    memray    Allocation-level memory: peak RSS + top allocation sites. WSL.
    sample    py-spy: attach to a running process (--pid) or record a spawned one.
    bench     pyperf A/B timing on a small kernel, min-of-N with spread.
    energy    Paired idle/load Windows EMI package energy, gated by the noise floor.
    sci       energy, then Software Carbon Intensity via the GSF Impact Framework.
    prose     Bytes/words/lines for a file set, or a before/after pair. Counts only.

WHY SCALENE RUNS UNDER WSL -- measured 2026-08-17, do not "fix" this back.
    Scalene 2.3.0 on native Windows collects ZERO samples. An 8.66 s workload still
    produced `{}` (4 bytes) and printed "The specified code did not run for long enough
    to profile". Its sampler is signal-based and those signals do not fire here. The same
    target under the WSL venv interpreter produced a 144 KB profile with
    `memory: true`, `elapsed_time_sec: 2.80` and correct line attribution. So `scalene`
    mode carries the same WSL precondition gate as `memray`, and `profile` mode exists as
    the native fallback for Windows-only code that cannot run under Linux at all.

THE SECURITY PROPERTY -- do not build this any other way.
    `--run` hands this wrapper a command to execute. Built naively that is a total bypass
    of the SQA Bash guard. Five controls, all HERE, because no agent can edit this file
    (fixer-scope-guard.ps1 protects ~/.claude/tools, and every sqa-* agent carries
    Write/Edit in disallowedTools):

      1. --run takes an argv LIST, never a shell string. subprocess.run(argv, shell=False).
      2. The guard is RE-APPLIED before spawning: the command is piped into
         ~/.claude/hooks/sqa-guard-bash.ps1 and a non-zero exit refuses the run, echoing
         the guard's own stderr. This wrapper inherits the guard; it does not sidestep it.
      3. Shape restriction: argv[0] must be a Python interpreter, argv[1] a .py path or
         -m <allowlisted module>. Anything else is refused, never worked around.
      4. This wrapper owns every output path. --out is forced under the system temp dir;
         `..` anywhere in a supplied path is refused outright.
      5. The WSL/HTTP boundary: no caller string is ever interpolated into a wsl.exe
         invocation, an if-run manifest, or a URL. memray/scalene pass the already
         validated argv as a list with C:\\... -> /mnt/c/... translated here and asserted
         to resolve under the user's home. `sci` builds its manifest from validated FLOATS
         only. The LibreHardwareMonitor probe URL is a module constant.

    --timeout is mandatory with a default, and a timeout RETURNS A STRUCTURED RESULT --
    a workload that will not finish is itself a finding, not an error to swallow.

A NOTE ON PATHS WITH SPACES. sqa-guard-bash.ps1's allowlist matches `\\S+\\.py`, which a
quoted path containing spaces cannot satisfy -- and nearly every path in this user's tree
has spaces. So the target is run FROM ITS OWN DIRECTORY and the guard is shown the
basename form, which is what an agent would type anyway. Controls 1 and 3 still validate
the fully resolved absolute path. The chosen cwd is reported in the JSON as `cwd`.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"

# Python floor. The binding constraint is `sys.stdlib_module_names`, new in 3.10 and used by
# the WSL import precondition. Without this check a 3.9 interpreter imports the file fine and
# then dies deep inside a mode with an AttributeError, which the generic handler reports as
# `internal-error` -- a confusing answer to a simple question. Fail here instead, in the JSON
# contract every caller already parses.
if sys.version_info < (3, 10):
    print(json.dumps({
        "ok": False,
        "tool": "perf_probe",
        "version": VERSION,
        "control": "unsupported-python",
        "reason": ("perf_probe needs Python 3.10 or newer (sys.stdlib_module_names); this "
                   "interpreter is {}.{}.{}. Re-run with a newer interpreter.".format(
                       *sys.version_info[:3])),
    }))
    raise SystemExit(3)

# ---------------------------------------------------------------------------- constants

HOME = Path.home()
GUARD = HOME / ".claude" / "hooks" / "sqa-guard-bash.ps1"
TEMP_ROOT = Path(tempfile.gettempdir()).resolve()
WORK = TEMP_ROOT / "perf_probe"

# ---------------------------------------------------------------- MACHINE CONFIGURATION
#
# These describe the HOST, not the target under measurement, so they are read from the
# environment with this machine's values as the defaults. Every one of them was a bare literal
# until 2026-08-21; on any other machine the WSL pair silently refused every WSL-backed mode
# (a username that does not exist), and the grid-intensity pair silently reported an
# AUSTRALIAN carbon number for a run on another continent -- confidently, with a citation, and
# wrong. A wrong number presented as measured is worse than a refusal.
#
# Overriding is a deliberate act with a consequence, so nothing here is auto-detected: the
# `env` mode reports the resolved values, and `sci` labels every figure with the region whose
# intensity it used.
WSL_DISTRO = os.environ.get("SQA_WSL_DISTRO", "Ubuntu")
WSL_PYTHON = os.environ.get("SQA_WSL_PYTHON", "/home/{}/sci-env/bin/python".format(
    os.environ.get("SQA_WSL_USER", HOME.name)))

# LibreHardwareMonitor. Optional cross-check only -- never a failure, never launched by an
# agent. Filter by SensorId, never by Text: a temperature sensor shares the text "CPU Package".
# The sensor id is INTEL-SPECIFIC; on AMD the tree is /amdcpu/0/..., and on a second socket
# /intelcpu/1/.... A wrong id is not an error, only `available: false`.
LHM_URL = os.environ.get("SQA_LHM_URL", "http://localhost:8085/data.json")
LHM_CPU_PACKAGE_SENSOR_ID = os.environ.get("SQA_LHM_SENSOR_ID", "/intelcpu/0/power/0")
LHM_TIMEOUT_S = 1.0

# Grid carbon intensity, gCO2e/kWh.
#
# REGION IS NOT DETECTED, AND THAT IS THE POINT OF THESE TWO ENV VARS. The defaults below are
# Australian, because that is where this tool was written. Nothing in the code notices that it
# is running somewhere else -- so before 2026-08-21 a `sci` run in Berlin or Toronto emitted an
# Australian carbon figure, carrying a real citation, with no indication it was the wrong grid.
# That is the failure mode this file elsewhere calls out by name: a number that is wrong in a
# way fluent enough to pass unnoticed.
#
# Set SQA_GRID_REGION and SQA_GRID_INTENSITY together to measure against your own grid. The
# region string is a LABEL ONLY -- it is echoed into the output so the figure is attributable;
# it never selects the number. Both `env` and `sci` report the resolved pair.
SQA_GRID_REGION = os.environ.get("SQA_GRID_REGION", "").strip()
try:
    SQA_GRID_INTENSITY = float(os.environ["SQA_GRID_INTENSITY"])
except (KeyError, ValueError):
    SQA_GRID_INTENSITY = None

# AUS is read from codecarbon's own offline data file at runtime and quoted with its path;
# this is the fallback if that file cannot be read.
AUS_INTENSITY_FALLBACK = 548.692
# Victoria, scope 2 location-based, from the National Greenhouse Accounts Factors 2025.
#
# PROVENANCE, STATED EXACTLY. The DCCEEW primary PDF
# (national-greenhouse-account-factors-2025.pdf) and its publication landing page BOTH
# timed out on fetch (60 s, twice each) on 2026-08-17, so this constant is corroborated by
# TWO INDEPENDENT SECONDARY SOURCES that agree to the digit -- carbonly.ai and emisso.app,
# which also agree on every other state (NSW/ACT 0.64, QLD 0.67, SA 0.22, WA-SWIS 0.50,
# TAS 0.20, NT 0.56). That is corroboration, NOT primary verification, and the difference
# is recorded here rather than smoothed over. Anyone re-running this should fetch the
# primary PDF and either confirm the value or correct it.
VIC_INTENSITY = 780.0
VIC_AS_OF = "2025 (NGA Factors 2025, applying to the 2025-26 reporting period)"
VIC_SOURCE = ("Australian National Greenhouse Accounts Factors 2025 (DCCEEW), Victoria "
              "scope 2 electricity, 0.78 kg CO2-e/kWh, location-based. NOT primary-"
              "verified: the DCCEEW PDF and landing page both timed out on 2026-08-17; "
              "value corroborated by two independent secondary sources that agree on all "
              "states.")

SCI_NONCONFORMANCE = ("operational-only, M = 0, non-conformant with ISO/IEC 21031:2024")

# Modules a --run may legitimately invoke with -m. Mirrors sqa-guard-bash.ps1:156.
ALLOWED_DASH_M = {
    "pytest", "unittest", "doctest", "timeit", "compileall", "py_compile", "json.tool",
}
# The only interpreter flags a --run may carry. Deliberately tiny.
ALLOWED_PY_FLAGS = {"-u"}

INTERPRETER_RE = re.compile(r"^(?:python|python3|python3\.\d+|py)(?:\.exe)?$", re.I)

# Timing/energy claims are worthless without this attached. Emitted on every measuring run.
NOISE_DISCLOSURE = [
    "Windows offers no CPU isolation; `pyperf system tune` is non-functional on this host.",
    "Turbo and thermal throttling vary between reps; battery vs mains changes the ceiling.",
    "Defender may scan during a run.",
    "OneDrive and Google Drive both sync this tree and can steal I/O mid-measurement.",
]
ENERGY_DISCLOSURE = (
    "package-wide counter, attributed by paired-baseline subtraction, not per-process"
)

# ---------------------------------------------------------------------------- envelope


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
        "tool": "perf_probe.py",
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


# ---------------------------------------------------------------------------- control 4


def ensure_work_dir() -> Path:
    WORK.mkdir(parents=True, exist_ok=True)
    return WORK


def owned_output(name: str) -> Path:
    """Every artefact this tool writes goes here. Callers cannot choose a location."""
    return ensure_work_dir() / name


def validate_out(supplied: str | None) -> Path | None:
    """Control 4. A caller MAY name an output file, but only inside the temp tree."""
    if supplied is None:
        return None
    if ".." in Path(supplied).parts or ".." in supplied.replace("\\", "/").split("/"):
        raise Refusal("control-4-output-path",
                      f"--out contains '..': {supplied!r}. Path traversal is refused "
                      "outright rather than normalised, because a normalised traversal "
                      "still means the caller chose the location.")
    p = Path(supplied)
    if not p.is_absolute():
        p = WORK / p
    try:
        resolved = p.resolve()
    except OSError as e:
        raise Refusal("control-4-output-path", f"--out cannot be resolved: {e}")
    if TEMP_ROOT not in resolved.parents and resolved != TEMP_ROOT:
        raise Refusal("control-4-output-path",
                      f"--out resolves to {resolved}, which is outside the system temp "
                      f"directory ({TEMP_ROOT}). This wrapper owns every output path.")
    return resolved


# ---------------------------------------------------------------------------- control 5


def win_to_wsl(win_path: Path) -> str:
    """Control 5. Translate here, and assert containment; never interpolate a caller string."""
    resolved = Path(win_path).resolve()
    try:
        resolved.relative_to(HOME)
    except ValueError:
        raise Refusal("control-5-wsl-boundary",
                      f"{resolved} does not resolve under {HOME}. WSL modes refuse any "
                      "path outside the user's home so a translated path cannot reach "
                      "the rest of the filesystem.")
    drive = resolved.drive.rstrip(":").lower()
    if not drive:
        raise Refusal("control-5-wsl-boundary", f"{resolved} has no drive letter to translate.")
    rest = str(resolved)[2:].replace("\\", "/")
    return f"/mnt/{drive}{rest}"


def wsl_run(argv: list[str], timeout: int) -> subprocess.CompletedProcess:
    """argv is a LIST. Nothing is ever passed through a shell."""
    return subprocess.run(["wsl.exe", "-d", WSL_DISTRO, "--"] + argv,
                          capture_output=True, text=True, timeout=timeout,
                          errors="replace")


# ---------------------------------------------------------------------------- controls 1-3


def split_run_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    """Everything after the first bare `--run` is the run command, verbatim.

    Done by hand rather than with argparse.REMAINDER so that flags belonging to the
    target (`-o`, `--json`, ...) are never eaten by this tool's own parser.
    """
    if "--run" not in argv:
        return argv, []
    i = argv.index("--run")
    return argv[:i], argv[i + 1:]


def check_run_shape(run_argv: list[str]) -> dict:
    """Control 3. argv[0] a Python interpreter, argv[1] a .py path or -m <allowlisted>."""
    if not run_argv:
        raise Refusal("control-3-shape", "--run was given no command.")

    exe = run_argv[0]
    if not INTERPRETER_RE.match(Path(exe).name):
        raise Refusal("control-3-shape",
                      f"--run must start with a Python interpreter; got {exe!r}. This "
                      "wrapper profiles Python workloads and refuses to become a general "
                      "command runner, which is exactly what would make it a guard bypass.")

    rest = run_argv[1:]
    flags = []
    while rest and rest[0].startswith("-") and rest[0] != "-m":
        if rest[0] not in ALLOWED_PY_FLAGS:
            raise Refusal("control-3-shape",
                          f"interpreter flag {rest[0]!r} is not allowed. Only "
                          f"{sorted(ALLOWED_PY_FLAGS)} may precede the target.")
        flags.append(rest.pop(0))

    if not rest:
        raise Refusal("control-3-shape", "--run names an interpreter but no target.")

    if rest[0] == "-m":
        if len(rest) < 2:
            raise Refusal("control-3-shape", "--run has -m with no module.")
        module = rest[1]
        if module not in ALLOWED_DASH_M:
            raise Refusal("control-3-shape",
                          f"-m {module!r} is not on the allowlist "
                          f"({sorted(ALLOWED_DASH_M)}). Report it as a recommendation "
                          "rather than working around this list.")
        # `args` is ALWAYS "everything after the target", for both kinds. Never slice it
        # again downstream -- a double slice here silently dropped the first argument and
        # showed the guard a command that was not the one about to run. Measured, fixed.
        return {"kind": "module", "module": module, "flags": flags, "script": None,
                "cwd": Path.cwd(), "args": rest[2:], "target_token": None}

    target = rest[0]
    if not target.lower().endswith(".py"):
        raise Refusal("control-3-shape",
                      f"--run target {target!r} is not a .py file and not -m <module>.")
    script = Path(target)
    if not script.is_absolute():
        script = (Path.cwd() / script)
    try:
        script = script.resolve()
    except OSError as e:
        raise Refusal("control-3-shape", f"--run target cannot be resolved: {e}")
    if not script.is_file():
        raise Refusal("control-3-shape",
                      f"--run target does not exist: {script}. A missing entry point is "
                      "[Needs-info], never an invocation to invent.")
    return {"kind": "script", "module": None, "flags": flags, "script": script,
            "cwd": script.parent, "args": rest[1:], "target_token": target}


def guard_command_string(shape: dict) -> str:
    """The spelling the guard is shown.

    DERIVED FROM local_argv() so the two can never drift. Showing the guard a command
    that differs from the one about to run is the whole failure mode this wrapper exists
    to prevent, so it must be structurally impossible, not merely intended.
    """
    return " ".join(local_argv(shape, "python"))


def reapply_guard(command: str) -> None:
    """Control 2. Fail CLOSED: a guard we cannot consult is a guard we must assume denies."""
    if not GUARD.is_file():
        raise Refusal("control-2-guard",
                      f"the SQA Bash guard is missing at {GUARD}. This wrapper refuses to "
                      "run anything it cannot first submit to the guard.")
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", str(GUARD)],
            input=payload, capture_output=True, text=True, timeout=60, errors="replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Refusal("control-2-guard",
                      f"the guard could not be consulted ({e}); refusing, fail-closed.")
    if proc.returncode != 0:
        raise Refusal("control-2-guard",
                      f"sqa-guard-bash.ps1 refused {command!r} (exit {proc.returncode}).",
                      guard_stderr=(proc.stderr or "").strip())


def prepare_run(run_argv: list[str]) -> dict:
    """Controls 1, 2 and 3 in the one place, so no mode can skip one."""
    shape = check_run_shape(run_argv)
    cmd = guard_command_string(shape)

    # The guard must be shown EVERY token that will be spawned. If a caller token is
    # missing from the string the guard judged, the guard judged a DIFFERENT command --
    # which is exactly how a wrapper becomes a bypass. This caught a real double-slice bug
    # that dropped the first script argument and showed the guard `python x.py rm -rf x`
    # for a `--run` of `python x.py && rm -rf x`. Fail closed on any drift.
    #
    # The ONE documented rewrite is the target path -> its basename (see the module
    # docstring: the guard's allowlist cannot match a quoted path containing spaces, and
    # nearly every path in this tree has them). Nothing else may change.
    spawned = local_argv(shape, "python")
    for token in run_argv[1:]:
        if token and token != shape.get("target_token") and token not in spawned:
            raise Refusal("control-2-guard",
                          f"internal consistency check failed: token {token!r} from --run "
                          "does not appear in the command submitted to the guard. "
                          "Refusing rather than running a command the guard never saw.")
    expected = len(shape["flags"]) + len(shape["args"]) + (1 if shape["kind"] == "script" else 2)
    if len(spawned) - 1 != expected:
        raise Refusal("control-2-guard",
                      f"internal consistency check failed: the spawned command has "
                      f"{len(spawned) - 1} tokens where {expected} were expected.")

    reapply_guard(cmd)
    shape["guard_command"] = cmd
    return shape


def local_argv(shape: dict, interpreter: str) -> list[str]:
    """The argv actually spawned, in basename-from-its-own-directory form.

    The single source of truth for "what will run". guard_command_string() is built from
    this, and every mode spawns this (or a WSL translation of it).
    """
    argv = [interpreter] + shape["flags"]
    if shape["kind"] == "module":
        return argv + ["-m", shape["module"]] + shape["args"]
    return argv + [shape["script"].name] + shape["args"]


# ---------------------------------------------------------------------------- WSL gate


def top_level_imports(script: Path) -> list[str]:
    try:
        tree = ast.parse(script.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return []
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                mods.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                mods.add(node.module.split(".")[0])
    return sorted(m for m in mods if m not in sys.stdlib_module_names)


def wsl_precondition(shape: dict, timeout: int) -> dict:
    """Refuse a partial run reported as a result. [Needs-info] names the missing module."""
    r = wsl_run([WSL_PYTHON, "-c", "import sys; print(sys.version.split()[0])"], timeout=60)
    if r.returncode != 0:
        raise Refusal("wsl-precondition",
                      f"the WSL venv interpreter {WSL_PYTHON} is not usable: "
                      f"{(r.stderr or r.stdout).strip()[:300]}")
    venv_python = r.stdout.strip()

    if shape["kind"] != "script":
        return {"venv_python": venv_python, "imports_checked": [], "missing": []}

    mods = top_level_imports(shape["script"])
    missing = []
    for m in mods:
        probe = wsl_run([WSL_PYTHON, "-c", f"import {m}"], timeout=120)
        if probe.returncode != 0:
            missing.append(m)
    if missing:
        raise Refusal("wsl-precondition",
                      f"[Needs-info] the WSL venv ({WSL_PYTHON}) cannot import "
                      f"{missing}, which {shape['script'].name} needs. Refusing rather "
                      "than reporting a partial run as a result. Install into the venv "
                      f"with `wsl -d {WSL_DISTRO} -- {WSL_PYTHON} -m pip install "
                      f"{' '.join(missing)}` or use --mode profile, which runs natively.")
    return {"venv_python": venv_python, "imports_checked": mods, "missing": []}


# ---------------------------------------------------------------------------- energy


def _emi():
    from codecarbon.core.units import Time
    from codecarbon.core.windows_emi import WindowsEMI, is_emi_available
    if not is_emi_available():
        raise Refusal("energy-unavailable",
                      "the Windows Energy Meter Interface reports unavailable. EMI needs "
                      "Windows 11 on bare metal. Never retry pyRAPL (raises "
                      "FileNotFoundError on Windows) and never look for "
                      "/sys/class/powercap under WSL (measured empty three times).")
    return WindowsEMI, Time


def sample_energy(seconds: float) -> dict:
    """One paired-baseline sample. Returns joules and mean watts over `seconds`."""
    WindowsEMI, Time = _emi()
    meter = WindowsEMI()
    meter.start()
    t0 = time.perf_counter()
    time.sleep(seconds)
    dt = time.perf_counter() - t0
    d = meter.get_cpu_details(Time(seconds=dt))
    return _fold_emi(d, dt)


def _fold_emi(details: dict, dt: float) -> dict:
    """codecarbon names the watts key 'Processor Power Delta_N(kWh)'. It is WATTS."""
    kwh = sum(v for k, v in details.items() if "Energy Delta" in k)
    watts = sum(v for k, v in details.items() if "Power Delta" in k)
    return {"seconds": dt, "energy_kwh": kwh, "energy_j": kwh * 3.6e6, "watts": watts}


def measure_load_energy(spawn, seconds_hint: float) -> dict:
    """Run the workload with the meter open around it."""
    WindowsEMI, Time = _emi()
    meter = WindowsEMI()
    meter.start()
    t0 = time.perf_counter()
    outcome = spawn()
    dt = time.perf_counter() - t0
    d = meter.get_cpu_details(Time(seconds=dt))
    folded = _fold_emi(d, dt)
    folded["process"] = outcome
    return folded


def lhm_cross_check() -> dict:
    """Optional corroboration. Never a failure, never a launch attempt."""
    try:
        import requests
    except ImportError:
        return {"available": False, "reason": "requests not installed"}
    try:
        r = requests.get(LHM_URL, timeout=LHM_TIMEOUT_S)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return {"available": False,
                "reason": f"LHM: not running (cross-check unavailable) [{type(e).__name__}]"}

    found = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("SensorId") == LHM_CPU_PACKAGE_SENSOR_ID:
                found.append(node)
            for child in node.get("Children", []) or []:
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(data)
    if not found:
        return {"available": False,
                "reason": f"LHM answered but exposes no sensor {LHM_CPU_PACKAGE_SENSOR_ID}"}
    raw = str(found[0].get("Value", "")).replace(",", ".")
    m = re.search(r"[-+]?\d*\.?\d+", raw)
    return {"available": True,
            "sensor_id": LHM_CPU_PACKAGE_SENSOR_ID,
            "watts": float(m.group()) if m else None,
            "raw": found[0].get("Value")}


SNR_MARGIN = 3.0


def energy_gate(idle_samples: list[dict], load_samples: list[dict]) -> dict:
    """The noise floor. Below it: a phrase, never a number.

    WHY THIS IS NOT THE PLAN'S "load >= 2x idle" RULE -- measured 2026-08-17.
    That rule is unreachable on this machine, and the reason is a property of the hardware,
    not of the measurement. This is an Intel Core Ultra 7 155H whose PACKAGE counter
    (RAPL_Package0_PKG -- the only channel EMI exposes here) includes uncore, iGPU and the
    memory controller, so it sits at a ~19 W floor before any workload starts:

        idle 5 s ............ 18.88 W
        1-core spin 5 s ..... 21.26 W
        22-core spin 6 s .... 28.11 W   <- FULL LOAD, and still only 1.49x idle
        idle 5 s again ...... 20.80 W

    Nothing this laptop can run reaches 2x idle, so the original rule refuses every
    workload including the ones with a 9 W signal -- a mode that can never emit a number.
    The plan's calibration came from a session whose idle read near zero (its recorded
    "0.34 / 9.10 / 10.52 J over 3 s" is 0.1-3.5 W), i.e. a different counter behaviour.

    So the gate now tests SIGNAL AGAINST MEASURED NOISE rather than against an absolute
    ratio: the load-idle delta must exceed 3x the idle baseline's own run-to-run spread,
    over >= 3 reps. That is strictly the more meaningful test -- it is calibrated on this
    session's actual variance instead of on a constant that encodes someone else's idle
    floor. The 2x-idle ratio is still COMPUTED AND REPORTED as a diagnostic, so the change
    is visible in every result rather than buried here.

    Discrimination, measured: O(n^2) pure Python delta 0.25 W vs idle spread 0.79 W ->
    REFUSED. 22-core spin delta ~9 W vs spread ~1 W -> resolvable.
    """
    idle_w = [s["watts"] for s in idle_samples]
    load_w = [s["watts"] for s in load_samples]
    mean_idle = statistics.fmean(idle_w)
    mean_load = statistics.fmean(load_w)
    idle_spread = max(idle_w) - min(idle_w)
    delta_w = mean_load - mean_idle
    threshold = SNR_MARGIN * idle_spread

    ratio_2x = bool(mean_idle > 0 and mean_load >= 2.0 * mean_idle)
    cond_snr = bool(len(idle_w) >= 3 and delta_w > 0 and delta_w > threshold)
    resolvable = cond_snr

    out = {
        "resolvable": resolvable,
        "reps": len(load_w),
        "idle_watts_mean": mean_idle,
        "idle_watts_spread": idle_spread,
        "idle_watts_each": idle_w,
        "load_watts_mean": mean_load,
        "load_watts_each": load_w,
        "delta_watts": delta_w,
        "snr_threshold_watts": threshold,
        "snr_margin": SNR_MARGIN,
        "gate": "delta > 3 x idle run-to-run spread, over >= 3 reps",
        "condition_snr_delta_gt_3x_idle_spread": cond_snr,
        "diagnostic_load_ge_2x_idle": ratio_2x,
        "diagnostic_note": (
            "`diagnostic_load_ge_2x_idle` is REPORTED, NOT GATING. This machine's package "
            "counter idles at ~19 W and peaks near 28 W at 22-core load (1.49x), so a 2x "
            "absolute ratio is unreachable here and would refuse every workload. See "
            "energy_gate()'s docstring for the measurements."),
    }
    if resolvable:
        secs = [s["seconds"] for s in load_samples]
        attributed_j = [max(0.0, (s["watts"] - mean_idle) * s["seconds"])
                        for s in load_samples]
        out["package_energy_j_each"] = [s["energy_j"] for s in load_samples]
        out["package_energy_j_median"] = statistics.median(s["energy_j"] for s in load_samples)
        out["attributed_energy_j_each"] = attributed_j
        out["attributed_energy_j_median"] = statistics.median(attributed_j)
        out["attributed_energy_kwh_median"] = out["attributed_energy_j_median"] / 3.6e6
        out["load_seconds_median"] = statistics.median(secs)
        out["statement"] = ENERGY_DISCLOSURE
    else:
        why = []
        if len(idle_w) < 3:
            why.append(f"only {len(idle_w)} reps; the noise floor needs at least 3")
        if delta_w <= 0:
            why.append(f"load {mean_load:.2f} W is not above idle {mean_idle:.2f} W")
        elif delta_w <= threshold:
            why.append(f"delta {delta_w:.2f} W does not clear {SNR_MARGIN:g}x the idle "
                       f"spread ({threshold:.2f} W) over {len(idle_w)} reps")
        out["statement"] = "energy not resolvable above the machine's idle floor"
        out["why"] = why
        out["fallback"] = "use the CPU-time proxy; do not quote a joule figure"
    return out


def aus_intensity() -> dict:
    """Read codecarbon's own offline constant, and quote the file it came from."""
    try:
        import codecarbon
        p = (Path(codecarbon.__file__).parent / "data" / "private_infra"
             / "global_energy_mix.json")
        data = json.loads(p.read_text(encoding="utf-8"))
        value = float(data["AUS"]["carbon_intensity"])
        return {"g_per_kwh": value, "source": str(p), "region": "AUS (national annual average)"}
    except Exception as e:
        return {"g_per_kwh": AUS_INTENSITY_FALLBACK,
                "source": f"hardcoded fallback ({type(e).__name__}: {e})",
                "region": "AUS (national annual average)"}


# ---------------------------------------------------------------------------- modes


def mode_env(args) -> int:
    res = {"emi": {}, "wsl": {}, "windows_python": {}, "lhm": {}, "impact_framework": {}}

    # The resolved HOST configuration, and which of it came from the environment rather than
    # the defaults. A user on a machine unlike the authoring one needs to see this before
    # trusting any WSL-backed mode or any carbon figure -- `env` is the mode the agents are
    # told to run when something refuses and they need to say why.
    res["host_config"] = {
        "wsl_distro": WSL_DISTRO,
        "wsl_python": WSL_PYTHON,
        "lhm_url": LHM_URL,
        "lhm_sensor_id": LHM_CPU_PACKAGE_SENSOR_ID,
        "grid_region": SQA_GRID_REGION or "AUS/VIC (default -- NOT detected)",
        "grid_intensity_override": SQA_GRID_INTENSITY,
        "overridden": sorted(k for k in (
            "SQA_WSL_DISTRO", "SQA_WSL_PYTHON", "SQA_WSL_USER", "SQA_LHM_URL",
            "SQA_LHM_SENSOR_ID", "SQA_GRID_REGION", "SQA_GRID_INTENSITY",
        ) if os.environ.get(k)),
        "_note": ("Region is NEVER auto-detected. Unless SQA_GRID_REGION and "
                  "SQA_GRID_INTENSITY are both set, every sci figure uses Australian grid "
                  "intensity regardless of where this machine is."),
    }

    try:
        from codecarbon.core.windows_emi import is_emi_available
        res["emi"] = {"available": bool(is_emi_available())}
    except Exception as e:
        res["emi"] = {"available": False, "reason": f"{type(e).__name__}: {e}"}

    import importlib.util as iu
    for m in ("scalene", "pyperf", "numpy", "pandas", "requests", "codecarbon",
              "tiktoken", "anthropic"):
        res["windows_python"][m] = iu.find_spec(m) is not None
    res["windows_python"]["py-spy-exe"] = bool(_which("py-spy"))
    res["windows_python"]["scalene_native_usable"] = False
    res["windows_python"]["_scalene_note"] = (
        "Scalene 2.3.0 collects zero samples on native Windows (measured 2026-08-17: an "
        "8.66 s workload still produced a 4-byte '{}'). --mode scalene therefore runs "
        "under WSL. --mode profile is the native fallback.")

    try:
        r = wsl_run([WSL_PYTHON, "-c",
                     "import sys,importlib.util as u;"
                     "mods=['numpy','scipy','pandas','matplotlib','memray','scalene',"
                     "'sklearn','nbformat'];"
                     "print(sys.version.split()[0]);"
                     "print(','.join(m for m in mods if u.find_spec(m)))"], timeout=120)
        lines = (r.stdout or "").strip().splitlines()
        res["wsl"] = {"reachable": r.returncode == 0,
                      "python": lines[0] if lines else None,
                      "modules": (lines[1].split(",") if len(lines) > 1 and lines[1] else [])}
    except Exception as e:
        res["wsl"] = {"reachable": False, "reason": f"{type(e).__name__}: {e}"}

    try:
        r = wsl_run(["bash", "-lc", "command -v if-run; command -v if-check"], timeout=120)
        res["impact_framework"] = {"available": r.returncode == 0,
                                   "paths": (r.stdout or "").split()}
    except Exception as e:
        res["impact_framework"] = {"available": False, "reason": str(e)}

    res["lhm"] = lhm_cross_check()
    res["grid_intensity"] = {
        "aus": aus_intensity(),
        "vic": {"g_per_kwh": VIC_INTENSITY, "as_of": VIC_AS_OF, "source": VIC_SOURCE},
    }
    res["guard"] = {"path": str(GUARD), "present": GUARD.is_file()}
    res["work_dir"] = str(WORK)
    return emit("env", True, res, notes=[
        "Nothing was executed. This mode reports capability only.",
        "RAPL is empty under WSL2 (measured three times) and pyRAPL cannot work on "
        "Windows -- neither is ever retried.",
    ])


def _which(name: str) -> str | None:
    import shutil
    return shutil.which(name)


def mode_profile(args, shape) -> int:
    """Native Windows CPU + memory attribution with the stdlib. Always works here."""
    out_prof = owned_output("cprofile.out")
    driver = owned_output("_profile_driver.py")
    driver.write_text(
        "import cProfile, pstats, runpy, sys, tracemalloc, json, io, os\n"
        "target = sys.argv[1]\n"
        "outfile = sys.argv[2]\n"
        "sys.argv = [target] + sys.argv[3:]\n"
        "tracemalloc.start(25)\n"
        "pr = cProfile.Profile()\n"
        "pr.enable()\n"
        "try:\n"
        "    runpy.run_path(target, run_name='__main__')\n"
        "except SystemExit:\n"
        "    pass\n"
        "pr.disable()\n"
        "cur, peak = tracemalloc.get_traced_memory()\n"
        "snap = tracemalloc.take_snapshot()\n"
        "tracemalloc.stop()\n"
        "st = pstats.Stats(pr)\n"
        "rows = []\n"
        "for func, (cc, nc, tt, ct, _cal) in st.stats.items():\n"
        "    rows.append({'file': func[0], 'lineno': func[1], 'func': func[2],\n"
        "                 'ncalls': nc, 'tottime': tt, 'cumtime': ct})\n"
        "rows.sort(key=lambda r: r['tottime'], reverse=True)\n"
        "allocs = []\n"
        "for s in snap.statistics('lineno')[:15]:\n"
        "    f = s.traceback[0]\n"
        "    allocs.append({'file': f.filename, 'lineno': f.lineno,\n"
        "                   'size_mb': s.size / 1048576.0, 'count': s.count})\n"
        "json.dump({'total_time_s': st.total_tt, 'rows': rows[:30],\n"
        "           'tracemalloc_peak_mb': peak / 1048576.0,\n"
        "           'tracemalloc_current_mb': cur / 1048576.0,\n"
        "           'top_allocations': allocs},\n"
        "          open(outfile, 'w', encoding='utf-8'), indent=1)\n",
        encoding="utf-8")

    if shape["kind"] != "script":
        raise Refusal("mode-profile",
                      "--mode profile needs a .py target; -m modules are not supported "
                      "because runpy cannot attribute inside an installed package here.")

    argv = [sys.executable, str(driver), shape["script"].name, str(out_prof)] \
        + shape["args"]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(argv, cwd=str(shape["cwd"]), capture_output=True,
                              text=True, timeout=args.timeout, errors="replace")
        timed_out = False
    except subprocess.TimeoutExpired:
        return emit("profile", True, {
            "timed_out": True,
            "timeout_s": args.timeout,
            "finding": "the workload did not finish inside the timeout. That is itself a "
                       "finding -- report it as one, do not raise the timeout silently.",
            "guard_command": shape["guard_command"],
        }, disclosures=NOISE_DISCLOSURE)
    wall = time.perf_counter() - t0

    if not out_prof.is_file():
        raise Refusal("mode-profile",
                      f"the profile driver produced no output. stderr: "
                      f"{(proc.stderr or '')[-600:]}")
    data = json.loads(out_prof.read_text(encoding="utf-8"))
    hot = [r for r in data["rows"] if r["tottime"] > 0][:12]
    return emit("profile", True, {
        "profiler": "cProfile + tracemalloc (stdlib, native Windows)",
        "cwd": str(shape["cwd"]),
        "guard_command": shape["guard_command"],
        "wall_seconds": wall,
        "profiled_seconds": data["total_time_s"],
        "exit_code": proc.returncode,
        "timed_out": timed_out,
        "hot_functions": hot,
        "peak_memory_mb": data["tracemalloc_peak_mb"],
        "top_allocations": data["top_allocations"],
        "stdout_tail": (proc.stdout or "")[-500:],
        "stderr_tail": (proc.stderr or "")[-500:],
    }, disclosures=NOISE_DISCLOSURE, notes=[
        "cProfile attributes by FUNCTION, not by line. For line-level attribution use "
        "--mode scalene (WSL).",
        "tracemalloc counts Python-level allocations only; C-extension arenas (numpy) are "
        "under-counted. Use --mode memray for the allocator's own view.",
        "cProfile adds per-call overhead, so wall_seconds here exceeds an unprofiled run. "
        "Never quote a profiled wall time as the workload's cost -- use --mode bench.",
    ])


def mode_scalene(args, shape) -> int:
    pre = wsl_precondition(shape, args.timeout)
    if shape["kind"] != "script":
        raise Refusal("mode-scalene", "--mode scalene needs a .py target.")
    wsl_target = win_to_wsl(shape["script"])
    out_json = "/tmp/perf_probe_scalene.json"
    argv = [WSL_PYTHON, "-m", "scalene", "run", "-o", out_json, wsl_target]
    if shape["args"]:
        argv += ["---"] + shape["args"]
    try:
        r = wsl_run(argv, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        return emit("scalene", True, {
            "timed_out": True, "timeout_s": args.timeout,
            "finding": "the workload did not finish inside the timeout; that is a finding.",
        }, disclosures=NOISE_DISCLOSURE)

    got = wsl_run(["cat", out_json], timeout=120)
    raw = got.stdout or ""
    if len(raw.strip()) < 20:
        raise Refusal("mode-scalene",
                      "Scalene produced an empty profile. Under WSL that means the target "
                      "ran too briefly to sample -- give it more work. (On native Windows "
                      "this happens ALWAYS, which is why this mode uses WSL.) "
                      f"scalene stderr: {(r.stderr or '')[-400:]}")
    prof = json.loads(raw)

    if not prof.get("memory"):
        memory_note = ("memory == false: Scalene disabled memory profiling silently. NO "
                       "memory claim may be made from this run.")
    else:
        memory_note = "memory == true, asserted before reading any memory field."

    lines_out = []
    for fname, fdata in (prof.get("files") or {}).items():
        for L in fdata.get("lines", []):
            cpu = (L.get("n_cpu_percent_python", 0) or 0) + (L.get("n_cpu_percent_c", 0) or 0)
            if cpu <= 0 and not (L.get("n_peak_mb") or 0):
                continue
            lines_out.append({
                "file": fname, "lineno": L.get("lineno"),
                "line": (L.get("line") or "").rstrip()[:160],
                "cpu_percent_python": L.get("n_cpu_percent_python"),
                "cpu_percent_c": L.get("n_cpu_percent_c"),
                "cpu_percent_total": cpu,
                "peak_mb": L.get("n_peak_mb") if prof.get("memory") else None,
                "n_mallocs": L.get("n_mallocs") if prof.get("memory") else None,
                "raw_cpu_samples": len(L.get("cpu_samples_list") or []),
            })
    lines_out.sort(key=lambda r: r["cpu_percent_total"], reverse=True)

    return emit("scalene", True, {
        "profiler": f"Scalene under WSL ({WSL_DISTRO}, {pre['venv_python']})",
        "guard_command": shape["guard_command"],
        "wsl_target": wsl_target,
        "memory_flag": bool(prof.get("memory")),
        "memory_assertion": memory_note,
        "elapsed_time_sec": prof.get("elapsed_time_sec"),
        "max_footprint_mb": prof.get("max_footprint_mb") if prof.get("memory") else None,
        "total_samples": prof.get("samples"),
        "hot_lines": lines_out[:15],
        "imports_checked": pre["imports_checked"],
        "exit_code": r.returncode,
        "stdout_tail": (r.stdout or "")[-400:],
    }, disclosures=NOISE_DISCLOSURE, notes=[
        memory_note,
        "Use n_peak_mb, never n_growth_mb.",
        "MEASURED 2026-08-17: in Scalene 2.3.0 `cpu_samples_list` comes back EMPTY even on "
        "a good profile, so it cannot be used to discard thin attributions. Judge instead "
        "on the profile's top-level `total_samples` and on elapsed_time_sec x percent; a "
        "line under ~1% of a short run is noise.",
        "This ran under Linux. A Windows-only timing characteristic will not appear here.",
    ])


def mode_memray(args, shape) -> int:
    pre = wsl_precondition(shape, args.timeout)
    if shape["kind"] != "script":
        raise Refusal("mode-memray", "--mode memray needs a .py target.")
    wsl_target = win_to_wsl(shape["script"])
    bin_out, json_out = "/tmp/perf_probe_memray.bin", "/tmp/perf_probe_memray.json"
    argv = [WSL_PYTHON, "-m", "memray", "run", "-f", "-o", bin_out, wsl_target] \
        + shape["args"]
    try:
        run = wsl_run(argv, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        return emit("memray", True, {"timed_out": True, "timeout_s": args.timeout,
                                     "finding": "workload did not finish; that is a finding."})
    stats = wsl_run([WSL_PYTHON, "-m", "memray", "stats", "--json", "-f",
                     "-o", json_out, bin_out], timeout=args.timeout)
    got = wsl_run(["cat", json_out], timeout=120)
    if len((got.stdout or "").strip()) < 20:
        raise Refusal("mode-memray",
                      f"memray produced no stats. run stderr: {(run.stderr or '')[-300:]} "
                      f"stats stderr: {(stats.stderr or '')[-300:]}")
    d = json.loads(got.stdout)
    meta = d.get("metadata", {}) or {}
    peak = meta.get("peak_memory")
    return emit("memray", True, {
        "profiler": f"memray under WSL ({WSL_DISTRO}, {pre['venv_python']})",
        "guard_command": shape["guard_command"],
        "peak_memory_bytes": peak,
        "peak_memory_mb": (peak / 1048576.0) if isinstance(peak, (int, float)) else None,
        "total_allocations": d.get("total_num_allocations"),
        "total_bytes_allocated": d.get("total_bytes_allocated"),
        "top_allocations_by_size": (d.get("top_allocations_by_size") or [])[:10],
        "top_allocations_by_count": (d.get("top_allocations_by_count") or [])[:10],
        "allocator_type_distribution": d.get("allocator_type_distribution"),
        "imports_checked": pre["imports_checked"],
        "exit_code": run.returncode,
    }, disclosures=NOISE_DISCLOSURE, notes=[
        "peak_memory is the allocator's peak RSS, which INCLUDES C-extension arenas that "
        "tracemalloc cannot see.",
        "This ran under Linux; Windows allocator behaviour differs.",
    ])


def mode_sample(args, shape) -> int:
    exe = _which("py-spy")
    if not exe:
        raise Refusal("mode-sample", "py-spy is not on PATH.")
    if args.pid:
        out = owned_output("pyspy_dump.json")
        r = subprocess.run([exe, "dump", "--pid", str(args.pid), "--json"],
                           capture_output=True, text=True, timeout=args.timeout,
                           errors="replace")
        if r.returncode != 0:
            raise Refusal("mode-sample",
                          f"py-spy dump failed (exit {r.returncode}): "
                          f"{(r.stderr or '')[-400:]}. Attaching to another process may "
                          "need an elevated shell on Windows.")
        out.write_text(r.stdout, encoding="utf-8")
        return emit("sample", True, {
            "method": "py-spy dump (attached, zero instrumentation overhead)",
            "pid": args.pid,
            "threads": json.loads(r.stdout) if r.stdout.strip().startswith("[") else r.stdout,
        }, disclosures=NOISE_DISCLOSURE)

    if shape is None:
        raise Refusal("mode-sample", "--mode sample needs either --pid or --run.")
    out = owned_output("pyspy_record.json")
    argv = [exe, "record", "--format", "speedscope", "--output", str(out), "--"] \
        + local_argv(shape, sys.executable)
    try:
        r = subprocess.run(argv, cwd=str(shape["cwd"]), capture_output=True, text=True,
                           timeout=args.timeout, errors="replace")
    except subprocess.TimeoutExpired:
        return emit("sample", True, {"timed_out": True, "timeout_s": args.timeout,
                                     "finding": "workload did not finish; that is a finding."})
    if not out.is_file():
        raise Refusal("mode-sample",
                      f"py-spy record produced nothing (exit {r.returncode}): "
                      f"{(r.stderr or '')[-400:]}")
    prof = json.loads(out.read_text(encoding="utf-8"))
    frames = prof.get("shared", {}).get("frames", [])
    tallies: dict[int, int] = {}
    for p in prof.get("profiles", []):
        for s in p.get("samples", []):
            if s:
                tallies[s[-1]] = tallies.get(s[-1], 0) + 1
    total = sum(tallies.values()) or 1
    top = sorted(tallies.items(), key=lambda kv: kv[1], reverse=True)[:12]
    return emit("sample", True, {
        "method": "py-spy record (sampling, no instrumentation overhead)",
        "guard_command": shape["guard_command"],
        "total_samples": total,
        "hot_leaves": [{
            "function": frames[i].get("name") if i < len(frames) else str(i),
            "file": frames[i].get("file") if i < len(frames) else None,
            "line": frames[i].get("line") if i < len(frames) else None,
            "samples": n, "percent": 100.0 * n / total,
        } for i, n in top],
        "speedscope_file": str(out),
    }, disclosures=NOISE_DISCLOSURE, notes=[
        "Sampling attributes to the LEAF frame; a hot caller with cheap leaves will not "
        "appear here. Cross-read with --mode profile before naming a hot path.",
    ])


def mode_bench(args, shape) -> int:
    out = owned_output("pyperf.json")
    if out.exists():
        out.unlink()
    env = dict(os.environ)
    # pyperf spawns workers; `python -s -c "import pyperf"` fails because the package
    # lives in the USER site dir. The guard cannot express an env-var prefix, so the
    # PYTHONPATH is injected here, internally, where no caller can reach it.
    import site
    user_site = site.getusersitepackages()
    env["PYTHONPATH"] = os.pathsep.join(
        [p for p in (user_site, env.get("PYTHONPATH", "")) if p])
    argv = [sys.executable, "-m", "pyperf", "command",
            "--processes", str(args.processes), "--values", str(args.values),
            "-o", str(out), "--"] + local_argv(shape, sys.executable)
    try:
        r = subprocess.run(argv, cwd=str(shape["cwd"]), capture_output=True, text=True,
                           timeout=args.timeout, env=env, errors="replace")
    except subprocess.TimeoutExpired:
        return emit("bench", True, {"timed_out": True, "timeout_s": args.timeout,
                                    "finding": "workload did not finish; that is a finding."})
    if not out.is_file():
        raise Refusal("mode-bench",
                      f"pyperf produced no result (exit {r.returncode}): "
                      f"{(r.stderr or '')[-600:]}")
    d = json.loads(out.read_text(encoding="utf-8"))
    values = []
    for b in d.get("benchmarks", []):
        for run in b.get("runs", []):
            values.extend(run.get("values") or [])
    values = [v for v in values if isinstance(v, (int, float))]
    if not values:
        raise Refusal("mode-bench", "pyperf recorded no timing values.")
    return emit("bench", True, {
        "harness": "pyperf command",
        "guard_command": shape["guard_command"],
        "runs": len(values),
        "min_s": min(values),
        "median_s": statistics.median(values),
        "mean_s": statistics.fmean(values),
        "stdev_s": statistics.stdev(values) if len(values) > 1 else 0.0,
        "spread_pct": (100.0 * (max(values) - min(values)) / min(values)) if min(values) else None,
        "pyperf_json": str(out),
        "stdout_tail": (r.stdout or "")[-400:],
    }, disclosures=NOISE_DISCLOSURE, notes=[
        "Quote MIN-of-N, not the mean: the minimum is the least-perturbed sample.",
        "Sub-10% deltas are not reportable (Georges/Buytaert/Eeckhout, OOPSLA 2007). "
        "The reportable bar on this host is 20%, because Windows offers no CPU isolation.",
        "An A/B comparison is only valid across BYTE-IDENTICAL argv. Different input "
        "sizes or iteration counts is the reward hack, not evidence of one.",
    ])


def _run_workload_once(shape, timeout: int) -> dict:
    argv = local_argv(shape, sys.executable)
    try:
        p = subprocess.run(argv, cwd=str(shape["cwd"]), capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return {"exit_code": p.returncode, "timed_out": False,
                "stderr_tail": (p.stderr or "")[-300:]}
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "timed_out": True, "stderr_tail": ""}


def _energy_measure(args, shape) -> dict:
    idle, load = [], []
    for _ in range(args.reps):
        idle.append(sample_energy(args.idle_seconds))
        load.append(measure_load_energy(lambda: _run_workload_once(shape, args.timeout),
                                        args.idle_seconds))
    gate = energy_gate(idle, load)
    gate["idle_seconds_each"] = [s["seconds"] for s in idle]
    gate["lhm_cross_check"] = lhm_cross_check()
    if gate["lhm_cross_check"].get("available") and gate.get("load_watts_mean"):
        lw = gate["lhm_cross_check"]["watts"]
        if isinstance(lw, (int, float)) and lw:
            gate["lhm_agreement"] = {
                "emi_watts": gate["load_watts_mean"], "lhm_watts": lw,
                "relative_difference_pct":
                    100.0 * abs(gate["load_watts_mean"] - lw) / lw,
                "note": "LHM samples instantaneously; EMI integrates over the run. A gap "
                        "is expected -- this corroborates the order of magnitude only.",
            }
    return gate


def mode_energy(args, shape) -> int:
    gate = _energy_measure(args, shape)
    gate["guard_command"] = shape["guard_command"]
    return emit("energy", gate["resolvable"] or True, gate,
                disclosures=NOISE_DISCLOSURE + [ENERGY_DISCLOSURE], notes=[
        "Never import pyRAPL: it is installed, advertises this capability, and raises "
        "FileNotFoundError('/sys/devices/system/cpu/present') on Windows.",
        "Never look for /sys/class/powercap under WSL -- measured empty three times.",
        "Race-to-idle INVERTS on high-turbo multi-core silicon (Kim & Hoffmann, IEEE "
        "CPSNA 2015), and this is an Intel Core Ultra 7 155H. Faster is a strong signal, "
        "not proof of less energy.",
    ])


def mode_sci(args, shape) -> int:
    gate = _energy_measure(args, shape)
    if not gate["resolvable"]:
        return emit("sci", True, {
            "sci": None,
            "reason": gate["statement"],
            "why": gate.get("why"),
            "energy": gate,
        }, disclosures=NOISE_DISCLOSURE + [ENERGY_DISCLOSURE], notes=[
            "E was not resolvable above the idle floor, so no SCI figure is computed. "
            "Modelling E instead of measuring it is forbidden."])

    duration = float(gate["load_seconds_median"])
    if duration < 1.0:
        return emit("sci", True, {
            "sci": None,
            "reason": f"the workload ran {duration:.3f} s. The Impact Framework's Sci "
                      "plugin validates `duration >= 1` (sci/index.js inputValidation), "
                      "so a sub-second workload cannot be expressed as an SCI figure. "
                      "Give it more work rather than inflating the number.",
            "energy": gate,
        }, disclosures=NOISE_DISCLOSURE + [ENERGY_DISCLOSURE])

    energy_kwh = float(gate["attributed_energy_kwh_median"])
    r_value = float(args.functional_unit_value)
    if r_value <= 0:
        raise Refusal("mode-sci", "--functional-unit-value must be > 0.")
    fu = re.sub(r"[^a-z0-9_-]", "", args.functional_unit.lower()) or "runs"

    aus = aus_intensity()
    runs = {}
    for label, intensity, meta in (
        ("aus", aus["g_per_kwh"], aus),
        ("vic", VIC_INTENSITY, {"g_per_kwh": VIC_INTENSITY, "as_of": VIC_AS_OF,
                                "source": VIC_SOURCE, "region": "Victoria"}),
    ):
        runs[label] = _if_run_sci(energy_kwh, float(intensity), duration, fu, r_value,
                                  label, args.timeout)
        runs[label]["intensity"] = meta

    headline = runs["aus"]
    gap = None
    if headline.get("sci") and runs["vic"].get("sci"):
        gap = 100.0 * (runs["vic"]["sci"] - headline["sci"]) / headline["sci"]

    return emit("sci", True, {
        "sci_gco2e_per_unit": headline.get("sci"),
        "functional_unit": fu,
        "functional_unit_value": r_value,
        "conformance": SCI_NONCONFORMANCE,
        "formula": "SCI = ((E x I) + M) / R, computed by @grnsft/if, not by this tool",
        "E_kwh": energy_kwh,
        "M": 0,
        "duration_s": duration,
        "headline_aus": runs["aus"],
        "sensitivity_vic": runs["vic"],
        "vic_vs_aus_gap_pct": gap,
        "energy": gate,
        "guard_command": shape["guard_command"],
    }, disclosures=NOISE_DISCLOSURE + [ENERGY_DISCLOSURE], notes=[
        f"Every SCI number here is {SCI_NONCONFORMANCE}.",
        "SciEmbodied is deliberately not used: its baseline is a cloud server, not this "
        "laptop.",
        "Operational-only. Marginal and real-time grid intensity are out of scope.",
    ])


def _if_run_sci(energy_kwh: float, intensity: float, duration: float, fu: str,
                r_value: float, label: str, timeout: int) -> dict:
    """Control 5: the manifest is built from VALIDATED FLOATS and one sanitised token."""
    for name, v in (("energy", energy_kwh), ("intensity", intensity),
                    ("duration", duration), ("functional-unit value", r_value)):
        if not isinstance(v, float) or v != v or v in (float("inf"), float("-inf")):
            raise Refusal("control-5-sci", f"{name} is not a finite float: {v!r}")
    # Sci's inputValidation demands carbon >= 0, duration >= 1, and the functional-unit
    # key present with a value >= 0. Assert here so a validation error is never reported
    # as a measurement failure.
    if energy_kwh < 0 or duration < 1 or r_value < 0:
        raise Refusal("control-5-sci",
                      "Sci preconditions not met (energy >= 0, duration >= 1, R >= 0).")

    manifest = (
        "name: perf-probe-sci\n"
        f"description: operational-only SCI, M = 0 ({label})\n"
        "tags: null\n"
        "initialize:\n"
        "  plugins:\n"
        "    multiply-carbon:\n"
        "      method: Multiply\n"
        "      path: builtin\n"
        "      config:\n"
        "        input-parameters:\n"
        "          - energy\n"
        "          - grid/carbon-intensity\n"
        "        output-parameter: carbon\n"
        "    sci:\n"
        "      method: Sci\n"
        "      path: builtin\n"
        "      config:\n"
        f"        functional-unit: {fu}\n"
        "tree:\n"
        "  children:\n"
        "    workload:\n"
        "      pipeline:\n"
        "        compute:\n"
        "          - multiply-carbon\n"
        "          - sci\n"
        "      inputs:\n"
        "        - timestamp: 2000-01-01T00:00:00Z\n"
        f"          duration: {duration!r}\n"
        f"          energy: {energy_kwh!r}\n"
        f"          grid/carbon-intensity: {intensity!r}\n"
        f"          {fu}: {r_value!r}\n"
    )
    man_win = owned_output(f"sci_{label}.yaml")
    man_win.write_text(manifest, encoding="utf-8")
    man_wsl = win_to_wsl(man_win)
    out_stem = f"/tmp/perf_probe_sci_{label}"

    def one_run(stem: str) -> tuple[dict | None, str]:
        r = wsl_run(["bash", "-lc", f"if-run -m {man_wsl} -o {stem}"], timeout=timeout)
        got = wsl_run(["cat", f"{stem}.yaml"], timeout=120)
        text = got.stdout or ""
        if len(text.strip()) < 20:
            return None, f"if-run wrote no output manifest. stderr: {(r.stderr or '')[-300:]}"
        return {"text": text}, ""

    first, err = one_run(out_stem)
    if first is None:
        return {"sci": None, "error": err,
                "fallback": _arithmetic_fallback(energy_kwh, intensity, r_value)}

    text = first["text"]
    # if-run EXITS 0 EVEN ON A HARD VALIDATION ERROR (measured 2026-08-17). The output
    # manifest's `status:` field is the only reliable signal.
    status = "fail" if re.search(r"^\s*status:\s*fail", text, re.M) else (
        "success" if re.search(r"^\s*status:\s*success", text, re.M) else "unknown")
    if status != "success":
        return {"sci": None, "if_status": status,
                "error": "if-run reported a non-success status in its output manifest.",
                "fallback": _arithmetic_fallback(energy_kwh, intensity, r_value)}

    m_sci = re.findall(r"^\s*sci:\s*([0-9.eE+-]+)\s*$", text, re.M)
    m_carbon = re.findall(r"^\s*carbon:\s*([0-9.eE+-]+)\s*$", text, re.M)
    sci_val = float(m_sci[-1]) if m_sci else None
    carbon = float(m_carbon[-1]) if m_carbon else None

    verification = _verify_reproducible(man_wsl, out_stem, text, timeout)

    return {
        "sci": sci_val,
        "carbon_gco2e": carbon,
        "if_status": status,
        "if_version": (re.search(r"if-version:\s*(\S+)", text) or [None, None])[1]
        if re.search(r"if-version:\s*(\S+)", text) else None,
        "verification": verification,
        "manifest": str(man_win),
    }


def _verify_reproducible(man_wsl: str, out_stem: str, first_text: str, timeout: int) -> dict:
    """if-check, and the honest fallback when if-check structurally cannot run.

    MEASURED 2026-08-17: `if-check` shells out to `if-env`, which throws
    MissingManifestDependenciesError when `execution.environment.dependencies` is empty
    (if-env/util/helpers.js:47). A builtins-only manifest -- which ours is, by design --
    ALWAYS has an empty dependency list, so if-check can never verify it. It also exits 0
    on failure, so the exit code proves nothing either way.
    """
    chk = wsl_run(["bash", "-lc", f"if-check -m {out_stem}.yaml"], timeout=timeout)
    blob = (chk.stdout or "") + (chk.stderr or "")
    if re.search(r"\bsuccessfully verified\b|✔", blob, re.I) and "✖" not in blob:
        return {"method": "if-check", "verified": True, "detail": blob.strip()[-300:]}

    unsupported = ("dependencies are not available" in blob
                   or "MissingManifestDependencies" in blob
                   or "could not verify" in blob)

    second = wsl_run(["bash", "-lc", f"if-run -m {man_wsl} -o {out_stem}_v2"],
                     timeout=timeout)
    got = wsl_run(["cat", f"{out_stem}_v2.yaml"], timeout=120)
    second_text = got.stdout or ""
    if len(second_text.strip()) < 20:
        return {"method": "double-run determinism", "verified": False,
                "detail": "the second if-run produced no manifest, so reproducibility is "
                          "UNPROVEN. Do not quote the figure as verified. "
                          f"stderr: {(second.stderr or '')[-200:]}"}

    def computation(t: str) -> str:
        """Everything from `tree:` down -- the inputs and the outputs, i.e. the actual
        computation. The `execution:` block above it is metadata ABOUT the invocation
        (timestamp, the argv, the output stem) and necessarily differs between two runs.

        Filtering that block line-by-line does not work: if-run WRAPS the `command:` value
        across several lines, so the continuation carrying the `-o` stem survives a
        `startswith('command:')` filter and two identical computations compare unequal.
        Measured 2026-08-17 -- the first version of this check reported every SCI figure
        as unverified for exactly that reason.
        """
        lines = t.splitlines()
        for i, ln in enumerate(lines):
            if ln.startswith("tree:"):
                return "\n".join(lines[i:])
        return ""

    a, b = computation(first_text), computation(second_text)
    identical = (a == b) and len(a.strip()) > 20
    return {
        "method": "double-run determinism (if-check unavailable)",
        "verified": identical,
        "if_check_unsupported": unsupported,
        "detail": (
            "if-check cannot verify a builtins-only manifest: it delegates to if-env, "
            "which requires a non-empty execution.environment.dependencies, and if-run "
            "writes [] for builtins. Reproducibility was instead proved by running if-run "
            "twice and comparing the `tree:` section -- the inputs and outputs, i.e. the "
            "computation -- of the two output manifests. "
            + ("They are identical." if identical else
               "THEY DIFFER -- the figure is NOT reproducible and must not be quoted.")),
    }


def _arithmetic_fallback(energy_kwh: float, intensity: float, r_value: float) -> dict:
    carbon = energy_kwh * intensity
    return {"carbon_gco2e": carbon, "sci": carbon / r_value if r_value else None,
            "label": "IF unavailable -- arithmetic fallback, not verified by if-check"}


def mode_prose(args) -> int:
    """Counts only. Never content, never a rewrite. Bytes/words/lines are a PROXY."""
    def count(p: Path) -> dict:
        raw = p.read_bytes()
        try:
            text = raw.decode("utf-8")
            decoded = True
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            decoded = False
        return {"path": str(p), "bytes": len(raw), "words": len(text.split()),
                "lines": text.count("\n") + (0 if text.endswith("\n") or not text else 1),
                "utf8": decoded}

    def resolve(spec: str) -> Path:
        p = Path(spec)
        if not p.is_absolute():
            p = Path.cwd() / p
        p = p.resolve()
        if not p.is_file():
            raise Refusal("mode-prose", f"not a file: {p}")
        return p

    result: dict = {"unit_note": (
        "bytes/words/lines are a PROXY FOR TOKENS and must never be called tokens. No "
        "tokenizer is installed on this host (tiktoken, anthropic, transformers and "
        "tokenizers are all absent, and no ANTHROPIC_API_KEY is set). If `anthropic` plus "
        "a key ever land, upgrade to messages.count_tokens and say which was used.")}

    if args.before or args.after:
        if not (args.before and args.after):
            raise Refusal("mode-prose", "--before and --after must be given together.")
        b, a = count(resolve(args.before)), count(resolve(args.after))
        delta = {k: a[k] - b[k] for k in ("bytes", "words", "lines")}
        pct = {k: (100.0 * delta[k] / b[k] if b[k] else None)
               for k in ("bytes", "words", "lines")}
        result.update({"before": b, "after": a, "delta": delta, "delta_pct": pct})
        result["warning"] = (
            "A shrinking number is NOT evidence the cut was correct. Judge by what "
            "survived: every removed passage must be duplicated elsewhere -- citing the "
            "surviving location -- or demonstrably behaviour-free. A dropped rule is a "
            "Critical finding against the cut. No target percentage is ever set.")
    else:
        if not args.files:
            raise Refusal("mode-prose", "--mode prose needs --files, or --before/--after.")
        rows = [count(resolve(f)) for f in args.files]
        result["files"] = rows
        result["total"] = {k: sum(r[k] for r in rows) for k in ("bytes", "words", "lines")}
        result["warning"] = ("Length alone is never a finding. A 96 KB SKILL.md that is "
                             "96 KB of load-bearing rules is correct, and saying so is a "
                             "valid result.")
    return emit("prose", True, result, notes=[
        "This mode is read-only: it counts, it never rewrites.",
        "Raw size fails the honest-metric test -- deleting the file scores perfectly. "
        "Route prose work as artifact-integrity, with qa-harness invariants as the metric "
        "and size reported only beside them.",
    ])


# ---------------------------------------------------------------------------- main

MODES = ("env", "profile", "scalene", "memray", "sample", "bench", "energy", "sci", "prose")
NEEDS_RUN = {"profile", "scalene", "memray", "bench", "energy", "sci"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="perf_probe.py", add_help=True,
        description="Read-only measurement instrument for the SQA suite. "
                    "Emits exactly one JSON object on stdout.")
    p.add_argument("--mode", required=True, choices=MODES)
    p.add_argument("--timeout", type=int, default=300,
                   help="seconds; a timeout returns a structured result, not an error")
    p.add_argument("--reps", type=int, default=3,
                   help="paired idle/load reps for energy/sci (minimum 3)")
    p.add_argument("--idle-seconds", type=float, default=3.0)
    p.add_argument("--processes", type=int, default=5, help="pyperf processes")
    p.add_argument("--values", type=int, default=3, help="pyperf values per process")
    p.add_argument("--pid", type=int, default=None, help="sample mode: attach to this pid")
    p.add_argument("--functional-unit", default="runs")
    p.add_argument("--functional-unit-value", type=float, default=1.0)
    p.add_argument("--files", nargs="+", default=None, help="prose mode: file set")
    p.add_argument("--before", default=None, help="prose mode: baseline file")
    p.add_argument("--after", default=None, help="prose mode: proposed replacement file")
    p.add_argument("--out", default=None,
                   help="optional output path; FORCED under the system temp directory")
    return p


def main(argv: list[str]) -> int:
    own, run_argv = split_run_argv(argv)
    parser = build_parser()
    args = parser.parse_args(own)
    mode = args.mode

    try:
        if args.reps < 3 and mode in ("energy", "sci"):
            raise Refusal("argument", "--reps must be at least 3: the noise floor is "
                                      "defined by run-to-run spread across >=3 reps.")
        validate_out(args.out)
        ensure_work_dir()

        if mode == "env":
            return mode_env(args)
        if mode == "prose":
            return mode_prose(args)

        shape = None
        if run_argv:
            shape = prepare_run(run_argv)
        elif mode in NEEDS_RUN:
            raise Refusal("no-run-command",
                          f"--mode {mode} needs a workload: pass `--run python <target>.py "
                          "[args]`. With no run command the correct report is static-only, "
                          "and saying so. Never invent an invocation.")

        if mode == "profile":
            return mode_profile(args, shape)
        if mode == "scalene":
            return mode_scalene(args, shape)
        if mode == "memray":
            return mode_memray(args, shape)
        if mode == "sample":
            return mode_sample(args, shape)
        if mode == "bench":
            return mode_bench(args, shape)
        if mode == "energy":
            return mode_energy(args, shape)
        if mode == "sci":
            return mode_sci(args, shape)
        raise Refusal("argument", f"unhandled mode {mode}")

    except Refusal as r:
        return emit(mode, False, refusal={
            "control": r.control, "reason": r.reason,
            "guard_stderr": r.guard_stderr or None})
    except subprocess.TimeoutExpired as e:
        return emit(mode, True, {"timed_out": True, "detail": str(e),
                                 "finding": "the workload did not finish inside the "
                                            "timeout; that is itself a finding."})
    except Exception as e:  # never let a traceback replace the JSON contract
        return emit(mode, False, refusal={
            "control": "internal-error",
            "reason": f"{type(e).__name__}: {e}",
            "guard_stderr": None})


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
