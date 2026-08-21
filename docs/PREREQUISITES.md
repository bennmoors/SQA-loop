# Prerequisites

What to install before running `install.ps1`, and **what actually breaks if you skip each one**.

The suite is built to degrade honestly. A specialist with a missing tool says so in its report
rather than pretending it ran something. So most of this page is optional — but "optional" means
"you lose a named capability", not "it doesn't matter", and each entry says which.

> **Do not read a "not installed" note here as permanent.** The ledger protocol this suite ships
> with (`qa-history/PROTOCOL.md`, rule **R3**) exists because negative findings are the most
> dangerous kind of recorded fact: correct when measured, silently false later. Re-check rather
> than trusting this page.

---

## Tier 0 — required

Without these the installer refuses or the suite cannot function at all.

| What | Check | Install |
|---|---|---|
| **Windows 10/11** | `winver` | — |
| **PowerShell 5.1+** | `$PSVersionTable.PSVersion` | ships with Windows |
| **Claude Code**, run at least once | `~/.claude/` exists | [claude.com/claude-code](https://claude.com/claude-code) |
| **Python 3.10+** on PATH | `python --version` | `winget install Python.Python.3.13` |

**Why Python 3.10 specifically:** `perf_probe.py` uses `sys.stdlib_module_names`, added in 3.10.
Older interpreters now fail with a clear `unsupported-python` refusal instead of a confusing
internal error.

**Why Windows only:** both PreToolUse guards are PowerShell, and `perf_probe.py` shells out to
`powershell.exe` for every measured run. `install.ps1` refuses on macOS and Linux rather than
installing agents whose guards would silently never fire. See [PORTING.md](PORTING.md).

## Tier 1 — strongly recommended

| What | Install | Without it |
|---|---|---|
| **git** | `winget install Git.Git` | Every specialist loses `git status`/`diff`/`log`/`show`, which is the primary review input for a diff target. Nothing errors; the reviews just get worse. |

---

## Tier 2 — per-agent optional tooling

### `sqa-security` — scanners

The agent names these in its own definition and runs whichever it finds. **All are absent by
default.** With none installed, `sqa-security` performs a reading-and-reasoning review and
**explicitly reports that no scan was run** — it never implies coverage it does not have.

| Tool | Install | Covers |
|---|---|---|
| **gitleaks** | `winget install Gitleaks.Gitleaks` | committed secrets, history scanning |
| **pip-audit** | `pip install pip-audit` | Python dependency CVEs |
| **osv-scanner** | `winget install Google.OSVScanner` | multi-ecosystem lockfile CVEs |
| **bandit** | `pip install bandit` | Python security anti-patterns |
| **npm audit** | ships with Node | JS/TS dependency CVEs |
| **semgrep** | see note below | taint/dataflow rules, OWASP rulesets |
| **trufflehog** | see note below | verified secret detection |

> **semgrep on Windows.** semgrep does not support native Windows; upstream directs Windows users
> to WSL. If you have the WSL lane below, install it there (`pip install semgrep` inside WSL) and
> invoke it through WSL. Installing it natively will appear to work and then fail at runtime.

> **trufflehog is not on winget** (checked 2026-08-21). Use `scoop install trufflehog`, a release
> binary from [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog/releases),
> or Docker. If you cannot install it, nothing breaks — gitleaks covers overlapping ground.

**These are allowlisted.** Every tool above has an explicit read-only entry in
`hooks/sqa-guard-bash.ps1`, and each tool's own mutating flag (`semgrep --autofix`,
`npm audit fix`, `pip-audit --fix`) is blocked and has a corpus case proving it. Before
2026-08-21 none of them were allowlisted, so the guard refused the entire documented workflow —
invisible on a machine with no scanners installed, which is exactly the trap R3 warns about.

### `sqa-embedded` — static analyzers

| Tool | Install | Without it |
|---|---|---|
| **cppcheck** | `winget install Cppcheck.Cppcheck` | no automated C/C++ static analysis; review is by reading |
| **clang-tidy** | `winget install LLVM.LLVM` | same, and no clang-tidy check families |

Both are allowlisted read-only; `clang-tidy -fix`, `-fix-errors` and `-fix-notes` are blocked.

### `sqa-efficiency` — measurement

This agent measures **only** through `tools/perf_probe.py`. It never invokes a profiler directly.
Each `--mode` degrades independently, and `--mode env` reports exactly what is available right now.

**Native Windows** (`pip install …`):

| Package | Enables | Without it |
|---|---|---|
| *(stdlib only)* | `--mode profile` — cProfile + tracemalloc | always works; this is the fallback |
| *(stdlib only)* | `--mode prose` — bytes/words/lines | always works |
| **codecarbon** | `--mode energy`, `--mode sci` | no energy measurement; falls back to CPU time |
| **pyperf** | `--mode bench` — A/B min-of-N timing | no defensible small-kernel benchmark |
| **py-spy** | `--mode sample` — attach to a live process | cannot profile an already-running process |

`py-spy` must be **on PATH as an executable** (`pip install py-spy` provides this); the importable
module is not what perf_probe uses.

**The WSL2 lane** — needed only for `scalene`, `memray` and full `sci`:

```powershell
wsl --install -d Ubuntu
```
then inside WSL:
```bash
python3 -m venv ~/sci-env && source ~/sci-env/bin/activate
pip install scalene memray numpy pandas scipy matplotlib
npm install -g @grnsft/if          # provides if-run / if-check, for --mode sci
```

perf_probe expects the venv interpreter at `/home/<your-windows-username>/sci-env/bin/python`.
If yours differs, set the overrides below. **Scalene collects zero samples on native Windows** —
that is why this lane exists rather than being a convenience.

**Environment overrides** (all optional; `--mode env` shows the resolved values and which came
from the environment):

| Variable | Default | Set it when |
|---|---|---|
| `SQA_WSL_DISTRO` | `Ubuntu` | your distro is named differently |
| `SQA_WSL_USER` | your Windows username | your WSL username differs |
| `SQA_WSL_PYTHON` | `/home/<user>/sci-env/bin/python` | your venv is elsewhere |
| `SQA_GRID_REGION` | *(unset)* | **you are not in Australia** — see below |
| `SQA_GRID_INTENSITY` | *(unset)* | as above, in gCO2e/kWh |
| `SQA_LHM_URL` | `http://localhost:8085/data.json` | LibreHardwareMonitor on another port |
| `SQA_LHM_SENSOR_ID` | `/intelcpu/0/power/0` | AMD (`/amdcpu/0/…`) or a second socket |

> ### ⚠ Grid region is never auto-detected
> `--mode sci` computes a carbon figure from a grid-intensity constant, and the defaults are
> **Australian**. Nothing in the code notices you are somewhere else, so an un-overridden `sci` run
> in Berlin or Toronto emits an Australian number, with a real citation, and no indication it is
> the wrong grid. Set both `SQA_GRID_REGION` and `SQA_GRID_INTENSITY`, or treat `sci` output as
> unusable.

**LibreHardwareMonitor** (optional, Intel only) — an independent cross-check on the energy reading.
It must be launched **elevated by hand**; no agent will ever start it. Its absence is reported as
`available: false`, never as a failure.

---

## Tier 3 — the loop's metric

Only needed when a run routes to a metric loop. The critic loop is complete without them.

| What | Install | Used for |
|---|---|---|
| **cosmic-ray** | `pip install cosmic-ray` | mutation score — the metric for a `functionality` goal |
| **autoresearch** skill | separate install | the generic hill-climbing driver |

`qa-harness/mutate.py` (shipped here) is the metric for the `artifact-integrity` goal and needs
nothing beyond Python.

**Security goals never get a metric**, by design. Static-analysis false-positive rates run 3–48%,
and hill-climbing a security number rewards *suppressing* findings over fixing them.

---

## Tier 4 — plugins and addons

None are required. One interacts with this suite and needs configuring if you have it.

### `ponytail` — configure it, or it will corrupt your reports

[ponytail](https://github.com/DietrichGebert) injects a "lazy senior dev" instruction set into
agents. Its output rule — *"code first, then at most three short lines"* — **directly contradicts**
this suite's mandated `VERDICT:` line, evidence labels and coverage matrix, and
`qa-harness/agent_invariants.py` byte-diffs that format. Unscoped, it also costs roughly 5× the
tokens on a full specialist fan-out.

Scope it to the fixer only, in `~/.claude/settings.json`:

```json
{ "env": { "PONYTAIL_SUBAGENT_MATCHER": "^code-reviewer$" } }
```

`code-reviewer` is the one agent that actually writes code, and minimal-diff discipline reinforces
its existing mandate.

> **The matcher fails OPEN.** A bad regex, an unreported `agent_type`, or malformed stdin all
> result in *injection*, not skipping. Verify rather than assuming — pipe a payload straight at the
> hook and confirm you get no output back:
>
> ```bash
> echo '{"agent_type":"sqa-functional"}' | node "$HOME/.claude/plugins/cache/ponytail/ponytail/<version>/hooks/ponytail-subagent.js"
> ```

### Not needed

`last30days`, `watch`, `claude-in-chrome` and the Gmail/Drive connectors have no role here. The
suite uses no MCP servers and no network access of its own.

---

## Verifying what you actually have

```powershell
.\install.ps1 -Verify                      # the three mechanical gates
python ~/.claude/tools/perf_probe.py --mode env
```

`--mode env` runs nothing and reports what is measurable right now — EMI availability, the WSL
lane, which Python packages resolve, LibreHardwareMonitor, the Impact Framework, and the resolved
host configuration including whether any override is in effect. It is the honest answer to "why
did that mode refuse?", and the agents are instructed to run it when they need to explain a
refusal.
