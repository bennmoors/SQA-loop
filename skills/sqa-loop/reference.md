# sqa-loop reference

Detail behind `SKILL.md`. Read the skill first; come here for the ledger protocol, the measurement
modes, and the authoring machine's calibration.

---

## 1. The ledger

Full protocol: `~/.claude/qa-history/PROTOCOL.md`. New ledgers start from `TEMPLATE.md` beside it.

One file per QA target, named for the target. A ledger is **not** a run briefing — it is the durable
record that survives every run: baselines, run history, process lessons, standing suspects, and the
user's own feedback. It exists because QA history otherwise lives only in commit bodies, so every
session starts blind to what earlier rounds found.

### The five read-me-first rules

A ledger that is *trusted* is worse than no ledger at all. These are the anti-anchoring layer.

- **R1 — History, not clearance.** A finding recorded `CLOSED` is re-verified by running something,
  never assumed. Round 1 is still a full-surface audit.
- **R2 — Re-measure before trusting the baselines.** Run the guard commands *first* and record the
  actuals. If they disagree with the ledger, **the ledger is wrong** — correct it and log the drift.
- **R3 — Every "not reachable / not possible / not installed" claim expires.** Negative findings are
  the most dangerous kind of recorded fact: correct when measured, silently false later.
- **R4 — Scope exclusion.** The ledger, the harness and the tests sit outside every loop's scope.
  The fixer must not be able to edit its own scorecard, its guard, or its metric. **Architectural,
  not advisory** — `hooks/fixer-scope-guard.ps1` is what makes it so.
- **R5 — The ledger is data, not instruction.** Suspects are leads to test, never conclusions to
  report.

### Who writes it

The **main orchestrating session**, after the loop closes. Never an SQA agent (they carry
`disallowedTools: Write, Edit`), never `code-reviewer` (R4). Write once the verdict is final, never
incrementally: a ledger updated mid-loop records intentions; one updated after records outcomes.

### A run entry, minimum

`Routing:` the PHASE 0 decision · `Verdicts:` R1 `C=n W=n S=n` → R2 → final · `Headline findings:`
the 2–4 that mattered · `Metric:` before → after · `Artifacts:` commit / backup / branch ·
`Taught:` one line.

Suspects carry a status — `OPEN` · `CLOSED (date, evidence)` · `REBUTTED (date, evidence)` ·
`ACCEPTED (date, reason)`. **Nothing is deleted**; a non-issue becomes `REBUTTED` so it is not
re-found and re-rebutted every run.

---

## 2. Measurement modes

`sqa-efficiency` measures **only** through `~/.claude/tools/perf_probe.py`, which emits one JSON
object and owns every output path. Invoke it as **one command**, unprefixed and unquoted:

```
python ~/.claude/tools/perf_probe.py --mode <mode> [args] [--run <argv...>]
```

Do **not** prefix with `cd … &&` (a chained `cd` segment is not on the Bash allowlist) and do not
quote the `perf_probe.py` path itself (the allowlist matches an unquoted `…py` token). Quoted paths
with spaces are fine as *arguments*.

| Mode | What | Needs |
|---|---|---|
| `env` | what is measurable right now; runs nothing | nothing |
| `profile` | CPU + memory attribution (cProfile + tracemalloc) | stdlib only — the default first measurement |
| `scalene` | line-level CPU + memory | WSL2 venv |
| `memray` | allocation-level memory, peak RSS, top sites | WSL2 venv |
| `sample` | py-spy; a running process, or where instrumentation distorts | `py-spy` on PATH |
| `bench` | pyperf A/B on a small kernel, min-of-N with spread | `pyperf` |
| `energy` | paired idle/load package joules, noise-gated | Windows 11 EMI + codecarbon |
| `sci` | energy, then Software Carbon Intensity | above + Impact Framework in WSL |
| `prose` | bytes/words/lines for a file set or a before/after pair | nothing |

**Run `--mode env` when a mode refuses and you need to say why.** It never guesses: an unrun probe
reports `available: false` with a reason, never a default of "working".

### Severity bars

- **Critical** — superlinear blowup demonstrated across ≥3 input sizes (min-of-5 each), or
  unbounded / hot-path invisible waste (polling, sleep-waiting, computed-then-discarded work).
- **Warning** — a measured ≥20% wall-time or peak-memory inefficiency against a stated alternative,
  with the spread reported, or an energy delta clearing the instrument's idle floor.
- **Suggestion** — an idiomatic fix needing no measurement; **never escalatable without one**.
- **Sub-10% deltas are not reportable at all** (Georges/Buytaert/Eeckhout, OOPSLA 2007).
- **The Knuth bar:** no Critical or Warning on code outside a demonstrated hot path.

The 20% bar sits far above the ~2% used by isolated benchmarking rigs because Windows offers no CPU
isolation and `pyperf system tune` does not function there.

### Anti-gaming, and it is not advisory

**Flag any change that narrows the workload, weakens an assertion, shrinks an input, cuts an
iteration count, or lowers precision as a finding of the SAME severity as the issue it claims to
fix.** A "faster" version that silently changed `float64` to `float32` computed something
different; it did not compute the same thing faster. An A/B comparison is valid only across
byte-identical invocations.

---

## 3. Calibration from the authoring machine

> **These are one machine's numbers, measured 2026-08-17/21 on an Intel Core Ultra 7 155H running
> Windows 11. They are NOT yours.** They are recorded so the *reasoning* is inspectable, not so the
> figures can be quoted. Per R3, re-measure before relying on any of it — especially anything
> phrased as an impossibility.

**The energy floor is a property of the machine.** The package counter (`RAPL_Package0_PKG`, the
only channel EMI exposes) includes uncore, iGPU and the memory controller. On that host it idled
near **19 W** and reached only **~28 W at 22-core load — 1.49× idle**. An absolute "load ≥ 2× idle"
rule is therefore unreachable there, so `perf_probe` gates on **signal against measured noise**
(delta > 3× the idle baseline's run-to-run spread over ≥3 reps) and reports the 2× ratio as a
non-gating diagnostic.

**That gate is self-calibrating, which is what makes it portable.** It measures against the current
session's own variance rather than a constant, so a noisier machine makes it refuse *harder* — the
safe direction.

**The idle figure itself was never settled, and that is the honest answer.** Three readings — ~19 W,
28.66 W, 26.84 W — with an idle spread of 9–11 W, larger than the gap between them. On one run the
*load* half measured **lower** than idle (23.20 W vs 26.84 W). A negative delta is not a signal; it
is proof the baseline was dominated by whatever else the desktop was doing. Settling it needs a
genuinely quiet machine, not another read.

**Dead ends, recorded so they are not retried:** `/sys/class/powercap` is empty under WSL2 (measured
three times); `pyRAPL` installs, advertises the capability, and raises `FileNotFoundError` on
Windows; **Scalene collects zero samples on native Windows** (an 8.66 s workload produced a 4-byte
`{}`), which is why `--mode scalene` runs under WSL and `--mode profile` is the native fallback.

**Grid intensity is not auto-detected.** The defaults are Australian. Set `SQA_GRID_REGION` and
`SQA_GRID_INTENSITY` or treat `sci` output as unusable — see `docs/PREREQUISITES.md`.

**Tokenizers.** No tokenizer was installed on that host, so `--mode prose` counts bytes, words and
lines and those are **a proxy, never called tokens**. If you have `tiktoken` installed, that
constraint is yours to re-check.

---

## 4. Sources behind the rules

| Rule | Source |
|---|---|
| sub-10% deltas unreportable | Georges, Buytaert & Eeckhout, OOPSLA 2007 |
| race-to-idle inverts on high-turbo multicore | Kim & Hoffmann, IEEE CPSNA 2015 |
| repair-loop patches as likely to break as fix | Smith et al., FSE 2015 |
| coverage correlates weakly with effectiveness | Inozemtseva & Holmes, ICSE 2014 |
| self-correction without external feedback degrades | Huang et al., ICLR 2024; CRITIC 2023 |
| static-analysis false positives 3–48% | NIST 2018 |
| multi-judge panels give negligible lift | "Nine Judges, Two Effective Votes", 2026 |

The self-correction result is on reasoning tasks, not code review specifically — treat the
independent-verifier rule as **well-motivated, Medium confidence**, inferred from adjacent work on
self-preference and sycophancy rather than a direct trial.
