# Porting off Windows

`install.ps1` refuses on macOS and Linux. This page says exactly what a port would have to satisfy,
so the refusal is a specification rather than a dead end.

## Why it refuses instead of degrading

Three hard dependencies, in descending order of severity:

1. **Both PreToolUse guards are PowerShell.** On a platform without `powershell`, the hook command
   fails to execute. A hook that fails to *run* does not block — the exit-code contract only treats
   `2` as a block, and everything else lets the tool call proceed. So the agents would install,
   load, and run with `sqa-guard-bash.ps1` silently inert: five "read-only" specialists able to run
   anything, and `code-reviewer` on `acceptEdits` with no protected-path boundary.
2. **`perf_probe.py` shells out to `powershell.exe` for every `--run` mode** — it re-applies the
   Bash guard to whatever command it is handed. That call fails closed (good), so every measured
   mode simply refuses.
3. **`win_to_wsl()` requires a drive letter.** On a platform where `Path.drive` is `""`, every
   WSL-backed mode refuses.

Point 1 is the one that makes refusal correct. Points 2 and 3 fail loudly; point 1 fails silently,
and a review suite whose read-only guarantee is decorative is worse than no suite.

## What a port must satisfy

**The corpora are the specification.** Do not reimplement from the prose — reimplement against the
tests that already exist.

### 1. Reimplement the guards

`hooks/sqa-guard-bash.ps1` (305 lines) and `hooks/fixer-scope-guard.ps1` (105 lines). Python is the
natural target: it is already a hard dependency, and `perf_probe.py` could then call the guard with
`sys.executable` instead of `powershell.exe`, collapsing dependency 2 as a side effect.

Required behaviour, all of it load-bearing:

- **Exit 0 = allow, exit 2 = block, stderr carries the reason.** Nothing else blocks.
- **Fail OPEN on a stdin parse error** — a bug in the guard must never wedge a legitimate run.
- **Fail CLOSED on evaluation timeout** — a command that cannot be checked in bounded time is not
  allowed through. The PowerShell original caps regex evaluation at 2 s.
- **Quote-aware segment splitting**, then match each segment **whole** against the allowlist.
- **Strip comments before matching**, and refuse `$(…)` and backticks outright.
- **Redirect containment**: only `/dev/null`, `NUL`, `$null`, or a path with a `temp`/`tmp` segment,
  and a `..` anywhere in the target disqualifies it.
- For the scope guard: match protected **prefixes with an optional trailing separator**, and
  distinguish a path *mentioned* in a command from a path that is the *target of a write*.

### 2. Prove equivalence, do not assert it

```
python qa-harness/guard_corpus.py --guard <your-port> --agent-file <an-agent.md>
python qa-harness/scope_corpus.py --guard <your-port> --agent-file agents/code-reviewer.md
python qa-harness/adversarial_probe.py <your-port>
```

The bar: **the port must score identically to the PowerShell original, case for case** — not merely
"as high". Current reference figures, measured 2026-08-21:

| Corpus | Score | Note |
|---|---|---|
| `guard_corpus` | **107/107 = 100.0%** (block 70/70, allow 37/37) | the bar to match |
| `scope_corpus` | **34/39 = 87.2%** (block 22/27, allow 12/12) | five known upstream bypasses — see [GUARDS.md](GUARDS.md#known-gaps) |

A port that "fixes" the five `scope_corpus` failures is doing two things at once. Land the port at
parity first, then close the gaps as a separate reviewed change, so a regression in either is
attributable.

> **`--guard` was once silently ignored.** The `frontmatter` invocation did not reference it, so
> `--guard` measured the incumbent regardless — a guard whose entire body was `exit 0` scored
> **78.7%, byte-identical to the real guard's score**. It is fixed (`_wiring.py` rewrites the script
> path inside the production wiring string), but sanity-check your harness the same way: point
> `--guard` at a stub that always exits 0 and confirm the score collapses. If it does not, you are
> measuring nothing.

### 3. Rewire

Agent frontmatter hook commands are PowerShell-shaped:

```yaml
command: "& '…/sqa-guard-bash.ps1'; exit $LASTEXITCODE"
shell: powershell
```

A POSIX port needs its own shape, and the `; exit $LASTEXITCODE` suffix exists specifically to work
around a PowerShell `-Command` quirk — it is not needed elsewhere. But
`qa-harness/agent_invariants.py` **asserts that substring is present**, so porting means updating
that invariant too, and updating it means deciding what the equivalent guarantee is on the new
platform. Do not simply delete the check: it is what stops the four-week silent-allow regression
from recurring.

`install.ps1` itself would need a `install.sh` sibling, or a rewrite in Python.

### 4. perf_probe

Lower priority — the guards are what make the suite safe; `perf_probe` only makes one specialist
quantitative. `--mode profile` and `--mode prose` are stdlib-only and would work immediately once
the guard call is portable. `--mode energy` and `--mode sci` are Windows-11-specific by construction
(they use the Energy Meter Interface); on Linux the equivalent is `/sys/class/powercap`, which is
**empty under WSL2** but real on bare-metal Linux. `--mode scalene` and `--mode memray` would stop
needing the WSL hop entirely.

## What is already portable

Worth knowing, so a port is not larger than it needs to be:

- **The guards contain no hardcoded username.** They match on `(?i)/\.claude/…` regexes.
- **The energy noise gate is self-calibrating** — it tests signal against the current session's own
  measured variance, not an absolute constant, so it needs no per-machine tuning.
- **`qa-history/PROTOCOL.md` and `TEMPLATE.md` are target-agnostic** and need no changes.
- **The seven agent prompts are platform-neutral** apart from the one hook line each.
- **`agent_invariants.py`, `mutate.py`, `skill_invariants.py`** are pure Python with no Windows
  assumptions.

The port is essentially two files and one invariant.
