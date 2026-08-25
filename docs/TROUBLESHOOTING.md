# Troubleshooting

---

## The guards

### "I changed a hook and it did nothing"

**An edit to an existing agent's `hooks:` block registers only at SESSION START.** Change the wiring
of an agent that already exists and it is not live in the session you changed it in. Restart Claude
Code before believing any in-session measurement of it.

Narrowed, because the broad version of this rule is wrong: a **brand-new** agent file is picked up
whole, same session, hooks included. Only *edits* to an existing agent lag. Do not use the restart
rule as a reason to assume a newly installed agent is running unguarded.

The corpora are unaffected — they invoke the guard directly, so `install.ps1 -Verify` is accurate
immediately.

### "Is the guard actually firing?"

Ask it directly rather than inferring:

```powershell
python ~/.claude/qa-harness/guard_corpus.py --gate     # exit 0 = every case behaved
python ~/.claude/qa-harness/scope_corpus.py --gate
```

`--invocation frontmatter` is the default, meaning the wiring is read **live from the installed
agent file**. If you want to see the failure mode the `; exit $LASTEXITCODE` suffix prevents, run
`--invocation broken` and watch the score collapse.

### "An SQA agent said the guard blocked python / the instrument is unreachable"

It did not. The Bash guard is an **allowlist**, and two spellings of an otherwise-fine command fail:

- **Do not prefix with `cd … &&`** — a chained `cd` segment is not on the allowlist.
- **Do not quote the `perf_probe.py` path itself** — the allowlist matches an unquoted `…py` token.
  Quoted paths with spaces are fine as *arguments*: `--files "C:/…/My Folder/x.md"` passes.

The correct shape, as one command:

```
python ~/.claude/tools/perf_probe.py --mode profile --run python myscript.py
```

Measured: 11 of 13 spellings pass. An agent that hit the `cd &&` refusal once concluded the
instrument was unreachable. It is not — re-spell within the allowlist.

### "My scanner is refused"

If it is `semgrep`, `gitleaks`, `npm audit`, `pip-audit`, `osv-scanner`, `trufflehog`, `bandit`,
`cppcheck` or `clang-tidy`, the read-only form is allowlisted and should pass. What is deliberately
blocked is that tool's **own mutating flag** — `semgrep --autofix`, `npm audit fix`,
`pip-audit --fix`, `clang-tidy -fix`. Drop the flag.

Anything else genuinely read-only that you need is an allowlist addition, and it belongs in
`hooks/sqa-guard-bash.ps1` **with a paired corpus case** — see
[GUARDS.md § Adding a case](GUARDS.md#adding-a-case).

---

## Verdicts and the loop

### "The verdict line isn't being parsed"

The line must start with the word `VERDICT` and nothing else — no `##`, no bold, no bullet, no
preamble sentence. If an agent is emitting something ahead of it, that is a defect in the agent file
worth reporting, not a parsing problem to work around.

### "The loop won't converge"

Three usual causes:

1. **`[Needs-info]` items are being counted.** They must not be — they belong under Open questions.
   An unreproducible finding in the verdict line keeps the loop open forever.
2. **Intake counts are being reported instead of remaining defects.** A pass that fixes six findings
   and leaves none open reports `(CLEAN)`, not `Critical=6`.
3. **Later rounds are re-auditing untouched code.** Round 1 is the full-surface audit; later passes
   scope to the diffs plus one hop. Findings on untouched code are report-body notes.

### "An efficiency Warning is holding a security loop open"

It should not. On a non-`performance` goal, efficiency Warnings are carried and reported but
excluded from the aggregate `Warning=N`. If they are gating, the lead is not applying the carve-out
— check that you routed the goal class explicitly in PHASE 0.

---

## Measurement

### "`--mode scalene` / `memray` refuses"

They run under WSL. Check `--mode env` first, then:

- Is WSL installed, and is the distro actually named `Ubuntu`? Override with `SQA_WSL_DISTRO`.
- Does `/home/<your-username>/sci-env/bin/python` exist? Override with `SQA_WSL_PYTHON`, or
  `SQA_WSL_USER` if only the username differs.
- Does that venv have every import your target needs? The refusal names the missing modules.

Scalene collects **zero samples** on native Windows — an 8.66 s workload produced a 4-byte `{}`.
The WSL hop is why, not a preference. `--mode profile` is the native fallback and always works.

### "Energy says it is not resolvable"

That is a correct answer, not a failure. The gate tests signal against measured noise: the delta
must exceed 3× the idle baseline's own run-to-run spread. On a busy machine, or one with a
high-floor package counter, small workloads do not clear it.

**Quote the refusal sentence and fall back to the CPU-time proxy. Never invent a number.** If the
load half measures *lower* than idle, that is not a signal — it is proof the baseline was dominated
by something else on the machine.

### "The carbon number looks wrong"

It probably is. `--mode sci` uses **Australian** grid intensity unless you set both
`SQA_GRID_REGION` and `SQA_GRID_INTENSITY`. Region is never auto-detected. Run `--mode env` and read
`host_config.grid_region`.

### "perf_probe says unsupported-python"

It needs 3.10+ (`sys.stdlib_module_names`). Check with `python --version`; if you have several
interpreters, make sure the one on PATH is the new one.

---

## Install

### "install.ps1 refuses on my machine"

If you are on macOS or Linux, that is deliberate and [PORTING.md](PORTING.md) explains what a port
would need. Otherwise check PowerShell ≥ 5.1, Python ≥ 3.10 on PATH, and that `~/.claude/` exists
(Claude Code installed and run at least once).

### "It says 0 of 7 agent files repointed"

That is success, not a failure — the guard paths already matched your home directory. The rewrite is
idempotent by design.

### "Gate 3 fails on a fresh install"

Expected as of 2026-08-24: `scope_corpus` scores 53/57, with four known must-block failures in
`fixer-scope-guard.ps1`'s Bash branch. They are documented upstream bypasses, not an install fault
— read [GUARDS.md § Known gaps](GUARDS.md#known-gaps) before relying on the fixer boundary. Gates 1
and 2 should both be clean; if either is not, that *is* an install problem.

### "I want to undo the install"

```powershell
.\install.ps1 -Uninstall
```

It removes the agents, guards, tools, harness and skill. It deliberately leaves
`~/.claude/qa-history/*.md` (your ledgers) and `~/.claude/settings.json` (your config) alone. Your
pre-install state is also in `~/.claude/qa-backups/<timestamp>-preinstall/`.

---

## Reports

### "An agent wrote a file"

Only `code-reviewer` can. The other six carry `disallowedTools: Write, Edit` *and* the Bash
allowlist. If one did, that is a serious finding — capture the transcript and check
`install.ps1 -Verify`, because it means either the guard is not wired or `disallowedTools` was
edited out.

### "The report came back mangled"

Read agent reports **from a file**, never out of a PowerShell pipe — BOM and UTF-16 mangling. Same
class of trap: do not write `baseline.json` with a PowerShell `>` redirect; it prepends a UTF-8 BOM
and `json.load` then fails with "Unexpected UTF-8 BOM". Write it from Python, or read it back with
`encoding="utf-8-sig"`.

### "A specialist gave a five-domain verdict on its own"

If a report says `lead (direct)` in its coverage rows, `sqa-lead` could not spawn and ran the review
itself. It is required to say so prominently. A five-specialist verdict produced by one agent is the
most misleading output this suite can emit, and it has happened once — treat that report as a
single-agent read, not a suite verdict.
