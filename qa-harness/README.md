# qa-harness

Mechanical checks for the SQA suite itself. These turn *"is this correct?"* from a reading exercise
into a number, and they are what `install.ps1 -Verify` runs.

**The harness sits outside every loop's scope.** `fixer-scope-guard.ps1` refuses writes here from
`code-reviewer`, because an optimiser with write access to its own verifier edits the verifier —
observed behaviour in current coding agents, not a hypothetical.

---

## The nine files

| File | Kind | Target |
|---|---|---|
| `agent_invariants.py` | **gate** | agent `.md` definitions |
| `skill_invariants.py` | **gate** | skill directories |
| `mutate.py` | **metric** | either, via a checker |
| `guard_corpus.py` | **gate** | `sqa-guard-bash.ps1` behaviour |
| `scope_corpus.py` | **gate** | `fixer-scope-guard.ps1` behaviour |
| `run_shape_corpus.py` | **gate** | `perf_probe.check_run_shape()` — the `--lang` dispatch |
| `adversarial_probe.py` | *diagnostic only* | `sqa-guard-bash.ps1` |
| `_wiring.py` | helper | shared by both corpora |
| `README.md` | this | — |

Exit-code convention for the gates: **0** = all hold · **1** = at least one failed · **2** = target
unusable. `mutate.py` is the exception — it exits 0 whenever the run completes, because *the score
is the signal, not the exit code*.

---

## Invariant checkers

```
python agent_invariants.py <agents-dir-or-file> [--only PATTERN,...] [--settings PATH]
                           [--self-test] [--json] [--quiet]
python skill_invariants.py <skill-dir> [--json] [--quiet]
```

`agent_invariants.py` runs ~35 per-file assertions plus suite-level ones: frontmatter legality
(delimiters, kebab-case name matching the filename, only legal fields, description budget, legal
`color`/`model`/`permissionMode`/`effort`), tool hygiene (`tools` and `disallowedTools` **disjoint**,
no duplicates, body-referenced tools declared), hook wiring (the command names a script path, **that
path resolves on disk**, and the command contains `$LASTEXITCODE`), no inline secrets, no hardcoded
user path outside a hook command, cross-suite modal consistency, and that every specialist an
orchestrator names exists as a file.

It also enforces five **protocol-drift** rules, each self-scoped by an `applies` predicate:
`needs-info-gate`, `remaining-not-intake`, `no-self-certification`, `equivalent-mutant-bar`,
`ledger-pointer`.

`--only` takes comma-separated filename globs: `--only 'sqa-*.md,code-reviewer.md'`.
`--settings` defaults to `<target>/../settings.json`; it is read with `utf-8-sig` because Claude
Code sometimes writes a BOM. `--self-test` takes no target and validates every drift regex against
labelled positive and negative phrasings.

> **A self-scoped rule that stops applying leaves no trace.** Delete the text a rule keys on and the
> row **vanishes** — not even a SKIP — so the total silently drops by one and the suite still reads
> green. Compare pass counts across a change, not just the failure count.

---

## The metric

```
python mutate.py <target> [--mode skill|agent] [--checker PATH] [--checker-arg ARG]
                          [--score] [--json]
```

Seeds mutants into a temp **copy**, never the live files, and reports how many the checker caught.
`--score` prints one bare number. Checkers default by mode (`skill` → `skill_invariants.py`,
`agent` → `agent_invariants.py`), resolved relative to this directory.

Two rules it enforces so a score cannot be fake:

- **Every mutant is anchor-checked.** If the text it means to change does not occur, the mutant is
  `INVALID` — never silently skipped and never counted as a kill.
- **Every checker run is crash-checked.** `CHECKER-CRASH` is never credited as a kill.

**Reading a survivor: it means the CHECKER is missing an invariant, not that the target is broken.**
Fix the checker. The first run against a real skill scored 60% and exposed four checker gaps.

**What the score does not prove.** 4–39% of mutants are typically equivalent and unkillable, so part
of any score is theatre. Mutants are derived from the target's own text, so **scores are not
comparable across targets**. And these are invariants, not semantics — the harness cannot tell you
the target does the right thing. That is what the critic loop is for.

---

## Behavioural corpora

```
python guard_corpus.py [--guard PATH] [--agent-file PATH] [--only block|allow]
                       [--invocation file|frontmatter|fixed|broken] [--gate] [--score] [--json]
python scope_corpus.py [same flags]
```

Each case is `(id, expectation, command, why-this-case-exists)` and every case reports a **named**
result line. That is a rule paid for elsewhere: a self-written runner that credited any non-zero
exit as a pass once let 47 of 162 checks silently never run.

**Two-sided, and that is not optional.** A one-sided corpus is a metric satisfiable by damaging the
target: score must-block alone and `exit 2` on everything is perfect; score must-allow alone and
`exit 0` always wins. The must-allow half is the more interesting one — a guard that blocks
legitimate review work does not fail loudly, it makes the agent quietly work around it.

`--invocation` selects how the guard is called. **`frontmatter` is the default and is production**:
the wiring is re-read from the live agent file each run. `file` calls the script in isolation
(measures a configuration that does not exist in production), `fixed` is the exit-code-propagating
form, and `broken` is the old inert form, kept so the silent-allow regression stays demonstrable.

Reference scores, 2026-08-24: `guard_corpus` **176/176 (100.0%)** · `scope_corpus` **53/57 (93.0%)**
with four known upstream bypasses — see `docs/GUARDS.md`.

### `_wiring.py`, and the two defects that created it

Both corpora once carried duplicate wiring extraction with identical Critical defects:

- **Arbitrary command execution from document content.** The old regex scraped `^\s*command:\s*(.+)$`
  from the *whole* agent file and handed the capture to `powershell -Command`. An agent `.md` with
  no hooks but a prose line `command: echo hijacked` got that executed once per corpus case — a
  document-driven execution path into the harness that scores the fixer's work, on the one file
  class the fixer is allowed to edit. Now only the frontmatter `hooks:` block is read, and any
  command whose script path does not resolve to a real file is refused.
- **`--guard` silently ignored.** The `frontmatter` invocation never referenced it, so `--guard`
  measured the incumbent regardless. A guard whose entire body was `exit 0` scored **78.7%,
  byte-identical to the real guard's score** — the most convincing possible wrong answer. Now the
  script path is rewritten *inside* the production wiring string.

If you build your own harness, test it the same way: point it at a stub that always exits 0 and
confirm the score collapses.

### `run_shape_corpus.py`

```
python run_shape_corpus.py [--probe <perf_probe.py>] [--quiet|--score|--gate|--json]
```

Two-sided corpus for `perf_probe.check_run_shape()` — 30 cases, must-accept and must-refuse, fed to
the function **directly with no subprocess**, so the whole run is well under a second.

It exists because `perf_probe.py` had **no dedicated test at all**. Its correctness was asserted
only indirectly, through `guard_corpus` reaching it via `reapply_guard` — which tests the *guard*,
not the shape check. That was survivable while `check_run_shape` was one function with one language
in it, and stopped being survivable the moment it became a three-way `--lang` dispatch: a
per-language dispatch is exactly the shape where one branch silently loses a check while every other
branch keeps passing. The `py` branch is the one to watch, because it is supposed to be
byte-for-byte unchanged and a corpus is the only thing that can say so after the next edit.

It covers the two Tier 2 rules the guard cannot see — `ps1`/`sh` targets must resolve inside a temp
sandbox, and inline-code channels (`-Command`, `-EncodedCommand`, `bash -c`, any `sh` interpreter
flag) stay refused — plus the ordinary shape rules for all three languages.

Sanity-check it the same way as the other corpora: point `--probe` at a stub whose
`check_run_shape` accepts everything. Measured 2026-08-24 — real `perf_probe` **30/30 (100.0%)**,
permissive stub **12/30 (40.0%)**, `--score` 100.0 → 33.3, `--gate` PASS → FAIL. A missing or
unimportable target reports UNUSABLE and exits 2 rather than passing vacuously.

**It is not wired into `install.ps1 -Verify`**, which still runs three gates. Adding it is a
one-line change; it was left out because the installer's gate count is user-visible output.

---

## `adversarial_probe.py`

```
python adversarial_probe.py <path-to-guard.ps1>
```

**A diagnostic, not a gate.** No argparse, no `--json`, and it always exits 0 — read its MISSES
block rather than wiring it into CI. 32 cases deliberately *not* in `guard_corpus.py`, aimed at the
allowlist's own assumptions: interpreter payloads defeating literal-string denylists, segment-splitter
and quoting attacks, free-form allowlist arguments, redirect containment, and wrapper words
(`nice`, `timeout`, `sudo`, `/bin/rm`).

---

## Two rules the harness exists to enforce

1. **A checker that does not read the live files proves nothing.** Ten auditor mutants survived a
   predecessor whose every check exercised a hand-transcribed model of the target instead of the
   target.
2. **A mutant that does not apply, and a checker that crashes, both prove nothing.** Hence `INVALID`
   and `CHECKER-CRASH` as first-class statuses rather than silent skips.
