---
name: sqa-loop
description: Run a full software-quality assurance loop on a target — route the goal, dispatch the SQA specialist agents, hand findings to the fixer, verify with a fresh reviewer, and optionally hill-climb a metric inside that envelope. Use when asked to test, QA, verify, validate, review or harden something, e.g. "SQA this", "QA loop on src/", "run an SQA autoresearch loop that ensures security in my API", "make sure this is correct and tight". Not for a quick one-off read of a file.
---

# The SQA loop

Two loops, one envelope. The **critic loop** (`sqa-lead` → specialists → `code-reviewer`) finds
defects by adversarial review. The **metric loop** hill-climbs a number. They are not peers you
alternate between: **the metric loop always runs INSIDE the critic envelope, never the reverse.**
The critic verdict is the completion gate; the number never is.

Every agent starts with **zero context** — restate exact target paths, toolchain and rules in every
delegation. **Division of labour:** SQA agents test and report but never edit; `code-reviewer` is
the only agent that changes anything.

---

## PHASE 0 — ROUTE. Do this first, and print the decision before any work.

1. **Classify the goal:** `security` · `functionality` · `performance` · `artifact-integrity`
   (a prose target's own invariants).
2. **Test whether an honest metric exists.** It qualifies only if it is a shell command that prints
   a number, runs in seconds, is deterministic, and **cannot be satisfied by damaging the target**.
3. **Print one routing line**, e.g. *"functionality goal on `src/parser.py`; metric = mutation score
   over `src/`; guard = the existing pytest suite; running critic loop then metric loop."*
4. **If no honest metric exists, say so and run the critic loop alone.** **Never invent a number to
   satisfy the shape of the request** — a fabricated metric is worse than none, because the loop
   will faithfully optimise it.

| Goal | Shape | Metric |
|---|---|---|
| **functionality** | critic loop, then metric loop on the hardened result | mutation score (`cosmic-ray`) |
| **security** | **triage-then-verify, critic-only. No hill-climbing. Final sign-off is the user's.** | **none — refuse to produce one** |
| **performance** | metric loop primary, strongest guard | measured time/space, min-of-n, before/after |
| **artifact-integrity** | `qa-harness/` invariants + mutants **are** the metric | `mutate.py <dir> --score` |

**Raw file size is NEVER an honest metric** — "cannot be satisfied by damaging the target" is
exactly what a size metric *is* satisfied by, since deleting the file scores perfectly. Prose work
routes to `artifact-integrity`, where the invariant checkers are the metric and `--mode prose`
counts bytes/words/lines **beside** them. Those counts are a **proxy for tokens and are never
called tokens** unless a tokenizer is actually installed. No target percentage is ever set.

**Why security is never a metric loop:** static-analysis false-positive rates run 3–48%
(NIST 2018); hill-climbing a security number rewards *suppressing* findings (suppress-comment,
silenced linter) over fixing exploitability. Each Critical/Warning needs a **proof of
exploitability** before it counts, and each fix is verified by re-running that specific proof. If
no scanner is installed, say so rather than implying a scan happened.

### `sqa-efficiency` is dispatched by DEFAULT, whatever the goal class

The loop always looks at efficiency and never lets it outrank the job it was summoned for. Code
targets get the runtime axis, markdown targets get the prose axis, so a documentation-only diff is
a dispatch, not a skip; skip only a config-only diff, or a few lines with no loop, no I/O, no
allocation and no prose — and put the reason in the coverage matrix.

**Verdict carve-out:** when the goal class is *not* `performance`, an efficiency **Critical** counts
toward the gate (superlinear blowup and unbounded waste are correctness-adjacent) but efficiency
**Warnings are reported and carried, never gating** — a 20% regression must not hold a security or
correctness loop open. When the goal class **is** `performance`, they gate normally. The report
states which mode applied.

**Fix order:** goal-class fixes first, efficiency fixes last, then re-run the goal-class
verification; an efficiency edit that regresses the primary fix is reverted.

**On a `performance` goal that ordering is circular** — the efficiency fix *is* the goal-class fix.
Order it explicitly instead:

1. **Any correctness defect found in the same pass, first.** Correctness outranks measurement
   convenience, even when the correctness fix is the inconvenient one.
2. **Re-capture the baseline.** A correctness fix that changed *what the program computes* has
   invalidated the old baseline. This step is the whole point of the rule.
3. **Then the efficiency fix, measured against the NEW baseline.**

Skipping step 2 compares a corrected computation against the original's timing — a *different*
computation reported as a faster one. Same defect class as a silent `float64` → `float32` cut.

---

## The loop

0. **Read the ledger.** If a ledger exists for this target in `~/.claude/qa-history/`, read it plus
   `~/.claude/qa-history/PROTOCOL.md` before routing — it carries baselines, prior findings, process
   lessons and user feedback. It is **history, not clearance**: re-measure its guard numbers this
   session before trusting them, and re-verify anything it records as fixed. No ledger yet? Start
   one from `TEMPLATE.md` at the end of the run.
1. **Route** (PHASE 0) and print the decision.
2. **Snapshot.** Commit on a working branch, and keep a file-copy backup at
   `~/.claude/qa-backups/<timestamp>-<label>/` with per-round staging (`.pre-reviewer`,
   `.post-reviewer`, `.pre-roundN`) — that staging is what makes reverting a single round possible.
   **When `sqa-efficiency` is dispatched with a run command, capture the baseline measurement here,
   BEFORE any fix:** run the target's `perf_probe` invocation once and store the JSON as
   `baseline.json`. Step 5 re-runs the **byte-identical argv** and stores `final.json`. Identical
   argv is not a nicety — comparing two different workloads, input sizes or iteration counts *is*
   the reward hack. If the workload had to change, say so and report **no delta**.
   **Do NOT write `baseline.json` with a PowerShell `>` redirect** — it prepends a UTF-8 BOM and
   `json.load` then fails. Capture it from Python, or read it back with `encoding="utf-8-sig"`.
3. **Critic rounds.** `sqa-lead` → show the summary (FYI, **not** a gate) → `code-reviewer` with the
   findings handed over **verbatim** → a **fresh** `sqa-lead` verifies. Cap ~3 rounds. Later passes
   scope to the diffs plus one hop; findings on untouched code are report-body notes, never verdict
   counts.
4. **Metric loop** — only if PHASE 0 found an honest metric, and only once the critic rounds reach
   `Critical=0 | Warning=0`. Bounded 15–25 iterations. A guard command is **mandatory**.
5. **Final critic pass** on the metric loop's cumulative diff. A regression here reverts the loop's
   work — the SQA verdict outranks the number.
6. **Report:** routing decision · final VERDICT · metric before/after as real numbers · changelog ·
   backup path · suggestions applied vs not, each with a reason.
7. **Write the run entry** into the target's ledger per its append protocol. The main session writes
   it, after the verdict is final; never an SQA agent, never `code-reviewer`.

**Stopping:** `(CLEAN)` verdict **and** metric plateau; or the ~3-round / 25-iteration cap; or a
plateau (<2% change over 2 consecutive iterations — gains concentrate in the first 1–2 rounds). On
a cap, **stop and report what is outstanding** rather than grinding.

---

## Anti-gaming — hard architecture, not advice

Agents demonstrably overwrite tests, monkey-patch scorers and delete assertions when a metric is in
the way. So:

- **The fixer gets NO write access to the guard, the tests, the metric script, or the ledger.** They
  sit outside the loop's scope — a fixer that can edit its own scorecard is the same defect as one
  that can edit its own tests. `fixer-scope-guard.ps1` enforces this for `~/.claude/**`; for a
  project-local test suite, state the exclusion in the delegation and check the diff.
- **A guard command is mandatory** — the target's real suite. A guard failure reverts the iteration
  **regardless of the metric**. On a performance goal the guard must assert full correctness.
- **The metric must never be the same command as the guard**, or the loop scores its own homework.
- **Score on held-out checks the fixer never saw.** Patches that pass the repair loop's own tests
  were found *as likely to break functionality as fix it* (Smith et al., FSE 2015).
- **Report what the number does not prove.** 4–39% of mutants are equivalent and unkillable, so part
  of any climb is theatre. Mutation score is necessary, not sufficient — and it beats coverage,
  which correlates weakly with real effectiveness (Inozemtseva & Holmes, ICSE 2014).

---

## Rules

- **No approval gate on fixes at any severity.** Critical, Warning and Suggestion are all
  pre-approved; summaries are FYI. Three exceptions: findings the reviewer can **rebut with
  evidence**; changes to **user-observable behaviour** (output format, CLI/API surface, on-disk
  formats, defaults) — flag those instead of guessing; and **security fixes, which need the user's
  sign-off.**
- **Gate on the VERDICT line**, not prose: loop while Critical/Warning > 0, stop on `(CLEAN)`.
  `[Needs-info]` never counts toward the gate — surface those as open questions. Counts are defects
  **remaining after** that pass, never intake counts.
- **Reuse the fixer, keep the verifier independent.** Continue ONE `code-reviewer` across rounds.
  But **an agent must never certify its own fixes** — the verifying `sqa-lead` is always a different
  instance. Without external feedback, self-correction fails to improve and sometimes degrades
  output (Huang et al., ICLR 2024; CRITIC 2023). Those studies are on reasoning tasks, so for code
  review specifically treat this as **well-motivated, Medium confidence**.
- **Don't add more critics.** A 9-judge panel gave negligible-to-negative lift over its best single
  member because judge errors correlate across models of shared lineage. These five specialists are
  safe from that only because they are **domain-differentiated, not redundant judges of one
  question** — so route by domain and never fan out for its own sake. Fan-out costs ~15× tokens.
  The one deliberate exception is `sqa-efficiency`, admitted precisely *because* it satisfies the
  rule rather than bending it: no other specialist measures time, memory or energy.
- **Converge, don't restart.** Round 1 is the full-surface audit; later passes verify diffs + one hop.
- **Fixture diversity + mutation spot-check.** Vary every input dimension the code branches on
  (unicode/dash forms, encodings, locales, path shapes); a single-variant fixture set is a blind
  spot. Compile-check each mutant before believing it was caught.
- **Read agent reports from a file, never out of a PowerShell pipe** (BOM/UTF-16 mangling). Compare
  binary/PDF baselines by **content fingerprint**, never md5 of the container.
- **A survivor in `qa-harness` means the CHECKER is missing an invariant**, not that the target is
  broken. Fix the checker.
- Run only the specialists whose domain the target touches. Cap ~3 full rounds, then report.
- If SQA and the reviewer disagree, **the SQA/correctness verdict wins** — flag the conflict.

---

## Reference

`reference.md` in this skill directory carries the ledger protocol summary, the measurement-mode
table, and the authoring machine's calibration figures — which are **that machine's numbers, not
yours**. Re-measure before quoting any of them.
