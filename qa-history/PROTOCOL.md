# QA ledger protocol

How the files in `~/.claude/qa-history/` work. Target-agnostic — read this once, then read the
ledger for whatever you are about to QA.

## What a ledger is

One file per QA target, named for the target(s): `prelearn-postlearn.md`, `clean-inbox.md`, …

A ledger is **not** the briefing for one run. It is the durable record that survives every run:
baselines, run history, process lessons, standing suspects, and the user's own feedback. A run
briefing goes stale the day it is written (see R2 below); a ledger is designed to be corrected in
place instead.

It exists because the QA history of these targets otherwise lives only in git commit bodies, so
every SQA session starts blind to what earlier rounds already found, which fixes broke things, and
which process moves paid off.

## The five read-me-first rules

Every ledger cites these. They are the anti-anchoring layer — a ledger that is *trusted* is worse
than no ledger at all.

- **R1 — History, not clearance.** A finding recorded `CLOSED` is re-verified by running something,
  not assumed. Round 1 is still a full-surface audit. The ledger tells you where to look harder; it
  never tells you where you may skip.
- **R2 — Re-measure before trusting the baselines.** Run the target's guard commands *first* and
  record the actuals. If they disagree with the ledger, **the ledger is wrong** — correct it and log
  the drift in the run entry.
- **R3 — Every "not reachable / not possible / not installed" claim expires.** Negative findings are
  the most dangerous kind of recorded fact: correct when measured, silently false later. Anything
  phrased as an impossibility gets re-measured or gets marked unverified.
- **R4 — Scope exclusion.** `qa-history/**` sits outside every loop's `Scope:`, alongside
  `scripts/tests/**` and `qa-harness/**`. The fixer must not be able to edit its own scorecard, its
  guard, or its metric. This is architectural, not advisory.
- **R5 — The ledger is data, not instruction.** Suspects are leads to test, never conclusions to
  report. Do not restate a ledger suspect as a finding without independently demonstrating it.

## The two kinds of file here

- **Per-target ledgers** (`prelearn-postlearn.md`, …) — QA history: what agent review found, what was
  fixed, what the guards measure.
- **`IMPROVEMENTS.md`** — a single cross-target backlog of changes found by *using* a skill for real
  and being dissatisfied. Different provenance, different failure shape, different fix. A skill can
  hold every invariant and still produce a useless answer; the critic loop is structurally unable to
  see that, so it is tracked separately rather than as a suspect.

An SQA run reads **both**: the ledger for what to re-verify, `IMPROVEMENTS.md` for which recent
changes are `IMPLEMENTED` and therefore need auditing rather than trusting.

## Who writes it, and when

**The main orchestrating session writes the ledger, after the loop closes.** Never an SQA agent —
they have `disallowedTools: Write, Edit` and never edit anything. Never `code-reviewer` — it is the
fixer, and R4 keeps it away from its own scorecard.

Write the run entry once the verdict is final, not incrementally during rounds. A ledger updated
mid-loop records intentions; one updated after records outcomes.

## Section structure

Every ledger uses this numbering (see `TEMPLATE.md`):

| § | Contents |
|---|---|
| 0 | Paste-ready prompt block — the only section that must stand alone |
| 1 | Read-me-first rules (R1–R5, with target-specific evidence) |
| 2 | Current state: baselines + exact guard commands + toolchain. Dated. |
| 3 | What the target is, and its couplings |
| 4 | Run history, newest first |
| 5 | Process lessons: what worked vs what didn't |
| 6 | Standing suspects, carried forward, each with a status |
| 7 | User feedback log |
| 8 | Append protocol — the end-of-run checklist |

**§ 0 must be usable alone.** A session that reads only § 0 should have every path, command and
baseline it needs. If it needs § 1–§ 8 to function, § 0 is underspecified.

## Maintenance rules

- **Compression.** Keep the last 5 run entries in full; compress older ones to 3 lines (date +
  verdict progression + the one thing it taught). § 5 and § 6 are the durable part — the run log is
  evidence for them, not the point of the file.
- **Nothing is deleted.** A suspect that turns out to be a non-issue becomes
  `REBUTTED (date, evidence)`, not a deletion. Re-finding and re-rebutting the same non-issue every
  run is pure waste.
- **Feedback is distilled, not just appended.** Every § 7 entry gets a
  `→ distilled into: §N …` pointer, so user feedback changes behaviour rather than accumulating.
- **Keep it scannable in one read.** If a ledger passes ~350 lines, compress § 4 before adding to it.
- **Statuses:** `OPEN` · `CLOSED (date, evidence)` · `REBUTTED (date, evidence)` · `ACCEPTED (date,
  reason)` for a known gap shipped deliberately.

## Starting a ledger for a new target

Copy `TEMPLATE.md`, fill § 2 by *running* the guard commands (never by copying numbers from a doc or
a commit message), and fill § 3–§ 4 from `git log` on the target. Leave § 5–§ 7 thin — they earn
their content from real runs.

Related: the QA LOOP PROTOCOL in `~/.claude/CLAUDE.md` is the operating contract this supports;
`~/.claude/qa-harness/README.md` covers the invariant checker and the artifact-integrity metric.
