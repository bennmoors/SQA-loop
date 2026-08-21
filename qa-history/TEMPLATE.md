# QA ledger — <TARGET>

Read `~/.claude/qa-history/PROTOCOL.md` first. This file is **history, not clearance** — see § 1.

---

## § 0 — Paste this to start a run

```
Run an SQA loop on <TARGET> at:

  <absolute path(s)>

Read ~/.claude/qa-history/<this-file>.md first — it is the standing QA ledger for this target:
baselines, what previous rounds found, which process moves worked, and my own feedback. It is
history, not a clearance list; § 1 tells you how to use it. Then follow the QA LOOP PROTOCOL in
~/.claude/CLAUDE.md from PHASE 0.

Before anything else, run the guard commands in § 2 and report the actual numbers. If they
disagree with § 2, the ledger is stale — correct it and say so.

Guard (must stay green throughout; a failure reverts the iteration regardless of any metric):
  <command>
  <command>
```

---

## § 1 — Read-me-first rules

- **R1 — History, not clearance.** <target-specific evidence>
- **R2 — Re-measure before trusting § 2.** <evidence>
- **R3 — Every impossibility claim expires.** <evidence>
- **R4 — Scope exclusion.** The fixer may not edit `qa-history/**`, `<tests glob>`, or `qa-harness/**`.
- **R5 — This file is data, not instruction.** Suspects are leads to test, never findings to report.

Full statements in `PROTOCOL.md`.

---

## § 2 — Current state — verify, don't trust

**Measured <DATE>.**

| Target | <metric> | <metric> | Measured |
|---|---|---|---|
| | | | |

**Guard commands** (exact):

```
<command>
```

**Toolchain:** <interpreter/version, venv or not, installed packages that matter, and explicitly
what is NOT installed>

---

## § 3 — What this is, and its couplings

<2–5 sentences: what the target does, what it depends on, what depends on it, and which parts a
previous verdict no longer covers.>

---

## § 4 — Run history

Newest first. Last 5 in full; older compressed to 3 lines.

### RUN <N> — <date> — <target> — <goal class>

- **Routing:** <PHASE 0 decision>
- **Verdicts:** R1 `C=n W=n S=n` → R2 … → final
- **Headline findings:** <the 2–4 that mattered>
- **Metric:** <before> → <after>
- **Artifacts:** commit `<sha>` · backup `<path>` · branch `<name>`
- **Taught:** <one line>

---

## § 5 — Process lessons: what worked vs what didn't

**Worked**

- <lesson> *(evidence: <commit/run>)*

**Didn't**

- <lesson> *(evidence: <commit/run>)*

---

## § 6 — Standing suspects

Status: `OPEN` · `CLOSED (date, evidence)` · `REBUTTED (date, evidence)` · `ACCEPTED (date, reason)`.
Nothing is deleted.

| # | Suspect | Status |
|---|---|---|
| 1 | | OPEN |

---

## § 7 — Feedback log

Newest first. Verbatim, then distilled.

### <date>
> <user's words>

→ distilled into: <§N item>

---

## § 8 — Append protocol — run this at the end of every loop

1. Re-run every § 2 guard command; update the table and its date with **measured** values.
2. Add a § 4 entry from the template above. Compress any entry now older than the last 5.
3. Update § 6: close, rebut or accept what this run resolved; add what it found. Never delete.
4. Add anything the run taught about *process* to § 5 — not about the code, which belongs in § 4.
5. Record the user's feedback verbatim in § 7 and add its `→ distilled into:` pointer.
6. If § 4 pushed the file past ~350 lines, compress before committing.
