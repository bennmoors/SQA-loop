# SQA-loop

A seven-agent software-quality review suite for [Claude Code](https://claude.com/claude-code), plus
the loop that drives it.

Six agents review and never edit. One agent fixes and never grades itself. Two PreToolUse guards
make both of those structurally true rather than merely instructed — which is the whole point, and
the reason this ships as an install script instead of a plugin.

```
                    ┌──────────────┐
   your target ───► │   sqa-lead   │  scopes, routes, merges
                    └──────┬───────┘
                           │ dispatches in parallel, by domain
        ┌──────────┬───────┴───┬────────────┬──────────────┐
        ▼          ▼           ▼            ▼              ▼
   functional   embedded   numerical    security      efficiency
        └──────────┴───────┬───┴────────────┴──────────────┘
                           │ merged, deduplicated, severity-ranked
                    VERDICT: Critical=N | Warning=N | Suggestion=N
                           │
                           ▼
                  ┌─────────────────┐
                  │  code-reviewer  │  the only agent that edits anything
                  └────────┬────────┘
                           │
                  a FRESH sqa-lead verifies — never the one that reviewed before
```

---

## What problem this solves

Asking a model to "review this code" gets you a plausible-sounding list. The failure modes are
well known and this suite is built around them:

- **A reviewer that also fixes will grade its own homework.** So the verifier is always a fresh
  instance, never the one that proposed the fix.
- **An agent with a metric in front of it will edit the metric.** So the fixer has no write access
  to the tests, the guard, the measurement wrapper, or the ledger — enforced by a hook, not a
  request.
- **"Review-and-verify only" is prose until something enforces it.** So the five specialists run
  behind a Bash *allowlist*: read git history, search, read files, run tests. Everything else is
  refused whatever it is called.
- **A number you optimise is a number you will corrupt.** Security work therefore never gets a
  metric loop, and raw file size is never a metric at all — deleting the file would score perfectly.

## The two loops

They are not peers you alternate between. **The metric loop always runs inside the critic
envelope, never the reverse.**

| | Critic loop | Metric loop |
|---|---|---|
| Finds defects by | adversarial review | hill-climbing a number |
| Run by | `sqa-lead` → specialists → `code-reviewer` | an iteration driver against a guard |
| Completion gate | **the VERDICT line** | never the gate, only a signal |
| Bounded by | ~3 rounds | 15–25 iterations, or a <2% plateau |

The critic verdict is what says "done". The number never is.

## The agents

| Agent | Domain | Edits? | Standard |
|---|---|---|---|
| **sqa-lead** | orchestration: scope, route, merge, one verdict | no | — |
| **sqa-functional** | general correctness, test design, coverage gaps | no | ISO/IEC 25010:2023, ISTQB |
| **sqa-security** | web/API/data-leak, PII flows, dependencies | no | OWASP Top 10:2025, ASVS 5.0 |
| **sqa-numerical** | PDE/ODE solvers, scientific computing | no | ASME V&V 20 / Roache |
| **sqa-embedded** | firmware, MCU, PCB, ISR/DMA/timing | no | MISRA-C / CERT-C spirit |
| **sqa-efficiency** | CPU, memory, I/O, energy — and token cost | no | ISO/IEC 25010 perf. efficiency |
| **code-reviewer** | applies fixes, proves them by running something | **yes** | — |

Each emits a first line the loop parses literally:

```
VERDICT: Critical=0 | Warning=0 | Suggestion=2 (CLEAN)
```

Findings carry an evidence label — `[Proven]` (a run demonstrates it), `[High]` (clear from quoted
code), `[Needs-info]` (depends on context the agent could not obtain). **Only `[Proven]` and
`[High]` may be Critical or Warning**, and `[Needs-info]` never counts toward the gate, so an
unreproducible finding cannot hold the loop open forever.

## The guards are the design

Two PreToolUse hooks, declared in each agent's frontmatter:

**`sqa-guard-bash.ps1`** — an *allowlist* on the five specialists' Bash tool. It began as a
denylist and was measured at **19 bypasses across 6 classes** in a single adversarial pass (comment
suffix, newline chain, prefix word, nested shell, interpreter one-liner, here-doc). Patching those
produced a longer denylist and no reason to believe it was complete, because every blocked case had
been the *obvious* spelling of its verb — the score measured the author's imagination, not the
guard. An allowlist inverts the burden: a novel spelling of `rm` fails for the same reason a novel
spelling of anything else does. It is not a read.

Shell and PowerShell review was added in two tiers. **Tier 1** is static analysis — `shellcheck`,
`shfmt`, `bash -n`, PSScriptAnalyzer and InjectionHunter — with write modes refused at *flag* level
rather than binary level. **Tier 2** is code-executing test runners (`bats`, `Invoke-Pester`), which
are constrained by *where* the target is: a disposable copy staged into temp, never the live repo
or the installed `~/.claude`. The detail worth knowing before trusting any of it is in
[docs/GUARDS.md](docs/GUARDS.md) — in particular that `-F` and `-Fi` both bind to PSScriptAnalyzer's
`-Fix`, so denying the literal string does nothing, and that a temp sandbox bounds what the tests
*modify* without sandboxing what the code *can do*.

**`fixer-scope-guard.ps1`** — refuses writes from `code-reviewer` to `qa-harness/`, `qa-history/`,
`qa-backups/`, `agents/`, `hooks/`, `tools/`, `settings.json` and `CLAUDE.md`. A fixer that can edit
its own scorer is the same defect as one that can edit its own tests.

Both are behaviourally tested, two-sided (must-block **and** must-allow), because a one-sided
corpus is satisfiable by damaging the target: score only "blocks dangerous things" and `exit 2` on
everything is a perfect score.

> ### Why there is no plugin
>
> Claude Code deliberately ignores `hooks:`, `permissionMode:` and `mcpServers:` in the frontmatter
> of **plugin-shipped** agents. Everything above lives in exactly that frontmatter. Installed as a
> plugin, this suite would load with both guards silently absent — five "read-only" specialists that
> can run anything, and a fixer running `acceptEdits` with no boundary at all. It would look
> identical to a working install.
>
> So: an install script, which puts the agents at user level where frontmatter hooks are honoured.

## Install

**Windows only.** See [Platform support](#platform-support) — this is a real constraint, not
caution.

```powershell
git clone https://github.com/bennmoors/SQA-loop.git
cd SQA-loop
.\install.ps1
```

It backs up anything it would overwrite to `~/.claude/qa-backups/<timestamp>-preinstall/`, copies
the suite into `~/.claude/`, rewrites the guard path baked into each agent's frontmatter to point at
*your* home directory, and then runs the three mechanical gates against what it just installed.

Then **restart Claude Code**. Agent hook wiring is read at session start, and an unguarded
specialist looks exactly like a guarded one.

```powershell
.\install.ps1 -Verify          # re-run the gates, change nothing
.\install.ps1 -MergeSettings   # also merge the Bash allowlist into settings.json (backs it up)
.\install.ps1 -Uninstall       # remove the suite; never deletes your ledgers or settings
```

Prerequisites, and what breaks without each: **[docs/PREREQUISITES.md](docs/PREREQUISITES.md)**.
The short version is Windows 11, PowerShell 5.1+, Claude Code, Python 3.10+. Everything else is
optional and degrades in a documented way.

## Use it

```
@agent-sqa-lead review src/parser.py
@agent-sqa-security src/api/
@agent-code-reviewer review the current diff
```

For the full loop — routing, rounds, anti-gaming, ledger discipline:

```
/sqa-loop src/parser.py
```

The `/sqa-loop` skill is installed for you. If you would rather have the protocol always-on instead
of invoked, paste [docs/QA-LOOP-PROTOCOL.md](docs/QA-LOOP-PROTOCOL.md) into your `~/.claude/CLAUDE.md`
— it costs about 11 KB of context in every session, which is why the skill is the default.

## Platform support

| | Status |
|---|---|
| Windows 11 + WSL2 + Intel | full capability |
| Windows 11, no WSL | everything except `scalene`, `memray`, `sci` |
| Windows 10, or a VM | above, minus `energy` (needs the Windows 11 Energy Meter Interface) |
| Non-Intel CPU | above; the optional LibreHardwareMonitor cross-check reports unavailable |
| macOS / Linux | **install refuses** |

The refusal is deliberate. Both guards are PowerShell and `perf_probe.py` shells out to
`powershell.exe` for every measured run, so on those platforms the agents would install, load, and
run with their guards silently inert. [docs/PORTING.md](docs/PORTING.md) specifies what a
cross-platform guard would have to satisfy, and how the existing corpora would validate it.

## What this does not do

Stated plainly, because a review suite that oversells itself is worse than none.

- **`fixer-scope-guard.ps1` has four known bypasses.** Its corpus scores **53/57 (93.0%)**, and the
  four failing must-block cases are documented in [docs/GUARDS.md](docs/GUARDS.md#known-gaps): an
  interpreter one-liner writing the guard, `perl -pi`, `git checkout` reverting the ledger, and
  `cd` followed by a relative redirect. The Bash allowlist (`176/176`) does not share them. A
  fifth — a nested shell running `Set-Content` — was closed on 2026-08-24 along with the whole
  PowerShell cmdlet-write class. Know this before you rely on the fixer boundary.
- **Mutation score is necessary, not sufficient.** 4–39% of mutants are equivalent and unkillable,
  so part of any climb is theatre.
- **No security scan happens unless you install a scanner.** `sqa-security` reads and reasons by
  default and says so; it does not imply a scan it did not run.
- **Energy figures need a signal.** The measurement gates on signal against measured noise, so on a
  busy or quiet-but-noisy machine it refuses rather than reporting a number. A refusal is the
  correct answer there.
- **`sci` reports Australian grid intensity unless you set `SQA_GRID_REGION` and
  `SQA_GRID_INTENSITY`.** Region is never auto-detected.

## Repository layout

```
agents/              the seven agent definitions — the suite itself
hooks/               the two PreToolUse guards
tools/perf_probe.py  the only instrument sqa-efficiency is allowed to use
qa-harness/          invariant checkers and two-sided behavioural corpora
qa-history/          ledger protocol (PROTOCOL.md) + a new-ledger template
skills/sqa-loop/     the loop, as an invocable skill
docs/                prerequisites, guards, agents, protocol, porting, troubleshooting
install.ps1          the only supported install path
```

## Credits and licence

Built and hardened over roughly two months of real use, with every rule in these files traceable to
something that actually went wrong. MIT — see [LICENSE](LICENSE).
