#!/usr/bin/env python3
"""mutate.py -- mutation harness for skill artifacts. THIS IS THE METRIC ENTRYPOINT.

Seeds mutants into a COPY of the live skill files, re-runs the real checkers against the
mutated copy, and reports how many mutants were killed. A mutant that survives is a rule no
checker constrains -- i.e. you could delete that rule from the skill and nothing would notice.

    python mutate.py <skill-dir>            # human-readable table
    python mutate.py <skill-dir> --score    # ONE NUMBER (mutation score %) -- use as Metric:
    python mutate.py <skill-dir> --json

Exit 0 always when the run completes (the score is the signal, not the exit code), 2 if the
target is unusable.

TWO LESSONS THIS FILE ENCODES, both paid for with real wrong results:

  1. "the old harness mutated a hand-written Python model ... Ten independent auditor mutants
      -- deleting Hard Rule 1's injection guard, SS 7's bidi strip, the P3 assertion,
      emptying SS 5.3's abort list -- all survived, because nothing read the files."
     So every mutant here edits a real copy of the real files.

  2. Every mutant is ANCHOR-CHECKED (a mutation that does not apply proves nothing) and every
     checker run is CRASH-CHECKED (a checker that dies proves nothing either). A harness that
     silently skips inapplicable mutants inflates its own score.

Mutants are DERIVED FROM THE TARGET'S OWN TEXT rather than hardcoded, so this works on a skill
it has never seen. Each operator is paired with the invariant that should catch it.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover
    pass

HERE = Path(__file__).resolve().parent

# The checker is PLUGGABLE as of 2026-08-10. It used to be a hardcoded module global, which
# meant this harness could only ever score skill artifacts -- and `~/.claude/agents/*.md`, the
# files that drive the whole QA loop, had no mechanical metric at all. `--mode agent` pairs
# the agent invariant checker with agent-shaped operators; `--mode skill` is unchanged, and
# an existing `mutate.py <skill-dir> --score` invocation behaves exactly as before.
DEFAULT_CHECKERS = {
    "skill": HERE / "skill_invariants.py",
    "agent": HERE / "agent_invariants.py",
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def derive_mutants(skill_dir: Path):
    """Build (op, label, relpath, find, replace, expected_catch) from the target's own content.

    `replace == ""` means delete. Every entry must have a `find` that actually occurs, or the
    anchor check will report it as INVALID rather than counting it.
    """
    muts = []
    skill = read(skill_dir / "SKILL.md")
    fm_match = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", skill, re.S)
    fm = fm_match.group(1) if fm_match else ""

    # --- op1: drop a tool from disallowed-tools (should break the removed-tool assertion or
    # the body's own claim about it)
    dis = re.search(r"^disallowed-tools:(.*)$", fm, re.M)
    if dis:
        tools = [t.strip() for t in dis.group(1).split(",") if t.strip()]
        # prefer a tool the body actually talks about -- that is the one with an invariant
        talked = [t for t in tools if t.split("__")[-1] in skill]
        for tool in (talked[:1] or tools[:1]):
            muts.append(("drop-disallowed", f"remove `{tool}` from disallowed-tools",
                         "SKILL.md", f"{tool}, ", "",
                         r"body asserts .* is removed; it is on disallowed-tools"))

    # --- op2: create an allowed/disallowed overlap (should break disjointness)
    allo = re.search(r"^allowed-tools:(.*)$", fm, re.M)
    if allo and dis:
        first_allowed = [t.strip() for t in allo.group(1).split(",") if t.strip()]
        if first_allowed:
            t = first_allowed[0]
            muts.append(("overlap", f"add allowed tool `{t}` to disallowed-tools too",
                         "SKILL.md", "disallowed-tools:", f"disallowed-tools: {t},",
                         r"allowed-tools and disallowed-tools are disjoint"))

    # --- op3: break a local section cross-reference (should break § resolution)
    local_refs = []
    for i, line in enumerate(skill.split("\n")):
        if re.search(r"(?i)playbook|\.md\b|handbook", line):
            continue
        for m in re.finditer(r"§\s*(\d+)\b", line):
            local_refs.append(m.group(0))
    if local_refs:
        ref = local_refs[0]
        muts.append(("dangling-section", f"repoint {ref!r} to a section that does not exist",
                     "SKILL.md", ref, "§ 97",
                     r"every locally cited § section resolves"))

    # --- op4: cite an undefined Hard Rule (should break Hard Rule resolution)
    if re.search(r"Hard Rule\s+\d+", skill):
        muts.append(("dangling-rule", "cite Hard Rule 99, which is not defined",
                     "SKILL.md",
                     re.search(r"Hard Rule\s+\d+", skill).group(0), "Hard Rule 99",
                     r"every cited Hard Rule N is defined"))

    # --- op5: delete a whole Hard Rule body (should break contiguous numbering)
    #
    # DELETE A MIDDLE RULE, NOT THE LAST ONE (corrected 2026-08-11, found the moment attribution
    # started being enforced). Deleting the last of N rules leaves {1..N-1}, which IS contiguous,
    # so the contiguity invariant correctly passes and the mutant was caught -- if at all -- by
    # the *citation* check, only because the deleted rule happened to be cited elsewhere. The
    # operator was credited to an invariant that never fired, and on a skill whose rules are not
    # cross-cited it would have been missed entirely. A middle rule leaves a hole: {1..N} \ {k}.
    rules = re.findall(r"(?m)^(\d+)\.\s+\*\*.+$", skill)
    if len(rules) >= 3:
        mid = rules[len(rules) // 2]
        target = re.search(r"(?m)^%s\.\s+\*\*.+$" % re.escape(mid), skill)
        if target:
            muts.append(("delete-rule", f"delete Hard Rule {mid} (a MIDDLE rule) entirely",
                         "SKILL.md", target.group(0), "",
                         r"Hard Rules are numbered contiguously"))

    # --- op6: hardcode an absolute user path (should break M4)
    if "${CLAUDE_SKILL_DIR}" in skill:
        muts.append(("hardcode-path", "replace ${CLAUDE_SKILL_DIR} with an absolute user path",
                     "SKILL.md", "${CLAUDE_SKILL_DIR}", "C:/Users/example/.claude/skills/x",
                     r"M4 no hardcoded user path"))

    # --- op7: blow the description budget (should break M1)
    desc = re.search(r"^description:(.*)$", fm, re.M)
    if desc:
        muts.append(("budget", "pad description past the 1536-char listing budget",
                     "SKILL.md", "description:", "description: " + ("padding. " * 210),
                     r"M1 description\+when_to_use within \d+ chars"))

    # --- op8: unlink a bundled file (should break the orphan check)
    for name in ("reference.md", "rubric.md"):
        if (skill_dir / name).is_file() and name in skill:
            muts.append(("orphan", f"remove every mention of {name} from SKILL.md",
                         "SKILL.md", [(name, "nothing-here.txt", "all")], "M4 no orphan"))
            break

    # --- op9: strip a state file's data-not-instruction declaration.
    # The checker accepts several wordings, so a mutant that removes only one leaves the file
    # still declaring itself -- a weak mutant that survives for the wrong reason. Emit one
    # mutant per distinct wording present so the whole declaration is genuinely removed.
    state_dir = skill_dir / "state"
    if state_dir.is_dir():
        for sf in sorted(state_dir.glob("*.md")):
            content = read(sf)
            edits = [(ph, "guidance") for ph in
                     ("data, not instruction", "data, never instruction") if ph in content]
            authorises = re.search(r"[Nn]othing in this file authoris\w*", content)
            if authorises:
                edits.append((authorises.group(0), "This file notes"))
            if not edits:
                continue
            # ONE mutant that removes EVERY accepted wording at once. Stripping just one leaves
            # the file still declaring itself, which survives for the wrong reason.
            muts.append(("strip-data-decl",
                         f"strip all {len(edits)} data-not-instruction declaration(s) "
                         f"from {sf.name}",
                         f"state/{sf.name}", edits,
                         r"declares its contents are data, not instruction"))
            break

    # --- op10: duplicate a table anchor (should break append-anchor uniqueness)
    if state_dir.is_dir():
        for sf in sorted(state_dir.glob("*.md")):
            content = read(sf)
            lines = content.split("\n")
            for i in range(len(lines) - 1):
                if lines[i].startswith("|") and re.match(r"^\|[-\s|:]+\|$", lines[i + 1]):
                    pair = f"{lines[i]}\n{lines[i + 1]}"
                    muts.append(("dup-anchor",
                                 f"duplicate a header+separator anchor in {sf.name}",
                                 f"state/{sf.name}", pair, pair + "\n" + pair,
                                 r"header\+separator append anchors are unique"))
                    break
            else:
                continue
            break

    return muts


def derive_agent_mutants(agents_dir: Path, only=()):
    """Agent-file operators, each paired with the invariant in agent_invariants.py that must
    catch it. Derived from the target's own text, exactly like the skill operators.

    An agent .md has none of the structure the skill operators key on (no SKILL.md, no `§ N`,
    no `Hard Rule N`, no kebab-case tool lists, no state/), so `derive_mutants` yields at most
    one valid mutant against this target -- and mutate.py returns 0.0 when `valid` is empty,
    which would read as "nothing is constrained" rather than "the wrong operators were used".
    """
    muts = []
    paths = sorted(p for p in agents_dir.glob("*.md"))
    if only:
        paths = [p for p in paths if any(fnmatch.fnmatch(p.name, pat) for pat in only)]
    if not paths:
        return muts

    def fm_of(text):
        m = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n(.*)$", text, re.S)
        return (m.group(1), m.group(2)) if m else ("", text)

    docs = {p.name: (p, *fm_of(read(p))) for p in paths}

    def first(pred):
        for name, (p, fm, body) in docs.items():
            got = pred(name, fm, body)
            if got:
                return name, fm, body, got
        return None

    # --- A1: repoint a hook script at a file that does not exist.
    hit = first(lambda n, fm, b: re.search(r"([\w.-]+\.ps1)", fm))
    if hit:
        name, _, _, m = hit
        muts.append(("break-hook-path", f"{name}: repoint the hook at a missing script",
                     name, m.group(1), "sqa-guard-bash-MISSING.ps1", "hook script exists"))

    # --- A2: desync the VERDICT template in ONE file. The gate parses this line; a reworded
    # template does not error, it just silently stops matching.
    hit = first(lambda n, fm, b: re.search(r"`(VERDICT: Critical=[^`]*)`", b))
    if hit:
        name, _, _, m = hit
        muts.append(("desync-verdict", f"{name}: reword the VERDICT line template",
                     name, m.group(1), m.group(1).replace("Suggestion=", "Suggestions="),
                     r"VERDICT template matches"))

    # --- A3: give a review-only agent write access and remove its declared scope exclusion.
    # This is the C1 defect in miniature: can write, nothing bounds it but prose.
    hit = first(lambda n, fm, b: re.search(r"^tools:\s*(.+)$", fm, re.M)
                if re.search(r"^disallowedTools:.*\bEdit\b", fm, re.M)
                and "Edit" not in re.search(r"^tools:\s*(.+)$", fm, re.M).group(1) else None)
    if hit:
        name, fm, _, m = hit
        dis_line = re.search(r"^disallowedTools:.*$", fm, re.M).group(0)
        muts.append(("drop-write-scope",
                     f"{name}: grant Edit and delete its disallowedTools line",
                     name,
                     [(m.group(0), m.group(0) + ", Edit"), (dis_line + "\n", "")],
                     r"can write, and declares a scope exclusion"))

    # --- A4: delete the sentence that carries the [Needs-info] gate rule.
    hit = first(lambda n, fm, b: re.search(
        r"[^\n]*\bonly\s*\[Proven\][^\n]*?(?:Critical|Warning)[^\n]*", b, re.I))
    if hit:
        name, _, _, m = hit
        muts.append(("drop-gate-rule", f"{name}: delete the [Needs-info] gate sentence",
                     name, m.group(0), "", r"protocol rule 'needs-info-gate'"))

    # --- A5: rename a legal frontmatter field to one that does not exist.
    hit = first(lambda n, fm, b: re.search(r"^effort:", fm, re.M))
    if hit:
        muts.append(("illegal-field", f"{hit[0]}: rename `effort:` to `reasoningEffort:`",
                     hit[0], "\neffort:", "\nreasoningEffort:",
                     r"every frontmatter field is one of"))

    # --- A6: an illegal display colour.
    hit = first(lambda n, fm, b: re.search(r"^color:\s*(\w+)$", fm, re.M))
    if hit:
        name, _, _, m = hit
        muts.append(("illegal-color", f"{name}: set an illegal colour",
                     name, m.group(0), "color: chartreuse", r"color is one of"))

    # --- A7: put a granted tool on the denylist too. reference.md:38 -- disallowedTools is
    # applied FIRST, so an overlap silently REMOVES the tool the author meant to grant.
    hit = first(lambda n, fm, b: re.search(r"^disallowedTools:.*$", fm, re.M)
                and re.search(r"^tools:\s*([A-Za-z]+)", fm, re.M))
    if hit:
        name, fm, _, m = hit
        dis = re.search(r"^disallowedTools:\s*(.*)$", fm, re.M)
        muts.append(("tool-overlap", f"{name}: put granted `{m.group(1)}` on disallowedTools",
                     name, dis.group(0), f"disallowedTools: {m.group(1)}, {dis.group(1)}",
                     r"tools and disallowedTools are disjoint"))

    # --- A8: revoke a tool the body still instructs the agent to use. A doc that instructs an
    # impossible action is a defect of the same kind as a crashing function.
    hit = first(lambda n, fm, b: re.search(r"`([A-Z][A-Za-z]+)`\s+tool\b", b))
    if hit:
        name, fm, _, m = hit
        tool = m.group(1)
        tline = re.search(r"^tools:\s*(.+)$", fm, re.M)
        if tline and tool in tline.group(1):
            stripped = ", ".join(t.strip() for t in tline.group(1).split(",")
                                 if t.strip() != tool)
            muts.append(("dead-tool-instruction",
                         f"{name}: revoke `{tool}` while the body still instructs its use",
                         name, tline.group(0), f"tools: {stripped}",
                         r"body instructs use of"))

    # --- A9: point an orchestrator's roster at a specialist that does not exist.
    hit = first(lambda n, fm, b: re.search(r"\*\*(sqa-[a-z-]+)\*\*", b)
                if "Agent" in fm else None)
    if hit:
        name, _, _, m = hit
        muts.append(("break-roster", f"{name}: rename a rostered specialist to a missing one",
                     name, m.group(0), "**sqa-nonexistent**",
                     r"every specialist it names exists"))

    # --- A10: desync the evidence vocabulary in one file.
    hit = first(lambda n, fm, b: "[Needs-info]" in b)
    if hit:
        muts.append(("desync-evidence-vocab", f"{hit[0]}: rename [Needs-info] to [Unclear]",
                     hit[0], [("[Needs-info]", "[Unclear]", "all")],
                     r"evidence-label vocabulary matches"))

    # --- A11: break the name/filename correspondence every delegation relies on.
    hit = first(lambda n, fm, b: re.search(r"^name:\s*(\S+)$", fm, re.M)
                if n == "code-reviewer.md" else None)
    if hit:
        name, _, _, m = hit
        muts.append(("name-mismatch", f"{name}: change `name:` away from the filename stem",
                     name, m.group(0), "name: code-review",
                     r"name matches the filename stem"))

    # --- A12: list a tool the harness never grants a subagent (reference.md:71-73).
    hit = first(lambda n, fm, b: re.search(r"^tools:\s*(.+)$", fm, re.M))
    if hit:
        name, _, _, m = hit
        muts.append(("never-granted-tool", f"{name}: list AskUserQuestion in tools",
                     name, m.group(0), m.group(0) + ", AskUserQuestion",
                     r"lists no tool the harness never grants"))

    # --- A13: blow the description budget.
    hit = first(lambda n, fm, b: re.search(r"^description:", fm, re.M))
    if hit:
        muts.append(("desc-budget", f"{hit[0]}: pad description past the listing budget",
                     hit[0], "\ndescription:", "\ndescription: " + ("padding. " * 150),
                     r"description within \d+ chars"))

    # --- A14: point a hook matcher at a tool the agent does not have -- dead wiring that
    # reads as a guarantee.
    hit = first(lambda n, fm, b: re.search(r"^\s*-\s*matcher:\s*Bash\s*$", fm, re.M)
                if not re.search(r"^tools:.*\bEdit\b", fm, re.M) else None)
    if hit:
        name, _, _, m = hit
        muts.append(("dead-hook-matcher", f"{name}: point the hook matcher at a missing tool",
                     name, m.group(0), m.group(0).replace("Bash", "Edit"),
                     r"is a tool this agent has"))

    # --- A16: silently move ONE member of the sqa-* family onto a different model. Findings
    # merged from specialists running different models are not comparable, and nothing else
    # constrains this. (Operator validated independently before being added: it SURVIVES the
    # pre-change checker and is KILLED by the patched one.)
    hit = first(lambda n, fm, b: re.search(r"^model:\s*(\S+)\s*$", fm, re.M)
                if n.startswith("sqa-") else None)
    if hit:
        name, _, _, m = hit
        cur = m.group(1).strip().strip("\"'")
        muts.append(("desync-family-model",
                     f"{name}: move one sqa-* specialist onto a different model",
                     name, m.group(0),
                     "model: " + ("sonnet" if cur != "sonnet" else "opus"),
                     r"model matches the sqa-\* family's"))

    # --- A17: rewrite `tools:` as a legal YAML BLOCK SEQUENCE while granting Edit and deleting
    # the scope exclusion. Semantically identical to A3, spelled differently -- and that spelling
    # is what defeated the checker for a month (suspect 10): the block collapsed to one bogus
    # element, so `{"Edit","Write"} & set(tools)` was empty and the write-scope invariant retired
    # itself with `SKIP -- agent cannot write`. An unbounded fixer scored 20 passed, 0 failed.
    # A3 and A17 differ ONLY in YAML spelling; if one is killed and the other survives, the
    # checker is matching syntax rather than meaning.
    hit = first(lambda n, fm, b: re.search(r"^tools:\s*(.+)$", fm, re.M)
                if re.search(r"^disallowedTools:.*\bEdit\b", fm, re.M) else None)
    if hit:
        name, fm, _, m = hit
        dis_line = re.search(r"^disallowedTools:.*$", fm, re.M).group(0)
        granted = [t.strip() for t in m.group(1).split(",") if t.strip()]
        block = "tools:\n" + "\n".join(f"  - {t}" for t in granted + ["Edit", "Write"])
        muts.append(("block-sequence-write-scope",
                     f"{name}: grant Edit/Write via a block-sequence `tools:` and drop the "
                     "disallowedTools line",
                     name,
                     [(m.group(0), block), (dis_line + "\n", "")],
                     r"can write, and declares a scope exclusion"))

    # --- A18: `tools: *` grants everything, including Edit and Write, without ever spelling
    # them. Same vacuity class as A17: the write-scope check keys on membership, and `*` is a
    # member of nothing.
    hit = first(lambda n, fm, b: re.search(r"^tools:\s*(.+)$", fm, re.M)
                if re.search(r"^disallowedTools:.*\bEdit\b", fm, re.M) else None)
    if hit:
        name, fm, _, m = hit
        dis_line = re.search(r"^disallowedTools:.*$", fm, re.M).group(0)
        muts.append(("wildcard-write-scope",
                     f"{name}: replace `tools:` with `*` and drop the disallowedTools line",
                     name,
                     [(m.group(0), "tools: *"), (dis_line + "\n", "")],
                     r"can write, and declares a scope exclusion"))

    # --- A15: hardcode an absolute user path into the prose body.
    hit = first(lambda n, fm, b: "Output format" in b)
    if hit:
        muts.append(("hardcode-path", f"{hit[0]}: hardcode an absolute user path in the body",
                     hit[0], "Output format",
                     "Output format (template at C:/Users/example/notes/fmt.md)",
                     "no hardcoded user path"))

    return muts


def run_checker(target: Path, checker: Path, extra_args=()):
    """Return (failing_labels, failed_count, crashed, raw).

    WHY THE LABEL SET AND NOT JUST THE COUNT (fixed 2026-08-10, found by this harness's own
    agent-mode run). The kill criterion used to be `failed > baseline_failed`. That is wrong
    whenever a mutant BOTH introduces a failure AND removes a different one -- the total is
    conserved and a genuine kill is recorded as SURVIVED.

    Measured: revoking `Agent` from sqa-lead's tools raised
    "body instructs use of `Agent`; it is granted in tools" and simultaneously retired
    "carries protocol rule 'no-self-certification'", because that rule only applies to an
    agent that HAS the Agent tool. Failures 17 -> 17, and the harness scored it SURVIVED --
    i.e. reported a checker gap that did not exist, and would have sent someone to add an
    invariant that was already there. A conserved count is not an unchanged outcome.
    """
    proc = subprocess.run(
        [sys.executable, str(checker), str(target), "--json", *extra_args],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode == 2:
        return set(), -1, True, (proc.stdout or "") + (proc.stderr or "")
    try:
        payload = json.loads(proc.stdout)
    except (ValueError, TypeError):
        return set(), -1, True, (proc.stdout or "") + (proc.stderr or "")
    if payload.get("status") == "checker_crashed":
        return set(), -1, True, proc.stdout
    labels = {r["label"] for r in payload.get("rows", []) if r.get("ok") is False}
    return labels, int(payload.get("failed", -1)), False, proc.stdout


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("skill_dir", metavar="target",
                    help="a skill directory (--mode skill) or an agents directory (--mode agent)")
    ap.add_argument("--mode", choices=sorted(DEFAULT_CHECKERS), default="skill",
                    help="which artifact family to mutate and which checker to pair with")
    ap.add_argument("--checker", default="",
                    help="override the checker script for this mode")
    ap.add_argument("--checker-arg", action="append", default=[],
                    help="extra argument passed through to the checker, repeatable "
                         "(e.g. --checker-arg --settings --checker-arg C:/…/settings.json)")
    ap.add_argument("--score", action="store_true",
                    help="print ONLY the mutation score as a bare number (for Metric:)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    target_dir = Path(args.skill_dir).resolve()
    checker = Path(args.checker).resolve() if args.checker else DEFAULT_CHECKERS[args.mode]
    extra = list(args.checker_arg)
    if not checker.is_file():
        print("0.0" if args.score else f"UNUSABLE: no checker at {checker}")
        return 2
    if args.mode == "skill" and not (target_dir / "SKILL.md").is_file():
        print("0.0" if args.score else f"UNUSABLE: no SKILL.md under {target_dir}")
        return 2
    if args.mode == "agent" and not any(target_dir.glob("*.md")):
        print("0.0" if args.score else f"UNUSABLE: no agent .md files under {target_dir}")
        return 2

    # Baseline: the live artifact should be clean, or "killed" is ambiguous -- a mutant would
    # be credited for a failure that was already there. A red baseline is handled (scores are
    # relative to it and the run says so) but it is never silently ignored.
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / target_dir.name
        shutil.copytree(target_dir, base,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        baseline_labels, baseline_failed, baseline_crashed, raw = run_checker(
            base, checker, extra)

    if baseline_crashed:
        print("0.0" if args.score
              else f"CHECKER CRASHED ON THE UNMUTATED TARGET:\n{raw[:400]}")
        return 2

    if args.mode == "agent":
        # Mirror whatever --only the checker was given, so the operators never seed a mutant
        # into a file the checker has been told to ignore (that mutant could only ever
        # SURVIVE, and would depress the score for a reason unrelated to coverage).
        only = []
        for i, a in enumerate(extra):
            if a == "--only" and i + 1 < len(extra):
                only = [s.strip() for s in extra[i + 1].split(",") if s.strip()]
            elif a.startswith("--only="):
                only = [s.strip() for s in a.split("=", 1)[1].split(",") if s.strip()]
        seeded = derive_agent_mutants(target_dir, only)
    else:
        seeded = derive_mutants(target_dir)

    # Normalise both mutant shapes to (op, label, rel, [(find, replace), ...], expected).
    mutants = []
    for m in seeded:
        if len(m) == 6:
            op, label, rel, find, replace, expected = m
            mutants.append((op, label, rel, [(find, replace)], expected))
        else:
            op, label, rel, edits, expected = m
            mutants.append((op, label, rel, list(edits), expected))

    rows = []
    for op, label, rel, edits, expected in mutants:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / target_dir.name
            shutil.copytree(target_dir, work,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            target_file = work / rel
            if not target_file.is_file():
                rows.append({"op": op, "label": label, "status": "INVALID",
                             "why": f"{rel} missing", "expected": expected})
                continue
            content = read(target_file)
            # ANCHOR CHECK -- a mutation that does not apply proves nothing. EVERY edit in the
            # mutant must apply, or the mutant is INVALID rather than silently partial.
            missing = [e[0] for e in edits if e[0] not in content]
            if missing:
                rows.append({"op": op, "label": label, "status": "INVALID",
                             "why": f"anchor not found: {missing[0][:48]!r}",
                             "expected": expected})
                continue
            # An edit may be (find, replace) -> first occurrence only, or
            # (find, replace, "all") -> every occurrence. Replacing only the first mention of a
            # linked filename leaves the others in place, so the mutant survives for the wrong
            # reason -- a weak mutant, not a real gap.
            for edit in edits:
                if len(edit) == 3 and edit[2] == "all":
                    content = content.replace(edit[0], edit[1])
                else:
                    content = content.replace(edit[0], edit[1], 1)
            target_file.write_text(content, encoding="utf-8")

            labels, failed, crashed, raw = run_checker(work, checker, extra)
            if crashed:
                # CRASH CHECK -- a checker that dies is not evidence the mutant was caught.
                rows.append({"op": op, "label": label, "status": "CHECKER-CRASH",
                             "why": raw[:160], "expected": expected})
                continue
            # A KILL is a failure that was NOT failing before -- an identity, not a tally.
            fresh = sorted(labels - baseline_labels)
            retired = sorted(baseline_labels - labels)

            # ...AND IT MUST BE THE RIGHT IDENTITY (added 2026-08-11, found while trying to pin
            # the suspect-10 fix). `expected` was recorded on every operator and never checked,
            # so a mutant counted as killed by ANY fresh failure. Measured: a block-sequence
            # `tools:` granting Edit+Write with the scope exclusion deleted was scored KILLED by
            # the PRE-FIX checker -- credited to "body instructs use of `Bash`", an accidental
            # side-effect of the garbage tool list, while the write-scope invariant it exists to
            # test never fired at all. A score built from those kills measures that SOMETHING
            # noticed, not that the named invariant constrains anything -- and it made the one
            # defect the checker was written to catch look covered.
            hit = [lab for lab in fresh if re.search(expected, lab, re.I)] if expected else fresh
            if fresh and hit:
                why = f"new failure: {hit[0]}"
                if retired:
                    # Worth surfacing: the mutant also silenced a check, which is how the old
                    # count-based criterion mis-scored this exact case as SURVIVED.
                    why += f"  (and silenced {len(retired)}: {retired[0]})"
                rows.append({"op": op, "label": label, "status": "KILLED",
                             "why": why, "expected": expected})
            elif fresh:
                rows.append({"op": op, "label": label, "status": "MISATTRIBUTED",
                             "why": f"detected, but NOT by the named invariant -- fresh failures "
                                    f"were {fresh[:2]}", "expected": expected})
            else:
                why = f"no new failure (still {failed})"
                if retired:
                    why += f"; it SILENCED {len(retired)} check(s): {retired[0]}"
                rows.append({"op": op, "label": label, "status": "SURVIVED",
                             "why": why, "expected": expected})

    # MISATTRIBUTED is valid-but-not-killed: the mutant is a real defect the named invariant
    # failed to catch, so it belongs in the denominator. Folding it into KILLED would restore
    # exactly the overstatement this status exists to expose.
    valid = [r for r in rows if r["status"] in ("KILLED", "SURVIVED", "MISATTRIBUTED")]
    killed = [r for r in rows if r["status"] == "KILLED"]
    misattributed = [r for r in rows if r["status"] == "MISATTRIBUTED"]
    score = (100.0 * len(killed) / len(valid)) if valid else 0.0

    if args.score:
        # Bare number on stdout, nothing else. This is what `Verify:` consumes.
        print(f"{score:.1f}")
        return 0

    if args.json:
        print(json.dumps({
            "target": target_dir.name, "mode": args.mode,
            "checker": checker.name, "baseline_failures": baseline_failed,
            "seeded": len(rows), "valid": len(valid), "killed": len(killed),
            "survived": len([r for r in rows if r["status"] == "SURVIVED"]),
            "misattributed": len(misattributed),
            "invalid": len([r for r in rows if r["status"] == "INVALID"]),
            "crashes": len([r for r in rows if r["status"] == "CHECKER-CRASH"]),
            "mutation_score": round(score, 1), "rows": rows,
        }, indent=2))
        return 0

    print(f"Mutation harness — {target_dir.name}  [mode={args.mode}, checker={checker.name}]")
    print(f"  baseline checker failures on the unmutated target: {baseline_failed}")
    if baseline_failed:
        print("  NOTE: baseline is not clean, so scores are relative to that baseline.")
    print()
    for r in rows:
        mark = {"KILLED": "killed  ", "SURVIVED": "SURVIVED", "INVALID": "invalid ",
                "MISATTRIBUTED": "MISATTR ", "CHECKER-CRASH": "CRASH   "}[r["status"]]
        print(f"  {mark}  {r['label']}")
        if r["status"] in ("SURVIVED", "INVALID", "MISATTRIBUTED", "CHECKER-CRASH"):
            print(f"            -> {r['why']}  (expected catch: {r['expected']})")
    print()
    print(f"  seeded {len(rows)} · valid {len(valid)} · killed {len(killed)} · "
          f"survived {len([r for r in rows if r['status'] == 'SURVIVED'])} · "
          f"misattributed {len(misattributed)} · "
          f"invalid {len([r for r in rows if r['status'] == 'INVALID'])}")
    print(f"  MUTATION SCORE: {score:.1f}%")
    if any(r["status"] == "SURVIVED" for r in rows):
        print("  A survivor means no invariant constrains that rule — the checker, not the "
              "skill, is what needs fixing.")
    if misattributed:
        print("  A MISATTRIBUTED mutant was detected by SOME check, but not the one the operator "
              "names — the named invariant is not doing the work the score credits it with.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
