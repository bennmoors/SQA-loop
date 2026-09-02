#!/usr/bin/env python3
"""agent_invariants.py -- mechanical invariant checker for a directory of subagent .md files.

The sibling of `skill_invariants.py`. That one checks a SKILL directory; this one checks
`~/.claude/agents/`, which `skill_invariants.py` cannot read at all (it hard-requires a
`SKILL.md`, reads kebab-case `allowed-tools`/`disallowed-tools`, and keys `name` on the
DIRECTORY name -- none of which an agent file has).

    python agent_invariants.py <agents-dir-or-file> [--only PATTERN,...] [--settings PATH]
                                                    [--json] [--quiet]

Exit 0 = all invariants hold. Exit 1 = at least one FAIL. Exit 2 = target unusable.

THE LESSON THIS FILE INHERITS, quoted from the harness it is modelled on:

    "the previous version of this file contained zero file reads. Every green check exercised
     a hand-transcribed model, so it proved only that the transcription was self-consistent --
     deleting a rule from the skill could not fail it."

So: every check below reads the live files. Delete a clause from an agent and a check must
fail. If you add a check, add a mutant to mutate.py that proves it can fail.

WHY THIS EXISTS AT ALL. The QA LOOP PROTOCOL in ~/.claude/CLAUDE.md declares several rules
"architectural, not advisory", and an audit on 2026-08-10 found that NONE of them were
enforced by anything -- they lived only in whatever the delegation prompt happened to restate
that round. Two examples, both load-bearing:

  * `[Needs-info]` never counting toward the gate is encoded in all four specialists and in
    code-reviewer -- but NOT in sqa-lead, the one file whose VERDICT line the loop gates on.
  * "the fixer gets no write access to the guard, the tests, the metric, or qa-history"
    (PROTOCOL.md R4, verbatim: "This is architectural, not advisory") was enforced by prose
    alone: code-reviewer.md carried no disallowedTools, no hooks, and settings.json had no
    permissions.deny block whatsoever.

A rule nothing can fail is documentation, not architecture. This file is the difference.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover
    pass

# ---------------------------------------------------------------------------- constants

# The 16 legal frontmatter fields, per the Claude Code subagent frontmatter reference.
LEGAL_FIELDS = {
    "name", "description", "tools", "disallowedTools", "model", "permissionMode",
    "maxTurns", "skills", "mcpServers", "hooks", "memory", "background", "effort",
    "isolation", "color", "initialPrompt",
}
LEGAL_COLORS = {"red", "blue", "green", "yellow", "purple", "orange", "pink", "cyan"}
LEGAL_MODEL_ALIASES = {"sonnet", "opus", "haiku", "fable", "inherit"}
LEGAL_PERMISSION_MODES = {"default", "acceptEdits", "auto", "dontAsk", "bypassPermissions",
                          "plan", "manual"}
LEGAL_EFFORT = {"low", "medium", "high", "xhigh", "max"}
LEGAL_MEMORY = {"user", "project", "local"}

# Tools the harness NEVER hands a subagent, whatever the frontmatter says (reference.md:71-73).
# Listing one is dead wiring that reads as a capability the agent does not have.
NEVER_AVAILABLE = {"AskUserQuestion", "EnterPlanMode", "ScheduleWakeup", "WaitForMcpServers"}
# ExitPlanMode is available only under permissionMode: plan, so it is checked conditionally.

# A description is loaded into EVERY session's routing context. Long ones are a standing tax.
DESC_BUDGET = 1024

SECRET_RE = re.compile(
    r"""(?ix)
    (?: api[_-]?key | secret | password | passwd | bearer | private[_-]?key )
    \s* [:=] \s* ['"][A-Za-z0-9_\-/+]{16,}['"]
    | AIza[A-Za-z0-9_\-]{20,}
    | sk-[A-Za-z0-9]{20,}
    | ghp_[A-Za-z0-9]{20,}
    """
)

# An absolute user path. NOTE the `\\\\` alternative, which skill_invariants.py's version does
# NOT have: inside a YAML double-quoted scalar a Windows path is written with DOUBLED
# backslashes ("C:\\Users\\example\\..."), so a `[\\/]` class consumes the first backslash and
# then sees a second backslash where it expected `Users`. Measured 2026-08-10: the hardcoded
# hook path present in all five SQA agents passed skill_invariants' M4 path check by accident
# of YAML escaping. Do not inherit that blind spot.
ABS_PATH_RE = re.compile(
    r"[A-Za-z]:(?:\\\\|[\\/])Users(?:\\\\|[\\/])[A-Za-z0-9_.-]+"
    r"|/home/[A-Za-z0-9_.-]+"
    r"|/Users/[A-Za-z0-9_.-]+"
)

# The canonical verdict line every reviewing agent must emit as its FIRST line. The main
# session parses this; drift in it breaks the loop's gate silently rather than loudly.
VERDICT_SIGNATURE = "VERDICT: Critical="


# ------------------------------------------------------------------- protocol drift table
#
# The mechanised form of the CLAUDE.md-vs-agent-file drift audit. Each entry names a rule the
# QA LOOP PROTOCOL states, the file class that must carry it, and a pattern that must match
# that file's body. `applies` receives (name, body, meta) so a rule can scope itself.
#
# Keep the patterns loose enough to survive rewording and tight enough that deleting the rule
# fails the check. Every entry here needs a matching mutant in mutate.py.

def _emits_verdict(name, body, meta):
    return VERDICT_SIGNATURE in body


def _is_orchestrator(name, body, meta):
    return "Agent" in tool_list(meta.get("tools", "")) and _emits_verdict(name, body, meta)


def _talks_about_mutants(name, body, meta):
    return re.search(r"\bmutants?\b|\bmutation\b", body, re.I) is not None


def _is_sqa_suite(name, body, meta):
    return name.startswith("sqa-") or name == "code-reviewer"


PROTOCOL_RULES = [
    {
        "id": "needs-info-gate",
        "applies": _emits_verdict,
        # The `` `? `` around each label is load-bearing, not tidiness: these files write the
        # labels as `[Proven]` -- backtick, bracket, name, bracket, backtick -- and a pattern
        # that allows the brackets but not the backticks cannot match the very sentence it
        # exists to find. Measured 2026-08-10: sqa-lead was given the rule verbatim and still
        # reported FAIL, i.e. the checker was wrong about a file that was right.
        # `or` was missing from the separator class, so the checker FAILED the most natural
        # English spelling of the rule -- "Only [Proven] or [High]" (suspect 15). Same class as
        # the backtick bug above: a checker that cannot match the phrasing it demands sends
        # someone to "fix" a file that was already correct. Separators now cover / , or and.
        "pattern": re.compile(
            r"(?is)only\s*`?\[?Proven\]?`?\s*(?:[/,]|\bor\b|\band\b)?\s*`?\[?High\]?`?"
            r"[^.]{0,90}(?:Critical|Warning)"
            r"|`?\[?Needs-info\]?`?[^.]{0,120}(?:never counts|never be counted|does not count"
            r"|not counted|may not be|excluded from)[^.]{0,80}"
            r"(?:Critical|Warning|gate|verdict)"),
        "why": "QA LOOP PROTOCOL -- '[Needs-info] never counts toward the gate'. An agent that "
               "emits a VERDICT line without this rule can put an unreproducible finding into "
               "the counts the loop gates on. Encoded in all four specialists and in "
               "code-reviewer; MISSING from sqa-lead, whose template positively offers "
               "[Proven|High|Needs-info] under Critical/Warning (2026-08-10).",
    },
    {
        "id": "remaining-not-intake",
        "applies": _emits_verdict,
        # The first alternative used to be `\bremaining\b … (pass|review|round)`, which matched
        # any sentence containing both words -- "Report the remaining open questions after this
        # review" passed the rule while carrying none of it (suspect 15). The rule is about what
        # the COUNTS mean, so the pattern now requires a counting word near "remaining", or an
        # explicit disavowal of intake counts.
        "pattern": re.compile(
            r"(?is)\b(?:count|counts|defects|findings|number)\b[^.]{0,60}\bremaining\b"
            r"|\bremaining\b[^.]{0,60}\b(?:count|counts|defects|findings)\b"
            r"|\bnever\b[^.]{0,60}\bintake\b"
            r"|\bnot\b[^.]{0,40}\bintake counts\b"),
        "why": "QA LOOP PROTOCOL -- counts are defects REMAINING after the pass, never intake "
               "counts. Origin (a planning note from the loop that surfaced it): restating intake "
               "counts 'read as alarming regressions twice this loop'. Encoded ONLY in "
               "code-reviewer; missing from every sqa-* file including the aggregator.",
    },
    {
        "id": "no-self-certification",
        "applies": _is_orchestrator,
        "pattern": re.compile(
            r"(?is)(?:never|do not|must not|refuse)[^.]{0,110}"
            r"(?:certif\w*|verif\w*|sign off)[^.]{0,110}your own"
            r"|your own[^.]{0,80}(?:fixes|design|proposal|earlier pass|prior pass)"
            r"[^.]{0,80}(?:never|not|refuse|decline)"),
        "why": "QA LOOP PROTOCOL -- 'an agent must never certify its own fixes'. An earlier "
               "ledger records the exact failure: 'the round-3 verifier had proposed the unified "
               "rule, so it could not certify its own design'. Encoded in no agent file.",
    },
    {
        "id": "equivalent-mutant-bar",
        "applies": _talks_about_mutants,
        "pattern": re.compile(
            r"(?is)equivalent[^.]{0,160}mutant|mutant[^.]{0,160}equivalent"
            r"|survivor[^.]{0,160}(?:every read|enumerate)"),
        "why": "An earlier ledger -- 'Three successive readings of one mutant, three "
               "different errors.' An equivalence claim needs the same evidence bar as a "
               "defect claim: enumerate every read of the mutated symbol AND run the whole "
               "suite before characterising a survivor. Any agent that reasons about mutants "
               "must carry the bar.",
    },
    {
        "id": "ledger-pointer",
        "applies": _is_sqa_suite,
        # A bare mention of `qa-history` is not a pointer TO it: "Do not read qa-history; it is
        # stale." satisfied the old pattern while instructing the exact opposite (suspect 15).
        # Require a reading verb near the reference -- and note the gap allows dots, because the
        # real phrasing is a PATH ("~/.claude/qa-history/<target>.md"); a dot-excluding gap was
        # my first fix and it rejected the very sentence the rule is written to find.
        "pattern": re.compile(
            r"(?is)(?:read|consult|check|review|start with|see)\b[^\n]{0,40}?"
            r"(?:qa-history|PROTOCOL\.md)"
            r"|(?:qa-history|PROTOCOL\.md)[^\n]{0,60}\b(?:first|before|must be read)\b"),
        "reject": re.compile(
            r"(?is)(?:do not|don't|never|no need to|skip)\s+(?:read|consult|check)\b[^\n]{0,40}?"
            r"(?:qa-history|PROTOCOL\.md)"),
        "why": "No agent file mentions qa-history, PROTOCOL.md or R1-R5, so every dispatched "
               "specialist starts blind to every prior lesson unless that round's delegation "
               "happens to restate it -- which is why the same lessons keep being re-derived.",
    },
]


# Labelled examples for every PROTOCOL_RULES entry: phrasings that DO carry the rule and
# phrasings that only look like they do. Run with --self-test.
#
# THIS TABLE EXISTS BECAUSE THE SAME DEFECT LANDED TWICE. RUN 1: `needs-info-gate` allowed
# `[Proven]` but not `` `[Proven]` ``, so it failed sqa-lead on the exact sentence it had just
# been given. RUN 2: the same rule still rejected "Only [Proven] or [High]" -- the most natural
# English spelling -- because the separator class had `/` and `,` and `and` but not `or`. Both
# times a correct file was reported as defective, which is the failure mode that erodes trust in
# the whole checker. Negative cases matter just as much: `remaining-not-intake` matched "Report
# the remaining open questions after this review" and `ledger-pointer` matched "Do not read
# qa-history; it is stale." -- a rule that passes on text instructing the OPPOSITE is worse than
# no rule, because it reports coverage that does not exist.
RULE_EXAMPLES = {
    "needs-info-gate": (
        ["Only [Proven] or [High] may be Critical or Warning.",
         "Only [Proven]/[High] may be Critical or Warning.",
         "Only `[Proven]` and `[High]` may be Critical/Warning.",
         "[Needs-info] never counts toward the gate.",
         "A [Needs-info] finding does not count toward Critical or Warning."],
        ["Findings are labelled by evidence quality.",
         "Label each finding [Proven], [High] or [Needs-info]."],
    ),
    "remaining-not-intake": (
        ["Counts are defects remaining after the pass, never intake counts.",
         "Report the number of findings remaining after your fixes.",
         "These are remaining defects, not intake counts."],
        ["Report the remaining open questions after this review.",
         "Surface the remaining questions in the review round."],
    ),
    "no-self-certification": (
        ["You must never certify your own fixes.",
         "Do not verify your own earlier pass."],
        ["Certify each finding with evidence."],
    ),
    "equivalent-mutant-bar": (
        ["An equivalent mutant needs the same evidence bar as a defect claim.",
         "Before calling a survivor equivalent, enumerate every read of the symbol."],
        ["Mutation score is reported as a percentage."],
    ),
    "ledger-pointer": (
        ["Read ~/.claude/qa-history/<target>.md before routing.",
         "Consult qa-history for prior lessons.",
         "Read PROTOCOL.md first.",
         "qa-history/<target>.md must be read first."],
        ["Do not read qa-history; it is stale.",
         "Never read qa-history.",
         "No need to check PROTOCOL.md."],
    ),
}


def self_test() -> int:
    """Assert every PROTOCOL_RULES pattern matches what it claims and nothing that it doesn't."""
    rules = {r["id"]: r for r in PROTOCOL_RULES}
    failures = 0
    for rule_id, (positives, negatives) in RULE_EXAMPLES.items():
        rule = rules.get(rule_id)
        if rule is None:
            print(f"  FAIL  {rule_id}: no such rule in PROTOCOL_RULES")
            failures += 1
            continue
        for text, want in [(t, True) for t in positives] + [(t, False) for t in negatives]:
            got = rule["pattern"].search(text) is not None
            if got and rule.get("reject") and rule["reject"].search(text):
                got = False
            if got != want:
                kind = "MISSED a phrasing that carries the rule" if want else \
                       "MATCHED text that does not carry the rule"
                print(f"  FAIL  {rule_id}: {kind}: {text!r}")
                failures += 1
    missing = sorted({r["id"] for r in PROTOCOL_RULES} - set(RULE_EXAMPLES))
    for rule_id in missing:
        print(f"  FAIL  {rule_id}: has no entry in RULE_EXAMPLES -- every rule must be pinned")
        failures += 1
    total = sum(len(p) + len(n) for p, n in RULE_EXAMPLES.values())
    print(f"self-test: {total - failures}/{total} phrasings correct across "
          f"{len(RULE_EXAMPLES)} rules" + (" — PASS" if not failures else " — FAIL"))
    return 1 if failures else 0


# ---------------------------------------------------------------------------- primitives

class Result:
    def __init__(self):
        self.rows = []

    def check(self, ok: bool, label: str, detail: str = ""):
        self.rows.append({"ok": bool(ok), "label": label, "detail": detail})

    def skip(self, label: str, why: str):
        self.rows.append({"ok": None, "label": label, "detail": f"n/a - {why}"})

    @property
    def failures(self):
        return [r for r in self.rows if r["ok"] is False]

    @property
    def passes(self):
        return [r for r in self.rows if r["ok"] is True]

    @property
    def skips(self):
        return [r for r in self.rows if r["ok"] is None]


def split_frontmatter(text: str):
    """Return (frontmatter_text, body) or (None, text)."""
    match = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n(.*)$", text, re.S)
    return (match.group(1), match.group(2)) if match else (None, text)


def yaml_scalars(fm: str) -> dict:
    """Minimal top-level YAML reader: plain scalars, and nested blocks kept as raw text.

    Hand-rolled on purpose -- pyyaml is not installed here, and a checker must not require a
    dependency the target machine may lack. Nested structures (`hooks:`) come back as their
    raw indented text, which is all the hook checks below need.
    """
    out, key, buf = {}, None, []
    for line in fm.split("\n"):
        m = re.match(r"^([A-Za-z][\w-]*):\s*(.*)$", line)
        if m and not line[:1].isspace():
            if key is not None:
                out[key] = "\n".join(buf).strip()
            key, rest = m.group(1), m.group(2).strip()
            buf = [] if rest in ("|", ">", "|-", ">-", "") else [rest]
        elif key is not None:
            # Keep nested lines VERBATIM (not stripped): indentation is the only thing that
            # distinguishes a nested `hooks:` key from a top-level one when re-reading.
            buf.append(line)
    if key is not None:
        out[key] = "\n".join(buf).strip()
    return out


class UnresolvableTools(list):
    """A `tools:` value this parser could not reduce to tool names.

    Subclasses an EMPTY list on purpose. Every downstream test is either a membership test
    (`"Write" in tools`) or a truthiness test (`not tools`), and for both the fail-safe answer
    is the one an empty list gives: an unresolvable grant must never look like a *narrow* grant.
    `not tools` is the checker's spelling of "unbounded", so an unparseable value routes into
    the write-scope check rather than around it. `.raw` carries the text for the FAIL row.
    """

    def __init__(self, raw):
        super().__init__()
        self.raw = raw


def tool_list(value: str):
    """Parse a `tools:`/`disallowedTools:` value into tool names.

    THREE SPELLINGS ARE LEGAL YAML and all three appear in real agent files; this used to
    understand only the first. Measured 2026-08-11 on a fixture that was exactly the C1 defect
    the write-scope invariant exists to catch -- an agent grantied Edit+Write with no scope
    exclusion at all scored `20 passed, 0 failed` because a block sequence collapsed to one
    bogus element, `{"Edit","Write"} & set(tools)` came back empty, and the invariant retired
    itself with `SKIP -- agent cannot write`. The disjointness, duplicate and never-granted
    checks passed vacuously on the same garbage.

        tools: Read, Edit          -> flow scalar   (the suite's own form)
        tools: [Read, Edit]        -> flow sequence
        tools:\\n  - Read\\n  - Edit -> block sequence  (the one that collapsed)

    Anything else returns UnresolvableTools rather than a plausible-looking list: guessing at a
    grant is how the original defect stayed invisible for a month.
    """
    v = (value or "").strip()
    if not v:
        return []

    if v.startswith("[") and v.endswith("]"):
        return [t for t in (x.strip().strip("'\"") for x in v[1:-1].split(",")) if t]

    lines = [ln.strip() for ln in v.split("\n") if ln.strip()]
    if len(lines) > 1 or (lines and lines[0].startswith("-")):
        if not all(ln.startswith("-") for ln in lines):
            return UnresolvableTools(v)
        return [t for t in (ln.lstrip("-").strip().strip("'\"") for ln in lines) if t]

    return [t for t in (x.strip().strip("'\"") for x in v.split(",")) if t]


def yaml_unescape(value: str) -> str:
    """Undo double-quoted YAML escaping for the one case that matters here: Windows paths."""
    v = value.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1].replace('\\\\', '\\').replace('\\"', '"')
    if len(v) >= 2 and v[0] == "'" and v[-1] == "'":
        return v[1:-1]
    return v


def _modal(pairs):
    """Return (most common key, {key: [who, ...]}) over a list of (key, who) pairs.

    Ties break on the greater `str(key)` so the answer does not depend on dict insertion
    order -- a checker whose PASS/FAIL rows move with the order files were globbed is not a
    contract. Module-level rather than nested so suite checks that run BEFORE the
    verdict-line block can use it too.
    """
    groups = {}
    for key, who in pairs:
        groups.setdefault(key, []).append(who)
    return max(groups, key=lambda k: (len(groups[k]), str(k))), groups


def hook_entries(hooks_block: str):
    """Yield (matcher, command, shell) for every hook command in a raw `hooks:` block."""
    if not hooks_block:
        return
    matcher = None
    for line in hooks_block.split("\n"):
        m = re.search(r"^\s*-?\s*matcher:\s*(.+?)\s*$", line)
        if m:
            matcher = yaml_unescape(m.group(1))
            continue
        c = re.search(r"^\s*-?\s*command:\s*(.+?)\s*$", line)
        if c:
            yield matcher, yaml_unescape(c.group(1)), None


def command_script_path(command: str):
    """Extract the script path a hook command invokes, or None.

    Handles the documented Windows form `& 'C:\\path\\to\\hook.ps1'` and a bare path.
    """
    quoted = re.findall(r"'([^']+)'|\"([^\"]+)\"", command)
    for a, b in quoted:
        cand = a or b
        if re.search(r"\.(ps1|py|sh|cmd|bat|js|mjs|exe)$", cand, re.I):
            return cand
    bare = re.search(r"(\S+\.(?:ps1|py|sh|cmd|bat|js|mjs|exe))\b", command, re.I)
    return bare.group(1) if bare else None


# ------------------------------------------------------------------------ per-file checks

def check_one(res: Result, path: Path, settings: dict | None):
    """Every invariant that is decidable from a single agent file."""
    tag = path.name
    text = path.read_text(encoding="utf-8")
    fm, body = split_frontmatter(text)

    res.check(fm is not None, f"{tag}: frontmatter delimited by --- markers")
    if fm is None:
        return None

    # THE ONE THAT WAS MISSING, added 2026-08-23 after it cost a whole specialist.
    #
    # `sqa-functional.md` sat on disk, readable, with every field this checker looks for, and
    # Claude Code SILENTLY REFUSED TO REGISTER IT -- so `sqa-lead` dispatched three specialists
    # instead of four and reported no error. Cause: an unquoted `description:` scalar containing
    # an embedded ": ", which is a YAML syntax error. `sqa-efficiency.md` had the identical defect
    # and happened to survive the loader, i.e. it was luck, not correctness.
    #
    # Why this checker could not see it: yaml_scalars() below is a LENIENT hand-rolled extractor.
    # It pulls out the fields it wants and never asks whether the document is well-formed, so a
    # file that no real parser accepts still passed every other check here -- including
    # "every specialist sqa-lead names exists as an agent", which reported the agent as present.
    # A checker that reads files cannot see a registry, so it must at least verify the thing the
    # registry will parse.
    try:
        import yaml as _yaml
    except ImportError:
        res.skip(f"{tag}: frontmatter is valid YAML", "PyYAML not installed")
    else:
        try:
            _yaml.safe_load(fm)
            res.check(True, f"{tag}: frontmatter is valid YAML")
        except Exception as exc:
            first = str(exc).strip().splitlines()[0][:120]
            res.check(False, f"{tag}: frontmatter is valid YAML",
                      f"{type(exc).__name__}: {first} -- Claude Code will refuse to load this "
                      f"agent and will NOT report an error. Usually an unquoted value containing "
                      f'": "; quote the scalar.')

    meta = yaml_scalars(fm)

    # ------------------------------------------------------------------ identity
    name = meta.get("name", "")
    res.check(bool(name), f"{tag}: has a name")
    res.check(bool(re.match(r"^[a-z0-9-]{1,64}$", name)),
              f"{tag}: name is lowercase/hyphens, <=64 chars", name)
    # reference.md:35 says the filename need not match `name`. It is a HOUSE convention here,
    # and worth holding: every delegation in the ledgers addresses agents by file stem.
    res.check(name == path.stem, f"{tag}: name matches the filename stem",
              f"name={name!r} stem={path.stem!r}")
    res.check("\t" not in fm, f"{tag}: frontmatter contains no tabs")

    # ------------------------------------------------------------------ field legality
    unknown = sorted(set(meta) - LEGAL_FIELDS)
    res.check(not unknown, f"{tag}: every frontmatter field is one of the 16 legal ones",
              f"unknown={unknown}")

    desc = meta.get("description", "")
    res.check(bool(desc), f"{tag}: description present")
    res.check(len(desc) <= DESC_BUDGET,
              f"{tag}: description within {DESC_BUDGET} chars",
              f"{len(desc)} chars (headroom {DESC_BUDGET - len(desc)})")

    if "color" in meta:
        res.check(meta["color"] in LEGAL_COLORS, f"{tag}: color is one of the 8 legal values",
                  meta["color"])
    if "model" in meta:
        mv = meta["model"]
        res.check(mv in LEGAL_MODEL_ALIASES or bool(re.match(r"^claude-[\w.\[\]-]+$", mv)),
                  f"{tag}: model is a legal alias or a full model id", mv)
    if "permissionMode" in meta:
        res.check(meta["permissionMode"] in LEGAL_PERMISSION_MODES,
                  f"{tag}: permissionMode is legal", meta["permissionMode"])
    if "effort" in meta:
        res.check(meta["effort"] in LEGAL_EFFORT, f"{tag}: effort is legal", meta["effort"])
    if "memory" in meta:
        res.check(meta["memory"] in LEGAL_MEMORY, f"{tag}: memory scope is legal",
                  meta["memory"])
    if "maxTurns" in meta:
        res.check(bool(re.match(r"^\d+$", meta["maxTurns"].strip())),
                  f"{tag}: maxTurns is an integer", meta["maxTurns"])
    if "isolation" in meta:
        res.check(meta["isolation"] == "worktree", f"{tag}: isolation is 'worktree'",
                  meta["isolation"])

    # ------------------------------------------------------------------ tool hygiene
    tools = tool_list(meta.get("tools", ""))
    disallowed = tool_list(meta.get("disallowedTools", ""))
    if tools or disallowed:
        overlap = sorted(set(tools) & set(disallowed))
        # Not merely untidy: reference.md:38 says disallowedTools is applied BEFORE tools, so
        # a tool in both is REMOVED. An overlap silently means the opposite of what it reads as.
        res.check(not overlap, f"{tag}: tools and disallowedTools are disjoint",
                  f"overlap={overlap} (disallowedTools wins -- the tool is removed)")
        res.check(len(tools) == len(set(tools)), f"{tag}: no duplicates in tools")
        res.check(len(disallowed) == len(set(disallowed)),
                  f"{tag}: no duplicates in disallowedTools")

    dead = sorted(set(tools) & NEVER_AVAILABLE)
    if meta.get("permissionMode") != "plan":
        dead += ["ExitPlanMode"] if "ExitPlanMode" in tools else []
    res.check(not dead, f"{tag}: lists no tool the harness never grants a subagent",
              f"never-granted={sorted(dead)} (reference.md:71-73)")

    # A tool the BODY instructs the agent to use must actually be granted. Dead instructions
    # are a defect of the same kind as a crashing function -- one skill's SKILL.md once told an
    # agent to "grant each subagent WebSearch and WebFetch and nothing else", which is not a
    # capability that exists (recorded in that skill's ledger).
    if tools:
        used = set()
        for m in re.finditer(r"`([A-Z][A-Za-z]+)`\s+tool\b", body):
            used.add(m.group(1))
        for m in re.finditer(r"\b(?:with|via|using)\s+(?:the\s+)?"
                             r"((?:`?[A-Z][A-Za-z]+`?)(?:\s*/\s*`?[A-Z][A-Za-z]+`?)*)", body):
            for t in re.findall(r"[A-Z][A-Za-z]+", m.group(1)):
                used.add(t)
        known = {"Read", "Grep", "Glob", "Bash", "Edit", "Write", "Agent", "WebSearch",
                 "WebFetch", "Task", "NotebookEdit", "Skill", "PowerShell", "SendMessage"}
        for t in sorted(used & known):
            res.check(t in tools or t in ("SendMessage",),
                      f"{tag}: body instructs use of `{t}`; it is granted in tools",
                      f"tools={tools}")

    # ------------------------------------------------------------------ hooks wiring
    hooks_raw = meta.get("hooks", "")
    if hooks_raw:
        entries = list(hook_entries(hooks_raw))
        res.check(bool(entries), f"{tag}: hooks block declares at least one command")
        for matcher, command, _ in entries:
            script = command_script_path(command)
            res.check(script is not None,
                      f"{tag}: hook command names a script path", command[:60])
            if script:
                # THE point of this check. Five agents carry the same hardcoded absolute path
                # and nothing has ever verified it resolves. A hook whose script is missing
                # fails open and the guarantee it encodes silently disappears.
                res.check(Path(script).is_file(),
                          f"{tag}: hook script exists on disk", script)
            if matcher:
                # A PreToolUse hook on a tool the agent cannot use is dead wiring. A matcher
                # may be an alternation (`Edit|Write|Bash`) -- every branch must be a tool
                # the agent actually has, or that branch is decoration.
                branches = [b.strip() for b in matcher.split("|") if b.strip()]
                orphan = [b for b in branches if b not in tools and b not in ("*", ".*")]
                res.check(not tools or not orphan,
                          f"{tag}: every branch of hook matcher `{matcher}` is a tool "
                          f"this agent has", f"not granted: {orphan}; tools={tools}")

            # A hook that blocks must propagate exit 2. PowerShell's -Command form does NOT:
            # a script whose entire body is `exit 2` returns 0 through `& 'path'`. Measured
            # 2026-08-10 -- the Bash guard had been inert for four weeks because of it.
            if str(command).lstrip().startswith("&"):
                res.check("$LASTEXITCODE" in command,
                          f"{tag}: hook command propagates the script's exit code",
                          "a `& 'script'` command form swallows `exit 2` and the block "
                          "becomes an allow; append `; exit $LASTEXITCODE`")
    else:
        res.skip(f"{tag}: hooks wiring", "agent declares no hooks")

    # ------------------------------------------------------------------ write-scope policy
    # Any agent that can change files must have its blast radius bounded by something other
    # than the delegation prompt. PROTOCOL.md R4: "This is architectural, not advisory."
    # FAIL, never SKIP, on a tools: this parser could not read. A checker that cannot decide
    # whether an agent can write must say so loudly: the silent SKIP is what hid an unbounded
    # fixer behind `20 passed, 0 failed`.
    for label, value in (("tools", tools), ("disallowedTools", disallowed)):
        if isinstance(value, UnresolvableTools):
            res.check(False, f"{tag}: {label} is parseable",
                      f"could not reduce to tool names: {value.raw[:80]!r} -- write scope is "
                      "therefore UNDECIDABLE, and is being treated as unbounded")

    # `not tools` means the key is absent, which grants everything; `*` grants everything
    # explicitly. Both must route INTO the check, not around it.
    can_write = ((not tools) or ("*" in tools)
                 or bool({"Edit", "Write", "NotebookEdit"} & set(tools)))
    if can_write:
        by_disallowed = bool({"Edit", "Write"} & set(disallowed))
        by_hook = any((matcher or "") in ("Edit", "Write", "*", ".*")
                      or "|" in (matcher or "")
                      for matcher, _, _ in hook_entries(hooks_raw))
        by_settings = False
        if settings:
            deny = (settings.get("permissions") or {}).get("deny") or []
            by_settings = any(re.match(r"^(Edit|Write|NotebookEdit)\s*\(", str(d))
                              for d in deny)
        res.check(by_disallowed or by_hook or by_settings,
                  f"{tag}: can write, and declares a scope exclusion",
                  "no disallowedTools entry, no Edit/Write hook, and settings.json declares "
                  "no permissions.deny for Edit/Write -- the boundary is prose only")
    else:
        res.skip(f"{tag}: write-scope policy", "agent cannot write")

    # ------------------------------------------------------------------ hygiene
    secret = SECRET_RE.search(text)
    res.check(secret is None, f"{tag}: no inline secret",
              "" if secret is None else f"matched {secret.group(0)[:24]!r}")

    # An absolute user path OUTSIDE a hook command is unportable prose. Inside one it is
    # currently unavoidable (there is no ${CLAUDE_AGENT_DIR}), and the existence check above
    # is what makes it safe -- so those occurrences are excluded rather than ignored.
    hook_cmds = " ".join(c for _, c, _ in hook_entries(hooks_raw))
    outside = text
    for _, c, _ in hook_entries(hooks_raw):
        outside = outside.replace(c, " ")
        outside = outside.replace(c.replace("\\", "\\\\"), " ")
    hits = sorted(set(ABS_PATH_RE.findall(outside)) - set(ABS_PATH_RE.findall(hook_cmds)))
    res.check(not hits, f"{tag}: no hardcoded user path outside a hook command", f"{hits[:3]}")

    # ------------------------------------------------------------------ protocol drift
    for rule in PROTOCOL_RULES:
        if not rule["applies"](name, body, meta):
            continue
        # A rule may declare a `reject` pattern: text that LOOKS like the rule but instructs the
        # opposite. Kept separate from `pattern` because "mentions X but not negated" is not
        # expressible as one Python regex (lookbehind must be fixed-width), and the heroic
        # single-regex version of this was itself the suspect-15 defect.
        carried = rule["pattern"].search(body) is not None
        if carried and rule.get("reject") and rule["reject"].search(body):
            carried = False
        res.check(carried, f"{tag}: carries protocol rule '{rule['id']}'", rule["why"])

    return {"path": path, "name": name, "meta": meta, "body": body, "text": text,
            "tools": tools, "disallowed": disallowed}


# ------------------------------------------------------------------------- suite checks

def check_suite(res: Result, files: list, on_disk: set | None = None):
    """Invariants that only exist ACROSS agent files -- the suite-level contract."""

    # ------------------------------------------------------------ model family consistency
    # The four specialists and their lead are dispatched as ONE suite and their reports are
    # merged into ONE verdict. Severity calibration, thoroughness and false-positive rate all
    # move with the model, so a family whose members silently run on DIFFERENT models produces
    # findings that are not comparable -- sqa-lead would be merging reports it has no basis to
    # weigh against each other, and a Warning from one member would not mean what a Warning
    # from the next one means. `model:` is one word of frontmatter, no member can observe
    # another's, and nothing else in this file reads across the family: the drift is invisible
    # at every point where it would change a verdict.
    #
    # ONE ROW PER AGENT, for the reason spelled out at the VERDICT template below: a single
    # suite-wide row is already red once ONE member drifts and can never register a second.
    #
    # Placed BEFORE the `reviewing` early-return deliberately. The family is defined by the
    # `sqa-` name prefix, not by emitting a VERDICT line, so a round that reworded the VERDICT
    # template out of every specialist must not also silently retire this check.
    family = [f for f in files if f["name"].startswith("sqa-")]
    if len(family) < 2:
        res.skip("suite: sqa-* model consistency",
                 f"needs 2+ sqa-* agents in the run, saw {len(family)}")
    else:
        # Compared after YAML unquoting, so `model: "opus"` and `model: opus` are one model
        # and not a spurious FAIL. NOT case-folded: a full model id is case-sensitive, and an
        # off-case alias is already caught by the per-file legality check. An absent `model:`
        # is its own group -- it means "inherit the session's model", which is only comparable
        # with another member that also inherits, never with a member that pins one.
        model_pairs = [(yaml_unescape(f["meta"].get("model", "")) or "<unset>", f["name"])
                       for f in family]
        modal_model, model_groups = _modal(model_pairs)
        for key, who in model_pairs:
            res.check(key == modal_model,
                      f"{who}.md: model matches the sqa-* family's",
                      f"declares {key!r}; {len(model_groups[modal_model])} of "
                      f"{len(model_pairs)} sqa-* agents declare {modal_model!r}")

    reviewing = [f for f in files if VERDICT_SIGNATURE in f["body"]]
    if not reviewing:
        res.skip("suite: verdict-line contract", "no agent emits a VERDICT line")
        return

    # The VERDICT line is the loop's gate. Drift in its shape breaks the gate SILENTLY -- the
    # main session parses the first line, so a reworded template does not error, it just stops
    # matching. Byte-identical or it is not a contract.
    #
    # ONE ROW PER AGENT, not one row for the suite. A single suite-wide row is already red the
    # moment ONE agent drifts, and can then never register a SECOND agent drifting -- so a
    # mutant that desyncs another file survives against an invariant that genuinely exists.
    # Measured 2026-08-10: renaming [Needs-info] in code-reviewer.md survived exactly that way.
    # A check that is already failing must still be able to detect further damage.
    sig_pairs = []
    for f in reviewing:
        m = re.search(r"`(VERDICT: Critical=[^`]*)`", f["body"])
        sig_pairs.append((m.group(1) if m else "<no backticked template>", f["name"]))
    modal_sig, sig_groups = _modal(sig_pairs)
    for key, who in sig_pairs:
        res.check(key == modal_sig,
                  f"{who}.md: VERDICT template matches the suite's",
                  f"has {key!r}; {len(sig_groups[modal_sig])} of {len(sig_pairs)} agents "
                  f"use {modal_sig!r}")

    # Same argument for the evidence vocabulary: the gate rule is phrased in terms of these
    # exact labels, so an agent using a different set cannot be gated correctly.
    vocab_pairs = []
    for f in reviewing:
        labels = tuple(sorted(set(re.findall(r"\[(Proven|High|Needs-info)\]", f["body"]))))
        vocab_pairs.append((labels, f["name"]))
    modal_vocab, vocab_groups = _modal(vocab_pairs)
    for key, who in vocab_pairs:
        res.check(key == modal_vocab,
                  f"{who}.md: evidence-label vocabulary matches the suite's",
                  f"defines {list(key)}; {len(vocab_groups[modal_vocab])} of "
                  f"{len(vocab_pairs)} agents define {list(modal_vocab)}")

    # An orchestrator's roster must resolve. A named specialist that does not exist is a
    # dispatch that silently becomes a no-op or a wrong-agent spawn.
    #
    # `on_disk` is every agent file in the target directory, NOT just the ones this run parsed:
    # resolving against the filtered set made `--only sqa-lead.md` report all four specialists
    # missing (suspect 14).
    by_name = on_disk if on_disk else {f["name"] for f in files}
    orchestrators = [f for f in files if "Agent" in f["tools"]]
    if not orchestrators:
        # Suspect 14: this used to be a silent early return with no row at all, so a run that
        # never checked any roster was indistinguishable from one that checked and passed.
        res.skip("suite: roster resolution", "no agent in this run declares the Agent tool")
    for f in orchestrators:
        roster = set(re.findall(r"\*\*(sqa-[a-z-]+)\*\*", f["body"]))
        if not roster:
            res.skip(f"{f['path'].name}: roster resolution", "no bolded specialist roster")
            continue
        missing = sorted(roster - by_name)
        res.check(not missing, f"{f['path'].name}: every specialist it names exists as an agent",
                  f"missing={missing} known={sorted(by_name)}")


# ------------------------------------------------------------------------------- driver

def run(target: Path, only: list[str] | None, settings_path: Path | None) -> Result:
    res = Result()
    if target.is_file():
        paths = all_paths = [target]
    else:
        all_paths = sorted(p for p in target.glob("*.md") if p.is_file())
        paths = all_paths
    if only:
        paths = [p for p in paths if any(fnmatch.fnmatch(p.name, pat) for pat in only)]
        # SUSPECT 14. A glob that matches nothing used to produce `0 passed, 0 failed` and
        # exit 0 -- a typo in the Guard command reported success while checking nothing at all.
        # This is the loudest failure in the file on purpose: it is indistinguishable from a
        # clean run at a glance, and it sits in the command CLAUDE.md tells people to trust.
        if not paths:
            res.check(False, f"--only {','.join(only)} matches at least one file",
                      f"matched 0 of {len(all_paths)} files in {target} -- this run checked "
                      "NOTHING; a green result here would be meaningless")
            return res

    settings = None
    if settings_path and settings_path.is_file():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            res.check(False, "settings.json parses as JSON", f"{exc.__class__.__name__}: {exc}")

    parsed = []
    for p in paths:
        info = check_one(res, p, settings)
        if info:
            parsed.append(info)
    # Roster resolution must see EVERY agent on disk, not just the filtered subset (suspect 14):
    # `--only sqa-lead.md` used to report all four specialists "missing" because the run had
    # filtered them out. A false FAIL trains people to ignore the row, which is how a true one
    # gets missed.
    check_suite(res, parsed, {p.stem for p in all_paths})
    return res


def main(argv=None) -> int:
    # --self-test takes no target, so it is handled before argparse demands one.
    if argv is None:
        argv = sys.argv[1:]
    if "--self-test" in argv:
        return self_test()

    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="an agents directory, or a single agent .md file")
    ap.add_argument("--self-test", action="store_true",
                    help="check every PROTOCOL_RULES pattern against labelled phrasings that "
                         "do and do not carry the rule; takes no target")
    ap.add_argument("--only", default="",
                    help="comma-separated filename globs to restrict the run, "
                         "e.g. 'sqa-*.md,code-reviewer.md'")
    ap.add_argument("--settings", default="",
                    help="path to settings.json (for the permissions.deny scope check); "
                         "defaults to <target>/../settings.json")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="print only the summary line")
    args = ap.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        msg = f"no such target: {target}"
        print(json.dumps({"status": "unusable", "error": msg}) if args.json
              else f"UNUSABLE: {msg}")
        return 2
    if target.is_dir() and not any(target.glob("*.md")):
        msg = f"no agent .md files under {target}"
        print(json.dumps({"status": "unusable", "error": msg}) if args.json
              else f"UNUSABLE: {msg}")
        return 2

    settings_path = Path(args.settings) if args.settings else (
        (target if target.is_dir() else target.parent).parent / "settings.json")
    only = [s.strip() for s in args.only.split(",") if s.strip()]

    try:
        res = run(target, only, settings_path)
    except Exception as exc:  # a checker that dies proves nothing -- say so loudly
        payload = {"status": "checker_crashed", "error": f"{exc.__class__.__name__}: {exc}"}
        print(json.dumps(payload) if args.json else f"CHECKER CRASHED: {payload['error']}")
        return 2

    if args.json:
        print(json.dumps({
            "status": "ok" if not res.failures else "fail",
            "target": str(target),
            "passed": len(res.passes), "failed": len(res.failures), "skipped": len(res.skips),
            "rows": res.rows,
        }, indent=2))
    else:
        if not args.quiet:
            for r in res.rows:
                mark = "PASS" if r["ok"] else ("SKIP" if r["ok"] is None else "FAIL")
                detail = f"  -- {r['detail']}" if r["detail"] else ""
                print(f"  {mark}  {r['label']}{detail}")
        print(f"{target.name}: {len(res.passes)} passed, {len(res.failures)} failed, "
              f"{len(res.skips)} skipped")
    return 1 if res.failures else 0


if __name__ == "__main__":
    sys.exit(main())
