#!/usr/bin/env python3
"""skill_invariants.py -- mechanical invariant checker for ANY skill directory.

Makes the skill-builder quality gate (M1-M4) and the cross-reference discipline checkable by
a machine instead of by reading. Generic: it derives everything from the target's own files,
so it works on a skill it has never seen.

    python skill_invariants.py <skill-dir> [--json] [--quiet]

Exit 0 = all invariants hold. Exit 1 = at least one FAIL. Exit 2 = target unusable.

THE LESSON THIS FILE EXISTS TO ENCODE, quoted from the harness it generalises:

    "Round-4 defect (found by audit): the previous version of this file contained zero file
     reads. Every green check exercised a hand-transcribed model, so it proved only that the
     transcription was self-consistent -- deleting a rule from the skill could not fail it."

So: every check below reads the live files. Delete a clause from a skill and a check must fail.
If you add a check, add a mutant to mutate.py that proves it can fail.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover
    pass

DESC_BUDGET = 1536  # description + when_to_use, per the skill-builder quality gate M1
SECRET_RE = re.compile(
    r"""(?ix)
    (?: api[_-]?key | secret | password | passwd | bearer | private[_-]?key )
    \s* [:=] \s* ['"][A-Za-z0-9_\-/+]{16,}['"]
    | AIza[A-Za-z0-9_\-]{20,}
    | sk-[A-Za-z0-9]{20,}
    | ghp_[A-Za-z0-9]{20,}
    """
)
# An absolute path in a shipped file. ${CLAUDE_SKILL_DIR}/%OneDrive% are the sanctioned forms.
ABS_PATH_RE = re.compile(r"(?:[A-Za-z]:[\\/]Users[\\/][A-Za-z0-9_.-]+|/home/[A-Za-z0-9_.-]+)")


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
    """Minimal top-level YAML reader: plain scalars and `|`/`>` block scalars.

    Deliberately hand-rolled -- pyyaml is not installed here, and the checker must not
    require a dependency the target machine may lack.
    """
    out, key, buf, block = {}, None, [], False
    for line in fm.split("\n"):
        m = re.match(r"^([A-Za-z][\w-]*):\s*(.*)$", line)
        if m and not line[:1].isspace():
            if key is not None:
                out[key] = "\n".join(buf).strip()
            key, rest = m.group(1), m.group(2).strip()
            block = rest in ("|", ">", "|-", ">-", "")
            buf = [] if block else [rest]
        elif key is not None:
            buf.append(line.strip())
    if key is not None:
        out[key] = "\n".join(buf).strip()
    return out


def tool_list(value: str):
    return [t.strip() for t in (value or "").split(",") if t.strip()]


def headings(text: str):
    """Every markdown heading, normalised for reference matching."""
    return [h.strip() for h in re.findall(r"^#{1,6}\s+(.+)$", text, re.M)]


def run(skill_dir: Path) -> Result:
    res = Result()
    skill_path = skill_dir / "SKILL.md"
    text = skill_path.read_text(encoding="utf-8")
    fm, body = split_frontmatter(text)

    # ---------------------------------------------------------------- M2 frontmatter
    res.check(fm is not None, "M2 frontmatter delimited by --- markers")
    if fm is None:
        return res
    meta = yaml_scalars(fm)
    res.check("name" in meta, "M2 frontmatter has a name")
    res.check(meta.get("name", "") == skill_dir.name,
              "M2 name matches directory name",
              f"name={meta.get('name')!r} dir={skill_dir.name!r}")
    res.check(bool(re.match(r"^[a-z0-9-]{1,64}$", meta.get("name", ""))),
              "M2 name is lowercase/hyphens, <=64 chars", meta.get("name", ""))
    res.check("\t" not in fm, "M2 frontmatter contains no tabs")

    # ---------------------------------------------------------------- M1 description
    desc = meta.get("description", "")
    when = meta.get("when_to_use", "")
    res.check(bool(desc), "M1 description present")
    total = len(desc) + len(when)
    res.check(total <= DESC_BUDGET,
              f"M1 description+when_to_use within {DESC_BUDGET} chars",
              f"{len(desc)}+{len(when)}={total} (headroom {DESC_BUDGET - total})")
    res.check(bool(re.match(r"^(Use (when|for)|Activates|Conduct|Manages|Automates|Helps|Guides)",
                            desc.strip())),
              "M1 description opens in third person with a trigger clause",
              desc[:60])

    # ---------------------------------------------------- allowed / disallowed hygiene
    allowed = tool_list(meta.get("allowed-tools", ""))
    disallowed = tool_list(meta.get("disallowed-tools", ""))
    if allowed or disallowed:
        overlap = sorted(set(allowed) & set(disallowed))
        res.check(not overlap, "allowed-tools and disallowed-tools are disjoint",
                  f"overlap={overlap}")
        res.check(len(allowed) == len(set(allowed)), "no duplicates in allowed-tools")
        res.check(len(disallowed) == len(set(disallowed)), "no duplicates in disallowed-tools")
        # A tool the body ASSERTS is removed must genuinely be on disallowed-tools.
        # Conditionals ("If `X` is denied, ...") are not assertions -- they describe a runtime
        # possibility for a tool that deliberately prompts, so they must not be matched.
        # `\*{0,2}` because the claim is usually emphasised: "`Write` is **disallowed outright**".
        #
        # The name group is a LIST, and that is load-bearing rather than tidiness. The earlier
        # single-name form ("`X` is removed") silently ignored the plural claim
        # "**`apply_sensitive_message_label` and `apply_sensitive_thread_label` are removed from
        # the pool.**" -- so a mutant deleting a Trash route from disallowed-tools SURVIVED a full
        # run of this checker (an inbox-sorting skill, 2026-08-09). The two most dangerous tools in that
        # skill were the two the assertion check could not see, precisely because the author had
        # written about them together. Emphasis markers may also precede the first backtick, hence
        # the leading `\*{0,2}`.
        # The optional non-backticked TAIL before the verb is load-bearing too. One of that
        # skill's hard rules reads "`Write`, `Bash`, ... `Skill` and subagent spawning are removed
        # from the pool" -- the list ends in an unbackticked phrase, so a pattern requiring the
        # last backtick to be followed immediately by is/are saw nothing, and a mutant deleting
        # `Bash` and `Write` from disallowed-tools scored 40 passed / 0 failed (2026-08-09).
        for m in re.finditer(
                r"(?:^|[.;]\s+|\n)\s*(?:-\s*)?\*{0,2}"
                r"((?:`[A-Za-z_][\w.]*(?:__[\w.]+)*`(?:\s*,\s*|\s+and\s+|\s*)?)+?)"
                r"\*{0,2}(?:\s*(?:,\s*)?(?:and\s+)?[a-z][a-z\s]{0,40}?)?"
                r"\s+(?:is|are)\s+"
                r"\*{0,2}(?:structurally\s+)?(?:removed|disallowed|denied)\b", body, re.M):
            # Conditional guard: look back to the start of the SENTENCE, not a fixed 40 chars.
            # The old window missed "...only when the user opts out"-style lead-ins that sit
            # further left, producing six spurious FAILs on realistic prose.
            head = body[max(0, m.start() - 300):m.start()]
            # Split on a terminator followed by whitespace OR markdown emphasis. Requiring plain
            # whitespace fails on "...calling it.**" -- the sentence boundary is invisible, the
            # previous sentence gets swallowed, and its "**if** a tool you need..." triggers the
            # conditional guard. That silently suppressed the Trash-route assertion while the total
            # check count still read 45, because unrelated assertions had started firing (2026-08-09).
            # Count-only verification could not see this; only listing the checks could.
            sentence = re.split(r"(?<=[.!?])[\s*_`]+|\n\s*\n", head)[-1].lower()
            # Markers must be CONDITIONAL, not merely common. A first cut at this list included bare
            # `only`, and the sentence preceding the inbox-sorting skill's Trash-route bullet happens to end
            # "...the only kind of completeness claim worth making" -- so the guard silently skipped
            # the single most important denial in the skill and the count fell 45 -> 43 (2026-08-09).
            # Only the compound forms carry conditional meaning; the bare adverbs do not.
            if re.search(r"\bif\b|\bwhen\b|\bunless\b|\bshould\b"
                         r"|\bonly\s+(?:when|if|where)\b|\bwould\s+be\b|\bmay\s+be\b",
                         sentence):
                continue
            for claimed in re.findall(r"`([A-Za-z_][\w.]*(?:__[\w.]+)*)`", m.group(1)):
                # EXACT match, or an MCP-namespaced form ending in `__<claimed>`. The old
                # `claimed in d` substring test false-passed `Bash` because `BashOutput` was on
                # the list -- so the single most consequential denial in the skill was "verified"
                # by an unrelated tool that merely shares a prefix.
                res.check(any(claimed == d or d.endswith("__" + claimed) for d in disallowed),
                          f"body asserts `{claimed}` is removed; it is on disallowed-tools")
    else:
        res.skip("allowed/disallowed hygiene", "skill sets neither list")

    # ------------------------------------------------------------ M4 orphans & linkage
    bundled = [p for p in skill_dir.rglob("*")
               if p.is_file()
               and p.name != "SKILL.md"
               and "__pycache__" not in p.parts
               and not p.name.endswith((".pyc", ".bak"))]
    linkable = [p for p in bundled if p.suffix in (".md", ".py", ".ps1", ".sh", ".json", ".html",
                                                   ".toml", ".txt")]
    all_prose = text + "".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in linkable if p.suffix == ".md")
    for p in linkable:
        rel = p.relative_to(skill_dir).as_posix()
        # A file counts as referenced if it is named directly OR if its containing directory is
        # (e.g. `python -m unittest discover -s scripts/tests` legitimately covers every test
        # module in that directory without naming any of them).
        parents = [q.as_posix() for q in p.relative_to(skill_dir).parents
                   if q.as_posix() not in (".", "")]
        # A TOP-LEVEL bundled file must be linked from SKILL.md itself -- that is the whole
        # point of M4 ("so Claude knows it exists and loads it lazily"); being mentioned only
        # by a sibling document does not get it loaded. Nested files may be covered by any
        # bundled doc, including via their directory.
        if not parents:
            referenced = p.name in text
            where = "SKILL.md"
        else:
            referenced = (rel in all_prose or p.name in all_prose
                          or rel.replace("/", "\\") in all_prose
                          or any(d in all_prose or d.replace("/", "\\") in all_prose
                                 for d in parents))
            where = "SKILL.md or a bundled .md"
        res.check(referenced, f"M4 no orphan: {rel} is referenced", "" if referenced else
                  f"neither the file nor its directory is mentioned in {where}")

    # -------------------------------------------------------- M4 paths and secrets
    for p in [skill_path] + linkable:
        content = p.read_text(encoding="utf-8", errors="replace")
        rel = p.relative_to(skill_dir).as_posix()
        # state/ files legitimately record concrete paths the skill resolved at runtime.
        # state/ and subjects/ are runtime registries: they legitimately record the concrete
        # absolute paths the skill resolved on this machine. M4 targets shipped instructions.
        if not rel.startswith(("state/", "subjects/")):
            hits = sorted(set(ABS_PATH_RE.findall(content)))
            res.check(not hits, f"M4 no hardcoded user path in {rel}", f"{hits[:3]}")
        secret = SECRET_RE.search(content)
        res.check(secret is None, f"M4 no inline secret in {rel}",
                  "" if secret is None else f"matched {secret.group(0)[:24]!r}")

    # ------------------------------------------------------- cross-reference integrity
    ref_path = skill_dir / "reference.md"
    if ref_path.is_file():
        ref = ref_path.read_text(encoding="utf-8")
        ref_headings = headings(ref)
        # Section numbers actually defined, e.g. "## § 3 Foo" or "## 3. Foo"
        defined = set()
        for h in ref_headings:
            for m in re.finditer(r"(?:§\s*|^)(\d+(?:\.\d+)*)", h):
                defined.add(m.group(1))
        # Only LOCAL citations count. A line naming another document ("the shared playbook's
        # § 9", "the ops playbook ... § 2") points at that document's sections, not this
        # skill's, and flagging those produced false dangling-reference reports.
        # Prose wraps, so the document name can sit on the line BEFORE the citation. Check a
        # two-line window; a one-line check produced a false dangling report on a wrapped
        # sentence referring to the shared playbook's section.
        # "reference.md § 2" and "rubric.md § 6" are LOCAL citations -- those files belong to
        # this skill. Only genuinely foreign documents make a citation non-local. An earlier
        # `\.md\b` catch-all silently skipped almost every real citation, which let a dangling
        # reference survive the mutation harness.
        own = {"reference.md", "rubric.md", "SKILL.md", skill_dir.name}
        external = re.compile(r"(?i)playbook|handbook|another skill|sibling skill"
                              r"|\b(?!reference\.md|rubric\.md|SKILL\.md)[\w-]+\.md\b")
        cited = set()
        lines = (text + "\n" + ref).split("\n")
        for i, line in enumerate(lines):
            window = (lines[i - 1] + " " + line) if i else line
            if external.search(window):
                continue
            cited.update(re.findall(r"§\s*(\d+(?:\.\d+)*)", line))
        missing = sorted(cited - defined, key=lambda s: [int(x) for x in s.split(".")])
        res.check(not missing, "every locally cited § section resolves to a reference.md heading",
                  f"dangling={missing}")
    else:
        res.skip("§ cross-references", "no reference.md")

    # Hard Rule N citations must be within the range the skill actually defines.
    defined_rules = {int(n) for n in re.findall(r"^\s*(\d+)\.\s+\*\*", body, re.M)}
    rule_block = re.search(r"^##+\s*(?:THE\s+)?HARD RULES?\b(.*?)(?=^##\s|\Z)", body,
                           re.M | re.S)
    if rule_block:
        rules_in_block = {int(n) for n in re.findall(r"^\s*(\d+)\.\s", rule_block.group(1), re.M)}
        cited_rules = {int(n) for n in re.findall(r"Hard Rule\s+(\d+)", all_prose)}
        unknown = sorted(cited_rules - rules_in_block)
        res.check(not unknown, "every cited Hard Rule N is defined in the Hard Rules section",
                  f"undefined={unknown} defined={sorted(rules_in_block)}")
        res.check(rules_in_block == set(range(1, len(rules_in_block) + 1)),
                  "Hard Rules are numbered contiguously from 1",
                  f"got={sorted(rules_in_block)}")
    else:
        res.skip("Hard Rule citations", "no Hard Rules section")

    # PHASE N references must resolve to a phase the skill defines.
    phases = {int(n) for n in re.findall(r"^##+\s*PHASE\s+(\d+)", body, re.M)}
    if phases:
        cited_phases = {int(n) for n in re.findall(r"PHASE\s+(\d+)", all_prose)}
        res.check(not (cited_phases - phases), "every cited PHASE N is defined",
                  f"undefined={sorted(cited_phases - phases)}")
    else:
        res.skip("PHASE references", "skill has no PHASE headings")

    # ------------------------------------------------------------- state-file discipline
    for state in sorted((skill_dir / "state").glob("*.md")) if (skill_dir / "state").is_dir() else []:
        content = state.read_text(encoding="utf-8")
        rel = state.relative_to(skill_dir).as_posix()
        declares = ("data, not instruction" in content
                    or "data, never instruction" in content
                    or re.search(r"[Nn]othing in this file authoris", content) is not None)
        res.check(declares, f"{rel} declares its contents are data, not instruction")
        # Append anchors must be unique. The documented anchor is the header line PLUS the
        # separator line, so uniqueness of that PAIR is what matters -- two tables with the
        # same column count share a separator row and that is fine on its own.
        lines = content.split("\n")
        pairs = [f"{lines[i]}\n{lines[i + 1]}" for i in range(len(lines) - 1)
                 if re.match(r"^\|[-\s|:]+\|$", lines[i + 1]) and lines[i].startswith("|")]
        res.check(len(pairs) == len(set(pairs)),
                  f"{rel} header+separator append anchors are unique",
                  f"{len(pairs)} anchors, {len(set(pairs))} distinct")
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("skill_dir")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="print only the summary line")
    args = ap.parse_args(argv)

    skill_dir = Path(args.skill_dir)
    if not (skill_dir / "SKILL.md").is_file():
        msg = f"no SKILL.md under {skill_dir}"
        print(json.dumps({"status": "unusable", "error": msg}) if args.json else f"UNUSABLE: {msg}")
        return 2

    try:
        res = run(skill_dir)
    except Exception as exc:  # a checker that dies proves nothing -- say so loudly
        payload = {"status": "checker_crashed", "error": f"{exc.__class__.__name__}: {exc}"}
        print(json.dumps(payload) if args.json else f"CHECKER CRASHED: {payload['error']}")
        return 2

    if args.json:
        print(json.dumps({
            "status": "ok" if not res.failures else "fail",
            "skill": skill_dir.name,
            "passed": len(res.passes), "failed": len(res.failures), "skipped": len(res.skips),
            "rows": res.rows,
        }, indent=2))
    else:
        if not args.quiet:
            for r in res.rows:
                mark = "PASS" if r["ok"] else ("SKIP" if r["ok"] is None else "FAIL")
                detail = f"  -- {r['detail']}" if r["detail"] else ""
                print(f"  {mark}  {r['label']}{detail}")
        print(f"{skill_dir.name}: {len(res.passes)} passed, {len(res.failures)} failed, "
              f"{len(res.skips)} skipped")
    return 1 if res.failures else 0


if __name__ == "__main__":
    sys.exit(main())
