"""Shared hook-wiring extraction for guard_corpus.py and scope_corpus.py.

WHY THIS FILE EXISTS (2026-08-11). Both corpora carried a near-identical `wiring_from_agent()`
(suspect 8: "divergence would make the two guards' measurements incomparable"), and both carried
the same two Critical defects in it:

  SUSPECT 11 -- ARBITRARY COMMAND EXECUTION FROM DOCUMENT CONTENT. The old regex searched the
  WHOLE agent file for `^\\s*command:\\s*(.+)$` and handed the capture to `powershell -Command`.
  An agent .md with no hooks at all but a prose line `command: echo hijacked` got that executed
  once per corpus case. Agent .md files are the one file class the fixer is allowed to edit, so
  this was a document-driven execution path into the harness that scores the fixer's work.
  Fixed by reading ONLY the frontmatter `hooks:` block, and refusing any command whose script
  path does not resolve to a real file on disk.

  SUSPECT 12 -- `--guard` SILENTLY IGNORED. The `frontmatter` invocation is
  `lambda g, w: [..., "-Command", w]` -- it never referenced `g`. Passing `--guard` therefore
  measured the incumbent no matter what was passed. Measured: a guard whose entire body is
  `exit 0` scored 78.7%, byte-identical to the real guard's score, which is the most convincing
  possible wrong answer. Fixed here rather than in the invocation table: `guard_override`
  rewrites the script path INSIDE the production wiring string, so an A/B keeps the real
  deployment shape (`& '<path>'; exit $LASTEXITCODE`) and only swaps which script it runs.
"""

import re
from pathlib import Path

SCRIPT_RE = re.compile(r"\.(?:ps1|py|sh|cmd|bat|exe)$", re.I)


def _frontmatter(text: str) -> str:
    m = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", text, re.S)
    if not m:
        raise ValueError("no --- delimited frontmatter")
    return m.group(1)


def _hooks_block(fm: str) -> str:
    """Return the raw indented text under a TOP-LEVEL `hooks:` key, or '' if there is none."""
    out, collecting = [], False
    for line in fm.split("\n"):
        if re.match(r"^hooks:\s*$", line):
            collecting = True
            continue
        if collecting:
            # A non-indented, non-blank line ends the block: it is the next top-level key.
            if line.strip() and not line[:1].isspace():
                break
            out.append(line)
    return "\n".join(out)


def script_path_of(command: str):
    """The script path a hook command invokes, or None. Handles `& 'C:\\path.ps1'` and bare."""
    for a, b in re.findall(r"'([^']+)'|\"([^\"]+)\"", command):
        cand = a or b
        if SCRIPT_RE.search(cand):
            return cand
    bare = re.search(r"(\S+\.(?:ps1|py|sh|cmd|bat|exe))\b", command, re.I)
    return bare.group(1) if bare else None


def wiring_from_agent(agent_file: Path, guard_override: Path | None = None) -> str:
    """Read the hook command an agent file ACTUALLY declares, from its frontmatter hooks: block.

    Hardcoding the wiring is how these corpora were wrong once already: `frontmatter` used to be
    a literal f"& '{g}'", and the moment the agents were rewired the corpus went on measuring the
    old configuration and reported must-block 0/26 against a guard that was by then working. So
    the wiring is parsed from the live file every run -- but from the hooks: block ONLY, and only
    if it names a script that exists.

    `guard_override` swaps the script path inside that wiring, so a candidate guard is exercised
    through the real deployment shape instead of a synthetic one.
    """
    text = agent_file.read_text(encoding="utf-8")
    hooks = _hooks_block(_frontmatter(text))
    if not hooks.strip():
        raise ValueError(f"{agent_file.name} declares no frontmatter hooks: block")

    m = re.search(r"^\s*-?\s*command:\s*(.+?)\s*$", hooks, re.M)
    if not m:
        raise ValueError(f"no command: inside the hooks: block of {agent_file.name}")

    raw = m.group(1).strip()
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        raw = raw[1:-1].replace('\\\\', '\\').replace('\\"', '"')
    elif len(raw) >= 2 and raw[0] == "'" and raw[-1] == "'":
        raw = raw[1:-1]

    declared = script_path_of(raw)
    if declared is None:
        raise ValueError(
            f"the hook command in {agent_file.name} names no script path: {raw!r}. Refusing to "
            "hand it to a shell -- see suspect 11.")
    if not Path(declared).is_file():
        raise ValueError(
            f"the hook command in {agent_file.name} points at {declared!r}, which is not a file "
            "on disk. Refusing to hand it to a shell -- see suspect 11.")

    if guard_override is not None:
        raw = raw.replace(declared, str(guard_override))
    return raw
