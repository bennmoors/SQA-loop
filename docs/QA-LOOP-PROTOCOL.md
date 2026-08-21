# The loop as an always-on protocol

You have two ways to get the QA loop. This page is about the second one.

| | `/sqa-loop` skill | pasted into `CLAUDE.md` |
|---|---|---|
| Loads | on invocation | every session, always |
| Context cost | only when used | ~11 KB, permanently |
| Triggered by | `/sqa-loop <target>`, or a matching request | any request that sounds like QA |
| Installed by | `install.ps1` | you, by hand |

**The skill is the default and the recommended path.** It is installed for you at
`~/.claude/skills/sqa-loop/`, and Claude Code will reach for it when you ask to test, QA, verify,
validate or harden something — you do not have to type the slash command.

## When the always-on form is worth it

Paste it if you want the routing discipline applied to *every* quality-adjacent request without the
model first deciding a skill is relevant. That is a real difference: a skill is invoked, a
`CLAUDE.md` rule is simply in force. If your work is mostly review and you would rather never miss
the routing step, the permanent context cost is a fair trade.

## How

**There is one source of truth: `skills/sqa-loop/SKILL.md`.** This page deliberately does not
duplicate the protocol text, because two copies of a 250-line operating contract drift, and a
drifted copy of a rule is worse than no copy.

1. Open `skills/sqa-loop/SKILL.md`.
2. Copy everything **below** the YAML frontmatter (that is, from the `# The SQA loop` heading down).
3. Paste it into `~/.claude/CLAUDE.md` under a heading of your own, e.g.
   `## QA LOOP PROTOCOL (follow when asked to test / QA / verify / harden anything)`.
4. Add a trigger sentence at the top so it fires without being asked, e.g.:

   > **Trigger:** any request to test, QA, verify, validate or harden something — "SQA this",
   > "QA loop on `<path>`", "make sure this is correct and tight". Not for a quick one-off read.

Do **not** paste the frontmatter — `name:` and `description:` are skill metadata and mean nothing in
`CLAUDE.md`.

## If you do both

Harmless, but redundant: you pay the context cost and the skill adds nothing you do not already
have. Pick one. If you paste it, you can delete `~/.claude/skills/sqa-loop/` — though keeping
`reference.md` is worthwhile either way, since `SKILL.md` points at it for the ledger protocol,
measurement modes and calibration figures rather than inlining them.

## Keeping it current

An update to this repo changes `SKILL.md`; a pasted copy will not follow. After
`git pull && .\install.ps1`, re-copy the body if you are using the always-on form. The skill route
has no such step, which is the other reason it is the default.
