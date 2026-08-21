# fixer-scope-guard.ps1 -- PreToolUse guard on the QA loop's fixer.
#
# PROTOCOL.md R4: "The fixer must not be able to edit its own scorecard, its guard, or its
# metric. This is architectural, not advisory."
#
# It was advisory. Measured 2026-08-10: code-reviewer.md declared no disallowedTools, no
# hooks, and permissionMode: acceptEdits (so edits apply with no prompt), and settings.json
# had no permissions.deny block at all. The boundary held only because every delegation
# happened to restate it in prose -- and a live probe confirmed the fixer DOES respect the
# prose. But declining is not the same as being prevented, and the ledger records four
# separate rounds in which a fixer's own CLEAN claim was refuted by an independent verifier.
#
# WHY A HOOK AND NOT settings.json permissions.deny: deny rules there are global. Denying
# Edit on qa-history/** would also block the MAIN SESSION, which PROTOCOL.md:52 requires to
# write the ledger after the loop closes. The exclusion has to be scoped to the agent.
#
# Contract: exit 0 = allow, exit 2 = block (stderr is fed back to Claude as the reason).
#
# MUST be wired as:  command: "& '<this file>'; exit $LASTEXITCODE"
# Without the explicit exit, PowerShell's -Command form returns 0 for a script that exits 2,
# and the block silently becomes an allow. That defect went unnoticed in the sibling Bash
# guard for four weeks. See qa-harness/guard_corpus.py.

$ErrorActionPreference = 'Stop'
try {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { exit 0 }
    $payload = $raw | ConvertFrom-Json
    $path = ''
    $cmd = ''
    if ($payload.tool_input) {
        foreach ($k in @('file_path', 'path', 'notebook_path')) {
            if ($payload.tool_input.$k) { $path = [string]$payload.tool_input.$k; break }
        }
        if ($payload.tool_input.command) { $cmd = [string]$payload.tool_input.command }
    }
    if ([string]::IsNullOrWhiteSpace($path) -and [string]::IsNullOrWhiteSpace($cmd)) { exit 0 }
} catch {
    exit 0
}

# Normalise separators so a rule cannot be dodged by spelling the path the other way.
$p = $path -replace '\\', '/'

# Each rule: a regex, and the reason it exists. Order is not significant; first match wins.
# Each rule matches the protected PREFIX with an optional trailing separator -- NOT a
# trailing-slash-plus-filename shape. Measured 2026-08-10: the old `/qa-history/` and
# `/agents/[^/]+\.md$` forms matched no path that WAS the directory, so
# `rm -rf C:/Users/example/.claude/qa-history` returned exit 0. One command destroyed the
# ledger, the metric, every agent definition or both guards -- the exact reach R4 exists to
# deny -- and it was allowed because the rules described files inside the directory rather
# than the directory itself.
$protected = @(
    @{ re = '(?i)/\.claude/qa-harness(/|$)'
       why = 'the QA metric and its checkers. A fixer that can edit its own scorer is the same defect as one that can edit its own tests.' },
    @{ re = '(?i)/\.claude/qa-history(/|$)'
       why = 'the QA ledgers. PROTOCOL.md:52 -- the main orchestrating session writes these after the loop closes, never the fixer.' },
    @{ re = '(?i)/\.claude/qa-backups(/|$)'
       why = 'the pre-loop snapshots. They are the revert path; a fixer that can delete them removes the ability to undo its own round.' },
    @{ re = '(?i)/\.claude/agents(/|$)'
       why = 'an agent definition. No agent edits any agent definition, including its own -- an agent rewriting the prompt it is being judged against cannot be reviewed.' },
    @{ re = '(?i)/\.claude/hooks(/|$)'
       why = 'a PreToolUse guard, including this one. A guard the guarded process can edit is not a guard.' },
    @{ re = '(?i)/\.claude/tools(/|$)'
       why = 'a measurement wrapper. A fixer that can edit the instrument that scores its own fix can make any number say anything.' },
    @{ re = '(?i)/\.claude/(settings\.json|CLAUDE\.md)$'
       why = 'the session configuration and the operating contract -- the two files that decide what every later run is allowed to do.' }
)

function Deny([string]$what, [string]$why) {
    [Console]::Error.WriteLine("Scope guard blocked a write to '$what'. That path is $why It sits outside every QA loop's Scope: by design (PROTOCOL.md R4). If this change is genuinely needed, report it as a recommendation and let the main session make it.")
    exit 2
}

if ($path) {
    foreach ($rule in $protected) { if ($p -imatch $rule.re) { Deny $path $rule.why } }
}

# Bash can reach the same paths without ever touching Edit/Write, so an Edit-only scope guard
# is a door with no wall beside it. But the fixer must still be able to RUN the metric --
# `python .../qa-harness/mutate.py <skill> --score` names a protected path and is legitimate.
# So the rule is not "mentions a protected path"; it is "a protected path appears as the
# TARGET of a write". Only redirect targets and mutator arguments are tested.
if ($cmd) {
    $targets = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($cmd, '(?:>>?|\btee\b(?:\s+-a)?)\s*(?<t>[^\s|;&<>]+)')) {
        $targets.Add($m.Groups['t'].Value.Trim('"', "'"))
    }
    foreach ($m in [regex]::Matches($cmd,
            '\b(?:rm|rmdir|cp|mv|ln|touch|mkdir|shred|unlink|truncate)\b(?<args>(?:\s+-{1,2}[\w-]+)*(?:\s+[^\s|;&]+)+)')) {
        foreach ($a in ($m.Groups['args'].Value -split '\s+')) {
            if ($a -and $a -notmatch '^-') { $targets.Add($a.Trim('"', "'")) }
        }
    }
    foreach ($m in [regex]::Matches($cmd, '\bsed\b[^|;&]*?(?:-i|--in-place)\S*\s+(?:''[^'']*''|"[^"]*"|\S+)\s+(?<t>[^\s|;&]+)')) {
        $targets.Add($m.Groups['t'].Value.Trim('"', "'"))
    }
    foreach ($t in $targets) {
        $tn = $t -replace '\\', '/'
        foreach ($rule in $protected) { if ($tn -imatch $rule.re) { Deny $t $rule.why } }
    }
}

exit 0
