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
       why = 'the session configuration and the operating contract -- the two files that decide what every later run is allowed to do.' },
    # PROTOCOL.md R4 names THREE exclusions -- qa-history, qa-harness, and a skill's own
    # scripts/tests. Only the first two were enforced here, because every rule above is anchored
    # on `/.claude/` and that was true of the skills too until 2026-08-04, when prelearn and
    # postlearn were relocated into the OneDrive tree
    # (.../UNIVERSITY/.claude/skills/<skill>/scripts/tests/). None of the `/\.claude/<name>` rules
    # match `/.claude/skills/...`, so from that date the fixer could edit the very suites that gate
    # its own iterations -- the defect CLAUDE.md calls "the same defect as one that can edit its
    # own scorecard".
    #
    # HISTORY, because this rule was added, reverted and re-added inside one session, and the next
    # reader deserves a reason rather than churn. Added 2026-08-21 during the RUN 5 efficiency
    # loop; reverted the same day because `scope_corpus.py` deliberately ALLOWED a repro-test
    # write, and regressing a corpus on the strength of one's own opinion is exactly backwards.
    # The user then ruled explicitly -- "Do not let the fixer edit" -- which settles the conflict
    # in R4's favour, and the corpus expectation moved with it in the same commit.
    #
    # Anchored on `(/|$)` like every rule above: a trailing-slash-plus-filename shape let
    # `rm -rf .../qa-history` through on 2026-08-10.
    @{ re = '(?i)/skills/[^/]+/(scripts/)?tests(/|$)'
       why = "a skill's own test suite, which is the guard an SQA loop reverts iterations against. A fixer that can edit its own tests can make any iteration pass (PROTOCOL.md R4; user ruling 2026-08-21)." }
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
    # POWERSHELL CMDLET WRITES. The POSIX pass above cannot see them, and the gap was measured
    # 2026-08-23: `Set-Content`, `Out-File`, `New-Item` and `Add-Content` all reached
    # ~/.claude/agents and ~/.claude/qa-history UNBLOCKED, while every POSIX spelling of the same
    # write was refused. The guard's coverage therefore depended on which language the fixer
    # happened to reach for -- and this suite is about to make PowerShell traffic routine, which
    # turns a latent hole into a load-bearing one.
    #
    # TWO REASONS THE MUTATOR PASS ABOVE MISSES THESE, both of which this block has to handle:
    #   1. `Set-Content` names no POSIX verb, so that alternation never matches.
    #   2. Its target arrives as the VALUE of a NAMED PARAMETER (`-Path X`), and the mutator pass
    #      discards every token starting with `-`. A named-parameter value was only ever reachable
    #      positionally, so writing `-Path` was by itself enough to defeat it.
    #
    # A read-only searcher is exempted BY HEAD: `grep -rn "Set-Content" ~/.claude/qa-harness/`
    # names both a protected path and a cmdlet while writing nothing, and reviewing PowerShell is
    # precisely the work that generates that command. Refusing it teaches routing around the guard.
    $psWriters = 'Set-Content|Out-File|Add-Content|New-Item|Clear-Content|Remove-Item|' +
                 'Rename-Item|Move-Item|Copy-Item|Set-ItemProperty|New-ItemProperty|' +
                 'Tee-Object|Export-Csv|Export-Clixml|Set-Acl'
    $psTargetParams = 'Path|LiteralPath|FilePath|Destination|OutFile|Target|NewName'
    $searcherHead = '^\s*(?:grep|egrep|fgrep|rg|ag|ack|findstr|Select-String)\b'

    if ($cmd -notmatch $searcherHead) {
        foreach ($m in [regex]::Matches($cmd, "\b(?:$psWriters)\b(?<args>[^;|&]*)",
                                        [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $toks = @($m.Groups['args'].Value -split '\s+' | Where-Object { $_ })
            for ($j = 0; $j -lt $toks.Count; $j++) {
                $tok = $toks[$j]
                if ($tok -imatch "^-(?:$psTargetParams)$") {
                    # Named parameter: the target is the NEXT token, not this one.
                    if ($j + 1 -lt $toks.Count) { $targets.Add($toks[$j + 1].Trim('"', "'")) }
                } elseif ($tok -imatch "^-(?:$psTargetParams):(?<v>.+)$") {
                    # `-Path:value` colon form binds with no space between name and value.
                    $targets.Add($Matches['v'].Trim('"', "'"))
                } elseif ($tok -notmatch '^-') {
                    # Positional: `Set-Content <path> <value>` binds -Path positionally. Collecting
                    # the value token too is harmless -- only a PROTECTED path can trigger a Deny.
                    $targets.Add($tok.Trim('"', "'"))
                }
            }
        }
    }

    foreach ($t in $targets) {
        $tn = $t -replace '\\', '/'
        foreach ($rule in $protected) { if ($tn -imatch $rule.re) { Deny $t $rule.why } }
    }
}

exit 0
