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
#
# ---------------------------------------------------------------------------------------
# THE BASH BRANCH IS AN ALLOWLIST NOW (2026-08-25), and the reason is the one the sibling
# guard's header already gives for its own inversion: "Patching them produced a longer
# denylist and no reason to believe the list was finally complete."
#
# Eight bypasses were measured against the extraction-only design in a single adversarial
# pass, and every one was a different SPELLING of one question -- "does this command write to
# a protected path?":
#     powershell -Command Set-Content -Path <protected>/hooks/pwn.ps1 'e'  (unquoted -Command)
#     powershell -Command "& { Set-Content ... }"                          (script block)
#     powershell -Command "$x = Set-Content ..."                           (assignment)
#     powershell -EncodedCommand <base64>                                  (nothing left to read)
#     [IO.StreamWriter]::new('<protected>/hooks/pwn.ps1')                  (a type, not a cmdlet)
#     [IO.FileStream]::new('<protected>/hooks/pwn.ps1','Create')           (truncates on open)
#     [IO.File]::AppendText('<protected>/hooks/pwn.ps1')                   (method not listed)
#     powershell -Command "$p='<protected>/...'; Set-Content -Path $p"     (variable indirection)
# Adding eight names would have produced a ninth spelling. So the burden is inverted:
#
#     IF A SEGMENT NAMES A PROTECTED PATH, IT MUST MATCH A NARROW READ-ONLY ALLOWLIST.
#     IF IT NAMES NONE, IT IS NONE OF THIS GUARD'S BUSINESS.
#
# The fixer's legitimate reasons to name one of these paths are few and enumerable: run the
# metric (`python .../qa-harness/mutate.py ...`), read (cat/head/tail/wc/ls), search
# (grep/rg/findstr/Select-String/Get-Content), and read-only git. Everything else -- every
# alias, .NET type, future cmdlet and indirection -- now fails by OMISSION rather than by
# having been anticipated.
#
# THREE STRUCTURAL RULES, each closing a class rather than a case:
#   1. PER SEGMENT, not per command. `grep -rn x <protected>/ ; Set-Content -Path <protected>/y`
#      cannot pass by containing an allowed prefix. The sibling guard learned this one too.
#   2. A PIPELINE CARRIES THE PROTECTED PATH FORWARD. `Get-ChildItem <protected>/qa-history |
#      Remove-Item` names the path in a read and does the write one segment later, where no
#      protected path appears at all. Every segment downstream of a naming segment, for as long
#      as the join is `|`, must be read-only too.
#   3. NO COMMAND SUBSTITUTION in a naming segment. `$(...)` and backticks are a command in
#      their own right, which this guard would have to parse recursively.
#
# -EncodedCommand IS REFUSED OUTRIGHT, wherever it appears. Base64 hides the path from any
# mention check, so it defeats rule 1 by construction, and the fixer has no legitimate use for
# it. Prefix binding means `-e`, `-ec`, `-en` and `-enc...` all reach it.
#
# THE EXTRACTION PASSES ARE RETAINED BEHIND THE ALLOWLIST, as defence in depth -- the same two
# layers, in the same order, as the sibling guard. They are no longer the decision, and they
# are no longer where a new spelling gets added.
#
# WHAT THIS STILL CANNOT SEE, stated rather than implied: a script's CONTENTS. `python
# /tmp/x.py` names no protected path, and no command-text guard can read the file it runs. A
# fixer that writes a script and runs it is outside this mechanism's reach -- which is why R4
# remains a protocol rule as well as a hook.

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

# ONE NORMALISER, USED BY ALL THREE MATCHERS -- the Edit/Write path, the mention check on a
# command segment, and the extracted write targets. Separator spelling alone was not enough:
# every one of these reaches ~/.claude/hooks and NONE of them matched `\.claude/hooks`, measured
# 2026-08-25 against the first draft of the allowlist (all four returned exit 0):
#     C:/Users/x/.claude//hooks/pwn.ps1          (doubled separator)
#     C:/Users/x/.claude/./hooks/pwn.ps1         (no-op segment)
#     C:/Users/x/.claude/skills/../hooks/pwn.ps1 (traversal through a sibling)
#     C:\\Users\\x\\.claude\\hooks\\pwn.ps1      (doubled backslash, which collapses to the first)
# A prefix rule on an un-normalised path is not a containment check -- the sibling guard learned
# the same thing from `/tmp/../hooks/guard.ps1`. `..` is cancelled only against a real preceding
# segment, so a leading `../../x` is left alone rather than eaten.
function Get-NormalPath([string]$s) {
    $t = $s -replace '[\\/]+', '/'
    while ($t -match '/\./') { $t = $t -replace '/\./', '/' }
    while ($t -match '(?<=^|/)(?!\.\.?/)[^/]+/\.\./') {
        $t = $t -replace '(?<=^|/)(?!\.\.?/)[^/]+/\.\./', ''
    }
    return $t
}

$p = Get-NormalPath $path

# WHERE A PATH TOKEN STARTS, AND WHERE IT ENDS. Every rule used to begin with a literal `/`,
# which is right for an absolute path and wrong for every other spelling: `.claude/hooks/x`
# typed from the home directory matched NO rule at all, so `echo x > .claude/hooks/pwn.ps1`
# was allowed. `$AT` accepts the start of the string or any character that can precede a path
# token; `$END` accepts a separator, end of string, or any character that can follow one --
# which the old `(/|$)` could not do inside a command, where a path is followed by more
# arguments rather than by end-of-string. `.claude/qa-harness-old` is still NOT protected: the
# character after the name has to end the token.
$AT  = '(?:^|[\s"''=(,;|&/\\])'
$END = '(?:/|$|(?=[\s"''`;|&<>,)]))'

# Each rule: a regex, and the reason it exists. Order is not significant; first match wins.
# Each rule matches the protected PREFIX with an optional trailing separator -- NOT a
# trailing-slash-plus-filename shape. Measured 2026-08-10: the old `/qa-history/` and
# `/agents/[^/]+\.md$` forms matched no path that WAS the directory, so
# `rm -rf C:/Users/example/.claude/qa-history` returned exit 0. One command destroyed the
# ledger, the metric, every agent definition or both guards -- the exact reach R4 exists to
# deny -- and it was allowed because the rules described files inside the directory rather
# than the directory itself.
$protected = @(
    @{ re = '(?i)' + $AT + '\.claude/qa-harness' + $END
       why = 'the QA metric and its checkers. A fixer that can edit its own scorer is the same defect as one that can edit its own tests.' },
    @{ re = '(?i)' + $AT + '\.claude/qa-history' + $END
       why = 'the QA ledgers. PROTOCOL.md:52 -- the main orchestrating session writes these after the loop closes, never the fixer.' },
    @{ re = '(?i)' + $AT + '\.claude/qa-backups' + $END
       why = 'the pre-loop snapshots. They are the revert path; a fixer that can delete them removes the ability to undo its own round.' },
    @{ re = '(?i)' + $AT + '\.claude/agents' + $END
       why = 'an agent definition. No agent edits any agent definition, including its own -- an agent rewriting the prompt it is being judged against cannot be reviewed.' },
    @{ re = '(?i)' + $AT + '\.claude/hooks' + $END
       why = 'a PreToolUse guard, including this one. A guard the guarded process can edit is not a guard.' },
    @{ re = '(?i)' + $AT + '\.claude/tools' + $END
       why = 'a measurement wrapper. A fixer that can edit the instrument that scores its own fix can make any number say anything.' },
    @{ re = '(?i)' + $AT + '\.claude/(?:settings\.json|CLAUDE\.md)' + $END
       why = 'the session configuration and the operating contract -- the two files that decide what every later run is allowed to do.' },
    # PROTOCOL.md R4 names THREE exclusions -- qa-history, qa-harness, and a skill's own
    # scripts/tests. Only the first two were enforced here, because every rule above is anchored
    # on `/.claude/` and that was true of the skills too until 2026-08-04, when the review
    # targets were relocated into a project tree outside `~/.claude`
    # (<project>/.claude/skills/<skill>/scripts/tests/). None of the `/\.claude/<name>` rules
    # match `/.claude/skills/...`, so from that date the fixer could edit the very suites that gate
    # its own iterations -- the defect CLAUDE.md calls "the same defect as one that can edit its
    # own scorecard".
    #
    # HISTORY, because this rule was added, reverted and re-added inside one session, and the next
    # reader deserves a reason rather than churn. Added 2026-08-21 during the RUN 5 efficiency
    # loop; reverted the same day because `scope_corpus.py` deliberately ALLOWED a repro-test
    # write, and regressing a corpus on the strength of one's own opinion is exactly backwards.
    # The maintainer then ruled explicitly that the fixer may not edit tests, which settles the conflict
    # in R4's favour, and the corpus expectation moved with it in the same commit.
    #
    # Anchored like every rule above: a trailing-slash-plus-filename shape let
    # `rm -rf .../qa-history` through on 2026-08-10.
    @{ re = '(?i)/skills/[^/]+/(?:scripts/)?tests' + $END
       why = "a skill's own test suite, which is the guard an SQA loop reverts iterations against. A fixer that can edit its own tests can make any iteration pass (PROTOCOL.md R4; maintainer ruling 2026-08-21)." }
)

function Deny([string]$what, [string]$why) {
    [Console]::Error.WriteLine("Scope guard blocked a write to '$what'. That path is $why It sits outside every QA loop's Scope: by design (PROTOCOL.md R4). If this change is genuinely needed, report it as a recommendation and let the main session make it.")
    exit 2
}

# The refusal a command gets when it NAMES a protected path without being a read. It names the
# allowed forms, because a refusal an agent cannot act on is what teaches it to route around
# the guard -- and reading a protected file is legitimate work that has several spellings here.
function Deny-Segment([string]$seg, [string]$why, [string]$extra) {
    [Console]::Error.WriteLine("Scope guard refused '$seg'. It names a protected path -- that path is $why $extra`n`nA command that names a protected path must be plainly read-only, and this guard is an ALLOWLIST: it permits reading (cat, head, tail, wc, ls), searching (grep, rg, findstr, Select-String, Get-Content), read-only git (status, diff, log, show), the .NET read statics, and running the harness by script path (python <...>/qa-harness/<script>.py ...). Everything else is refused whatever it is called (PROTOCOL.md R4). To READ a protected file, use the Read or Grep tool or one of the readers above; to CHANGE one, report it as a recommendation and let the main session make it.")
    exit 2
}

if ($path) {
    foreach ($rule in $protected) { if ($p -imatch $rule.re) { Deny $path $rule.why } }
}

# Bash can reach the same paths without ever touching Edit/Write, so an Edit-only scope guard
# is a door with no wall beside it. But the fixer must still be able to RUN the metric --
# `python .../qa-harness/mutate.py <skill> --score` names a protected path and is legitimate.
# So the rule is not "mentions a protected path"; it is "names a protected path and is not
# plainly read-only".
if ($cmd) {

    # ------------------------------------------------------------------ tokenise into segments
    # Quote-aware, because the alternative is over-refusal: `grep -rn 'a; b' <protected>/` is ONE
    # command, and treating that semicolon as a separator would refuse a legitimate search.
    #
    # NO COMMENT HANDLING, DELIBERATELY. The sibling guard has to strip comments because its
    # allowlist judges every segment; this one judges only segments that NAME a protected path,
    # and text that is not executed cannot write. Not stripping also means this file cannot
    # repeat the sibling's `echo AAA#; <write>` defect, where a `#` that bash treats as an
    # ordinary word character was read as a comment and everything after it discarded. Splitting
    # happens first and unconditionally, so `... #; rm -rf <protected>` still arrives as two
    # segments and the second is still judged.
    #
    # BACKSLASH ESCAPING is honoured outside single quotes, for the reason the sibling documents:
    # without it `\"` desyncs quote parity from bash and separators stop splitting. Here that errs
    # toward refusal rather than toward allowing, but "safe direction" is not the same as
    # "correct", and an unquoted Windows path is full of backslashes.
    $segs = New-Object System.Collections.ArrayList
    $pipedIn = New-Object System.Collections.ArrayList   # was the separator BEFORE this segment a `|`?
    $sb = New-Object System.Text.StringBuilder
    $sq = $false; $dq = $false; $nextPiped = $false

    for ($i = 0; $i -lt $cmd.Length; $i++) {
        $ch = $cmd[$i]
        $next = if ($i + 1 -lt $cmd.Length) { $cmd[$i + 1] } else { [char]0 }

        if ($ch -eq '\' -and -not $sq -and $i + 1 -lt $cmd.Length) {
            [void]$sb.Append($ch); $i++; [void]$sb.Append($cmd[$i]); continue
        }
        if ($ch -eq "'" -and -not $dq) { $sq = -not $sq; [void]$sb.Append($ch); continue }
        if ($ch -eq '"' -and -not $sq) { $dq = -not $dq; [void]$sb.Append($ch); continue }

        # `>&` IS A REDIRECT, NOT A SEPARATOR. `2>&1` is one token to bash, and splitting on that
        # `&` cut `python .../mutate.py --score 2>&1 | tail` into a segment ending in a bare `2>`,
        # which matches no read-only row -- an over-refusal on an ordinary way to run the metric.
        if ($ch -eq '&' -and -not $sq -and -not $dq -and
            $sb.Length -gt 0 -and $sb[$sb.Length - 1] -eq '>') {
            [void]$sb.Append($ch); continue
        }

        if (-not $sq -and -not $dq -and
            ($ch -eq ';' -or $ch -eq "`n" -or $ch -eq "`r" -or $ch -eq '&' -or $ch -eq '|')) {
            # A single `|` pipes data onward; `||`, `&&`, `&`, `;` and a newline do not.
            # `|&` DOES: it is bash's `2>&1 |`, one operator spelled in two characters. Reading it
            # as `|` followed by a separate `&` closed an empty segment in between and left the
            # real downstream command marked as NOT piped, so the pipeline carry stopped there --
            # measured: `cat <protected>/list.txt |& xargs rm` came back ALLOW while the same
            # command with a plain `|` was refused.
            $isPipe = ($ch -eq '|' -and $next -ne '|')
            [void]$segs.Add($sb.ToString()); [void]$pipedIn.Add($nextPiped)
            $sb.Clear() | Out-Null
            $nextPiped = $isPipe
            if (($ch -eq '|' -and ($next -eq '|' -or $next -eq '&')) -or
                ($ch -eq '&' -and $next -eq '&')) { $i++ }
            continue
        }
        [void]$sb.Append($ch)
    }
    [void]$segs.Add($sb.ToString()); [void]$pipedIn.Add($nextPiped)

    # ------------------------------------------------------------------ the read-only allowlist
    # Anchored and matched against the WHOLE segment, so no row can admit a command by matching
    # its prefix. A trailing `# comment` is tolerated; the splitter has already dealt with any
    # separator inside it.
    #
    # $ARG is one argument: a quoted string, or a bare token carrying no shell metacharacter. `$`
    # is deliberately allowed (`$HOME/.claude/...` and `${HOME}` are ordinary spellings); `$(` and
    # backticks are refused separately, for the whole segment.
    $ARG  = '(?:"[^"`]*"|''[^'']*''|[^\s"''`;|&<>()]+)'
    $BARE = '[^\s"''`;|&<>()]*'
    # A REDIRECT IS A WRITE, so a naming segment may redirect only to a sink that discards or to a
    # real temp root -- location, not name, the rule the sibling guard reaches by another road.
    # `2>&1` is a duplication rather than a file and is admitted separately, because refusing it
    # would refuse `python .../mutate.py --score 2>&1 | tail`.
    $SINK = '(?:/dev/null|NUL|nul|\$null' +
            '|(?:[A-Za-z]:)?[\\/](?:temp|tmp)[\\/]' + $BARE +
            '|(?:' + $BARE + '[\\/])?AppData[\\/]Local[\\/]Temp[\\/]' + $BARE + ')'
    $TAIL = '(?:\s+(?:' + $ARG + '|\d?>{1,2}\s*' + $SINK + '|\d?>&\d?))*'
    # THE HARNESS ENTRYPOINT: an interpreter running a SCRIPT BY PATH. `-c`, `-e` and `-m` are
    # absent on purpose -- an inline program carries arbitrary code (it is how the guard was
    # neutralised in an earlier round) and `-m pip install --target <protected>` is a write. The
    # metric has never needed either. `(?!-)` in front stops `python -cfoo.py`, which python reads
    # as `-c foo.py`, from passing as a script path because the token happens to end in `.py`.
    $PYFILE = '(?:"[^"`]*\.py"|''[^'']*\.py''|' + $BARE + '\.py)'
    # git's read subcommands, minus the one flag of theirs that writes a file: `git diff
    # --output=<protected>` is a write wearing a read's name, while `--oneline` is not, and the
    # lookahead discriminates. `-c key=value` is NOT admitted -- `-c core.pager=<anything>` runs it.
    $gitRead = 'status|diff|log|show|blame|describe|rev-parse|rev-list|ls-files|ls-tree|cat-file|' +
               'shortlog|whatchanged|diff-tree|merge-base|count-objects|check-ignore|grep|' +
               'for-each-ref|symbolic-ref'
    $GITTAIL = '(?:\s+(?:(?!--?o(?:utput)?\b|--output=)' + $ARG +
               '|\d?>{1,2}\s*' + $SINK + '|\d?>&\d?))*'

    # EVERY ENTRY IS PARENTHESISED, and that is not decoration. PowerShell binds `,` TIGHTER than
    # `+`, so `@( 'a' + $TAIL, 'b' + $TAIL )` is not a two-element array -- it is ONE string,
    # `'a' + ($TAIL,'b') + $TAIL`, space-joined by the array-to-string cast. Measured here: an
    # unparenthesised six-row list came back as `count=1` and every legitimate read was refused
    # while every block still passed, which is the most convincing possible wrong answer. The
    # sibling guard's `$allowed` parenthesises for exactly this reason.
    $readOnly = @(
        # SEARCHERS. The daily work of a code reviewer, and the reason this is an allowlist rather
        # than "refuse anything naming a cmdlet": `grep -c "Set-Content" <protected>/qa-harness/`
        # writes nothing and must pass.
        ('(?:grep|egrep|fgrep|zgrep|rg|ag|ack|findstr)' + $TAIL),
        # READERS.
        ('(?:cat|head|tail|wc|ls|dir|nl|file|stat|du|tree|basename|dirname|realpath|readlink|' +
         'cmp|diff|sha1sum|sha256sum|md5sum|cksum|od|xxd|strings)' + $TAIL),
        # THE CONSTRAINING CASE: running the metric and the invariant checkers, both of which name
        # a protected directory and are the fixer's legitimate job.
        ('(?:python3?|py)(?:\s+-(?:u|B|E|I|q|s|S|O|OO|W\s+\S+|X\s+\S+))*\s+(?!-)' + $PYFILE + $TAIL),
        # READ-ONLY GIT. The fixer's own body tells it to run `git diff` and `git status`, and the
        # QA target is itself a git repo, so `git -C <protected> log` is real work.
        ('git(?:\s+(?:-C\s+' + $ARG + '|--no-pager|--git-dir=' + $ARG + '|--work-tree=' + $ARG + '))*' +
         '\s+(?:' + $gitRead + ')\b' + $GITTAIL),
        # POWERSHELL READ CMDLETS and their built-in aliases. Reviewing PowerShell is routine for
        # this suite now, and `Get-Content <protected>/hooks/x.ps1` is how it reads a file.
        ('(?:Get-Content|gc|Get-ChildItem|gci|Get-Item|gi|Get-ItemProperty|Get-FileHash|' +
         'Select-String|sls|Test-Path|Resolve-Path|Split-Path|Import-Csv|ConvertFrom-Json|' +
         'Measure-Object|Compare-Object|Format-Hex)' + $TAIL),
        # .NET READ STATICS. The write side is deliberately absent, so `[IO.File]::WriteAllText`,
        # `[IO.File]::AppendText`, `[IO.StreamWriter]::new` and `[IO.FileStream]::new(...,'Create')`
        # all fail by omission -- which is the point, since the last two are a type and a
        # constructor that no name list in this file had ever heard of.
        ('\[(?:System\.)?IO\.(?:File|Directory|Path|FileInfo|DirectoryInfo)\]::' +
         '(?:ReadAllText|ReadAllLines|ReadAllBytes|Exists|OpenText|OpenRead|GetFiles|GetDirectories|' +
         'EnumerateFiles|EnumerateDirectories|GetFileName|GetFullPath|GetDirectoryName|' +
         'GetLastWriteTime(?:Utc)?|GetCreationTime(?:Utc)?)\s*\([^)]*\)' + $TAIL)
    )

    # FAILS CLOSED ON A TIMEOUT. This hook runs in front of every Bash call the fixer makes, so a
    # pattern that cannot be evaluated in bounded time must not hold the session open -- and a
    # command that cannot be checked is not a read.
    $MATCH_TIMEOUT = [TimeSpan]::FromSeconds(2)
    function Test-ReadOnly([string]$s) {
        foreach ($r in $readOnly) {
            try {
                if ([regex]::IsMatch($s, '^\s*(?:' + $r + ')\s*(?:#[^\n]*)?$',
                                     [Text.RegularExpressions.RegexOptions]::IgnoreCase,
                                     $MATCH_TIMEOUT)) { return $true }
            } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
                return $false
            }
        }
        return $false
    }

    # ------------------------------------ two whole-segment refusals, checked BEFORE any path rule
    #
    # PER SEGMENT, NOT PER COMMAND, and the git one is why that matters. Written against `$cmd` it
    # asked "does this command contain a read subcommand anywhere?", so one harmless read bought a
    # pass for every git call beside it -- measured: `git log ; git -C <...>/.claude reset --hard`
    # came back ALLOW. Same defect the sibling guard's structural rule 1 exists for, reproduced in
    # a file whose own decision loop already obeys it.
    foreach ($seg in $segs) {
        $s = ([string]$seg).Trim()
        if (-not $s) { continue }

        # -EncodedCommand: refused wherever it appears, before anything looks at paths. Base64
        # hides the target from every check in this file, so it defeats the design rather than
        # bending it. ANCHORED ON THE COMMAND HEAD so that SEARCHING for the string
        # (`grep -rn -EncodedCommand notes.md`) is untouched -- auditing PowerShell is this suite's
        # own work. The alternation is a family because PowerShell binds prefixes: `-e`, `-ec`,
        # `-en` and `-enc...` all reach -EncodedCommand, while `-ex...` reaches -ExecutionPolicy,
        # which is why `e` carries a word boundary.
        if ($s -imatch '^\s*(?:\S*[\\/])?(?:powershell|pwsh)(?:\.exe)?\b' -and
            $s -imatch '\s-{1,2}(?:e|ec|en|enc\w*)\b') {
            [Console]::Error.WriteLine("Scope guard refused '$s'. -EncodedCommand (and its prefixes -e/-ec/-en/-enc) carries a base64 payload, which hides the path it writes to from every check this guard makes. The fixer has no legitimate use for it: run the command in plain text so it can be read, or report the change as a recommendation (PROTOCOL.md R4).")
            exit 2
        }

        # GIT ROOTED IN A .claude TREE. The one shape the path rules cannot see, because it names
        # no protected path at all:
        #     git -C <...>/.claude checkout -- qa-history/   (reverts the ledger)
        #     git -C <...>/.claude reset --hard              (reverts everything, from anywhere in
        #                                                     the repo -- git works on the repo,
        #                                                     not on the directory you point it at)
        # `.claude` alone is NOT protected: `.claude/skills/<skill>` is a legitimate fixer target
        # and blanket-protecting the root would refuse real work. So the rule is about the
        # SUBCOMMAND, and it only fires when git has been ROOTED there explicitly by -C,
        # --git-dir or --work-tree. That last condition is what keeps
        # `git commit -m "update .claude docs"` out of it -- a mention in a message is not a root.
        if ($s -imatch '^\s*git\b.*?(?:-C\s+|--git-dir=|--work-tree=)["'']?\S*\.claude' -and
            $s -notmatch ('^\s*git\b(?:\s+(?:-C\s+\S+|--no-pager|--git-dir=\S+|--work-tree=\S+))*' +
                          '\s+(?:' + $gitRead + ')\b')) {
            [Console]::Error.WriteLine("Scope guard refused '$s'. It roots git in a .claude tree and its subcommand is not a read (status, diff, log, show, blame, ls-files, rev-parse, grep and friends are), so it can reach the ledgers, the harness, the agent definitions or the guards through a path this guard cannot resolve. Read-only git is allowed; changing state in that tree is the main session's job (PROTOCOL.md R4).")
            exit 2
        }
    }

    # ------------------------------------------------------------------ extraction, as a backstop
    # Kept behind the allowlist as defence in depth: it catches a write whose target is protected
    # in a form the allowlist above might not have reached. It is no longer the decision.
    $targets = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($cmd, '(?:>>?|\btee\b(?:\s+-a)?)\s*(?<t>[^\s|;&<>]+)')) {
        $targets.Add($m.Groups['t'].Value.Trim('"', "'"))
    }
    # COMMAND POSITION, not "anywhere in the string". Unanchored, `\brm\b` matched inside a search
    # PATTERN, so `grep -rn "rm -rf ~/.claude/hooks" notes.md` extracted a protected target and was
    # refused -- the same over-refusal class as the `-c` one below. Anchoring costs no coverage
    # here, because a mutator that is NOT at command position (`sudo rm`, `xargs rm`, `env rm`)
    # still names a protected path and therefore still has to clear the read-only allowlist, where
    # it fails by omission.
    $CP = '(?:^|[;|&({`\n]|\$\()\s*'
    foreach ($m in [regex]::Matches($cmd,
            $CP + '(?:rm|rmdir|cp|mv|ln|touch|mkdir|shred|unlink|truncate)\b(?<args>(?:\s+-{1,2}[\w-]+)*(?:\s+[^\s|;&]+)+)')) {
        foreach ($a in ($m.Groups['args'].Value -split '\s+')) {
            if ($a -and $a -notmatch '^-') { $targets.Add($a.Trim('"', "'")) }
        }
    }
    foreach ($m in [regex]::Matches($cmd,
            $CP + 'sed\b[^|;&]*?(?:-i|--in-place)\S*\s+(?:''[^'']*''|"[^"]*"|\S+)\s+(?<t>[^\s|;&]+)')) {
        $targets.Add($m.Groups['t'].Value.Trim('"', "'"))
    }
    # POWERSHELL CMDLET WRITES. The POSIX pass above cannot see them, and the gap was measured
    # 2026-08-23: `Set-Content`, `Out-File`, `New-Item` and `Add-Content` all reached
    # ~/.claude/agents and ~/.claude/qa-history UNBLOCKED, while every POSIX spelling of the same
    # write was refused. The guard's coverage therefore depended on which language the fixer
    # happened to reach for -- and this suite has made PowerShell traffic routine, which turns a
    # latent hole into a load-bearing one.
    #
    # TWO REASONS THE MUTATOR PASS ABOVE MISSES THESE, both of which this block has to handle:
    #   1. `Set-Content` names no POSIX verb, so that alternation never matches.
    #   2. Its target arrives as the VALUE of a NAMED PARAMETER (`-Path X`), and the mutator pass
    #      discards every token starting with `-`. A named-parameter value was only ever reachable
    #      positionally, so writing `-Path` was by itself enough to defeat it.
    #
    # ANCHORED AT COMMAND POSITION, not exempted by command head. The first version skipped the
    # whole extractor whenever `$cmd` STARTED with a searcher, which meant one leading `grep`
    # disabled it for every later segment -- measured:
    #   Set-Content -Path <protected> 'x'                 -> BLOCK  (correct)
    #   grep -rn x . ; Set-Content -Path <protected> 'x'   -> ALLOW  (the whole pass was skipped)
    # Anchoring instead means a cmdlet name inside a search PATTERN never matches (the character
    # before it is a quote, which is not a command position), while a real invocation after a
    # separator does.
    #
    # THE NESTED-SHELL ALTERNATIVE NOW REQUIRES A POWERSHELL HEAD, and that is a FIX rather than a
    # tightening for its own sake. It used to read `-(?:c|Command)\s+["']`, which is equally the
    # shape of `grep -c "Set-Content"` -- so COUNTING matches of a cmdlet name inside a protected
    # directory was refused as though it were a nested shell writing one (measured 2026-08-25:
    # `grep -c "Set-Content" <protected>/qa-harness/` -> BLOCK, a real over-refusal on the exact
    # command reviewing PowerShell generates). Requiring the head removes that false positive and
    # covers `-co`/`-com`/`-comm` into the bargain, which all bind to -Command by prefix.
    $psCP = '(?:^|[;|&(`\n]|\$\(|(?:powershell|pwsh)(?:\.exe)?(?:\s+-\w+)*\s+-c\w*\s+["''])\s*'

    # NAMES ARE NOT THE CLASS, and matching them literally is the defect this suite already
    # rejected for `rm`. Three spellings reached protected paths past the first version:
    #   sc -Path <protected> 'x'                     -- the built-in ALIAS for Set-Content
    #   [IO.File]::WriteAllText('<protected>','p')   -- a .NET static, no cmdlet involved
    #   Set-Content -Pat:<protected> 'x'             -- PowerShell binds any unambiguous PREFIX
    # All three are covered here; the allowlist above is what covers the spellings nobody has
    # thought of yet.
    $psWriters = 'Set-Content|Out-File|Add-Content|New-Item|Clear-Content|Remove-Item|' +
                 'Rename-Item|Move-Item|Copy-Item|Set-ItemProperty|New-ItemProperty|' +
                 'Tee-Object|Export-Csv|Export-Clixml|Export-CliXml|Set-Acl|Set-Item|' +
                 'Start-Transcript|Out-Csv|ConvertTo-Json|Export-ModuleMember|' +
                 # built-in aliases for the above, which are what a terse writer actually types
                 'sc|ni|ri|ac|clc|cpi|mi|move|rni|si|sp|epcsv|oh|rd|del|erase|md'
    # Matched by PREFIX: PowerShell accepts any unambiguous abbreviation, so `-Pat`, `-Li` and
    # `-Dest` all bind. Over-collecting a token is free -- only a PROTECTED path triggers a Deny.
    $psTargetParams = @('Path', 'LiteralPath', 'FilePath', 'Destination', 'DestinationPath',
                        'OutFile', 'Target', 'NewName', 'ItemType', 'Value')

    function Test-TargetParam([string]$tok) {
        # Returns the inline value for `-Name:value`, '' for a bare `-Name`, or $null if this
        # token is not an abbreviation of any target parameter.
        if ($tok -notmatch '^-{1,2}([A-Za-z]+)(?::(.*))?$') { return $null }
        $name = $Matches[1]
        $inline = $Matches[2]
        foreach ($tp in $psTargetParams) {
            if ($tp.StartsWith($name, [System.StringComparison]::OrdinalIgnoreCase)) {
                if ($null -eq $inline) { return '' }
                return $inline
            }
        }
        return $null
    }

    foreach ($m in [regex]::Matches($cmd, "$psCP(?:$psWriters)\b(?<args>[^;|&]*)",
                                    [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        $toks = @($m.Groups['args'].Value -split '\s+' | Where-Object { $_ })
        for ($j = 0; $j -lt $toks.Count; $j++) {
            $tok = $toks[$j]
            $tp = Test-TargetParam $tok
            if ($null -ne $tp) {
                if ($tp -ne '') {
                    $targets.Add($tp.Trim('"', "'"))          # -Path:value
                } elseif ($j + 1 -lt $toks.Count) {
                    $targets.Add($toks[$j + 1].Trim('"', "'")) # -Path value
                }
            } elseif ($tok -notmatch '^-') {
                # Positional: `Set-Content <path> <value>` binds -Path positionally. Collecting
                # the value token too is harmless -- only a PROTECTED path can trigger a Deny.
                $targets.Add($tok.Trim('"', "'"))
            }
        }
    }

    # .NET STATIC WRITERS. No cmdlet name appears at all, so every name-based pass is blind to
    # them. `[IO.File]::WriteAllText('<protected>', 'payload')` is one expression and needs no
    # shell verb. Matched on the method name, with the first quoted argument taken as the target.
    $netWriters = 'WriteAllText|WriteAllLines|WriteAllBytes|AppendAllText|AppendAllLines|' +
                  'Create|CreateText|Copy|Move|Delete|Replace|CreateDirectory|SetAttributes'
    foreach ($m in [regex]::Matches($cmd,
            "\[(?:System\.)?IO\.(?:File|Directory|FileInfo|DirectoryInfo)\]::(?:$netWriters)\s*\(\s*(?<t>[^,)]+)",
            [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        $targets.Add($m.Groups['t'].Value.Trim().Trim('"', "'"))
    }

    foreach ($t in $targets) {
        $tn = Get-NormalPath $t
        foreach ($rule in $protected) { if ($tn -imatch $rule.re) { Deny $t $rule.why } }
    }

    # ------------------------------------------------------------------ THE DECISION
    # A segment that NAMES a protected path must be plainly read-only, and so must every segment
    # downstream of it in the same pipeline.
    #
    # $verifiedTo IS WHAT KEEPS THIS LINEAR. Without it, N naming segments in one pipeline each
    # walk the whole remainder -- O(N^2) allowlist matches, and this hook runs in front of every
    # tool call the fixer makes. Measured on a 500-hop pipeline of legitimate reads: 4659 ms
    # before, 749 ms after (min of 5, same command, same session; ~420 ms of that is PowerShell
    # process start, which every case here pays). Sound because a segment already
    # proved read-only is read-only whatever reached it, and the walk only ever moves forward.
    $verifiedTo = -1
    for ($k = 0; $k -lt $segs.Count; $k++) {
        $segRaw = ([string]$segs[$k]).Trim()
        if (-not $segRaw) { continue }
        # Mention detection reads a NORMALISED copy, so `C:\Users\x\.claude\hooks`,
        # `C:/Users/x/.claude//hooks` and `C:/Users/x/.claude/skills/../hooks` are one path. The
        # ALLOWLIST still matches the REAL text: a Windows path token is full of backslashes, and
        # normalising what gets judged would change which command is being judged.
        $segNorm = Get-NormalPath $segRaw
        $hit = $null
        foreach ($rule in $protected) { if ($segNorm -imatch $rule.re) { $hit = $rule; break } }
        if ($null -eq $hit) { continue }

        $j = $k
        while ($true) {
            if ($j -gt $verifiedTo) {
                $s = ([string]$segs[$j]).Trim()
                if ($s) {
                    if ($s -match '\$\(|`') {
                        Deny-Segment $s $hit.why "Command substitution is a command in its own right, and this guard would have to parse it recursively to know what it writes."
                    }
                    if (-not (Test-ReadOnly $s)) { Deny-Segment $s $hit.why '' }
                }
                $verifiedTo = $j
            }
            # Rule 2: follow the data. `Get-ChildItem <protected> | Remove-Item` names the path in
            # the read half and does the write one segment later, where no protected path appears.
            if (($j + 1) -lt $segs.Count -and $pipedIn[$j + 1]) { $j++ } else { break }
        }
    }
}

exit 0
