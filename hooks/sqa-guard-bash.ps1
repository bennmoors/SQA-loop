# sqa-guard-bash.ps1 -- PreToolUse guard for the SQA subagent suite.
#
# WIRED AND LIVE. It is referenced from the `hooks:` block of all six review specialists
# (sqa-lead, sqa-functional, sqa-embedded, sqa-numerical, sqa-security, sqa-efficiency) and is
# re-applied a second time, from inside `~/.claude/tools/perf_probe.py`, to every `--run` command
# that wrapper is handed. The header here used to read "CANDIDATE ... do not wire this into agent
# frontmatter", which was stale by weeks and contradicted the frontmatter of every file that
# already used it (corrected 2026-08-17).
#
# WHY THE SHAPE CHANGED. The denylist was measured at 19 bypasses across 6 unrelated classes in
# a single adversarial pass -- comment suffix, newline chain, prefix word / absolute path, nested
# shell, `;`-bearing interpreter one-liner, here-doc. Patching them produced a longer denylist
# and no reason to believe the list was finally complete: every must-block case had been the
# OBVIOUS spelling of its verb, so the score measured the author's imagination, not the guard.
# `/bin/rm`, `env rm`, `bash -c 'rm ...'` and `rm -rf x # git status` all name the same verb and
# only one of them was listed.
#
# An allowlist inverts the burden. The SQA agents' legitimate needs are narrow and enumerable:
# read git history, search files, read files, run tests. Anything not on that list is refused
# whatever it is called, so a novel spelling of `rm` fails for the same reason a novel spelling
# of anything else does -- it is not a read.
#
# THREE STRUCTURAL RULES, each closing a whole bypass class rather than a case:
#
#   1. EVERY SEGMENT MUST BE ALLOWED. The command is split on unquoted separators and each
#      segment is matched WHOLE. `git status && rm -rf build/` cannot pass by containing an
#      allowed prefix -- RUN 1's fast path did exactly that. This kills chaining outright.
#   2. COMMENTS ARE STRIPPED, NOT MATCHED. `rm -rf build/ # git status` leaves `rm -rf build/`,
#      which is not on the list. The old fast path matched `git status` as a substring and
#      allowed the whole thing.
#   3. NO COMMAND SUBSTITUTION. `$(...)` and backticks are refused outright: their contents are
#      a command this guard would have to parse recursively, and no legitimate SQA command in
#      two months of corpus cases has needed one.
#
# THE DENYLIST IS RETAINED BEHIND THE ALLOWLIST, as defence in depth. It is no longer the
# decision -- but for the two forms that legitimately carry arbitrary code (`python -c`,
# `node -e`, which sqa-numerical and sqa-functional both instruct agents to use for scratch
# drivers), the allowlist can only approve the FORM. The denylist is what inspects the payload.
# That is the one place where the old shape's weakness survives, and it is documented rather
# than hidden.
#
# Contract: exit 0 = allow, exit 2 = block (stderr is fed back to Claude as the reason).
# Fails OPEN on a parse error, CLOSED on a regex timeout -- a hang is an attack, not a typo.
#
# WIRING: `command: "& 'this.ps1'; exit $LASTEXITCODE"`. Without the `; exit $LASTEXITCODE` the
# script's exit 2 reaches the caller as 0 and this file is inert. Measured, twice.

$ErrorActionPreference = 'Stop'
try {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { exit 0 }
    $payload = $raw | ConvertFrom-Json
    $cmd = ''
    if ($payload.tool_input -and $payload.tool_input.command) {
        $cmd = [string]$payload.tool_input.command
    }
    if ([string]::IsNullOrWhiteSpace($cmd)) { exit 0 }
} catch {
    exit 0
}

function Deny([string]$why) {
    [Console]::Error.WriteLine("SQA guard: $why`n`nThe SQA suite is review-and-verify only, and this guard is an ALLOWLIST: it permits reading git history, searching and reading files, and running tests, and refuses everything else. Never commit, delete, move, chmod, install packages, or write into repository/source files. Put temporary artifacts in the system temp directory. If you need a form that is genuinely read-only and not on the list, report it as a recommendation rather than working around the guard.")
    exit 2
}

# ------------------------------------------------------------------ time budget
#
# THE CLOCK STARTS HERE, BEFORE ANY WORK, and that placement is the whole fix.
#
# v1 of this budget started the stopwatch just above the allowlist matcher and called
# Assert-Budget from exactly ONE site, inside Matches-Any. The tokeniser ran before the clock
# existed, and the redirect, here-doc and denylist scans never consulted it -- so the advertised
# bound covered one of four phases. Measured worst case 7775 ms ending in ALLOW, with no refusal
# emitted. An advertised bound that is false is worse than no bound, because it is quoted.
#
# WHY THIS MATTERS MORE THAN IT LOOKS. The denylist's interpreter-payload rules are genuinely
# quadratic and are DELIBERATELY left unbounded (see the note at the denylist): bounding their
# scanning spans re-opened a write channel at ~620 characters of padding, which is a far worse
# defect than being slow. So this budget is now the ONLY thing bounding time, and it has to cover
# every phase or it bounds nothing.
#
# It also removes a dependency on harness behaviour. Because the guard reaches its own budget and
# calls Deny itself, it never matters whether a PreToolUse hook that TIMES OUT is treated as
# blocking or non-blocking -- we exit 2 under our own power rather than hanging and finding out.
$MATCH_TIMEOUT = [TimeSpan]::FromSeconds(2)
$TOTAL_BUDGET_MS = 5000
$GUARD_CLOCK = [System.Diagnostics.Stopwatch]::StartNew()

function Assert-Budget {
    if ($GUARD_CLOCK.ElapsedMilliseconds -gt $TOTAL_BUDGET_MS) {
        Deny("checking this command exceeded the guard's total time budget of ${TOTAL_BUDGET_MS}ms. It fails CLOSED: a command that cannot be checked in bounded time is not allowed through. This is usually a very long or deeply nested command -- split it into separate calls.")
    }
}

# ------------------------------------------------------------------ tokenise into segments
# Quote-aware: separators inside quotes are literal. `grep -rn 'a; b' .` is ONE segment, and
# treating that semicolon as a separator would refuse a legitimate search.
#
# SEARCHER-QUOTE MASKING, added 2026-08-24, built in the SAME pass so nothing is re-derived.
# Alongside the real segments this builds a MASKED copy in which the quoted arguments of a
# read-only searcher are blanked to spaces. The masked copy is what the redirect and denylist
# scans read; the allowlist still matches the REAL text.
#
# The defect it fixes was measured against the live guard:
#     grep -rn "echo x > out.txt" deploy.sh    -> BLOCK   (redirect scan hit the search STRING)
#     grep -rn "| Set-Content" scripts/        -> BLOCK   (denylist hit inside the search STRING)
#     grep -rn "Set-Content" scripts/          -> ALLOW   (bare name was already fine)
# Searching for the text of a dangerous command is the daily work of a code reviewer, and this
# suite now makes PowerShell review routine, so that traffic is about to become constant.
# guard_corpus.py:22 already states the motive; blocking it is what teaches agents to route around
# the guard.
#
# WHY THIS CANNOT WEAKEN THE GUARD. Masking applies only INSIDE quotes, and only in a segment
# whose HEAD is a read-only searcher. A real `cat x | Set-Content y` is split at the unquoted `|`
# by this very loop, so its second segment's head is `Set-Content`, which no allowlist row admits
# -- it dies at the allowlist, before the denylist is consulted at all. Masking a quoted span
# therefore removes text that could only ever have been a false positive: an unquoted payload is
# untouched, and a quoted one is not a command.
$segments = New-Object System.Collections.ArrayList
$maskedSegments = New-Object System.Collections.ArrayList
$maskedAll = New-Object System.Text.StringBuilder
$buf = New-Object System.Text.StringBuilder
$mbuf = New-Object System.Text.StringBuilder
$sq = $false; $dq = $false
$segIsSearcher = $false
$SEARCHER_HEAD = '^\s*(?:grep|egrep|fgrep|rg|ag|ack|findstr|Select-String)\b'

# Append to the real buffer and to the masked buffer, blanking the char when it sits inside a
# searcher's quoted argument.
function Add-Char([char]$c, [bool]$masked) {
    [void]$buf.Append($c)
    if ($masked) { [void]$mbuf.Append(' '); [void]$maskedAll.Append(' ') }
    else         { [void]$mbuf.Append($c);  [void]$maskedAll.Append($c) }
}
function Close-Segment([char]$sep) {
    [void]$segments.Add($buf.ToString())
    [void]$maskedSegments.Add($mbuf.ToString())
    $buf.Clear() | Out-Null; $mbuf.Clear() | Out-Null
    if ($sep -ne [char]0) { [void]$maskedAll.Append($sep) }
}

for ($i = 0; $i -lt $cmd.Length; $i++) {
    if (($i -band 1023) -eq 0) { Assert-Budget }
    $ch = $cmd[$i]
    $next = if ($i + 1 -lt $cmd.Length) { $cmd[$i + 1] } else { [char]0 }

    # BACKSLASH ESCAPING. Outside single quotes, `\` makes the NEXT character literal, so `\"`
    # neither opens nor closes a quoted region. Without this the tokeniser's quote parity desyncs
    # from the shell's, and everything after the stray quote is treated as quoted: separators stop
    # splitting and the redirect and denylist scans go blind.
    #
    # MEASURED, on the live guard, before this fix:
    #   grep -rn "ab"   README.md ; cd /   -> BLOCK   (correct)
    #   grep -rn "a\"b" README.md ; cd /   -> ALLOW   (one backslash, and `cd /` executed)
    # It predates today's masking -- the original guard is bypassed identically -- but masking
    # widened the blast radius, because the desynced region is now blanked as well as unsplit.
    #
    # BOTH characters are appended, so the text the allowlist matches is unchanged; the only
    # effect is that the escaped character cannot act as a quote or a separator. That is also why
    # an unquoted Windows path (`C:\Users\...`) is safe here: `\U` appends `\` then `U`.
    # Single quotes are excluded because bash gives backslash no special meaning inside them.
    if ($ch -eq '\' -and -not $sq -and $i + 1 -lt $cmd.Length) {
        $escMask = ($segIsSearcher -and $dq)
        Add-Char $ch $escMask
        $i++
        Add-Char $cmd[$i] $escMask
        continue
    }

    # Decide searcher-ness at the moment a quote OPENS, using the segment text seen so far. The
    # head always precedes the first quote in any real invocation (`grep -rn "..."`).
    if (($ch -eq "'" -and -not $dq) -or ($ch -eq '"' -and -not $sq)) {
        if (-not $sq -and -not $dq) {
            $segIsSearcher = ($buf.ToString() -match $SEARCHER_HEAD)
        }
    }

    if ($ch -eq "'" -and -not $dq) { $sq = -not $sq; Add-Char $ch $false; continue }
    if ($ch -eq '"' -and -not $sq) { $dq = -not $dq; Add-Char $ch $false; continue }

    # Inside a searcher's quoted argument: blank it in the masked copy only.
    if (($sq -or $dq) -and $segIsSearcher) { Add-Char $ch $true; continue }

    if (-not $sq -and -not $dq) {
        # Command substitution: refused outright (rule 3).
        if (($ch -eq '$' -and $next -eq '(') -or $ch -eq '`') {
            Deny("command substitution is not permitted (found '$ch'). Its contents are a command in their own right; run the inner command on its own so it can be checked.")
        }
        # Comment: the rest of the LINE is not executed, so drop it (rule 2).
        #
        # THE NEWLINE THAT ENDS A COMMENT IS STILL A SEPARATOR, and forgetting that was a real
        # bypass. The `while` below stops ON the newline, then `continue` hands control to the
        # for-loop's own `$i++`, which steps PAST it -- so the newline was never processed as a
        # separator and the two lines fused into ONE segment. A greedy allowlist row then absorbed
        # the lot:
        #     ls # note<LF>cd /   ->  segment `ls  cd /`  ->  matched `(?:ls|dir)\s*.*`  ->  ALLOW
        # Measured on the live guard, and on the ORIGINAL guard too -- it predates today's work and
        # the corpus never caught it because `evade-comment-suffix` and `evade-newline-chain` are
        # separate cases that are never composed.
        # A `#` STARTS A COMMENT ONLY AT A WORD BOUNDARY. That is bash's actual rule, and getting
        # it wrong was a total allowlist bypass rather than a refinement:
        #     echo AAA#; echo BBB
        # bash sees `AAA#` as one ordinary word and runs BOTH commands. The guard treated the `#`
        # as a comment, discarded everything after it, and judged only `echo AAA`. Reproduced live
        # through a guarded Bash tool -- both lines printed while the guard had approved one.
        # Pre-existing, and invisible to the corpus because every `#` case put a space in front.
        #
        # The boundary is: start of input, or preceded by whitespace, or preceded by a separator
        # (the previous character having been consumed as one). `$prevCh` is 0 at start of input,
        # which is why the test reads as "not a word character before it".
        $prevCh = if ($i -gt 0) { $cmd[$i - 1] } else { [char]0 }
        $atWordStart = ($i -eq 0) -or ($prevCh -eq [char]0) -or
                       [char]::IsWhiteSpace($prevCh) -or
                       ($prevCh -eq ';') -or ($prevCh -eq '|') -or ($prevCh -eq '&')
        if ($ch -eq '#' -and $atWordStart) {
            while ($i -lt $cmd.Length -and $cmd[$i] -ne "`n") { $i++ }
            # THE NEWLINE THAT ENDS A COMMENT IS STILL A SEPARATOR. The loop above stops ON it and
            # `continue` hands control to the for-loop's own `$i++`, which steps PAST it -- so
            # without this the two lines fused into ONE segment and a greedy row absorbed the lot
            # (`ls # note<LF>cd /` -> ALLOW, measured on the original guard too).
            if ($i -lt $cmd.Length) { Close-Segment $cmd[$i]; $segIsSearcher = $false }
            continue
        }
        # Every separator below ALSO ends the searcher context: the next segment gets its own head.
        if ($ch -eq ';' -or $ch -eq "`n" -or $ch -eq "`r") {
            Close-Segment $ch; $segIsSearcher = $false; continue
        }
        if (($ch -eq '&' -and $next -eq '&') -or ($ch -eq '|' -and $next -eq '|')) {
            Close-Segment $ch; [void]$maskedAll.Append($next); $segIsSearcher = $false; $i++; continue
        }
        if ($ch -eq '|') {
            Close-Segment $ch; $segIsSearcher = $false; continue
        }
        # A single trailing `&` backgrounds the command; treat as a separator too.
        if ($ch -eq '&') {
            Close-Segment $ch; $segIsSearcher = $false; continue
        }
    }
    Add-Char $ch $false
}
Close-Segment ([char]0)
$maskedCmd = $maskedAll.ToString()

# ------------------------------------------------------------------ allowlisted command forms
# Anchored and matched against the WHOLE segment. Each entry is `^\s*<form>\s*$`.
#
# Read-only git subcommands. The `(?:-C\s+\S+\s+|-c\s+\S+\s+|--git-dir=\S+\s+)*` prefix is
# allowed because it is how a repo is addressed, but it CANNOT smuggle a write: the subcommand
# that follows still has to be one of these names, so `git -C repo commit` is refused by
# omission rather than by a pattern that has to anticipate it.
# ------------------------------------------------------------------ TIER 2 SANDBOX FRAGMENT
# A path INSIDE a temp directory. Tier 2 tools (bats, Invoke-Pester) execute the target's own
# code, so the operating policy is that they never touch the live repo or the installed
# ~/.claude copy -- only a disposable per-session copy staged into temp. This fragment is how
# that is enforced in the guard rather than merely instructed in an agent body.
#
# It matches the same directory shape as $tempOk below (a `temp`/`tmp` path segment), but is NOT
# anchored to the whole token, because here it is one argument among several. It also covers the
# WSL spelling `/mnt/c/Users/.../AppData/Local/Temp/...`, which is how bats sees a staged copy.
#
# `..` IS HANDLED SEPARATELY, by a `(?!.*\.\.)` lookahead on each Tier 2 row. Prefix matching on
# an un-normalised path is not a containment check -- `/tmp/../hooks/guard.ps1` starts with an
# approved prefix and lands in the repo. That was a measured bypass against the redirect rule and
# it would be the same bypass here.
# A REAL TEMP ROOT, not merely a directory called "tmp". The first version matched any path with
# a `temp`/`tmp` SEGMENT anywhere in it, which `<repo>/tmp/evil.sh` satisfies -- so a Tier 2 tool
# could be pointed at a directory the repo itself controls, and the containment claim in the docs
# was false. Location, not name: an absolute `/tmp`, an absolute `<drive>:\Temp`, or the real
# Windows per-user temp under `AppData\Local\Temp` (which also covers the WSL spelling
# `/mnt/c/Users/<u>/AppData/Local/Temp/...`).
$tempRoot = '(?:(?:[A-Za-z]:)?[\\/](?:temp|tmp)[\\/]' +
            '|(?:[^\s;|&]*[\\/])?AppData[\\/]Local[\\/]Temp[\\/])'
$tempArg = $tempRoot + '[^\s;|&]*'

# The same shape, but tolerating the SINGLE QUOTES shlex.join adds. perf_probe derives the string
# it shows this guard with shlex.join, which quotes any token containing a backslash -- and
# Path.resolve() always produces backslashes on Windows. An unquoted-only pattern would refuse
# every real `--lang ps1|sh` invocation. Stops at a quote or whitespace rather than at `;|&`,
# because inside the quotes those are literal.
# Same real-temp-root rule as $tempRoot above, but tolerating the single quotes shlex.join adds.
$qTempPath = "'?(?:(?:[A-Za-z]:)?[\\/](?:temp|tmp)[\\/]" +
             "|(?:[^\s']*[\\/])?AppData[\\/]Local[\\/]Temp[\\/])[^\s']*"

# THE HYPERFINE PAYLOAD FRAGMENTS, named once because the row needs the same two shapes in two
# places -- before the benchmarked target and after it. v3 wrote them out inline and only in the
# leading position, which is exactly why a flag AFTER the target was refused:
#     hyperfine 'python3 <temp>/bench.py --size 10'   -> BLOCK, and it should not be
# Two copies of a lookahead are two places to forget one, so they are variables.
#   $hfCh   one payload character: no quote, no shell metacharacter, no glob
#   $hfFlag a flag that is NOT a code channel. `-c`, `-e`, `-ec`, `-Command`, `-EncodedCommand`
#           and `--eval` all mean "the next token is a program", which is the hole this row
#           exists to close; every other flag is an ordinary argument to a staged script.
#   $hfTemp the benchmarked target, which must live under a real temp root (Tier 2: hyperfine
#           EXECUTES its payload, so it never runs the live repo or the installed ~/.claude copy).
$hfCh   = '[^''"$`(){};|&<>*?\s]'
$hfWord = $hfCh + '+'
$hfFlag = '(?!-(?:c|e|ec|Command|EncodedCommand|-eval)\b)-[\w-]+'
$hfTemp = '(?:(?:[A-Za-z]:)?[\\/](?:temp|tmp)[\\/]' +
          '|(?:' + $hfCh + '*[\\/])?AppData[\\/]Local[\\/]Temp[\\/])' + $hfCh + '*'

# The PARAMETERS Invoke-ScriptAnalyzer may receive. A POSITIVE allowlist, and it has to be:
# PowerShell binds any unambiguous parameter PREFIX, so `-F`, `-Fi` and `-Fix` all reach -Fix
# (measured 2026-08-24; `-Zzz` is rejected, so the probe discriminates). A negative match on the
# literal string `-Fix` is defeated by typing one fewer character. Anything starting with `-`
# that is not on this list is refused.
# `-Settings` IS DELIBERATELY ABSENT. A PSSA settings .psd1 carries its own `CustomRulePath` key,
# so `-Settings <any>.psd1` loads arbitrary rule modules and executes their top-level code -- it
# defeats the pinned `-CustomRulePath` below by a completely different door. Since agents can write
# into temp, an unpinned `-Settings` is the same arbitrary-code-execution hole with one more step.
# The bundled settings file is applied by lint_probe.py internally, where the caller cannot reach
# it, so nothing legitimate needs this parameter on the command line.
$psaParam = '-(?:Path|IncludeRule|ExcludeRule|Severity|Recurse|ReportSummary|IncludeDefaultRules|EnableExit)\b'

$gitOpts = '(?:-C\s+\S+\s+|-c\s+[\w.]+=\S+\s+|--git-dir=\S+\s+|--work-tree=\S+\s+|--no-pager\s+)*'
$gitRead = 'status|diff|log|show|blame|describe|rev-parse|rev-list|ls-files|ls-tree|cat-file|shortlog|whatchanged|diff-tree|merge-base|symbolic-ref|count-objects|verify-pack|check-ignore|grep|for-each-ref'

# EVERY CONCATENATION BELOW IS PARENTHESISED. In PowerShell the comma operator binds TIGHTER
# than `+`, so inside an array literal `"git" + 'stash...', 'tag...'` parses as
# `"git" + @('stash...','tag...')` -- ARRAY concatenation. The git prefix is silently dropped
# from every following entry and a bare `git\s+(?:opts)*` element joins the list. The incumbent
# documents this trap at its own $CP and I walked straight into it anyway: the first draft of
# this file scored must-allow 16/21, refusing `git apply --check`, `git stash list` and
# `git tag -l` -- three commands it explicitly lists as allowed.
$allowed = @(
    # --- git, read-only
    ("git\s+$gitOpts(?:$gitRead)\b.*"),
    ("git\s+$gitOpts" + 'stash\s+(?:list|show)\b.*'),
    ("git\s+$gitOpts" + 'tag\s+(?:-l|--list)\b.*'),
    ("git\s+$gitOpts" + 'branch\s+(?:-l|--list|--show-current|-v|-a|-r)\b.*'),
    ("git\s+$gitOpts" + 'remote\s+(?:-v|--verbose)\s*'),
    ("git\s+$gitOpts" + 'config\s+(?:--get|--list|-l)\b.*'),
    ("git\s+$gitOpts" + 'apply\b.*--(?:check|stat|summary|numstat)\b.*'),
    ("git\s+$gitOpts" + 'worktree\s+list\b.*'),

    # --- search and read
    '(?:grep|egrep|fgrep|rg|ag|ack)\s+.*',
    '(?:ls|dir)\s*.*',
    '(?:cat|bat|head|tail|less|more|nl|wc|file|stat|realpath|basename|dirname|readlink)\s+.*',
    # `env` and `printenv` PRINT the environment only when given no command. `env rm -rf build/`
    # runs rm -- it was a measured bypass class (prefix word), and putting a bare `env` on an
    # allowlist reintroduces it. Allowed only with no operand, or with -u/--unset style flags.
    '(?:env|printenv)(?:\s+(?:-[uU0]\b|\S+=\S+))*\s*',
    '(?:du|df|pwd|whoami|hostname|date|uname)\s*.*',
    '(?:which|where|type|command\s+-v)\s+.*',
    '(?:diff|cmp|comm|sort|uniq|cut|tr|column|fold|rev|tac|xxd|od|strings|jq|yq)\s+.*',
    'echo\s+.*',
    'printf\s+.*',
    'true|false',

    # `find` is read-only ONLY without its mutating actions. Those are refused here rather than
    # left to the denylist, so the allowlist alone is sufficient for this form.
    '(?!.*-(?:delete|exec|execdir|ok|okdir|fls|fprint|fprintf)\b)find\s+.*',
    # `sed` and `awk` are read-only ONLY without in-place editing.
    '(?!.*(?:\s-i\b|\s--in-place))sed\s+.*',
    '(?!.*-i\s+inplace)(?:awk|gawk|mawk)\s+.*',

    # --- test runners and the QA harness itself
    '(?:python3?|py)\s+-m\s+(?:unittest|pytest|doctest|json\.tool|timeit|compileall|py_compile)\b.*',
    '(?:pytest|tox|nose2)\b.*',
    'npm\s+(?:test|run\s+test|run\s+lint|ls|view|outdated)\b.*',
    '(?:yarn|pnpm)\s+(?:test|lint)\b.*',
    'node\s+--test\b.*',
    '(?:cargo|go)\s+(?:test|vet|check|build)\b.*',
    'ctest\b.*',
    'make\s+(?:test|check)\b.*',
    # Running a .py file by path -- how the QA harness metrics and checkers are invoked.
    '(?:python3?|py)\s+(?:-[A-Za-z]+\s+)*\S+\.py(?:\s+.*)?',
    # Linters and type checkers, all read-only in their default form.
    #
    # `shfmt` joins this row rather than getting its own, because the existing lookahead is already
    # exactly the flag-level rejection it needs: `-w` and `--write` are its only write modes.
    # Verified 2026-08-24 that shfmt REJECTS combined short flags itself (`shfmt -lw x.sh` ->
    # "flag provided but not defined: -lw"), so there is no `-lw` hole behind the `-w\b` boundary
    # -- two independent reasons, which is what this row needed before it could carry a formatter.
    # Read-only modes are `-d` (diff), `-l` (list) and bare stdout.
    # Known false positive, stated rather than discovered later: a FILENAME containing `-w`
    # (`shfmt -d my-w.sh`) is refused. Annoying; safe direction.
    '(?:ruff|mypy|flake8|pylint|black|isort|eslint|tsc|shellcheck|shfmt)\b(?!.*(?:--fix|--write|-w\b|--in-place)).*',

    # --- SHELL SYNTAX CHECK, Tier 1. `-n` is MANDATORY and the target must look like a script.
    # Without `-n` this is `bash <script>`, i.e. arbitrary execution; the flag is the entire
    # difference between a parse and a run, so it is matched positionally rather than by lookahead.
    # `bash -c` is NOT reachable here: `-c` is not `-n`, and there is no bare `bash` row.
    #
    # WORTH KNOWING WHAT THIS DOES NOT DO. `sh -n` is not a dialect check -- measured 2026-08-24,
    # it exits 0 on a `#!/bin/sh` script using `[[ ]]` and `local`, where `shellcheck -s sh`
    # returns SC3010 and SC3043. It is here because it catches genuine syntax errors with zero
    # setup and is the shell analogue of the mutant compile-check code-reviewer must run. Dialect
    # is shellcheck's job, through lint_probe.
    '(?:bash|sh)\s+-n\s+\S+\.(?:sh|bash|bats|ksh)\s*',

    # --- SECURITY AND STATIC-ANALYSIS SCANNERS, read-only forms only.
    #
    # WHY THESE ARE HERE. `sqa-security` is instructed by its own definition to run semgrep,
    # gitleaks, npm audit, pip-audit, osv-scanner, trufflehog and bandit; `sqa-embedded` to run
    # cppcheck and clang-tidy. NONE of them were on this allowlist, so every one was refused by
    # omission -- including `npm audit`, since the npm entry above permits only test/run/ls/view/
    # outdated. The gap never fired on the machine this guard was written on because none of the
    # scanners are installed there; a user who installs them per the README hits an immediate
    # refusal on the suite's own documented workflow. Added 2026-08-21 with paired must-allow and
    # must-block cases in qa-harness/guard_corpus.py.
    #
    # Each entry excludes that tool's OWN mutating flag by negative lookahead, in the same shape
    # as the linter entry above. The residual risk is identical to the one this file already
    # accepts for `pytest\b.*`: a read-only tool can still be pointed at a report path. Redirect
    # containment below covers `>`; a tool-specific `--output`-style flag is not parsed, here or
    # for pytest's `--junitxml`. That is a known, bounded and pre-existing limit, not a new one.
    '(?:semgrep)\b(?!.*(?:--autofix|--auto-fix)).*',
    'gitleaks\s+(?:detect|dir|git|protect|version)\b.*',
    'npm\s+audit\b(?!.*\bfix\b).*',
    '(?:pip-audit|pip_audit)\b(?!.*(?:--fix|-f\b)).*',
    'osv-scanner\b(?!.*(?:--experimental-licenses-summary\s+--fix|fix\b)).*',
    'trufflehog\b.*',
    '(?:bandit)\b.*',
    'cppcheck\b.*',
    'clang-tidy\b(?!.*(?:-fix\b|--fix\b|-fix-errors\b|--fix-errors\b|-fix-notes\b|--fix-notes\b)).*',

    # --- INTERPRETER ESCAPE. Allowed as a FORM only; the denylist below inspects the payload.
    # sqa-numerical and sqa-functional both instruct agents to write scratch drivers, so
    # refusing these outright would push work around the guard, which is worse than the risk.
    '(?:python3?|py|node|deno|bun|perl|ruby|php)\s+.*-(?:c|e|-eval)\b.*',

    # ------------------------------------------------------ TIER 2: CODE-EXECUTING TEST RUNNERS
    #
    # These RUN the target's own code, so unlike everything above they are constrained by WHERE
    # the target is, not only by how the command is spelled. Every one requires a path inside a
    # temp directory with no `..`, which is the disposable per-session sandbox the operating
    # policy mandates. The live repo and the installed ~/.claude copy are unreachable by
    # construction rather than by instruction.
    #
    # BE HONEST ABOUT WHAT THIS DOES AND DOES NOT BUY. A temp sandbox bounds what the TESTS
    # modify; it does not sandbox the code. A .bats or Pester file staged into temp still runs
    # with the user's full privileges. The containment is over blast radius on the artifacts this
    # suite protects, not over capability -- and that is the same accepted risk `pytest` and
    # `python foo.py` already carry two screens above, in new syntax rather than a new class.
    ("(?!.*\.\.)(?:wsl\s+(?:--\s+)?)?bats\b(?!.*(?:--output|--report-formatter|\s-o\b))(?:\s+--?[\w-]+(?:\s+\d+)?)*\s+" + $tempArg + '\s*'),
    # `-Output` and `-Path` TAKE VALUES; `-CI` and `-Detailed` are switches. The first version
    # treated all four as switches, so `-Output Detailed` was refused (the value `Detailed` had
    # nowhere to match) and the row was order-sensitive into the bargain. An over-refusal is a real
    # defect here, not a safe default: it is what teaches an agent to route around the guard.
    ("(?!.*\.\.)(?:powershell|pwsh)(?:\.exe)?\s+-NoProfile\s+-NonInteractive\s+-Command\s+Invoke-Pester" +
     # EVERY PATH TOKEN MUST BE IN TEMP, including one supplied through the option group. v2 wrote
     # `-(?:Output|Path)\s+\S+` there, which accepted an arbitrary path, so
     # `Invoke-Pester <temp>/tests -Path C:/Users/moors/.claude/hooks` satisfied the row -- the
     # containment this row's own comment claims was gone. `-Output` takes a word (Detailed,
     # Normal, None), never a path, so it is typed separately rather than sharing an alternation.
     "(?:\s+(?:-Output\s+\w+|-Path\s+" + $tempArg + "|-(?:CI|Detailed|PassThru)\b))*" +
     "(?:\s+(?:-Path\s+)?" + $tempArg + ")" +
     "(?:\s+(?:-Output\s+\w+|-Path\s+" + $tempArg + "|-(?:CI|Detailed|PassThru)\b))*\s*"),

    # --- STATIC ANALYSIS, Tier 1: Invoke-ScriptAnalyzer under a CLOSED PARAMETER GRAMMAR.
    #
    # This is the one row that admits PowerShell directly, and it carries the whole burden alone:
    # measured 2026-08-24, the denylist behind this allowlist has ZERO PowerShell payload rules
    # (`Start-Process`, `Invoke-Expression`, `iex`, `Import-Module`, `New-Object` all pass inside
    # an already-allowed form) and cannot see inside quotes at command position at all. So the
    # grammar itself must refuse metacharacters; there is no second line of defence.
    #
    # Three constraints, each measured rather than assumed:
    #   1. PARAMETERS ARE POSITIVELY ALLOWLISTED ($psaParam). Denying the literal `-Fix` does not
    #      work -- `-F` and `-Fi` both bind to it.
    #   2. -CustomRulePath IS PINNED to the installed InjectionHunter. Importing a module EXECUTES
    #      its top-level code, the parameter takes any caller path, and agents can already write
    #      into temp -- so an unpinned value is arbitrary code execution with the write
    #      precondition already met. That directory is not writable without admin (verified).
    #   3. VALUES MAY NOT CONTAIN ( ) $ { } ` ; | & < > -- no subexpressions, no substitution.
    # Tested against 12 allow/block cases including -F, -Fi, -CustomRulePath /tmp/evil.psm1,
    # `-Path (Start-Process calc)` and `-Path $(whoami)`.
    #
    # Note the routine path is NOT this row: lint_probe.py invokes PSSA internally against a
    # module-constant script, so an ordinary review never needs `-Command` at all. This exists for
    # a direct ad-hoc query, and is deliberately the narrower of the two doors.
    ('(?:powershell|pwsh)(?:\.exe)?\s+-NoProfile\s+-NonInteractive\s+-Command\s+Invoke-ScriptAnalyzer' +
     '(?:\s+(?:-CustomRulePath\s+"?''?C:[\\/]Program Files[\\/]WindowsPowerShell[\\/]Modules[\\/]InjectionHunter[\\/][\d.]+[\\/]InjectionHunter\.psd1''?"?' +
     '|' + $psaParam +
     '|(?![-])(?:"[^"$`(){};|&<>]*"|[^\s"''$`(){};|&<>]+)))*\s*'),

    # --- THE SUITE'S OWN PROBE SCRIPT, by exact path. Proposed separately from the target rule
    # above on purpose: this runs a script the SUITE ships, never a review target. The path is
    # pinned to `.claude/tools/ps_lint.ps1`, which fixer-scope-guard.ps1 protects from the fixer,
    # so it cannot be swapped for a script under review. Ordinary use goes through
    # `python .../lint_probe.py`, which already spawns this internally; the row exists so an agent
    # can invoke the backend directly when explaining a refusal.
    '(?!.*\.\.)(?:powershell|pwsh)(?:\.exe)?\s+-NoProfile\s+-NonInteractive\s+(?:-ExecutionPolicy\s+Bypass\s+)?-File\s+[^\s;|&]*[\\/]\.claude[\\/]tools[\\/]ps_lint\.ps1(?:\s+[^\s;|&]+)*\s*',

    # --- HYPERFINE, under a closed grammar. See the long note at the foot of this file.
    ('(?!.*\.\.)hyperfine(?:\s+(?:(?:-w|--warmup|-m|--min-runs|-M|--max-runs|-r|--runs|-N|--style)\s+\S+|-i|--ignore-failure))*' +
     # THE PAYLOAD IS A POSITIVE GRAMMAR, not "anything without metacharacters". v1 of this row
     # allowed `[^'"$`(){};|&<>*?]+` after the interpreter name, which admits FLAGS -- and measured
     # on the live guard, `hyperfine 'pwsh -Command <anything>'` and `hyperfine 'bash -c whoami'`
     # both ALLOWED: arbitrary execution through the one row whose entire purpose was to stop
     # exactly that. Same defect class as `-Fix` -- a character denylist cannot see that `-Command`
     # is a channel.
     #
     # TWO CORRECTIONS from the round-2 review, which found v2 wrong in BOTH directions:
     #   * It admitted `-File` and a bare positional with NO temp constraint, so
     #     `hyperfine 'pwsh -File C:/Users/moors/evil.ps1'` ran a script from anywhere -- while
     #     every sibling Tier 2 row requires a staged copy. hyperfine EXECUTES its payload, so it
     #     is Tier 2 and the target must be in temp like bats and Invoke-Pester.
     #   * Its `(?!-)` rejected EVERY flag, not just channel flags, so
     #     `hyperfine 'python3 bench.py --size 10'` went ALLOW -> BLOCK. An over-refusal on
     #     sqa-efficiency's own instrument is a real defect, not a safe default.
     # The resolution is to refuse the CHANNEL set by name and allow other flags, while requiring
     # the target to be a temp path. `--size 10` on a staged script is now expressible; inline code
     # and running from outside the sandbox are not.
     #
     # A THIRD CORRECTION, round 3: the trailing group was `(?:\s+(?!-)WORD)*`, which admits a
     # positional argument after the target but NO FLAG AT ALL -- so the very shape the second
     # correction set out to allow was still refused whenever the flag followed the script rather
     # than preceded it, which is where a script's own options actually go:
     #     hyperfine 'python3 <temp>/bench.py --size 10'   -> BLOCK   (measured)
     # Both positions now take $hfFlag, so a benign flag works either side of the target and a
     # channel flag is refused on both -- one lookahead, named once, rather than two spellings of
     # the rule that can drift apart.
     '(?:\s+''(?:bash|sh|pwsh|powershell|python3?)' +
     '(?:\s+' + $hfFlag + '(?:\s+(?!-)' + $hfWord + ')?)*' +
     '\s+' + $hfTemp +
     '(?:\s+(?:' + $hfFlag + '|(?!-)' + $hfWord + '))*''){1,2}\s*'),

    # --- SANDBOX STAGING. `cp` returns to the allowlist for exactly one shape: copying INTO a
    # temp directory, which is how a Tier 2 sandbox gets built. The destination must be the FINAL
    # token and must be a temp path; the matching denylist rule below is rewritten to fire on any
    # other `cp`. The case that makes this non-obvious is `cp /tmp/evil.psm1 hooks/guard.ps1` --
    # SOURCE in temp, destination in the repo -- which a naive "mentions temp" check would allow.
    ("(?!.*\.\.)cp\s+(?:-[rRpa]+\s+)*[^\s;|&-][^\s;|&]*\s+" + $tempArg + '\s*'),

    # --- PERF_PROBE's DERIVED COMMANDS, Tier 2. These are what `perf_probe.py --lang ps1|sh`
    # submits to this guard from inside itself (control 2), so they must land here or that mode
    # always fails at control-2 no matter how correct the wrapper is. They are also typeable
    # directly by an agent, which is the honest way to read them: this row IS the widening, and
    # perf_probe merely uses it.
    #
    # THE PATH IS QUOTED. shlex.join quotes any token containing a backslash, and Path.resolve()
    # always yields backslashes on Windows -- so the string this guard actually sees is
    # `pwsh -NoProfile -NonInteractive -File 'C:\...\Temp\sqa-a1\probe.ps1'`. Measured, not
    # assumed; an unquoted-only row would have refused every real invocation.
    #
    # SANDBOX-CONSTRAINED like the other Tier 2 rows. perf_probe asserts the same thing
    # internally in assert_sandboxed(), which is the authoritative check because it holds the
    # resolved absolute path; this row exists so the guard is not structurally blind to the
    # question. Note the contrast with `--lang py`, where local_argv() rewrites the target to its
    # BASENAME and no location rule is expressible here at all.
    #
    # RESIDUAL RISK, stated plainly: after this row a `.ps1` or `.sh` staged into temp is
    # arbitrary code, and it runs with the user's full privileges. Three things make it
    # defensible rather than a new class of hole -- the guard still judges the spelling; the
    # allowlist already accepts "run the target's own code" for `python foo.py` and `pytest`, so
    # this is the same accepted risk in new syntax; and the line that does NOT move is INLINE
    # code: `-Command`, `-EncodedCommand`, `bash -c`, here-docs and `$(...)` all stay refused.
    # That is a shape, not a list of dangerous verbs, which is why it survives a novel spelling.
    ("(?!.*\.\.)(?:powershell|pwsh)(?:\.exe)?\s+-NoProfile\s+-NonInteractive\s+-File\s+" + $qTempPath + "\.ps1'?(?:\s+.*)?"),
    ("(?!.*\.\.)(?:bash|sh)\s+" + $qTempPath + "\.(?:sh|bash)'?(?:\s+.*)?"),

    # --- PowerShell read-only cmdlets
    '(?:Get-Content|Select-String|Get-ChildItem|Get-Item|Test-Path|Measure-Object|Get-Command|Get-Help|Compare-Object|ConvertFrom-Json|Select-Object|Where-Object|ForEach-Object|Sort-Object|Format-List|Format-Table|Out-String|Write-Output|Write-Host)\b.*'
)

function Matches-Any([string]$text, [string[]]$pats) {
    foreach ($p in $pats) {
        Assert-Budget
        try {
            if ([regex]::IsMatch($text, '^\s*(?:' + $p + ')\s*$',
                                 [Text.RegularExpressions.RegexOptions]::IgnoreCase,
                                 $MATCH_TIMEOUT)) { return $true }
        } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
            Deny("evaluating one pattern against this command exceeded ${MATCH_TIMEOUT}. It fails CLOSED: a command that cannot be checked in bounded time is not allowed through.")
        }
    }
    return $false
}

# ------------------------------------------------------------------ redirects
# A redirect turns any read into a write. Allowed only to a sink that discards, or into a temp
# directory. Checked per segment, before the allowlist, because `cat x > y` has an allowed HEAD
# and is still a write.
# A LEADING FD NUMBER IS STILL A REDIRECT. The old form excluded `(?<![0-9<>])` to avoid firing
# on `2>&1`, and in doing so skipped `2> errors.txt` -- a write into the repo, measured as
# allowed. The fix is to exclude only the `>&` DUPLICATION form, not any digit: an optional fd
# number is consumed, and a target beginning with `&` is a duplication, not a file.
$redirectRe = '(?<![<>])[0-9]?>{1,2}\s*(?!&)(?<target>[^\s;|&]+)|>\|\s*(?<target2>[^\s;|&]+)'
# A `..` ANYWHERE in the target disqualifies it, checked separately below. `/tmp/../SKILL.md`
# starts with an approved prefix and lands in the repo root -- a measured bypass. Prefix
# matching on an un-normalised path is not a containment check.
# Tightened 2026-08-24 to the same REAL-temp-root rule as $tempRoot, for the same reason: the old
# form matched any path containing a `tmp` segment, so `<repo>/tmp/out.txt` counted as "somewhere
# harmless" and a redirect could write into the repository the guard exists to protect. Location,
# not name.
$tempOk = '^(?:/dev/null|NUL|nul|\$null)$' +
          '|^(?:[A-Za-z]:)?[\\/](?:temp|tmp|Temp|TEMP)[\\/]' +
          '|^(?:.*[\\/])?AppData[\\/]Local[\\/]Temp[\\/]'

for ($k = 0; $k -lt $segments.Count; $k++) {
    Assert-Budget
    $seg = $segments[$k]
    if ([string]::IsNullOrWhiteSpace($seg)) { continue }
    $s = $seg.Trim()
    # The redirect and here-doc scans read the MASKED segment, so a `>` inside a search PATTERN is
    # not mistaken for a redirection. The allowlist below still matches the REAL text -- masking
    # must never be able to make an unrecognised command look recognisable.
    $sMask = ([string]$maskedSegments[$k]).Trim()

    foreach ($m in [regex]::Matches($sMask, $redirectRe)) {
        $t = $m.Groups['target'].Value
        if (-not $t) { $t = $m.Groups['target2'].Value }
        if ($t -and (($t -notmatch $tempOk) -or ($t -match '\.\.'))) {
            Deny("this command redirects output into '$t'. A redirect is a write, and writes are only permitted to /dev/null, NUL, or a path inside a temp directory with no '..' in it -- never into the repository.")
        }
    }
    # Here-documents feed a program a script body; `python <<EOF` is an interpreter escape
    # wearing a different hat.
    if ($sMask -match '<<-?\s*[''"]?\w+') {
        Deny("here-documents are not permitted. Put the script in a temp file and run it by path, or use a single-line -c form so its contents can be checked.")
    }

    if (-not (Matches-Any $s $allowed)) {
        $head = ($s -split '\s+')[0]
        Deny("'$head' is not on the allowlist (full segment: '$s').")
    }
}

# ------------------------------------------------------------ denylist, defence in depth
# The allowlist has already refused everything it does not recognise. What remains is the
# payload of the forms that legitimately carry arbitrary code, plus a backstop against an
# allowlist entry being looser than intended. A hit here is a bug in the allowlist as much as
# an attack -- but it still blocks.
$CP = '(?:^|[;|&(`\n]|\$\()\s*'
$denylist = @(
    # COMMAND-POSITION ANCHORED. `\bgit\s+...commit\b` matches inside a search STRING, so
    # `grep -rn 'git commit' docs/` was refused -- a false positive the incumbent still carries
    # (measured: must-allow 19/21, both failures of exactly this shape). Searching for the text
    # of a dangerous command is the daily work of a code reviewer; blocking it is what teaches
    # agents to route around the guard.
    ($CP + 'git\s+(?:-{1,2}[\w-]+(?:[= ]\S+)?\s+)*(commit|push|add|reset|checkout|restore|clean|rebase|merge|stash\s+(?!list|show)|am|cherry-pick|revert|switch|rm|mv|filter-branch|update-ref|gc|worktree\s+(add|remove)|remote\s+(add|remove|set-url)|reflog\s+delete)\b'),
    # `cp` IS DELIBERATELY ABSENT FROM THIS ALTERNATION and handled by the rule below instead --
    # it is the one mutator with a legitimate shape (staging a Tier 2 sandbox). Everything else
    # here stays a flat refusal.
    ($CP + '(rm|rmdir|unlink|shred|mv|touch|mkdir|ln|install|dd|truncate|fallocate|mkfs|fdisk|parted)\s'),
    # `cp` fires UNLESS the FINAL token of the segment is a temp path. Anchoring on the last token
    # is the whole rule: a "mentions a temp path" check would allow
    # `cp /tmp/evil.psm1 hooks/guard.ps1`, where the SOURCE is in temp and the destination is the
    # guard itself. Destination validation is load-bearing here in a way it is nowhere else in
    # this file, which is why it has paired corpus cases for source/destination confusion.
    ($CP + 'cp\b(?![^;|&]*\s(?:[A-Za-z]:)?[\\/]?(?:[^\s;|&]*[\\/])?(?:temp|tmp)[\\/][^\s;|&]*\s*(?=$|[;|&]))'),
    '\bfind\b[^|;&]*-(delete|exec\s+(rm|mv|cp|chmod|sed)\b)',
    ($CP + '(Remove-Item|Clear-Content|Set-Content|Out-File|Add-Content|New-Item|Rename-Item|Move-Item|Copy-Item|Set-ItemProperty|New-ItemProperty)\b'),
    '\|\s*(Remove-Item|Clear-Content|Set-Content|Out-File|Add-Content|New-Item|Rename-Item|Move-Item|Copy-Item|Tee-Object)\b',
    '\bsed\b[^|;&]*(-i|--in-place)|\bperl\b[^|;&]*\s-i|\bawk\b[^|;&]*-i\s+inplace',
    ($CP + '(chmod|chown|chgrp|icacls|takeown|attrib)\s'),
    # Also command-position anchored, for the same reason: `rg 'npm install' README.md` is a
    # legitimate search.
    ($CP + '(npm\s+(install|i|ci|publish)|yarn\s+add|pnpm\s+(add|install)|pip3?\s+install|python\s+-m\s+pip\s+install|cargo\s+install|apt(-get)?\s+install|yum\s+install|brew\s+install|choco\s+install|pio\s+pkg\s+install)\b'),
    # THE SCANNING SPANS ARE BOUNDED AT {0,600}, NOT ATOMIC. Each interpreter-payload rule carries
    # two unbounded scanning spans around a literal, which is the classic quadratic-backtracking
    # shape and was measured as a real cost: a 700-character command took 2054 ms, 1050 chars
    # 4213 ms. The obvious fix -- wrapping each span in an atomic group `(?>...)` -- was tried and
    # is WRONG: an atomic greedy span consumes to end-of-string and can never give characters back,
    # so `\s-(c|e|...)` after it can never match. Measured: it silently disabled NINE must-block
    # cases at once (python-c-write, node-e-write, alias-shutil, dunder-import, getattr-indirect,
    # exec-string, open-write-spaced, py-subprocess, evade-semicolon-interpreter) while the guard
    # still looked healthy. A bound preserves the backtracking these rules genuinely need and caps
    # the worst case at ~600^2 steps per rule; the aggregate deadline in Assert-Budget is the
    # backstop for everything the bound does not cover.
    #
    # THE GAP MUST ALLOW `;`. It used to be `[^|;&]*`, so a semicolon anywhere in the inline
    # program ended the match and the write was never seen:
    #   python -c "import os; os.remove('scripts/probe.py')"     -> allowed
    # A semicolon is ordinary punctuation INSIDE an interpreter payload, not a shell separator
    # -- the segment splitter has already handled real shell separators, and it is quote-aware,
    # so by the time this runs a `;` here is part of the program. `[^|&]*` keeps the pipeline
    # and background guards while closing the class.
    '\b(python3?|node|perl|ruby|php|deno|bun)\b[^|&]*\s-(c|e|r|-eval)\b[^|&]*(open\s*\([^)]*[''"][waxr]\+?[''"]|writeFile|write_text|\.write\s*\(|os\.remove|os\.unlink|os\.rename|os\.rmdir|shutil\.(copy|move|rmtree)|Path\s*\([^)]*\)\.(write|unlink|rename)|unlink\s*\(|mkdir|makedirs|fs\.(write|unlink|rename|rm))',

    # METAPROGRAMMING ESCAPES inside an inline program. Measured 2026-08-11 against the
    # allowlist candidate: three payloads walked past the literal-name rule above --
    #   import shutil as s; s.rmtree('build')      (aliased module)
    #   __import__('os').remove('scripts/probe.py')  (no literal os.remove)
    #   import os; getattr(os,'remove')('f.py')      (verb as a string)
    # Matching write VERBS by name cannot survive renaming, because the name is data. So the
    # indirection machinery itself is refused: a read-only scratch driver has no need of
    # __import__, getattr, exec, eval, compile or importlib, and none of the corpus's
    # legitimate -c cases use them.
    # NOTE THE TRAILING `+`. A leading `+` on a continuation line is parsed as UNARY plus and
    # PowerShell then tries to cast the string to Int32 -- the script dies at runtime with
    # "Cannot convert value ... to type System.Int32", which the corpus reports as error(1) on
    # every case, allow and block alike. Measured on the first draft of this rule.
    ('\b(python3?|node|perl|ruby|php|deno|bun)\b[^|&]*\s-(c|e|r|-eval)\b[^|&]*' +
     '(__import__|importlib|\bgetattr\s*\(|\bsetattr\s*\(|\bexec\s*\(|\beval\s*\(' +
     '|\bcompile\s*\(|\bglobals\s*\(|Function\s*\(|require\s*\(\s*[''"]child_process)'),

    # An aliased import of a write-capable module. `import shutil as s` renames the namespace,
    # so every later reference is invisible to a literal-name rule.
    ('\b(python3?|py)\b[^|&]*\s-c\b[^|&]*' +
     '(import\s+(os|shutil|subprocess|pathlib|tempfile)\s+as\s+\w+' +
     '|from\s+(os|shutil|subprocess|pathlib)\s+import)'),

    # Shelling out from inside the interpreter is a nested shell by another name.
    ('\b(python3?|node|perl|ruby|php|deno|bun)\b[^|&]*\s-(c|e|r|-eval)\b[^|&]*' +
     '(os\.system|os\.popen|os\.exec|subprocess|child_process|\bsystem\s*\()')
)

# THE DENYLIST READS $maskedCmd, not $cmd. A quoted search pattern belonging to a read-only
# searcher has been blanked; everything else is byte-identical. A real `| Set-Content` is
# untouched -- and would already have died at the allowlist, since the segment splitter gives it
# its own segment whose head no row admits.
foreach ($p in $denylist) {
    Assert-Budget
    try {
        $hit = [regex]::IsMatch($maskedCmd, $p,
                                [Text.RegularExpressions.RegexOptions]::IgnoreCase, $MATCH_TIMEOUT)
    } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
        Deny("evaluating this command took over 2s. It fails CLOSED.")
    }
    if ($hit) {
        Deny("this command is state-changing or destructive (matched /$p/). It reached the denylist behind the allowlist, which means the allowlist let its form through -- most likely an inline interpreter program that writes.")
    }
}

exit 0
