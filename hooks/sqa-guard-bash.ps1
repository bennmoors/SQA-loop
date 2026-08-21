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

# ------------------------------------------------------------------ tokenise into segments
# Quote-aware: separators inside quotes are literal. `grep -rn 'a; b' .` is ONE segment, and
# treating that semicolon as a separator would refuse a legitimate search.
$segments = New-Object System.Collections.ArrayList
$buf = New-Object System.Text.StringBuilder
$sq = $false; $dq = $false
for ($i = 0; $i -lt $cmd.Length; $i++) {
    $ch = $cmd[$i]
    $next = if ($i + 1 -lt $cmd.Length) { $cmd[$i + 1] } else { [char]0 }

    if ($ch -eq "'" -and -not $dq) { $sq = -not $sq; [void]$buf.Append($ch); continue }
    if ($ch -eq '"' -and -not $sq) { $dq = -not $dq; [void]$buf.Append($ch); continue }

    if (-not $sq -and -not $dq) {
        # Command substitution: refused outright (rule 3).
        if (($ch -eq '$' -and $next -eq '(') -or $ch -eq '`') {
            Deny("command substitution is not permitted (found '$ch'). Its contents are a command in their own right; run the inner command on its own so it can be checked.")
        }
        # Comment: the rest of the LINE is not executed, so drop it (rule 2).
        if ($ch -eq '#') {
            while ($i -lt $cmd.Length -and $cmd[$i] -ne "`n") { $i++ }
            continue
        }
        if ($ch -eq ';' -or $ch -eq "`n" -or $ch -eq "`r") {
            [void]$segments.Add($buf.ToString()); $buf.Clear() | Out-Null; continue
        }
        if (($ch -eq '&' -and $next -eq '&') -or ($ch -eq '|' -and $next -eq '|')) {
            [void]$segments.Add($buf.ToString()); $buf.Clear() | Out-Null; $i++; continue
        }
        if ($ch -eq '|') {
            [void]$segments.Add($buf.ToString()); $buf.Clear() | Out-Null; continue
        }
        # A single trailing `&` backgrounds the command; treat as a separator too.
        if ($ch -eq '&') {
            [void]$segments.Add($buf.ToString()); $buf.Clear() | Out-Null; continue
        }
    }
    [void]$buf.Append($ch)
}
[void]$segments.Add($buf.ToString())

# ------------------------------------------------------------------ allowlisted command forms
# Anchored and matched against the WHOLE segment. Each entry is `^\s*<form>\s*$`.
#
# Read-only git subcommands. The `(?:-C\s+\S+\s+|-c\s+\S+\s+|--git-dir=\S+\s+)*` prefix is
# allowed because it is how a repo is addressed, but it CANNOT smuggle a write: the subcommand
# that follows still has to be one of these names, so `git -C repo commit` is refused by
# omission rather than by a pattern that has to anticipate it.
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
    '(?:ruff|mypy|flake8|pylint|black|isort|eslint|tsc|shellcheck)\b(?!.*(?:--fix|--write|-w\b|--in-place)).*',

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

    # --- PowerShell read-only cmdlets
    '(?:Get-Content|Select-String|Get-ChildItem|Get-Item|Test-Path|Measure-Object|Get-Command|Get-Help|Compare-Object|ConvertFrom-Json|Select-Object|Where-Object|ForEach-Object|Sort-Object|Format-List|Format-Table|Out-String|Write-Output|Write-Host)\b.*'
)

$MATCH_TIMEOUT = [TimeSpan]::FromSeconds(2)

function Matches-Any([string]$text, [string[]]$pats) {
    foreach ($p in $pats) {
        try {
            if ([regex]::IsMatch($text, '^\s*(?:' + $p + ')\s*$',
                                 [Text.RegularExpressions.RegexOptions]::IgnoreCase,
                                 $MATCH_TIMEOUT)) { return $true }
        } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
            Deny("evaluating this command took over 2s. It fails CLOSED: a command that cannot be checked in bounded time is not allowed through.")
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
$tempOk = '^(?:/dev/null|NUL|nul|\$null)$|^(?:[A-Za-z]:)?[\\/]?(?:.*[\\/])?(?:temp|tmp|Temp|TEMP)[\\/]'

foreach ($seg in $segments) {
    if ([string]::IsNullOrWhiteSpace($seg)) { continue }
    $s = $seg.Trim()

    foreach ($m in [regex]::Matches($s, $redirectRe)) {
        $t = $m.Groups['target'].Value
        if (-not $t) { $t = $m.Groups['target2'].Value }
        if ($t -and (($t -notmatch $tempOk) -or ($t -match '\.\.'))) {
            Deny("this command redirects output into '$t'. A redirect is a write, and writes are only permitted to /dev/null, NUL, or a path inside a temp directory with no '..' in it -- never into the repository.")
        }
    }
    # Here-documents feed a program a script body; `python <<EOF` is an interpreter escape
    # wearing a different hat.
    if ($s -match '<<-?\s*[''"]?\w+') {
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
    ($CP + '(rm|rmdir|unlink|shred|cp|mv|touch|mkdir|ln|install|dd|truncate|fallocate|mkfs|fdisk|parted)\s'),
    '\bfind\b[^|;&]*-(delete|exec\s+(rm|mv|cp|chmod|sed)\b)',
    ($CP + '(Remove-Item|Clear-Content|Set-Content|Out-File|Add-Content|New-Item|Rename-Item|Move-Item|Copy-Item|Set-ItemProperty|New-ItemProperty)\b'),
    '\|\s*(Remove-Item|Clear-Content|Set-Content|Out-File|Add-Content|New-Item|Rename-Item|Move-Item|Copy-Item|Tee-Object)\b',
    '\bsed\b[^|;&]*(-i|--in-place)|\bperl\b[^|;&]*\s-i|\bawk\b[^|;&]*-i\s+inplace',
    ($CP + '(chmod|chown|chgrp|icacls|takeown|attrib)\s'),
    # Also command-position anchored, for the same reason: `rg 'npm install' README.md` is a
    # legitimate search.
    ($CP + '(npm\s+(install|i|ci|publish)|yarn\s+add|pnpm\s+(add|install)|pip3?\s+install|python\s+-m\s+pip\s+install|cargo\s+install|apt(-get)?\s+install|yum\s+install|brew\s+install|choco\s+install|pio\s+pkg\s+install)\b'),
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

foreach ($p in $denylist) {
    try {
        $hit = [regex]::IsMatch($cmd, $p,
                                [Text.RegularExpressions.RegexOptions]::IgnoreCase, $MATCH_TIMEOUT)
    } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
        Deny("evaluating this command took over 2s. It fails CLOSED.")
    }
    if ($hit) {
        Deny("this command is state-changing or destructive (matched /$p/). It reached the denylist behind the allowlist, which means the allowlist let its form through -- most likely an inline interpreter program that writes.")
    }
}

exit 0
