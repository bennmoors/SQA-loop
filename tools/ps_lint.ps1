# ps_lint.ps1 -- the PowerShell backend for tools/lint_probe.py. PARSES, NEVER RUNS.
#
# WHY THIS FILE EXISTS AT ALL, rather than the agents calling Invoke-ScriptAnalyzer directly.
# `Invoke-ScriptAnalyzer` is a cmdlet, not an exe, so reaching it from the Bash tool means
# `pwsh -Command "..."` -- a general interpreter escape. Measured 2026-08-24 against the live
# guard: the denylist behind the allowlist has ZERO PowerShell payload rules. `Start-Process`,
# `Invoke-Expression`, `iex`, `Import-Module` and `New-Object` all pass inside an already-allowed
# form, and the denylist cannot see inside quotes at command position at all
# (`echo '<destructive> build/'` -> ALLOW; the same command bare -> BLOCK). So anything admitting
# PowerShell through the allowlist has NOTHING behind it.
#
# Routing it through a bundled script collapses that surface to one literal path. The guard sees
# `powershell -NoProfile -NonInteractive -File <this file>`, the caller supplies only file paths,
# and the two dangerous knobs become structurally unreachable rather than merely refused:
#
#   -Fix              cannot be expressed. This matters more than it looks: PowerShell binds ANY
#                     unambiguous parameter prefix, and `-F`, `-Fi` and `-Fix` all reach -Fix
#                     (measured; `-Zzz` is rejected, so the probe discriminates). A guard regex
#                     denying the literal string "-Fix" is bypassed by typing one fewer character.
#   -CustomRulePath   cannot be redirected. Importing a module EXECUTES its top-level code, the
#                     parameter accepts any caller path, and agents can already write into temp
#                     (`echo ... > /tmp/x.psm1` -> ALLOW). That is arbitrary code execution with
#                     the write precondition already satisfied. Here the path is a constant, and
#                     the directory it points at is not writable without admin (verified).
#
# It lives in tools/ so fixer-scope-guard.ps1's `/.claude/tools(/|$)` rule protects it exactly as
# it protects perf_probe.py. Do NOT follow perf_probe.mode_profile's pattern of generating a
# driver into temp -- temp is a directory the Bash guard deliberately lets agents write into, so a
# generated scanner is a scanner the scanned process can rewrite.
#
# PATHS ARE RESOLVED FROM $PSScriptRoot. install.ps1 copies tools/ wholesale, so this file is
# installed automatically, but it does NOT get the guard-path rewrite applied to the two hook
# scripts -- that regex only matches `& '...'` around the guard filenames. Nothing here may
# hardcode an absolute path.
#
# Output: ONE JSON object on stdout, nothing else. Diagnostics go to stderr.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
    [string[]] $Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SETTINGS = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'

# Pinned, not discovered. Resolving "wherever InjectionHunter happens to be" would reintroduce
# exactly the caller-influenced path this design exists to remove -- a module dropped into a
# user-writable directory earlier on $env:PSModulePath would win.
$IH_ROOT = 'C:\Program Files\WindowsPowerShell\Modules\InjectionHunter'

$findings = New-Object System.Collections.Generic.List[object]
$fileInfo = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param($Rule, $File, $Line, $Col, $Severity, $Domain, $Backend, $Message)
    $findings.Add([ordered]@{
        rule     = $Rule
        file     = $File
        line     = [int]$Line
        col      = [int]$Col
        severity = $Severity
        domain   = $Domain
        backend  = $Backend
        message  = $Message
    })
}

# --------------------------------------------------------------------- severity + domain policy
#
# NOT a passthrough, and the calibration fixture is this repo's own files (2026-08-24):
#   install.ps1  34 findings, 30 of them PSAvoidUsingWriteHost
#   sqa-guard-bash.ps1  1
#   fixer-scope-guard.ps1  0 -- on a file with a PROVEN write bypass
# Reporting raw counts would flood a verdict with style opinions about an installer while saying
# nothing about a security guard with a real hole.

# Capped at Suggestion whatever PSSA calls them: formatting opinions are not defects and must
# never gate a verdict. PSUseApprovedVerbs is deliberately NOT here -- it is the one style-adjacent
# rule with evidence behind it in this repo (an independent AST scan agreed with PSSA on
# `Matches-Any`), and an unapproved verb is a discoverability defect a caller actually hits.
$STYLE_ONLY = @(
    'PSAvoidUsingDoubleQuotesForConstantString', 'PSAlignAssignmentStatement',
    'PSUseConsistentIndentation', 'PSUseConsistentWhitespace', 'PSAvoidTrailingWhitespace',
    'PSPlaceOpenBrace', 'PSPlaceCloseBrace', 'PSUseCorrectCasing', 'PSAvoidSemicolonsAsLineTerminators'
)

# `domain` is the ANTI-DOUBLE-BILLING mechanism. Without it the same finding is claimed by two
# specialists and sqa-lead's dedup step has to guess which one meant it.
$SECURITY_RULES = @(
    'PSAvoidUsingInvokeExpression', 'PSAvoidUsingConvertToSecureStringWithPlainText',
    'PSAvoidUsingPlainTextForPassword', 'PSAvoidUsingUsernameAndPasswordParams',
    'PSUsePSCredentialType', 'PSUseConstrainedLanguageMode', 'PSAvoidUsingComputerNameHardcoded',
    'PSUsePSCredentialType', 'PSAvoidUsingBrokenHashAlgorithms'
)

# Capping for a reason OTHER than style: a rule that is sound but not applicable to the target.
# Kept as a mechanism though it is currently empty, and separate from $STYLE_ONLY so the two are
# not "tidied" together -- they cap for different reasons and will diverge again.
#
# Its first occupant was PSUseConstrainedLanguageMode, capped here and then EXCLUDED outright in
# PSScriptAnalyzerSettings.psd1 once measured: 14 findings across this repo's three .ps1 files
# against 5 from every other rule combined, all of them .NET type references a hook and an AST
# scanner must make. Capping was not enough -- burying real findings under Suggestions costs a
# reviewer the same attention whether or not the count gates a verdict.
$CAPPED_NOT_STYLE = @()

function Get-Severity {
    param($RuleName, $PssaSeverity)
    if ($STYLE_ONLY -contains $RuleName) { return 'Suggestion' }
    if ($CAPPED_NOT_STYLE -contains $RuleName) { return 'Suggestion' }
    switch ($PssaSeverity) {
        'Error'       { return 'Critical' }
        'Warning'     { return 'Warning' }
        'Information' { return 'Suggestion' }
        default       { return 'Suggestion' }
    }
}

function Get-Domain {
    param($RuleName)
    if ($SECURITY_RULES -contains $RuleName) { return 'security' }
    return 'functional'
}

# ------------------------------------------------------------------------------ backend probing
$pssaModule = Get-Module -ListAvailable PSScriptAnalyzer | Sort-Object Version -Descending | Select-Object -First 1
$pssaOk = $null -ne $pssaModule
if ($pssaOk) {
    # HANDLED, not suppressed. Get-Module -ListAvailable proves the module is ON DISK, which is not
    # the same as importable -- a broken manifest or a load-order conflict fails here. Swallowing
    # that with -ErrorAction SilentlyContinue would leave $pssaOk true and defer the failure to
    # every later Invoke-ScriptAnalyzer call, reporting a per-file error instead of one honest
    # "PSSA unavailable". This file's own AST check flagged the earlier version, which is the
    # dogfooding working.
    try {
        Import-Module PSScriptAnalyzer -ErrorAction Stop
    } catch {
        $pssaOk = $false
        [Console]::Error.WriteLine("PSScriptAnalyzer is present but failed to import: $($_.Exception.Message)")
    }
}

$ihPsd = $null
if (Test-Path $IH_ROOT) {
    $ihPsd = Get-ChildItem -Path $IH_ROOT -Filter 'InjectionHunter.psd1' -Recurse -ErrorAction SilentlyContinue |
             Sort-Object FullName -Descending | Select-Object -First 1
}
$ihOk = $null -ne $ihPsd

$settingsOk = Test-Path $SETTINGS

# ================================================================================ AST checks
#
# These are FIRST-PARTY, and they cover things PSSA's default rules do not. The first one alone
# justifies the file: a .ps1 that does not parse is a [Proven] Critical with no dependencies at
# all -- no module, no settings, no network.
function Invoke-AstChecks {
    param([string] $File)

    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($File, [ref]$tokens, [ref]$errors)

    if ($errors -and $errors.Count -gt 0) {
        foreach ($e in $errors) {
            Add-Finding -Rule 'AstParseError' -File $File -Line $e.Extent.StartLineNumber `
                -Col $e.Extent.StartColumnNumber -Severity 'Critical' -Domain 'functional' `
                -Backend 'ast' -Message $e.Message
        }
        # A file that does not parse cannot be walked. Report and stop -- every later check would
        # be reasoning about a tree that does not represent the source.
        return $false
    }

    # --- $null on the wrong side of -eq/-ne.
    # `$x -eq $null` is not a typo, it is a different operation: when $x is an array PowerShell
    # FILTERS it and returns the matching elements, so the result is an array, and an empty array
    # is falsy while a one-element array is not. `$null -eq $x` is the scalar comparison intended.
    $bins = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.BinaryExpressionAst] }, $true)
    foreach ($b in $bins) {
        if ($b.Operator -in @('Ieq', 'Ine', 'Ceq', 'Cne')) {
            $r = $b.Right
            if ($r -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $r.VariablePath.UserPath -eq 'null') {
                Add-Finding -Rule 'AstNullComparisonOrder' -File $File `
                    -Line $b.Extent.StartLineNumber -Col $b.Extent.StartColumnNumber `
                    -Severity 'Warning' -Domain 'functional' -Backend 'ast' `
                    -Message ('$null is on the right of -' + $b.Operator + '. On an array operand this FILTERS rather than compares; put $null on the left.')
            }
        }
    }

    # --- -ErrorAction SilentlyContinue on a call whose result is then trusted.
    # PowerShell's default $ErrorActionPreference is Continue, so non-terminating errors are
    # already easy to miss; SilentlyContinue removes even the record.
    $cmds = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($c in $cmds) {
        for ($i = 0; $i -lt $c.CommandElements.Count; $i++) {
            $el = $c.CommandElements[$i]
            if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and
                $el.ParameterName -match '^(?:ea|ErrorAction)$') {
                $val = $null
                if ($i + 1 -lt $c.CommandElements.Count) { $val = "$($c.CommandElements[$i + 1])" }
                if ($val -match 'SilentlyContinue|Ignore') {
                    # EXISTENCE PROBES ARE EXEMPT, and this exemption was earned rather than
                    # guessed: v1 of this check fired on install.ps1:67 and :90, which are
                    # `Get-Variable -Name IsWindows -EA SilentlyContinue` and
                    # `Get-Command $c -EA SilentlyContinue` -- THE canonical idiom for "does this
                    # exist?", where suppressing the error is the entire point and the result is
                    # tested on the very next line. A check whose first two real hits are both the
                    # correct spelling of the pattern is measuring the wrong thing.
                    $probe = $c.GetCommandName()
                    if ($probe -and $probe -match '^(?:Get-Command|Get-Variable|Get-Module|Get-Item|Get-ItemProperty|Get-Process|Get-Service|Resolve-Path|Test-Path|Get-ChildItem|Get-PSRepository|Get-PackageProvider)$') {
                        continue
                    }
                    # Suggestion, not Warning: proving the result is TRUSTED needs dataflow this
                    # does not have, so the honest claim is "look at this", not "this is a defect".
                    Add-Finding -Rule 'AstErrorActionSuppressed' -File $File `
                        -Line $el.Extent.StartLineNumber -Col $el.Extent.StartColumnNumber `
                        -Severity 'Suggestion' -Domain 'functional' -Backend 'ast' `
                        -Message ("Errors from " + $probe + " are discarded. If the result is then used, a failure is indistinguishable from an empty success. Not flagged as a defect because whether the result is trusted needs dataflow analysis.")
                }
            }
        }
    }

    # --- `$acc += item` inside a loop.
    # O(n^2): every += allocates a NEW array and copies. Measured elsewhere in this tree at
    # 16.2 s vs 1.0 s for List.Add at n=20000 -- the single highest-value efficiency finding in
    # the language, which is why it is a first-party check rather than left to a linter.
    $loopTypes = @(
        [System.Management.Automation.Language.ForEachStatementAst],
        [System.Management.Automation.Language.ForStatementAst],
        [System.Management.Automation.Language.WhileStatementAst],
        [System.Management.Automation.Language.DoWhileStatementAst],
        [System.Management.Automation.Language.DoUntilStatementAst]
    )
    $assigns = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
    foreach ($a in $assigns) {
        if ($a.Operator -ne 'PlusEquals') { continue }
        $p = $a.Parent
        $inLoop = $false
        while ($null -ne $p) {
            foreach ($t in $loopTypes) { if ($p -is $t) { $inLoop = $true; break } }
            if ($inLoop) { break }
            $p = $p.Parent
        }
        if ($inLoop) {
            # SUGGESTION, NOT WARNING, and the reason is the operating contract rather than doubt
            # about the pattern. The Knuth bar forbids a Critical or Warning outside a DEMONSTRATED
            # hot path, and static analysis cannot know n. v1 of this check reported Warning on
            # install.ps1:236, which appends inside `foreach ($n in @(<7 literal names>))` -- the
            # O(n^2) shape, at n=7, costing nothing. The 16x figure this rule is famous for was
            # measured at n=20000; escalating it is sqa-efficiency's call after a measurement,
            # never this file's from a parse tree.
            Add-Finding -Rule 'AstArrayAppendInLoop' -File $File `
                -Line $a.Extent.StartLineNumber -Col $a.Extent.StartColumnNumber `
                -Severity 'Suggestion' -Domain 'efficiency' -Backend 'ast' `
                -Message '`+=` inside a loop reallocates and copies the whole collection each iteration (O(n^2)); ~16x slower than List.Add at n=20000, negligible at small n. Escalate only against a measured hot path. Use [System.Collections.Generic.List[object]] and .Add().'
        }
    }

    # --- Missing Set-StrictMode.
    # Without it an undefined variable silently evaluates to $null, which is how a typo becomes a
    # wrong answer rather than an error.
    $hasStrict = $false
    foreach ($c in $cmds) {
        if ($c.GetCommandName() -eq 'Set-StrictMode') { $hasStrict = $true; break }
    }
    if (-not $hasStrict) {
        Add-Finding -Rule 'AstNoStrictMode' -File $File -Line 1 -Col 1 `
            -Severity 'Suggestion' -Domain 'functional' -Backend 'ast' `
            -Message 'No Set-StrictMode. An undefined variable evaluates to $null silently, so a typo produces a wrong answer instead of an error.'
    }

    # --- Native/external invocation whose exit code is never read.
    # THE EXACT DEFECT THAT LEFT THIS REPO'S OWN BASH GUARD INERT FOR FOUR WEEKS: a hook wired as
    # `& '<guard>'` returns 0 for a script that exits 2, so every block arrived as an allow and
    # the corpus scored the guard at 0 of 23 mutating commands blocked in production. Heuristic
    # and deliberately conservative -- it fires only when the call operator is used AND
    # $LASTEXITCODE appears NOWHERE in the file, which is the shape that actually loses the code.
    $srcText = [IO.File]::ReadAllText($File)
    if ($srcText -notmatch [regex]::Escape('$LASTEXITCODE')) {
        $invokes = $ast.FindAll({
            $args[0] -is [System.Management.Automation.Language.CommandAst] -and
            $args[0].InvocationOperator -eq 'Ampersand'
        }, $true)
        foreach ($iv in $invokes) {
            Add-Finding -Rule 'AstCallOperatorExitCodeLost' -File $File `
                -Line $iv.Extent.StartLineNumber -Col $iv.Extent.StartColumnNumber `
                -Severity 'Warning' -Domain 'functional' -Backend 'ast' `
                -Message 'Invoked with `&` and $LASTEXITCODE is never read in this file. Under PowerShell''s -Command form a called script''s `exit 2` reaches the caller as 0, so a failure becomes a success silently.'
        }
    }

    return $true
}

# ===================================================================================== main
foreach ($f in $Path) {
    $resolved = $null
    try { $resolved = (Resolve-Path -LiteralPath $f -ErrorAction Stop).ProviderPath }
    catch {
        $fileInfo.Add([ordered]@{ path = $f; exists = $false; parsed = $false })
        continue
    }

    $parsed = Invoke-AstChecks -File $resolved

    if ($pssaOk -and $parsed) {
        $pssaArgs = @{ Path = $resolved }
        if ($settingsOk) { $pssaArgs['Settings'] = $SETTINGS }
        try {
            foreach ($r in (Invoke-ScriptAnalyzer @pssaArgs)) {
                Add-Finding -Rule $r.RuleName -File $resolved -Line $r.Line -Col $r.Column `
                    -Severity (Get-Severity $r.RuleName $r.Severity) `
                    -Domain (Get-Domain $r.RuleName) -Backend 'pssa' -Message $r.Message
            }
        } catch {
            [Console]::Error.WriteLine("pssa failed on ${resolved}: $($_.Exception.Message)")
        }

        # InjectionHunter runs SEPARATELY, with default rules off, so its findings are attributable
        # to it rather than merged into PSSA's. Worth the second pass: measured 2026-08-24, PSSA's
        # 75 defaults returned 0 on fixer-scope-guard.ps1 and InjectionHunter returned 1 -- and
        # NEITHER found that file's real defect, which is the whole reason a clean run here is
        # reported as "which backend answered", never as "the file is safe".
        if ($ihOk) {
            try {
                foreach ($r in (Invoke-ScriptAnalyzer -Path $resolved -CustomRulePath $ihPsd.FullName -IncludeDefaultRules:$false)) {
                    Add-Finding -Rule $r.RuleName -File $resolved -Line $r.Line -Col $r.Column `
                        -Severity (Get-Severity $r.RuleName $r.Severity) `
                        -Domain 'security' -Backend 'injectionhunter' -Message $r.Message
                }
            } catch {
                [Console]::Error.WriteLine("injectionhunter failed on ${resolved}: $($_.Exception.Message)")
            }
        }
    }

    $fileInfo.Add([ordered]@{ path = $resolved; exists = $true; parsed = $parsed })
}

$pssaVersion = ''
if ($pssaOk) { $pssaVersion = $pssaModule.Version.ToString() }
$ihPath = ''
if ($ihOk) { $ihPath = $ihPsd.FullName }
# Computed BEFORE the literal below, not inline. `[ordered]@{ k = $(if (...) {...}) }` throws
# "Argument types do not match" in Windows PowerShell 5.1 -- the subexpression stops the braces
# being a hashtable LITERAL, which is the only thing [ordered] accepts.
$settingsPath = ''
if ($settingsOk) { $settingsPath = $SETTINGS }

# .ToArray() OUTSIDE the literal, for the same reason. Bisected on Windows PowerShell 5.1:
# `[ordered]@{ f = @($list) }` throws "Argument types do not match" whenever $list is a
# System.Collections.Generic.List[...], even an empty one -- while a plain nested [ordered], three
# levels of nesting, and sibling [ordered] values all work. Only the inline @() around a generic
# collection fails. Materialising first sidesteps it and renders identically.
$filesArr    = $fileInfo.ToArray()
$findingsArr = $findings.ToArray()

$out = [ordered]@{
    backends = [ordered]@{
        pssa            = [ordered]@{ available = $pssaOk; version = $pssaVersion; settings = $settingsPath }
        injectionhunter = [ordered]@{ available = $ihOk; path = $ihPath }
        ast             = [ordered]@{ available = $true; host = $PSVersionTable.PSVersion.ToString() }
    }
    files    = $filesArr
    findings = $findingsArr
}

# -Depth matters: Windows PowerShell 5.1 defaults to 2 and would silently truncate the nested
# finding objects to the string "System.Collections.Specialized.OrderedDictionary".
$out | ConvertTo-Json -Depth 8
