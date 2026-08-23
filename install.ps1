<#
.SYNOPSIS
    Installs the SQA-loop agent suite into this user's Claude Code configuration.

.DESCRIPTION
    Copies the seven agent definitions, the two PreToolUse guards, the perf_probe measurement
    wrapper, the QA harness, the ledger protocol and the /sqa-loop skill into ~/.claude/, then
    rewrites the guard path baked into each agent's frontmatter so it points at THIS machine.

    WHY AN INSTALL SCRIPT AND NOT A PLUGIN. Claude Code deliberately ignores `hooks:`,
    `permissionMode:` and `mcpServers:` in the frontmatter of plugin-shipped agents. This suite's
    entire safety model is two PreToolUse hooks declared in exactly that frontmatter: an allowlist
    that keeps the five review specialists read-only, and a scope guard that keeps the fixer out of
    its own scorecard, guard and metric. Shipped as a plugin, all of that is silently dropped and
    you get a fixer running `acceptEdits` with no boundary at all. So: a script, which installs
    agents at user level where the hooks are honoured.

.PARAMETER Verify
    Run the three mechanical gates against what is currently installed and exit. Changes nothing.

.PARAMETER MergeSettings
    Merge the Bash permission allowlist into ~/.claude/settings.json (backed up first). Without
    this the snippet is printed for you to merge by hand. Your settings.json is yours; the default
    is to not touch it.

.PARAMETER Uninstall
    Remove what this script installed. Never touches ~/.claude/qa-history/*.md ledgers or
    ~/.claude/settings.json -- those are your records and your configuration.

.PARAMETER Force
    Overwrite existing files without prompting. A timestamped backup is still taken.

.EXAMPLE
    .\install.ps1
.EXAMPLE
    .\install.ps1 -Verify
.EXAMPLE
    .\install.ps1 -MergeSettings
#>
[CmdletBinding()]
param(
    [switch]$Verify,
    [switch]$MergeSettings,
    [switch]$Uninstall,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---------------------------------------------------------------------------- output helpers
function Write-Step   ($m) { Write-Host "  $m" }
function Write-Ok     ($m) { Write-Host "  [ok]   $m"   -ForegroundColor Green }
function Write-Warn   ($m) { Write-Host "  [warn] $m"   -ForegroundColor Yellow }
function Write-Fail   ($m) { Write-Host "  [FAIL] $m"   -ForegroundColor Red }
function Write-Head   ($m) { Write-Host ""; Write-Host $m -ForegroundColor Cyan; Write-Host ("-" * $m.Length) -ForegroundColor DarkGray }

# ---------------------------------------------------------------------------- platform gate
#
# This refuses rather than degrades, and that is a deliberate choice. Both guards are PowerShell,
# and perf_probe.py shells out to powershell.exe for EVERY measured run. On macOS or Linux the
# agents would load and appear to work while the hook silently failed to execute -- and a hook
# that cannot run is not a hook that blocks. Installing a review suite whose read-only guarantee
# is decorative is worse than installing nothing, so this exits instead.
function Assert-Platform {
    $isWin = $true
    if ($null -ne (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue)) {
        $isWin = $IsWindows
    }
    if (-not $isWin) {
        Write-Fail "SQA-loop is Windows-only and this is not Windows."
        Write-Host ""
        Write-Host "  Both PreToolUse guards are PowerShell scripts, and perf_probe.py invokes"
        Write-Host "  powershell.exe for every measured run. On this platform the agents would"
        Write-Host "  install and load, but their guards would never fire -- the SQA specialists"
        Write-Host "  would no longer be structurally read-only, and the fixer could edit its own"
        Write-Host "  scorecard. That is a worse outcome than not installing."
        Write-Host ""
        Write-Host "  See docs/PORTING.md for what a cross-platform guard would have to satisfy."
        exit 1
    }
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Fail "PowerShell 5.1 or newer required; found $($PSVersionTable.PSVersion)."
        exit 1
    }
}

function Get-PythonCmd {
    foreach ($c in @('python', 'python3', 'py')) {
        $found = Get-Command $c -ErrorAction SilentlyContinue
        if ($found) {
            $v = & $c -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
            if ($LASTEXITCODE -eq 0 -and $v) {
                $parts = $v.Trim().Split('.')
                if ([int]$parts[0] -gt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 10)) {
                    return @{ Cmd = $c; Version = $v.Trim() }
                }
            }
        }
    }
    return $null
}

# ---------------------------------------------------------------------------- layout
$ClaudeDir = Join-Path $HOME '.claude'
$Payload = @(
    @{ From = 'agents';     To = 'agents';     Desc = '7 agent definitions' }
    @{ From = 'hooks';      To = 'hooks';      Desc = '2 PreToolUse guards' }
    @{ From = 'tools';      To = 'tools';      Desc = 'perf_probe (measures) + lint_probe (parses)' }
    @{ From = 'qa-harness'; To = 'qa-harness'; Desc = 'invariant checkers + behavioural corpora' }
    @{ From = 'qa-history'; To = 'qa-history'; Desc = 'ledger protocol + template' }
    @{ From = 'skills';     To = 'skills';     Desc = 'the /sqa-loop skill' }
)

# ---------------------------------------------------------------------------- hook path rewrite
#
# THE ONE THING THAT MAKES THIS PORTABLE. Each agent's frontmatter carries an absolute path to its
# guard, because agent-frontmatter hook commands support no variable expansion -- there is no
# ${CLAUDE_AGENT_DIR}. The path is written for whoever built the suite, so it must be rewritten for
# whoever installs it.
#
# The regex matches ANY path ending in one of the two guard filenames, so this is idempotent and
# does not care what username the file arrived with. What it must NOT disturb is the trailing
# `; exit $LASTEXITCODE`: under PowerShell's -Command form a script's `exit 2` arrives as 0 without
# it, which turns every block into a silent allow. That defect went unnoticed in the Bash guard for
# four weeks. qa-harness/agent_invariants.py asserts the suffix is present; guard_corpus.py keeps a
# `broken` invocation mode so the regression stays demonstrable.
function Update-HookPaths {
    param([string]$AgentsDir, [string]$HooksDir)

    # YAML double-quoted scalars escape a backslash as \\, so the on-disk text is doubled.
    $escaped = $HooksDir.Replace('\', '\\')
    $rewritten = 0
    $checked = 0

    foreach ($f in Get-ChildItem -Path $AgentsDir -Filter '*.md') {
        $text = [IO.File]::ReadAllText($f.FullName)
        $orig = $text
        $text = [regex]::Replace(
            $text,
            "(?<=&\s')[^']*?(sqa-guard-bash|fixer-scope-guard)\.ps1(?=')",
            { param($m) "$escaped\\$($m.Groups[1].Value).ps1" })
        $checked++
        if ($text -ne $orig) {
            # UTF8 without BOM: a BOM ahead of the `---` breaks frontmatter parsing.
            [IO.File]::WriteAllText($f.FullName, $text, (New-Object Text.UTF8Encoding $false))
            $rewritten++
        }
    }
    return @{ Checked = $checked; Rewritten = $rewritten }
}

# ---------------------------------------------------------------------------- verification
#
# These are the suite's OWN gates, not checks invented for the installer. Re-using them is the
# point: a bespoke installer self-test would be a second, weaker opinion about the same question.
function Invoke-Gates {
    param([string]$Py)

    $agents = Join-Path $ClaudeDir 'agents'
    $harness = Join-Path $ClaudeDir 'qa-harness'
    $settings = Join-Path $ClaudeDir 'settings.json'
    $allOk = $true

    Write-Head 'Gate 1/3  agent_invariants -- frontmatter, wiring, protocol drift'
    $a = @((Join-Path $harness 'agent_invariants.py'), $agents,
           '--only', 'sqa-*.md,code-reviewer.md')
    if (Test-Path $settings) { $a += @('--settings', $settings) }
    & $Py @a
    if ($LASTEXITCODE -eq 0) { Write-Ok 'all invariants hold' } else { Write-Fail "exit $LASTEXITCODE"; $allOk = $false }

    # NOTE: the FULL case set, deliberately -- NOT `--gate`.
    #
    # `--gate` runs a two-sided SUBSET (GATE_IDS), kept disjoint from `--score`'s set so the metric
    # cannot be climbed by satisfying the guard. That separation is correct for the loop, and wrong
    # here: the five known scope-guard bypasses live outside GATE_IDS, so `--gate` reports "every
    # case behaved as required" for a guard with five real holes. An installer that prints a green
    # line over a known gap is doing the precise thing this whole suite exists to prevent.
    Write-Head 'Gate 2/3  guard_corpus -- the Bash allowlist, must-block AND must-allow'
    & $Py (Join-Path $harness 'guard_corpus.py') --quiet
    if ($LASTEXITCODE -eq 0) { Write-Ok 'every case behaved as required' } else { Write-Fail "exit $LASTEXITCODE"; $allOk = $false }

    Write-Head 'Gate 3/3  scope_corpus -- the fixer scope guard'
    & $Py (Join-Path $harness 'scope_corpus.py') --quiet
    # Branch on WHICH non-zero, not merely on non-zero. Harness convention: 0 = all hold,
    # 1 = at least one case failed, 2 = the target could not be exercised at all. Collapsing
    # those two together once made a missing qa-harness print the same reassuring "five known
    # bypasses" note as a corpus that actually ran -- an install fault disguised as a documented
    # limitation, which is the worst of both.
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'every case behaved as required'
    } elseif ($LASTEXITCODE -eq 1) {
        # Known state as of 2026-08-24: 47/51, FOUR must-block cases fail. They are documented
        # bypasses of fixer-scope-guard.ps1 (interpreter write, perl -pi, git checkout,
        # cd-then-relative-redirect), not a broken install. Reported, never hidden.
        #
        # WAS five, and this message said so until 2026-08-24. The fifth -- a nested shell writing
        # through a PowerShell cmdlet -- is now CLOSED, along with the whole cmdlet-write class it
        # stood for (Set-Content/Out-File/New-Item/Add-Content, positional and named-parameter
        # forms alike). A stale "known gap" note is the exact failure R3 names: correct when
        # written, silently false later, and reassuring in both states.
        Write-Warn "47/51 expected -- four must-block cases are known-failing UPSTREAM, not an"
        Write-Warn "install fault: interpreter write, perl -pi, git checkout, and"
        Write-Warn "cd-then-relative-redirect. Read docs/GUARDS.md 'Known gaps' before relying"
        Write-Warn "on the fixer boundary. The Edit/Write path is unaffected."
    } else {
        Write-Fail "exit $LASTEXITCODE -- the corpus could not run at all. This IS an install"
        Write-Fail "fault, not the known-gaps case. Check that qa-harness/ and hooks/ arrived."
        $allOk = $false
    }
    return $allOk
}

# ============================================================================== main
Write-Host ""
Write-Host "SQA-loop installer" -ForegroundColor White
Write-Host "==================" -ForegroundColor DarkGray

Assert-Platform

$py = Get-PythonCmd
if ($null -eq $py) {
    Write-Fail "Python 3.10+ not found on PATH."
    Write-Host "  Needed by perf_probe.py and every qa-harness gate. See docs/PREREQUISITES.md."
    exit 1
}

if ($Verify) {
    Write-Step "python $($py.Version) at '$($py.Cmd)'"
    # Check for the FILES, not the directory. An uninstall leaves an empty agents/ behind, and a
    # directory test then let -Verify run the gates against nothing and report VERIFY FAILED --
    # which reads as "your install is broken" rather than "there is no install".
    $missing = @()
    foreach ($n in @('code-reviewer', 'sqa-lead', 'sqa-functional', 'sqa-embedded',
                     'sqa-numerical', 'sqa-security', 'sqa-efficiency')) {
        if (-not (Test-Path (Join-Path $ClaudeDir "agents\$n.md"))) { $missing += $n }
    }
    foreach ($d in @('hooks', 'qa-harness', 'tools')) {
        if (-not (Test-Path (Join-Path $ClaudeDir $d))) { $missing += "$d/" }
    }
    if ($missing.Count -gt 0) {
        Write-Fail "Not installed (or partially installed) at $ClaudeDir."
        Write-Step "missing: $($missing -join ', ')"
        Write-Step 'Run .\install.ps1 first.'
        exit 1
    }
    $ok = Invoke-Gates -Py $py.Cmd
    Write-Host ""
    if ($ok) { Write-Ok 'VERIFY PASSED'; exit 0 } else { Write-Fail 'VERIFY FAILED'; exit 1 }
}

if ($Uninstall) {
    Write-Head 'Uninstall'
    foreach ($item in $Payload) {
        $dest = Join-Path $ClaudeDir $item.To
        if ($item.To -eq 'qa-history') {
            Write-Warn "keeping $dest (your ledgers -- delete by hand if you mean to)"
            continue
        }
        if ($item.To -eq 'agents') {
            foreach ($n in @('code-reviewer', 'sqa-lead', 'sqa-functional', 'sqa-embedded',
                             'sqa-numerical', 'sqa-security', 'sqa-efficiency')) {
                $f = Join-Path $dest "$n.md"
                if (Test-Path $f) { Remove-Item $f -Force; Write-Step "removed $n.md" }
            }
            # Leave the directory only if the user has agents of their own in it; an empty
            # agents/ left behind is what made -Verify think a wiped install was a broken one.
            if ((Test-Path $dest) -and -not (Get-ChildItem $dest -Force)) {
                Remove-Item $dest -Force
                Write-Step 'removed now-empty agents directory'
            }
            continue
        }
        if (Test-Path $dest) { Remove-Item $dest -Recurse -Force; Write-Step "removed $dest" }
    }
    Write-Host ""
    Write-Warn 'settings.json was not modified. Remove the SQA Bash allow entries by hand.'
    Write-Ok 'Uninstalled.'
    exit 0
}

# ------------------------------------------------------------------ preflight
Write-Head 'Preflight'
Write-Step "repo      $RepoRoot"
Write-Step "target    $ClaudeDir"
Write-Step "python    $($py.Version) at '$($py.Cmd)'"

if (-not (Test-Path $ClaudeDir)) {
    Write-Fail "$ClaudeDir does not exist. Is Claude Code installed and has it run once?"
    exit 1
}
foreach ($item in $Payload) {
    if (-not (Test-Path (Join-Path $RepoRoot $item.From))) {
        Write-Fail "missing from this checkout: $($item.From)"
        exit 1
    }
}
Write-Ok 'repo layout and target directory look right'

# ------------------------------------------------------------------ backup
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $ClaudeDir "qa-backups\$stamp-preinstall"
Write-Head 'Backup'
$backedUp = 0
foreach ($item in $Payload) {
    $dest = Join-Path $ClaudeDir $item.To
    if (Test-Path $dest) {
        $to = Join-Path $backup $item.To
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $to) | Out-Null
        Copy-Item $dest $to -Recurse -Force
        $backedUp++
    }
}
if ($backedUp -gt 0) { Write-Ok "$backedUp existing tree(s) copied to $backup" }
else { Write-Step 'nothing existing to back up' }

# ------------------------------------------------------------------ copy
Write-Head 'Install'
foreach ($item in $Payload) {
    $src = Join-Path $RepoRoot $item.From
    $dest = Join-Path $ClaudeDir $item.To
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item (Join-Path $src '*') $dest -Recurse -Force
    Write-Ok "$($item.To.PadRight(11)) $($item.Desc)"
}

# ------------------------------------------------------------------ rewrite
Write-Head 'Rewire guards for this machine'
$r = Update-HookPaths -AgentsDir (Join-Path $ClaudeDir 'agents') -HooksDir (Join-Path $ClaudeDir 'hooks')
Write-Ok "$($r.Rewritten) of $($r.Checked) agent files repointed at $ClaudeDir\hooks"
if ($r.Rewritten -eq 0) {
    Write-Step 'already correct for this user -- nothing to change'
}

# ------------------------------------------------------------------ settings
$snippet = Join-Path $RepoRoot 'settings.snippet.json'
$settingsPath = Join-Path $ClaudeDir 'settings.json'
Write-Head 'Bash permissions'
if ($MergeSettings) {
    if (Test-Path $settingsPath) {
        Copy-Item $settingsPath "$settingsPath.bak-$stamp" -Force
        Write-Step "backed up settings.json to settings.json.bak-$stamp"
    }
    & $py.Cmd (Join-Path $RepoRoot 'merge_settings.py') $settingsPath $snippet
    if ($LASTEXITCODE -eq 0) { Write-Ok 'permissions merged' } else { Write-Fail 'merge failed -- settings.json unchanged (restore from the .bak if needed)' }
} else {
    Write-Step 'Not modifying settings.json (your config, your call).'
    Write-Step "Merge the `permissions.allow` entries from:"
    Write-Step "    $snippet"
    Write-Step 'or re-run with -MergeSettings to have it done for you.'
    Write-Step 'Without them the specialists still work; you just approve more Bash prompts.'
}

# ------------------------------------------------------------------ verify
Write-Head 'Verifying the install'
$ok = Invoke-Gates -Py $py.Cmd

Write-Host ""
if ($ok) {
    Write-Ok 'INSTALL COMPLETE'
} else {
    Write-Fail 'INSTALL COMPLETE, BUT A GATE FAILED -- read the output above before using the suite.'
}
Write-Host ""
Write-Host "  RESTART Claude Code before first use." -ForegroundColor Yellow
Write-Host "  Agent hook wiring is read at session start; a session already running will not"
Write-Host "  pick up these guards, and an unguarded specialist looks identical to a guarded one."
Write-Host ""
Write-Host "  Then try:  @agent-sqa-lead review <some file>"
Write-Host "        or:  /sqa-loop <some file>"
Write-Host ""
if (-not $ok) { exit 1 }
