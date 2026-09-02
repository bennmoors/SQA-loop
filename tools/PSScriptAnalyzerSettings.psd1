# PSScriptAnalyzerSettings.psd1 -- the triage policy for lint_probe.py's PowerShell backend.
#
# WHY THIS IS DATA AND NOT PYTHON. PSSA's own -Settings mechanism is the supported way to pin a
# rule set, it survives a PSSA upgrade that adds rules, and it keeps the policy reviewable as a
# table rather than buried in a mapping dict. It lives in tools/ so fixer-scope-guard.ps1's
# `/.claude/tools(/|$)` rule protects it exactly as it protects perf_probe.py -- a fixer that can
# edit the policy deciding which of its findings count can make any verdict say anything.
#
# THE CALIBRATION FIXTURE, measured 2026-08-24 on this repo's own files:
#
#   install.ps1             34 findings -- 30 of them PSAvoidUsingWriteHost
#   sqa-guard-bash.ps1       1 finding  -- PSUseApprovedVerbs (Matches-Any)
#   fixer-scope-guard.ps1    0 findings -- on a file with a PROVEN write bypass
#
# Those three numbers are the whole argument for this file. Piping raw PSSA output into a VERDICT
# would report 30 Warnings about an installer legitimately printing to the console, and 0 about a
# security guard with a real hole. Severity here is a POLICY mapping, not a passthrough, and the
# style rules below are capped so they can never gate a verdict.
#
# A clean PSSA run is NOT a security result. Say which backend answered.

@{
    # Start from every built-in rule, then subtract. An allowlist of rule names would silently
    # lose any rule a future PSSA adds, which is the failure mode this suite keeps re-learning.
    IncludeDefaultRules = $true

    ExcludeRules = @(
        # --- Excluded outright: wrong for the target classes this suite reviews.
        #
        # An installer, a hook and a CLI probe all print to the console ON PURPOSE. Write-Host is
        # the correct call there: Write-Output would pollute the pipeline and corrupt a function's
        # return value, which is a REAL defect this suite reports elsewhere. Keeping this rule on
        # would mean the noisiest finding in the corpus is also the one most likely to be wrong.
        # Note this is an exclusion, not a downgrade -- see the Suggestion list below for the
        # rules that are merely capped.
        'PSAvoidUsingWriteHost',

        # Fires on any function whose noun happens to be plural. It is a naming preference with no
        # behavioural consequence, and it accounted for 2 of install.ps1's 34.
        'PSUseSingularNouns',

        # PSSA cannot see across files, so it reports parameters used only by a caller or a
        # splatted hashtable. High false-positive rate on this codebase's hook scripts.
        'PSReviewUnusedParameter',

        # OFF BY MEASUREMENT, not by opinion, and this one was enabled first and then withdrawn.
        # PSUseConstrainedLanguageMode flags every construct CLM forbids, which means every .NET
        # type reference. Measured 2026-08-24 across this repo's three .ps1 files: 14 findings,
        # against 5 from every other rule combined -- all of them `[Console]`, `[regex]`,
        # `[TimeSpan]` and `[System.Management.Automation.Language.Parser]` doing exactly what a
        # PreToolUse hook and an AST scanner must do. It is only meaningful when the target is
        # INTENDED to run under Constrained Language Mode, and nothing in the invocation says so.
        #
        # Re-enable it deliberately for a CLM-targeted review by deleting this line. Do NOT leave
        # it on by default: 14-of-19 findings from one inapplicable rule is the flooding this whole
        # file exists to prevent, and burying real findings under Suggestions costs a reviewer the
        # same attention whether or not the count gates a verdict.
        #
        # Worth stating alongside it, because the two get confused: ExecutionPolicy is NOT a
        # security boundary -- Microsoft says so -- so `-ExecutionPolicy Bypass` is a smell, never
        # a vulnerability, and sqa-security is instructed not to report it as one.
        'PSUseConstrainedLanguageMode'
    )

    Rules = @{
        # --- Explicitly ON, and worth naming rather than inheriting silently.

        # The credential-handling family. These are the PSSA rules that carry genuine security
        # weight, as opposed to the style bulk above.
        PSAvoidUsingConvertToSecureStringWithPlainText = @{ Enable = $true }
        PSAvoidUsingPlainTextForPassword              = @{ Enable = $true }
        PSAvoidUsingUsernameAndPasswordParams         = @{ Enable = $true }
        PSUsePSCredentialType                         = @{ Enable = $true }
    }
}

# --------------------------------------------------------------------------------------------
# SEVERITY POLICY -- read by lint_probe.py, which owns the mapping. Recorded here so the policy
# lives in one place even though PSSA itself has no syntax for expressing it.
#
#   PSSA Error       -> Critical
#   PSSA Warning     -> Warning      (except the capped list below)
#   PSSA Information -> Suggestion
#
# CAPPED AT SUGGESTION regardless of what PSSA calls them -- style rules that cannot gate a
# verdict. A verdict count is a defect count; a formatting opinion is not a defect.
#
#   PSAvoidUsingDoubleQuotesForConstantString, PSAlignAssignmentStatement,
#   PSUseConsistentIndentation, PSUseConsistentWhitespace, PSAvoidTrailingWhitespace,
#   PSPlaceOpenBrace, PSPlaceCloseBrace, PSUseCorrectCasing
#
# NOT capped, deliberately: PSUseApprovedVerbs stays a Warning. It is the one style-adjacent rule
# this repo has evidence for -- it and an independent AST scan agreed on `Matches-Any` in
# sqa-guard-bash.ps1, and an unapproved verb is a discoverability defect a caller actually hits.
