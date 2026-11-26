@{
    # A finding of any listed severity fails CI. Information-level rules are
    # left out because they give style advice (positional parameters, missing
    # output-type declarations) and do not point at defects. ParseError is
    # listed because PSScriptAnalyzer drops a syntax error from the results
    # when the severity filter does not name it, and several of these scripts
    # are neither run nor parsed anywhere else in CI.
    Severity     = @('Error', 'Warning', 'ParseError')

    # Each exclusion turns a rule off for every script, so add one only with a
    # reason that holds for the whole class of files, and state it here.
    ExcludeRules = @(
        # These are console scripts and installers, where Write-Host is the
        # intended user-facing output.
        'PSAvoidUsingWriteHost',

        # This rule protects callers of exported cmdlets that take -WhatIf and
        # -Confirm. The functions it flags are private helpers inside e2e and
        # installer scripts (they build specs, command lines and wrapper files
        # or start a test process); nothing calls them with -WhatIf, so
        # SupportsShouldProcess would add a switch that nothing reads.
        'PSUseShouldProcessForStateChangingFunctions',

        # This rule keeps exported cmdlet nouns singular so that command names
        # stay predictable for users. No script here is a module, exports a
        # function, or is dot-sourced as a library, and install.ps1 runs
        # through irm | iex, so its functions live only in that session.
        # None of these names is a command that users are given.
        'PSUseSingularNouns'
    )
}
