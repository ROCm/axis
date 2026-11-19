# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = "Stop"

if (-not $PSVersionTable.PSVersion -or $PSVersionTable.PSVersion.Major -lt 7) {
    throw "Installer tests require PowerShell 7 or later (pwsh)"
}

$archive = Join-Path (Split-Path -Parent $PSScriptRoot) "dist/axis-windows-x86_64.zip"
$validChecksum = "$archive.sha256"

function Assert-InstallFails {
    param(
        [string]$TestArchive,
        [AllowEmptyString()][string]$TestChecksum,
        [string]$ExpectedError,
        [string]$InstallName
    )
    $env:AXIS_INSTALL_ARCHIVE = $TestArchive
    $env:AXIS_INSTALL_SHA256 = $TestChecksum
    $env:AXIS_DIR = Join-Path $env:RUNNER_TEMP $InstallName
    $savedErrorActionPreference = $ErrorActionPreference
    $savedNativeErrorPreference = $PSNativeCommandUseErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $PSNativeCommandUseErrorActionPreference = $false
        $output = & pwsh -NoLogo -NoProfile -File .\install.ps1 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
        $PSNativeCommandUseErrorActionPreference = $savedNativeErrorPreference
    }
    if ($exitCode -eq 0) {
        throw "installer unexpectedly accepted $InstallName"
    }
    if ($output -notmatch [regex]::Escape($ExpectedError)) {
        throw "installer failure did not contain '$ExpectedError': $output"
    }
    if (Test-Path -LiteralPath (Join-Path $env:AXIS_DIR "axis.exe")) {
        throw "installer wrote axis.exe before rejecting $InstallName"
    }
}

$missing = Join-Path $env:RUNNER_TEMP "missing-checksum.zip"
Copy-Item -LiteralPath $archive -Destination $missing
Assert-InstallFails $missing "" "Cannot find path" "axis-missing-checksum"

$wrongName = Join-Path $env:RUNNER_TEMP "wrong-name.zip"
Copy-Item -LiteralPath $archive -Destination $wrongName
Assert-InstallFails $wrongName $validChecksum "Invalid checksum file" "axis-wrong-name"

$tampered = Join-Path $env:RUNNER_TEMP "tampered.zip"
Copy-Item -LiteralPath $archive -Destination $tampered
$originalHash = (Get-FileHash -LiteralPath $tampered -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$tampered.sha256" -NoNewline -Value "$originalHash  $([System.IO.Path]::GetFileName($tampered))`n"
[System.IO.File]::AppendAllText($tampered, "tampered")
Assert-InstallFails $tampered "$tampered.sha256" "Checksum verification failed" "axis-tampered"

$global:LASTEXITCODE = 0
