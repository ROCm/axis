# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Build this checkout and the pinned MXC executor into an archive and checksum
# that install.ps1 installs through AXIS_INSTALL_ARCHIVE.
$ErrorActionPreference = "Stop"

if (-not $IsWindows) {
    throw "build_install_archive.ps1 builds the Windows archive; use build_install_archive.sh on Linux and macOS"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$releaseDir = Join-Path $repoRoot "target\release"
$archiveName = "axis-windows-x86_64.zip"
$archive = Join-Path $repoRoot "dist\$archiveName"

& cargo build --locked --release --manifest-path (Join-Path $repoRoot "Cargo.toml")
if ($LASTEXITCODE -ne 0) {
    throw "AXIS build failed with exit code $LASTEXITCODE"
}
& (Join-Path $PSScriptRoot "setup_windows_mxc.ps1") -SkipAxisBuild
& (Join-Path $PSScriptRoot "package_windows_archive.ps1") $releaseDir README.md

$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$archive.sha256" -NoNewline -Value "$hash  $archiveName`n"

Write-Host ""
Write-Host "Built $archive. Install it with:"
Write-Host "  `$env:AXIS_INSTALL_ARCHIVE = `"$archive`"; .\install.ps1"
