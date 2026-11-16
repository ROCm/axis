# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Package built AXIS binaries into the deterministic dist\axis-windows-x86_64.zip
# archive that release, nightly and CI build and that install.ps1 installs.
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ReleaseDir,
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$ExtraFiles = @()
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$targetDir = (Resolve-Path -LiteralPath $ReleaseDir).Path
$archiveRoot = "axis-windows-x86_64"

Push-Location $repoRoot
try {
    $packageDir = Join-Path "dist" $archiveRoot
    Remove-Item -LiteralPath $packageDir, "$packageDir.zip" -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
    foreach ($binary in @("axis.exe", "axisd.exe", "wxc-exec.exe", "axis-ssh-proxy.exe")) {
        Copy-Item -LiteralPath (Join-Path $targetDir $binary) -Destination $packageDir
    }
    Copy-Item -Path (Join-Path "policies" "*.yaml") -Destination $packageDir
    foreach ($file in @($ExtraFiles) + @("LICENSE", "install.ps1")) {
        Copy-Item -LiteralPath $file -Destination $packageDir
    }
    Copy-Item -LiteralPath "packaging/reproducibility/core-windows.json" -Destination (Join-Path $packageDir "REPRODUCIBILITY.json")

    Add-Type -AssemblyName System.IO.Compression
    $source = (Resolve-Path -LiteralPath $packageDir).Path
    $root = Split-Path $source -Parent
    # ZipFile resolves relative paths against the process directory, not the
    # PowerShell location, so the archive path must be absolute.
    $zip = [System.IO.Compression.ZipFile]::Open(
        (Join-Path $root "$archiveRoot.zip"),
        [System.IO.Compression.ZipArchiveMode]::Create
    )
    try {
        Get-ChildItem -LiteralPath $source -File -Recurse | Sort-Object FullName | ForEach-Object {
            $relative = [System.IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
            $entry = $zip.CreateEntry($relative, [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = [System.DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            $reader = [System.IO.File]::OpenRead($_.FullName)
            $writer = $entry.Open()
            try { $reader.CopyTo($writer) } finally { $writer.Dispose(); $reader.Dispose() }
        }
    } finally {
        $zip.Dispose()
    }
} finally {
    Pop-Location
}
