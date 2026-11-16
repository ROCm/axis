# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Build AXIS and its pinned Windows MXC executor from source.
param(
    [string]$MxcDir = (Join-Path $env:LOCALAPPDATA "axis-dev\mxc"),
    [switch]$SkipAxisBuild
)

$ErrorActionPreference = "Stop"

$mxcRepository = "https://github.com/microsoft/mxc"
# MXC v1.0.1; keep in sync with MXC_WINDOWS_REF in the workflows.
$mxcRef = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
$repoRoot = Split-Path -Parent $PSScriptRoot
$axisReleaseDir = Join-Path $repoRoot "target\release"
$installedExecutor = Join-Path $axisReleaseDir "wxc-exec.exe"

foreach ($command in @("git", "cargo")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is not available on PATH: $command"
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $MxcDir ".git") -PathType Container)) {
    if (Test-Path -LiteralPath $MxcDir) {
        throw "MXC destination exists but is not a Git checkout: $MxcDir"
    }

    $mxcParent = Split-Path -Parent $MxcDir
    New-Item -ItemType Directory -Path $mxcParent -Force | Out-Null
    Write-Host "Cloning pinned MXC source into $MxcDir"
    & git clone --filter=blob:none $mxcRepository $MxcDir
    if ($LASTEXITCODE -ne 0) {
        throw "MXC clone failed with exit code $LASTEXITCODE"
    }
}

Write-Host "Checking out pinned MXC revision $mxcRef"
& git -C $MxcDir fetch origin $mxcRef --depth=1
if ($LASTEXITCODE -ne 0) {
    throw "MXC fetch failed with exit code $LASTEXITCODE"
}
& git -C $MxcDir checkout --detach $mxcRef
if ($LASTEXITCODE -ne 0) {
    throw "MXC checkout failed with exit code $LASTEXITCODE"
}

Write-Host "Building wxc-exec.exe"
Push-Location (Join-Path $MxcDir "src")
try {
    & cargo build --release -p wxc --no-default-features --locked
    if ($LASTEXITCODE -ne 0) {
        throw "MXC build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

if (-not $SkipAxisBuild) {
    Write-Host "Building axis.exe"
    & cargo build --release -p axis-cli --manifest-path (Join-Path $repoRoot "Cargo.toml")
    if ($LASTEXITCODE -ne 0) {
        throw "AXIS build failed with exit code $LASTEXITCODE"
    }
    Write-Host "Building axis-ssh-proxy.exe"
    & cargo build --release -p axis-sandbox --bin axis-ssh-proxy --manifest-path (Join-Path $repoRoot "Cargo.toml")
    if ($LASTEXITCODE -ne 0) {
        throw "AXIS SSH proxy helper build failed with exit code $LASTEXITCODE"
    }
}

New-Item -ItemType Directory -Path $axisReleaseDir -Force | Out-Null
$builtExecutor = Join-Path $MxcDir "src\target\release\wxc-exec.exe"
if (-not (Test-Path -LiteralPath $builtExecutor -PathType Leaf)) {
    throw "MXC build completed without producing: $builtExecutor"
}
Copy-Item -LiteralPath $builtExecutor -Destination $installedExecutor -Force

# Configure this PowerShell process for a BaseContainer launch.
$env:AXIS_MXC_EXECUTOR = (Resolve-Path -LiteralPath $installedExecutor).Path

Write-Host ""
Write-Host "Windows MXC setup complete."
Write-Host "Executor: $env:AXIS_MXC_EXECUTOR"
Write-Host "BaseContainer mode selected (DACL fallback is disabled by AXIS policy)."
