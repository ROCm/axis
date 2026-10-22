# Build AXIS and its pinned Windows MXC executor from source.
param(
    [string]$MxcDir = (Join-Path $env:LOCALAPPDATA "axis-dev\mxc"),
    [switch]$SkipAxisBuild
)

$ErrorActionPreference = "Stop"

$mxcRepository = "https://github.com/microsoft/mxc"
# Windows stays on an older MXC revision than Linux until MXC BaseContainer can
# run least-privilege AppContainer children without DACL mutation:
# https://github.com/microsoft/mxc/issues/1496
$mxcRef = "1736b48398c3fe4d1315b2311c0951cc893eb3ae"
$repoRoot = Split-Path -Parent $PSScriptRoot
$patchPaths = @(
    (Join-Path $repoRoot "third_party\mxc\patches\0001-wxc-processcontainer-resource-limits.patch"),
    (Join-Path $repoRoot "third_party\mxc\patches\0002-wxc-job-list-resource-assignment.patch"),
    (Join-Path $repoRoot "third_party\mxc\patches\0003-axis-wfp-strict-proxy.patch")
)
$axisReleaseDir = Join-Path $repoRoot "target\release"
$installedExecutor = Join-Path $axisReleaseDir "wxc-exec.exe"

function Test-MxcPatch([string]$PatchPath, [switch]$Reverse) {
    # Windows PowerShell 5.1 turns native stderr into an ErrorRecord when the
    # caller uses Stop. A failed `git apply --check` is expected while deciding
    # whether the patch is already present, so inspect its exit code explicitly.
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        if ($Reverse) {
            & git -C $MxcDir apply --reverse --check --whitespace=error $PatchPath 2>$null
        } else {
            & git -C $MxcDir apply --check --whitespace=error $PatchPath 2>$null
        }
        return $LASTEXITCODE -eq 0
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
}

foreach ($command in @("git", "cargo")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is not available on PATH: $command"
    }
}
foreach ($patchPath in $patchPaths) {
    if (-not (Test-Path -LiteralPath $patchPath -PathType Leaf)) {
        throw "AXIS MXC patch not found: $patchPath"
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

# Make repeated runs safe: apply the AXIS patch only when it is not present.
if (Test-MxcPatch $patchPaths[0]) {
    Write-Host "Applying AXIS MXC patches"
    foreach ($patchPath in $patchPaths) {
        & git -C $MxcDir apply --whitespace=error $patchPath
        if ($LASTEXITCODE -ne 0) {
            throw "MXC patch failed for $patchPath with exit code $LASTEXITCODE"
        }
    }
} else {
    if (-not (Test-MxcPatch $patchPaths[-1] -Reverse)) {
        throw "MXC checkout is not in a state where the AXIS patches can be applied"
    }
    Write-Host "AXIS MXC patches are already applied"
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
