# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Gated AXIS-through-MXC ProcessContainer smoke and security checks.
param(
    [string]$AxisBin = ".\target\release\axis.exe"
)

$ErrorActionPreference = "Stop"
$IsolationTier = "BaseContainer"

function Exit-Skip([string]$Message) {
    Write-Host "SKIP: $Message"
    exit 0
}

function Exit-Fail([string]$Message) {
    Write-Host "FAIL: $Message"
    exit 1
}

if ($env:AXIS_RUN_MXC_BASECONTAINER_E2E -ne "1") {
    Exit-Skip "AXIS_RUN_MXC_BASECONTAINER_E2E=1 not set"
}
if ($env:OS -ne "Windows_NT") {
    Exit-Fail "Windows MXC ProcessContainer tests require a Windows host"
}
if (-not (Test-Path -LiteralPath $AxisBin -PathType Leaf)) {
    Exit-Fail "AXIS binary not found: $AxisBin"
}
$AxisBin = (Resolve-Path -LiteralPath $AxisBin).Path
if (-not $env:AXIS_TEST_MXC_EXECUTOR) {
    Exit-Fail "AXIS_TEST_MXC_EXECUTOR must name a trusted wxc-exec.exe"
}
if (-not (Test-Path -LiteralPath $env:AXIS_TEST_MXC_EXECUTOR -PathType Leaf)) {
    Exit-Fail "MXC executor not found: $env:AXIS_TEST_MXC_EXECUTOR"
}

$root = Join-Path ([System.IO.Path]::GetTempPath()) ("axis-mxc-processcontainer-e2e-" + [guid]::NewGuid().ToString("N"))
$workspace = Join-Path $root "workspace"
$outside = Join-Path $root "outside-sentinel.txt"
$readonly = Join-Path $root "readonly"
$readonlyFile = Join-Path $readonly "reference.txt"
$policy = Join-Path $root "policy.yaml"
$allowPolicy = Join-Path $root "allow-policy.yaml"
$timeoutPolicy = Join-Path $root "timeout-policy.yaml"
$processAllowPolicy = Join-Path $root "process-allow-policy.yaml"
$processLimitPolicy = Join-Path $root "process-limit-policy.yaml"
$portableProcessPolicy = Join-Path $root "portable-process-policy.yaml"
$memoryPolicy = Join-Path $root "memory-policy.yaml"
$cpuBaselinePolicy = Join-Path $root "cpu-baseline-policy.yaml"
$cpuLimitPolicy = Join-Path $root "cpu-limit-policy.yaml"
$resourceProbe = Join-Path $workspace "axis-windows-resource-probe.exe"
New-Item -ItemType Directory -Path $workspace -Force | Out-Null
New-Item -ItemType Directory -Path $readonly -Force | Out-Null
Set-Content -LiteralPath $outside -Value "AXIS_OUTSIDE_SENTINEL" -Encoding ASCII
Set-Content -LiteralPath $readonlyFile -Value "AXIS_READONLY_SENTINEL" -Encoding ASCII

$yamlReadonly = $readonly.Replace("'", "''")
$yamlOutside = $outside.Replace("'", "''")

$policyText = @"
version: 1
name: windows-mxc-$($IsolationTier.ToLowerInvariant())-e2e
runtime:
  containment: process
  provider: mxc
filesystem:
  read_only:
    - '$yamlReadonly'
  read_write:
    - "{workspace}"
  deny:
    - '$yamlOutside'
  compatibility: hard_requirement
process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0
  timeout_sec: 15
network:
  mode: block
"@
# Windows PowerShell 5.1 writes a BOM for `-Encoding UTF8`; serde_yaml does
# not accept that marker here. The fixture is intentionally ASCII-only.
Set-Content -LiteralPath $policy -Value $policyText -Encoding ASCII

$allowPolicyText = $policyText.Replace("mode: block", "mode: allow")
Set-Content -LiteralPath $allowPolicy -Value $allowPolicyText -Encoding ASCII

$timeoutPolicyText = $policyText.Replace("timeout_sec: 15", "timeout_sec: 1")
Set-Content -LiteralPath $timeoutPolicy -Value $timeoutPolicyText -Encoding ASCII

if ($IsolationTier -eq "BaseContainer") {
    $rustc = Get-Command rustc -ErrorAction SilentlyContinue
    if (-not $rustc) {
        Exit-Fail "rustc is required to compile the Windows resource-limit probe"
    }
    $resourceProbeSource = Join-Path $PSScriptRoot "helpers\resource_probe.rs"
    if (-not (Test-Path -LiteralPath $resourceProbeSource -PathType Leaf)) {
        Exit-Fail "resource probe source not found: $resourceProbeSource"
    }
    & $rustc.Source -O $resourceProbeSource -o $resourceProbe
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $resourceProbe -PathType Leaf)) {
        Exit-Fail "failed to compile Windows resource-limit probe"
    }

    $resourcePolicyText = $policyText.Replace("timeout_sec: 15", "timeout_sec: 60")
    Set-Content -LiteralPath $processAllowPolicy -Encoding ASCII -Value (
        $resourcePolicyText.Replace("max_processes: 0", "max_processes: 4")
    )
    Set-Content -LiteralPath $processLimitPolicy -Encoding ASCII -Value (
        $resourcePolicyText.Replace("max_processes: 0", "max_processes: 2")
    )
    Set-Content -LiteralPath $portableProcessPolicy -Encoding ASCII -Value (
        $resourcePolicyText.Replace("max_processes: 0", "max_processes: 32`n  identity: isolated`n  child_processes: deny")
    )
    Set-Content -LiteralPath $memoryPolicy -Encoding ASCII -Value (
        $resourcePolicyText.Replace("max_processes: 0", "max_processes: 6").Replace("max_memory_mb: 0", "max_memory_mb: 88")
    )
    Set-Content -LiteralPath $cpuBaselinePolicy -Encoding ASCII -Value (
        $resourcePolicyText.Replace("cpu_rate_percent: 0", "cpu_rate_percent: 100")
    )
    Set-Content -LiteralPath $cpuLimitPolicy -Encoding ASCII -Value (
        $resourcePolicyText.Replace("cpu_rate_percent: 0", "cpu_rate_percent: 10")
    )
}

function Invoke-AxisCommand([string]$CommandLine, [string]$PolicyPath = $policy) {
    Push-Location $workspace
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 promotes native stderr to a terminating
        # NativeCommandError under Stop. AXIS status messages use stderr.
        $ErrorActionPreference = "Continue"
        $output = & $AxisBin run --policy $PolicyPath -- cmd.exe /d /s /c $CommandLine 2>&1 | Out-String
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output = $output
        }
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
        Pop-Location
    }
}

function Invoke-AxisProgram([string]$Program, [string[]]$ProgramArgs, [string]$PolicyPath) {
    Push-Location $workspace
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = & $AxisBin run --policy $PolicyPath -- $Program @ProgramArgs 2>&1 | Out-String
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output = $output
        }
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
        Pop-Location
    }
}

function Test-HostTcpConnectivity {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync("1.1.1.1", 443)
        return $task.Wait(5000) -and $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

$inside = Join-Path $workspace "inside-write.txt"

$networkProbeCommand = 'curl.exe --silent --insecure --connect-timeout 5 --max-time 8 --output NUL https://1.1.1.1/'

$childStarted = Join-Path $workspace "timeout-child-started.txt"
$escapedChild = Join-Path $workspace "timeout-child-escaped.txt"
$delayedChildScript = Join-Path $workspace "timeout-child.cmd"
$timeoutParentScript = Join-Path $workspace "timeout-parent.cmd"
Set-Content -LiteralPath $delayedChildScript -Encoding ASCII -Value @"
@echo off
>"$childStarted" echo started
set /a ticks=0
set "lastSecond=%time:~6,2%"
:waitForTick
set "currentSecond=%time:~6,2%"
if "%currentSecond%"=="%lastSecond%" goto waitForTick
set "lastSecond=%currentSecond%"
set /a ticks+=1
if %ticks% LSS 4 goto waitForTick
>"$escapedChild" echo escaped
"@
Set-Content -LiteralPath $timeoutParentScript -Encoding ASCII -Value @"
@echo off
start "" /b cmd.exe /d /s /c "`"$delayedChildScript`""
:waitForever
goto waitForever
"@

$savedProcessGatePresent = Test-Path Env:\AXIS_RUN_MXC_PROCESS_E2E
$savedProcessGate = $env:AXIS_RUN_MXC_PROCESS_E2E
$savedSecretPresent = Test-Path Env:\OPENAI_API_KEY
$savedSecret = $env:OPENAI_API_KEY
$savedAllowedPresent = Test-Path Env:\OPENAI_ORG_ID
$savedAllowed = $env:OPENAI_ORG_ID
$workspaceSddl = if ($IsolationTier -eq "BaseContainer") { (Get-Acl -LiteralPath $workspace).Sddl } else { $null }
$readonlySddl = if ($IsolationTier -eq "BaseContainer") { (Get-Acl -LiteralPath $readonly).Sddl } else { $null }

try {
    # The generated MXC config disables DACL fallback, so an unavailable
    # BaseContainer fails closed instead of changing the isolation tier.
    $env:AXIS_RUN_MXC_PROCESS_E2E = "1"

    $missingExecutor = Join-Path $root "missing-wxc-exec.exe"
    $realExecutor = $env:AXIS_TEST_MXC_EXECUTOR
    $env:AXIS_TEST_MXC_EXECUTOR = $missingExecutor
    $fallbackMarker = Join-Path $workspace "must-not-run.txt"
    $fallback = Invoke-AxisCommand "echo unsafe>`"$fallbackMarker`""
    $env:AXIS_TEST_MXC_EXECUTOR = $realExecutor
    if ($fallback.ExitCode -eq 0 -or (Test-Path -LiteralPath $fallbackMarker)) {
        Exit-Fail "missing MXC executor fell back to host execution"
    }

    $smoke = Invoke-AxisCommand "echo AXIS_MXC_PROCESSCONTAINER_SMOKE"
    if ($smoke.ExitCode -ne 0 -or -not $smoke.Output.Contains("AXIS_MXC_PROCESSCONTAINER_SMOKE")) {
        $baseContainerUnavailable =
            $smoke.Output.Contains("BaseContainer is unavailable on this system") -and
            $smoke.Output.Contains("DACL fallback is disabled")
        if ($env:AXIS_SKIP_UNAVAILABLE_MXC_BASECONTAINER_E2E -eq "1" -and
            $baseContainerUnavailable) {
            Exit-Skip (
                "BaseContainer is unavailable on Windows build " +
                "$([System.Environment]::OSVersion.Version); verified missing-executor and " +
                "disabled-DACL-fallback fail-closed behavior, but did not run the live isolation suite"
            )
        }
        Exit-Fail "ProcessContainer smoke failed: exit=$($smoke.ExitCode) output=$($smoke.Output)"
    }

    $env:OPENAI_API_KEY = "must-not-cross-boundary"
    $env:OPENAI_ORG_ID = "axis-e2e-allowed"
    $environment = Invoke-AxisCommand 'if defined OPENAI_API_KEY (exit /b 41) else if "%OPENAI_ORG_ID%"=="axis-e2e-allowed" (echo AXIS_MXC_ENVIRONMENT_FILTERED) else (exit /b 42)'
    if ($environment.ExitCode -ne 0 -or -not $environment.Output.Contains("AXIS_MXC_ENVIRONMENT_FILTERED")) {
        Exit-Fail "environment filtering failed: exit=$($environment.ExitCode) output=$($environment.Output)"
    }

    $managedProfile = Invoke-AxisCommand 'echo AXIS_HOME=%HOME%&echo AXIS_USERPROFILE=%USERPROFILE%&echo AXIS_APPDATA=%APPDATA%&echo AXIS_LOCALAPPDATA=%LOCALAPPDATA%'
    $homeMatch = [regex]::Match($managedProfile.Output, "AXIS_HOME=([^\r\n]+)")
    $profileMatch = [regex]::Match($managedProfile.Output, "AXIS_USERPROFILE=([^\r\n]+)")
    $appdataMatch = [regex]::Match($managedProfile.Output, "AXIS_APPDATA=([^\r\n]+)")
    $localAppdataMatch = [regex]::Match($managedProfile.Output, "AXIS_LOCALAPPDATA=([^\r\n]+)")
    if ($managedProfile.ExitCode -ne 0 -or -not $homeMatch.Success -or -not $profileMatch.Success -or
        -not $appdataMatch.Success -or -not $localAppdataMatch.Success -or
        $homeMatch.Groups[1].Value -ne $profileMatch.Groups[1].Value -or
        $profileMatch.Groups[1].Value -eq $env:USERPROFILE -or
        -not $appdataMatch.Groups[1].Value.StartsWith($profileMatch.Groups[1].Value, [StringComparison]::OrdinalIgnoreCase) -or
        -not $localAppdataMatch.Groups[1].Value.StartsWith($profileMatch.Groups[1].Value, [StringComparison]::OrdinalIgnoreCase)) {
        Exit-Fail "managed Windows profile projection failed: exit=$($managedProfile.ExitCode) output=$($managedProfile.Output)"
    }

    $readonlyRead = Invoke-AxisCommand "type `"$readonlyFile`""
    if ($readonlyRead.ExitCode -ne 0 -or -not $readonlyRead.Output.Contains("AXIS_READONLY_SENTINEL")) {
        Exit-Fail "read-only path was not readable: exit=$($readonlyRead.ExitCode) output=$($readonlyRead.Output)"
    }

    $readonlyWrite = Invoke-AxisCommand "echo forbidden>`"$readonlyFile`""
    if ((Get-Content -LiteralPath $readonlyFile -Raw).Trim() -ne "AXIS_READONLY_SENTINEL") {
        Exit-Fail "read-only ProcessContainer path was modified: exit=$($readonlyWrite.ExitCode) output=$($readonlyWrite.Output)"
    }

    $outsideRead = Invoke-AxisCommand "type `"$outside`""
    if ($outsideRead.Output.Contains("AXIS_OUTSIDE_SENTINEL")) {
        Exit-Fail "default-deny ProcessContainer boundary allowed an outside read"
    }

    $workspaceWrite = Invoke-AxisCommand "echo writable>`"$inside`""
    if ($workspaceWrite.ExitCode -ne 0 -or
        -not (Test-Path -LiteralPath $inside -PathType Leaf) -or
        (Get-Content -LiteralPath $inside -Raw).Trim() -ne "writable") {
        Exit-Fail "workspace was not writable: exit=$($workspaceWrite.ExitCode) output=$($workspaceWrite.Output)"
    }

    if (Test-HostTcpConnectivity) {
        $blockedNetwork = Invoke-AxisCommand $networkProbeCommand
        if ($blockedNetwork.ExitCode -eq 0) {
            Exit-Fail "block-mode ProcessContainer unexpectedly reached 1.1.1.1:443"
        }
        $allowedNetwork = Invoke-AxisCommand $networkProbeCommand $allowPolicy
        if ($allowedNetwork.ExitCode -ne 0) {
            Exit-Fail "allow-mode ProcessContainer could not reach 1.1.1.1:443: exit=$($allowedNetwork.ExitCode) output=$($allowedNetwork.Output)"
        }
    } else {
        Write-Host "WARN: host cannot reach 1.1.1.1:443; network allow/block proof skipped"
    }

    if ($IsolationTier -eq "BaseContainer") {
        $resourceProbeSmoke = Invoke-AxisProgram -Program $resourceProbe -ProgramArgs @("burn", "1") -PolicyPath $policy
        if ($resourceProbeSmoke.ExitCode -ne 0 -or -not $resourceProbeSmoke.Output.Contains("burn checksum=")) {
            Exit-Fail "resource probe was not executable through the BaseContainer filesystem grant: exit=$($resourceProbeSmoke.ExitCode) output=$($resourceProbeSmoke.Output)"
        }
        $processMarkers = Join-Path $workspace "process-markers"
        $processAllowed = Invoke-AxisProgram -Program $resourceProbe -ProgramArgs @("spawn-hold", "3", "250", $processMarkers) -PolicyPath $processAllowPolicy
        if ($processAllowed.ExitCode -ne 0 -or (Get-ChildItem -LiteralPath $processMarkers -Filter "started-*.txt" -ErrorAction SilentlyContinue).Count -ne 3) {
            Exit-Fail "permitted process-tree size failed: exit=$($processAllowed.ExitCode) output=$($processAllowed.Output)"
        }
        Remove-Item -LiteralPath $processMarkers -Recurse -Force
        $processLimited = Invoke-AxisProgram -Program $resourceProbe -ProgramArgs @("spawn-hold", "3", "250", $processMarkers) -PolicyPath $processLimitPolicy
        if ($processLimited.ExitCode -eq 0 -or (Get-ChildItem -LiteralPath $processMarkers -Filter "started-*.txt" -ErrorAction SilentlyContinue).Count -ge 3) {
            Exit-Fail "process-count Job limit was not enforced: exit=$($processLimited.ExitCode) output=$($processLimited.Output)"
        }
        Remove-Item -LiteralPath $processMarkers -Recurse -Force -ErrorAction SilentlyContinue
        $portableDenied = Invoke-AxisProgram -Program $resourceProbe -ProgramArgs @("spawn-hold", "1", "250", $processMarkers) -PolicyPath $portableProcessPolicy
        if ($portableDenied.ExitCode -eq 0 -or (Get-ChildItem -LiteralPath $processMarkers -Filter "started-*.txt" -ErrorAction SilentlyContinue).Count -ne 0) {
            Exit-Fail "portable child_processes: deny did not map to a pre-execution one-process Job limit: exit=$($portableDenied.ExitCode) output=$($portableDenied.Output)"
        }

        $memorySingleMarkers = Join-Path $workspace "memory-single"
        $memorySingle = Invoke-AxisProgram -Program $resourceProbe -ProgramArgs @("spawn-allocate", "1", "48", "250", $memorySingleMarkers) -PolicyPath $memoryPolicy
        if ($memorySingle.ExitCode -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $memorySingleMarkers "allocated-0.txt") -PathType Leaf)) {
            Exit-Fail "single allocation should fit aggregate memory limit: exit=$($memorySingle.ExitCode) output=$($memorySingle.Output)"
        }
        $memoryAggregateMarkers = Join-Path $workspace "memory-aggregate"
        $memoryAggregate = Invoke-AxisProgram -Program $resourceProbe -ProgramArgs @("spawn-allocate", "2", "48", "500", $memoryAggregateMarkers) -PolicyPath $memoryPolicy
        if ($memoryAggregate.ExitCode -eq 0 -and (Get-ChildItem -LiteralPath $memoryAggregateMarkers -Filter "allocated-*.txt" -ErrorAction SilentlyContinue).Count -eq 2) {
            Exit-Fail "aggregate Job memory limit allowed two 48 MiB descendants under an 88 MiB cap"
        }

        $burnIterations = 150000000
        $cpuBaseline = Invoke-AxisProgram -Program $resourceProbe -ProgramArgs @("burn", "$burnIterations") -PolicyPath $cpuBaselinePolicy
        $cpuLimited = Invoke-AxisProgram -Program $resourceProbe -ProgramArgs @("burn", "$burnIterations") -PolicyPath $cpuLimitPolicy
        $baselineMatch = [regex]::Match($cpuBaseline.Output, "elapsed_ms=(\d+)")
        $limitedMatch = [regex]::Match($cpuLimited.Output, "elapsed_ms=(\d+)")
        if ($cpuBaseline.ExitCode -ne 0 -or $cpuLimited.ExitCode -ne 0 -or -not $baselineMatch.Success -or -not $limitedMatch.Success) {
            Exit-Fail "CPU resource probes failed: baseline=$($cpuBaseline.Output) limited=$($cpuLimited.Output)"
        }
        $baselineMs = [int64]$baselineMatch.Groups[1].Value
        $limitedMs = [int64]$limitedMatch.Groups[1].Value
        if ($limitedMs -lt [Math]::Max(500, $baselineMs * 2)) {
            Exit-Fail "10 percent CPU Job cap did not materially throttle work: baseline=${baselineMs}ms limited=${limitedMs}ms"
        }

        $timeout = Invoke-AxisCommand 'timeout-parent.cmd' $timeoutPolicy
        if ($timeout.ExitCode -eq 0 -or -not $timeout.Output.Contains("timed out")) {
            Exit-Fail "timeout was not enforced: exit=$($timeout.ExitCode) output=$($timeout.Output)"
        }
        Start-Sleep -Milliseconds 500
        if (-not (Test-Path -LiteralPath $childStarted -PathType Leaf)) {
            Exit-Fail "timeout descendant fixture did not start"
        }
        Start-Sleep -Seconds 5
        if (Test-Path -LiteralPath $escapedChild -PathType Leaf) {
            Exit-Fail "timeout descendant escaped the AXIS Job Object cleanup boundary"
        }
        if ((Get-Acl -LiteralPath $workspace).Sddl -ne $workspaceSddl -or
            (Get-Acl -LiteralPath $readonly).Sddl -ne $readonlySddl) {
            Exit-Fail "BaseContainer launch mutated host directory ACLs"
        }
    }

    Write-Host "PASS: AXIS Windows MXC $IsolationTier smoke and security checks"
} finally {
    if ($savedSecretPresent) {
        $env:OPENAI_API_KEY = $savedSecret
    } else {
        Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue
    }
    if ($savedAllowedPresent) {
        $env:OPENAI_ORG_ID = $savedAllowed
    } else {
        Remove-Item Env:OPENAI_ORG_ID -ErrorAction SilentlyContinue
    }
    if ($savedProcessGatePresent) {
        $env:AXIS_RUN_MXC_PROCESS_E2E = $savedProcessGate
    } else {
        Remove-Item Env:AXIS_RUN_MXC_PROCESS_E2E -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
