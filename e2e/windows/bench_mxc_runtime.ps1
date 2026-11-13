# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Gated Windows MXC runtime benchmarks.
#
# This harness does not install MXC, enable Windows features, import WSL
# distributions, or mutate host runtime state. It runs only when the caller opts
# into concrete benchmark gates and provides the matching MXC executor through
# PATH or AXIS_TEST_MXC_EXECUTOR.
$ErrorActionPreference = "Stop"

function Exit-Skip([string]$Message) {
    Write-Host "  SKIP: $Message"
    exit 0
}

function Exit-Fail([string]$Message) {
    Write-Host "  FAIL: $Message"
    exit 1
}

function Test-PositiveInteger([string]$Name, [string]$Value) {
    $parsed = 0
    if (-not [int]::TryParse($Value, [ref]$parsed) -or $parsed -le 0) {
        Exit-Fail "$Name must be a positive integer"
    }
    return $parsed
}

function Get-EnvOrDefault([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrEmpty($value)) {
        return $Default
    }
    return $value
}

function Resolve-MxcExecutor {
    if ($env:AXIS_TEST_MXC_EXECUTOR) {
        if (-not (Test-Path -LiteralPath $env:AXIS_TEST_MXC_EXECUTOR -PathType Leaf)) {
            Exit-Fail "AXIS_TEST_MXC_EXECUTOR does not exist: $env:AXIS_TEST_MXC_EXECUTOR"
        }
        return (Resolve-Path -LiteralPath $env:AXIS_TEST_MXC_EXECUTOR).Path
    }

    foreach ($candidate in @("wxc-exec.exe", "wxc.exe", "wxc", "mxc-exec.exe", "mxc-exec", "lxc-exec.exe", "lxc-exec")) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }

    Exit-Fail "set AXIS_TEST_MXC_EXECUTOR or provide wxc-exec, wxc, mxc-exec, or lxc-exec on PATH"
}

function Quote-Arg([string]$Value) {
    return '"' + $Value.Replace('"', '\"') + '"'
}

function New-BackendSpec([string]$Id, [string]$Containment, [string]$Class, [string]$CommandFamily) {
    return [pscustomobject]@{
        Id = $Id
        Containment = $Containment
        Class = $Class
        CommandFamily = $CommandFamily
    }
}

function Add-GatedBackend([System.Collections.ArrayList]$Backends, [string]$Gate, [object]$Spec) {
    if ([Environment]::GetEnvironmentVariable($Gate) -eq "1") {
        [void]$Backends.Add($Spec)
    }
}

$backends = [System.Collections.ArrayList]::new()
Add-GatedBackend $backends "AXIS_BENCH_MXC_WINDOWS_PROCESSCONTAINER" (New-BackendSpec "mxc-windows-processcontainer" "processcontainer" "process" "windows")
Add-GatedBackend $backends "AXIS_BENCH_MXC_WINDOWS_WSLC" (New-BackendSpec "mxc-windows-wslc" "wslc" "container" "linux")
Add-GatedBackend $backends "AXIS_BENCH_MXC_WINDOWS_SANDBOX" (New-BackendSpec "mxc-windows-sandbox" "windows_sandbox" "vm" "windows")
Add-GatedBackend $backends "AXIS_BENCH_MXC_WINDOWS_ISOLATION_SESSION" (New-BackendSpec "mxc-windows-isolation-session" "isolation_session" "vm" "windows")
Add-GatedBackend $backends "AXIS_BENCH_MXC_WINDOWS_MICROVM" (New-BackendSpec "mxc-windows-microvm" "microvm" "vm" "linux")
Add-GatedBackend $backends "AXIS_BENCH_MXC_WINDOWS_HYPERLIGHT" (New-BackendSpec "mxc-windows-hyperlight" "hyperlight" "vm" "linux")

if ($backends.Count -eq 0) {
    Exit-Skip "set one of AXIS_BENCH_MXC_WINDOWS_PROCESSCONTAINER=1, AXIS_BENCH_MXC_WINDOWS_WSLC=1, AXIS_BENCH_MXC_WINDOWS_SANDBOX=1, AXIS_BENCH_MXC_WINDOWS_ISOLATION_SESSION=1, AXIS_BENCH_MXC_WINDOWS_MICROVM=1, or AXIS_BENCH_MXC_WINDOWS_HYPERLIGHT=1"
}

if ($env:OS -ne "Windows_NT") {
    Exit-Fail "Windows MXC benchmark gates require a Windows host"
}

$runs = Test-PositiveInteger "AXIS_MXC_WINDOWS_BENCH_RUNS" (Get-EnvOrDefault "AXIS_MXC_WINDOWS_BENCH_RUNS" "5")
$density = Test-PositiveInteger "AXIS_MXC_WINDOWS_BENCH_DENSITY" (Get-EnvOrDefault "AXIS_MXC_WINDOWS_BENCH_DENSITY" "4")
$timeoutSeconds = Test-PositiveInteger "AXIS_MXC_WINDOWS_BENCH_TIMEOUT_SECONDS" (Get-EnvOrDefault "AXIS_MXC_WINDOWS_BENCH_TIMEOUT_SECONDS" "120")
$outputPath = $env:AXIS_MXC_WINDOWS_BENCH_OUTPUT
$executor = Resolve-MxcExecutor

if (($env:AXIS_BENCH_MXC_WINDOWS_WSLC -eq "1") -and -not $env:AXIS_MXC_WSLC_IMAGE_TAR_PATH) {
    Exit-Fail "AXIS_BENCH_MXC_WINDOWS_WSLC=1 requires AXIS_MXC_WSLC_IMAGE_TAR_PATH for repeatable WSLC input"
}

$tmpdir = Join-Path ([System.IO.Path]::GetTempPath()) ("axis-mxc-windows-bench-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmpdir | Out-Null

Write-Host "=== AXIS MXC Windows Runtime Benchmark ==="
Write-Host "executor: $executor"
Write-Host "tmpdir: $tmpdir"
Write-Host "runs: $runs"
Write-Host "density: $density"
Write-Host "timeout_seconds: $timeoutSeconds"
if ($outputPath) {
    Write-Host "output: $outputPath"
}
Write-Host ""

function New-CommandLine([object]$Backend, [string]$Marker, [int]$SleepMilliseconds, [string]$ConfigPath) {
    if ($Backend.CommandFamily -eq "linux") {
        $command = "echo $Marker"
        if ($SleepMilliseconds -gt 0) {
            $seconds = [math]::Round($SleepMilliseconds / 1000, 3)
            $command = "$command; sleep $seconds"
        }
        return "sh -c '$command'"
    }

    if ($Backend.Containment -eq "processcontainer") {
        $scriptPath = "$ConfigPath.cmd"
        $script = "@echo off`r`necho $Marker`r`n"
        if ($SleepMilliseconds -gt 0) {
            $ticks = [Math]::Max(1, [Math]::Ceiling($SleepMilliseconds / 10))
            $script += @"
set /a ticks=0
set "lastTick=%time:~6,5%"
:waitForTick
set "currentTick=%time:~6,5%"
if "%currentTick%"=="%lastTick%" goto waitForTick
set "lastTick=%currentTick%"
set /a ticks+=1
if %ticks% LSS $ticks goto waitForTick
"@
        }
        Set-Content -LiteralPath $scriptPath -Value $script -Encoding ASCII
        return 'cmd.exe /d /s /c ""' + $scriptPath + '""'
    }

    $command = "Write-Output '$Marker'"
    if ($SleepMilliseconds -gt 0) {
        $command = "$command; Start-Sleep -Milliseconds $SleepMilliseconds"
    }
    return "powershell -NoProfile -Command `"${command}`""
}

function Write-MxcConfig([string]$Path, [object]$Backend, [string]$Marker, [int]$SleepMilliseconds) {
    $config = [ordered]@{
        version = "0.6.0-alpha"
        containerId = ("axis-mxc-bench-" + $Backend.Containment + "-" + $Marker.ToLowerInvariant().Replace("_", "-"))
        containment = $Backend.Containment
        platform = "windows"
        process = [ordered]@{
            commandLine = New-CommandLine $Backend $Marker $SleepMilliseconds $Path
            timeout = $timeoutSeconds * 1000
        }
        filesystem = [ordered]@{
            readwritePaths = @()
            readonlyPaths = @()
            deniedPaths = @()
        }
        network = [ordered]@{ defaultPolicy = "allow" }
        lifecycle = [ordered]@{
            destroyOnExit = $true
            preservePolicy = $false
        }
    }

    if ($Backend.Containment -eq "processcontainer") {
        # The pinned MXC 1.x executor accepts only the 1.0.0 contract, which has
        # no platform field, directional network rules and no LPAC option.
        $config.version = "1.0.0"
        $config.Remove("platform")
        $config.network = [ordered]@{
            egress = [ordered]@{ default = "allow" }
            ingress = [ordered]@{ default = "deny"; hostLoopback = "deny" }
        }
        $config.filesystem.readonlyPaths = @("$Path.cmd")
        $config.processContainer = [ordered]@{ leastPrivilege = $false }
        $config.fallback = [ordered]@{ allowDaclMutation = $false }
    } elseif ($Backend.Containment -eq "wslc") {
        $config.experimental = [ordered]@{
            wslc = [ordered]@{
                targetOs = "linux"
                image = (Get-EnvOrDefault "AXIS_MXC_WSLC_IMAGE" "alpine:latest")
                imageTarPath = $env:AXIS_MXC_WSLC_IMAGE_TAR_PATH
                storagePath = (Get-EnvOrDefault "AXIS_MXC_WSLC_STORAGE_PATH" (Join-Path $tmpdir "wslc"))
                gpu = $false
            }
        }
    } elseif ($Backend.Containment -eq "windows_sandbox") {
        $config.experimental = [ordered]@{
            windows_sandbox = [ordered]@{
                idleTimeoutMs = [int](Get-EnvOrDefault "AXIS_MXC_WINDOWS_SANDBOX_IDLE_TIMEOUT_MS" "300000")
                daemonPipeName = (Get-EnvOrDefault "AXIS_MXC_WINDOWS_SANDBOX_PIPE_NAME" "axis-windows-sandbox")
            }
        }
    } elseif ($Backend.Containment -eq "isolation_session") {
        $config.experimental = [ordered]@{
            isolation_session = [ordered]@{
                configurationId = (Get-EnvOrDefault "AXIS_MXC_WINDOWS_ISOLATION_CONFIGURATION_ID" "medium")
            }
        }
    }

    # Windows PowerShell 5.1 writes a UTF-8 BOM that MXC rejects. Benchmark
    # fixtures are ASCII-only, so keep them portable across powershell/pwsh.
    $config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding ASCII
}

function Start-MxcConfig([string]$ConfigPath, [string]$Marker, [string]$Containment) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $executor
    $psi.Arguments = "--experimental --config " + (Quote-Arg $ConfigPath)
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $process = [System.Diagnostics.Process]::Start($psi)
    return [pscustomobject]@{
        Process = $process
        Stopwatch = $stopwatch
        Marker = $Marker
    }
}

function Complete-MxcConfig([object]$Handle) {
    $process = $Handle.Process
    $stopwatch = $Handle.Stopwatch
    $marker = $Handle.Marker

    if (-not $process.WaitForExit($timeoutSeconds * 1000 + 10000)) {
        try {
            $process.Kill($true)
        } catch {
            $process.Kill()
        }
        Exit-Fail "$marker exceeded outer benchmark timeout"
    }
    $stopwatch.Stop()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $exitCode = $process.ExitCode
    $peakWorkingSetKb = [math]::Round($process.PeakWorkingSet64 / 1024)
    $process.Dispose()

    if ($exitCode -ne 0) {
        Exit-Fail "$marker failed with exit $exitCode; stdout=$($stdout.Substring(0, [Math]::Min(400, $stdout.Length))); stderr=$($stderr.Substring(0, [Math]::Min(400, $stderr.Length)))"
    }
    if (-not $stdout.Contains($marker)) {
        Exit-Fail "$marker missing from stdout"
    }

    return [pscustomobject]@{
        wall_ms = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)
        max_rss_kb = $peakWorkingSetKb
    }
}

function Invoke-MxcConfig([string]$ConfigPath, [string]$Marker, [string]$Containment) {
    return Complete-MxcConfig (Start-MxcConfig $ConfigPath $Marker $Containment)
}

function Get-Summary([double[]]$Values) {
    $ordered = @($Values | Sort-Object)
    $p95Index = [Math]::Min($ordered.Count - 1, [Math]::Max(0, [Math]::Round(0.95 * ($ordered.Count - 1))))
    return [ordered]@{
        min = ($ordered | Select-Object -First 1)
        median = ($ordered[[Math]::Floor($ordered.Count / 2)])
        p95 = $ordered[$p95Index]
        max = ($ordered | Select-Object -Last 1)
    }
}

function Invoke-BackendBenchmark([object]$Backend) {
    $coldMarker = ("AXIS_MXC_BENCH_" + $Backend.Containment.ToUpperInvariant() + "_COLD")
    $coldConfig = Join-Path $tmpdir ($Backend.Containment + "-cold.json")
    Write-MxcConfig $coldConfig $Backend $coldMarker 0
    $cold = Invoke-MxcConfig $coldConfig $coldMarker $Backend.Containment

    $warmResults = @()
    for ($i = 0; $i -lt $runs; $i++) {
        $marker = ("AXIS_MXC_BENCH_" + $Backend.Containment.ToUpperInvariant() + "_WARM_" + $i)
        $config = Join-Path $tmpdir ($Backend.Containment + "-warm-" + $i + ".json")
        Write-MxcConfig $config $Backend $marker 0
        $warmResults += Invoke-MxcConfig $config $marker $Backend.Containment
    }

    $densityHandles = @()
    $densityStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $density; $i++) {
        $marker = ("AXIS_MXC_BENCH_" + $Backend.Containment.ToUpperInvariant() + "_DENSITY_" + $i)
        $config = Join-Path $tmpdir ($Backend.Containment + "-density-" + $i + ".json")
        Write-MxcConfig $config $Backend $marker 250
        $densityHandles += Start-MxcConfig $config $marker $Backend.Containment
    }
    $densityResults = @()
    foreach ($handle in $densityHandles) {
        $densityResults += Complete-MxcConfig $handle
    }
    $densityStopwatch.Stop()

    $warmWall = @($warmResults | ForEach-Object { [double]$_.wall_ms })
    $warmRss = @($warmResults | ForEach-Object { [double]$_.max_rss_kb })
    $densityWall = @($densityResults | ForEach-Object { [double]$_.wall_ms })
    $densityRss = @($densityResults | ForEach-Object { [double]$_.max_rss_kb })

    $lifecycleName = if ($Backend.Class -eq "vm") { "cold_start_ms" } else { "cold_lifecycle_ms" }
    $warmName = if ($Backend.Class -eq "vm") { "warm_start_ms" } else { "warm_lifecycle_ms" }

    $result = [ordered]@{
        backend = $Backend.Id
        containment = $Backend.Containment
        runs = $runs
        density = $density
        density_total_ms = [math]::Round($densityStopwatch.Elapsed.TotalMilliseconds, 3)
        density_member_ms = Get-Summary $densityWall
        max_rss_kb = [ordered]@{
            cold = $cold.max_rss_kb
            warm_max = ($warmRss | Measure-Object -Maximum).Maximum
            density_max = ($densityRss | Measure-Object -Maximum).Maximum
        }
        metric_gaps = @(
            [ordered]@{
                metric = "teardown"
                reason = "MXC executor output does not expose teardown separately; lifecycle values include startup, command execution, and cleanup."
            },
            [ordered]@{
                metric = "file_descriptors"
                reason = "Descriptor counts are not available as a native Windows host metric in this harness."
            },
            [ordered]@{
                metric = "process_count"
                reason = "Process-tree high-water marks are not yet collected by this PowerShell harness."
            }
        )
    }
    $result[$lifecycleName] = $cold.wall_ms
    $result[$warmName] = Get-Summary $warmWall
    return $result
}

try {
    $results = @()
    foreach ($backend in $backends) {
        $result = Invoke-BackendBenchmark $backend
        $results += [pscustomobject]$result
        $result | ConvertTo-Json -Depth 12 -Compress
    }

    if ($outputPath) {
        $parent = Split-Path -Parent $outputPath
        if ($parent) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
        $results | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $outputPath -Encoding UTF8
    }
} finally {
    Remove-Item -LiteralPath $tmpdir -Recurse -Force -ErrorAction SilentlyContinue
}
