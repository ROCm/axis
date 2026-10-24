# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Gated AXIS/MXC BaseContainer strict-proxy adversarial suite.
param(
    [string]$AxisBin = ".\target\release\axis.exe",
    [string]$PolicyPath = ".\e2e\windows\strict_proxy_smoke.yaml"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Exit-Fail([string]$Message) {
    throw "FAIL: $Message"
}

if ($env:AXIS_RUN_WINDOWS_WFP_E2E -ne "1") {
    Write-Host "SKIP: AXIS_RUN_WINDOWS_WFP_E2E=1 not set"
    exit 0
}
if ($env:OS -ne "Windows_NT") {
    Exit-Fail "strict WFP tests require Windows"
}

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Exit-Fail "the gated crash-recovery proof must run elevated"
}
$service = Get-Service -Name AxisWfpBroker -ErrorAction SilentlyContinue
if (-not $service -or $service.Status -ne "Running") {
    Exit-Fail "AxisWfpBroker must be installed and running"
}
if (-not $env:AXIS_TEST_MXC_EXECUTOR) {
    Exit-Fail "AXIS_TEST_MXC_EXECUTOR must name the patched wxc-exec.exe"
}
foreach ($path in @($AxisBin, $PolicyPath, $env:AXIS_TEST_MXC_EXECUTOR)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Exit-Fail "required file not found: $path"
    }
}
$AxisBin = (Resolve-Path -LiteralPath $AxisBin).Path
$PolicyPath = (Resolve-Path -LiteralPath $PolicyPath).Path
$env:AXIS_RUN_MXC_BASECONTAINER_E2E = "1"

$root = Join-Path ([IO.Path]::GetTempPath()) ("axis-wfp-e2e-" + [guid]::NewGuid().ToString("N"))
$workspace = Join-Path $root "workspace"
$probe = Join-Path $workspace "axis-windows-network-probe.exe"
$emptyInput = Join-Path $root "empty.stdin"
$auditLog = Join-Path $env:ProgramData "axis\logs\wfp-broker.jsonl"
$leaseDir = Join-Path $env:ProgramData "axis\wfp-leases"
New-Item -ItemType Directory -Path $workspace -Force | Out-Null
New-Item -ItemType File -Path $emptyInput -Force | Out-Null

try {
    & rustc -O (Join-Path $PSScriptRoot "helpers\network_probe.rs") -o $probe
    if ($LASTEXITCODE -ne 0) {
        Exit-Fail "failed to compile the raw-network probe"
    }

    function Invoke-Probe([string[]]$Arguments) {
        Push-Location $workspace
        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $output = "" | & $AxisBin run --policy $PolicyPath -- $probe @Arguments 2>&1 | Out-String
            return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
        } finally {
            $ErrorActionPreference = $saved
            Pop-Location
        }
    }

    function Invoke-Curl([string[]]$Arguments) {
        Push-Location $workspace
        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $output = "" | & $AxisBin run --policy $PolicyPath -- "$env:SystemRoot\System32\curl.exe" @Arguments 2>&1 | Out-String
            return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
        } finally {
            $ErrorActionPreference = $saved
            Pop-Location
        }
    }

    # Establish that the host can reach each adversarial endpoint; otherwise a
    # sandbox timeout would not distinguish WFP enforcement from host routing.
    foreach ($baseline in @(
        @("tcp", "1.1.1.1", "443"),
        @("dns", "1.1.1.1", "53"),
        @("quic", "1.1.1.1", "443")
    )) {
        & $probe @baseline | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Exit-Fail "host baseline failed for $($baseline -join ' ')"
        }
    }

    $auditStart = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

    $allowed = Invoke-Curl @(
        "--silent", "--show-error", "--fail", "--ssl-no-revoke",
        "--connect-timeout", "8", "--max-time", "20",
        "https://api.github.com/zen"
    )
    if ($allowed.ExitCode -ne 0) {
        Exit-Fail "allowed HTTPS did not traverse the AXIS proxy: $($allowed.Output)"
    }

    $endpointDenied = Invoke-Curl @(
        "--silent", "--show-error", "--fail", "--ssl-no-revoke",
        "--connect-timeout", "5", "--max-time", "10",
        "https://example.com/"
    )
    if ($endpointDenied.ExitCode -eq 0 -or -not $endpointDenied.Output.Contains("DENIED example.com:443")) {
        Exit-Fail "proxy endpoint policy did not deny example.com: $($endpointDenied.Output)"
    }

    foreach ($blocked in @(
        @("tcp-hold", "1.1.1.1", "443", "TCP_BLOCKED"),
        @("dns", "1.1.1.1", "53", "DNS_BLOCKED"),
        @("quic", "1.1.1.1", "443", "QUIC_BLOCKED")
    )) {
        $result = Invoke-Probe $blocked[0..2]
        if ($result.ExitCode -eq 0 -or -not $result.Output.Contains($blocked[3])) {
            Exit-Fail "raw bypass was not blocked for $($blocked[0]): $($result.Output)"
        }
    }

    # IPv6 proof does not depend on external IPv6 routing: a listening ::1
    # endpoint is reachable on the host and must still hit the lease's V6 block.
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Loopback, 0)
    $listener.Start()
    try {
        $v6Port = $listener.LocalEndpoint.Port
        $hostClient = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
        $hostClient.Connect([Net.IPAddress]::IPv6Loopback, $v6Port)
        $hostClient.Dispose()
        $ipv6 = Invoke-Probe @("tcp-hold", "::1", "$v6Port")
        if ($ipv6.ExitCode -eq 0 -or -not $ipv6.Output.Contains("TCP_BLOCKED")) {
            Exit-Fail "direct IPv6 loopback bypass was not blocked: $($ipv6.Output)"
        }
    } finally {
        $listener.Stop()
    }

    $events = Get-Content -LiteralPath $auditLog | ForEach-Object {
        try { $_ | ConvertFrom-Json } catch { $null }
    } | Where-Object {
        $_ -and $_.timestampUnixMs -ge $auditStart -and $_.event -eq "connection_blocked"
    }
    if (-not ($events | Where-Object { $_.protocol -eq 6 -and $_.remoteAddress -eq "1.1.1.1" -and $_.remotePort -eq 443 })) {
        Exit-Fail "no correlated WFP TCP block event was recorded"
    }
    if (-not ($events | Where-Object { $_.ipVersion -eq 6 -and $_.remoteAddress -eq "::1" })) {
        Exit-Fail "no correlated WFP IPv6 block event was recorded"
    }

    # Two leases must coexist without filter-key collision or cross-release.
    $concurrentBaseline = @(Get-ChildItem -LiteralPath $leaseDir -Filter "*.json" -ErrorAction SilentlyContinue | ForEach-Object Name)
    $firstOut = Join-Path $root "concurrent-first.out"
    $firstErr = Join-Path $root "concurrent-first.err"
    $secondOut = Join-Path $root "concurrent-second.out"
    $secondErr = Join-Path $root "concurrent-second.err"
    $first = Start-Process -FilePath $AxisBin -WindowStyle Hidden -PassThru `
        -WorkingDirectory $workspace -RedirectStandardInput $emptyInput `
        -RedirectStandardOutput $firstOut -RedirectStandardError $firstErr `
        -ArgumentList @("run", "--policy", $PolicyPath, "--", $probe, "hold", "20")
    $second = Start-Process -FilePath $AxisBin -WindowStyle Hidden -PassThru `
        -WorkingDirectory $workspace -RedirectStandardInput $emptyInput `
        -RedirectStandardOutput $secondOut -RedirectStandardError $secondErr `
        -ArgumentList @("run", "--policy", $PolicyPath, "--", $probe, "delay-tcp", "3", "1.1.1.1", "443")
    $concurrentJournals = @()
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        $concurrentJournals = @(Get-ChildItem -LiteralPath $leaseDir -Filter "*.json" -ErrorAction SilentlyContinue |
            Where-Object { $concurrentBaseline -notcontains $_.Name })
        if ($concurrentJournals.Count -eq 2) { break }
        Start-Sleep -Milliseconds 100
    }
    if ($concurrentJournals.Count -ne 2) {
        $first.Kill(); $second.Kill()
        Exit-Fail "two concurrent WFP lease journals did not coexist"
    }
    $first.Kill()
    $first.WaitForExit(10000) | Out-Null
    Start-Sleep -Milliseconds 200
    $remainingConcurrent = @(Get-ChildItem -LiteralPath $leaseDir -Filter "*.json" -ErrorAction SilentlyContinue |
        Where-Object { $concurrentBaseline -notcontains $_.Name })
    if ($remainingConcurrent.Count -ne 1) {
        $second.Kill()
        Exit-Fail "releasing one sandbox removed or retained another sandbox's WFP lease"
    }
    if (-not $second.WaitForExit(15000)) {
        $second.Kill()
        Exit-Fail "second concurrent sandbox did not complete"
    }
    # Flush asynchronous redirected-output handlers before reading the files.
    $second.WaitForExit()
    $secondOutput = @(
        Get-Content -LiteralPath $secondOut -ErrorAction SilentlyContinue
        Get-Content -LiteralPath $secondErr -ErrorAction SilentlyContinue
    ) | Out-String
    if (-not $secondOutput.Contains("TCP_BLOCKED")) {
        Exit-Fail "second sandbox bypassed its block after the first lease was released: $secondOutput"
    }

    # Broker restart: the dynamic permit disappears, persistent blocks remain,
    # MXC's pipe watchdog kills the child, and restart reaps the journal/blocks.
    $beforeJournals = @(Get-ChildItem -LiteralPath $leaseDir -Filter "*.json" -ErrorAction SilentlyContinue | ForEach-Object Name)
    $crashOut = Join-Path $root "crash.out"
    $crashErr = Join-Path $root "crash.err"
    $crashProcess = Start-Process -FilePath $AxisBin -WindowStyle Hidden -PassThru `
        -WorkingDirectory $workspace -RedirectStandardInput $emptyInput `
        -RedirectStandardOutput $crashOut -RedirectStandardError $crashErr `
        -ArgumentList @("run", "--policy", $PolicyPath, "--", $probe, "hold", "120")
    $newJournal = $null
    for ($attempt = 0; $attempt -lt 150; $attempt++) {
        $newJournal = Get-ChildItem -LiteralPath $leaseDir -Filter "*.json" -ErrorAction SilentlyContinue |
            Where-Object { $beforeJournals -notcontains $_.Name } | Select-Object -First 1
        if ($newJournal) { break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $newJournal) {
        $crashProcess.Kill()
        Exit-Fail "live lease journal did not appear"
    }
    $leaseId = [IO.Path]::GetFileNameWithoutExtension($newJournal.Name)

    Stop-Service -Name AxisWfpBroker -Force
    if (-not (Test-Path -LiteralPath $newJournal.FullName)) {
        Exit-Fail "broker crash removed persistent fail-closed block journal prematurely"
    }
    Start-Service -Name AxisWfpBroker
    if (-not $crashProcess.WaitForExit(15000)) {
        $crashProcess.Kill()
        Exit-Fail "MXC did not terminate the child after broker pipe loss"
    }
    for ($attempt = 0; $attempt -lt 100 -and (Test-Path -LiteralPath $newJournal.FullName); $attempt++) {
        Start-Sleep -Milliseconds 100
    }
    if (Test-Path -LiteralPath $newJournal.FullName) {
        Exit-Fail "broker restart did not reap the stale persistent blocks"
    }
    $reaped = Get-Content -LiteralPath $auditLog | ForEach-Object {
        try { $_ | ConvertFrom-Json } catch { $null }
    } | Where-Object { $_ -and $_.event -eq "stale_lease_reaped" -and $_.leaseId -eq $leaseId }
    if (-not $reaped) {
        Exit-Fail "broker restart did not audit stale lease recovery"
    }

    Write-Host "PASS: AXIS Windows MXC strict WFP proxy security checks"
} finally {
    if ((Get-Service -Name AxisWfpBroker -ErrorAction SilentlyContinue).Status -ne "Running") {
        Start-Service -Name AxisWfpBroker -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
