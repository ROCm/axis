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

if ($env:AXIS_RUN_WINDOWS_STRICT_PROXY_E2E -ne "1") {
    Write-Host "SKIP: AXIS_RUN_WINDOWS_STRICT_PROXY_E2E=1 not set"
    exit 0
}
if ($env:OS -ne "Windows_NT") {
    Exit-Fail "strict proxy tests require Windows"
}
if (-not $env:AXIS_TEST_MXC_EXECUTOR) {
    Exit-Fail "AXIS_TEST_MXC_EXECUTOR must name the pinned MXC wxc-exec.exe"
}
foreach ($path in @($AxisBin, $PolicyPath, $env:AXIS_TEST_MXC_EXECUTOR)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Exit-Fail "required file not found: $path"
    }
}
$AxisBin = (Resolve-Path -LiteralPath $AxisBin).Path
$PolicyPath = (Resolve-Path -LiteralPath $PolicyPath).Path
$env:AXIS_RUN_MXC_BASECONTAINER_E2E = "1"

$root = Join-Path ([IO.Path]::GetTempPath()) ("axis-proxy-e2e-" + [guid]::NewGuid().ToString("N"))
$workspace = Join-Path $root "workspace"
$probe = Join-Path $workspace "axis-windows-network-probe.exe"
$emptyInput = Join-Path $root "empty.stdin"
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
    # endpoint is reachable on the host and must still be blocked, since only
    # the IPv4 proxy endpoint is permitted.
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

    # Proxy mode allows ingress and host loopback for MXC's proxy mapping, so
    # prove the sandbox still reaches no other loopback service: an ephemeral
    # listener, the axisd TCP port, and another sandbox's AXIS proxy.
    # The test does not bind the axisd port itself: `axis run` connects to it
    # first and would talk to a stand-in listener.
    $loopbackListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $loopbackListener.Start()
    try {
        $ports = @($loopbackListener.LocalEndpoint.Port)
        $axisdClient = [Net.Sockets.TcpClient]::new()
        try {
            $axisdClient.Connect([Net.IPAddress]::Loopback, 18516)
            $ports += 18516
        } catch {
            Write-Host "NOTE: axisd is not listening on 127.0.0.1:18516; skipping the axisd port probe"
        } finally {
            $axisdClient.Dispose()
        }
        foreach ($port in $ports) {
            $hostClient = [Net.Sockets.TcpClient]::new()
            try {
                $hostClient.Connect([Net.IPAddress]::Loopback, $port)
            } catch {
                Exit-Fail "host cannot reach its own loopback listener on port ${port}: $_"
            } finally {
                $hostClient.Dispose()
            }
            $result = Invoke-Probe @("tcp-hold", "127.0.0.1", "$port")
            if ($result.ExitCode -eq 0 -or -not $result.Output.Contains("TCP_BLOCKED")) {
                Exit-Fail "sandbox reached host loopback port ${port}: $($result.Output)"
            }
        }
    } finally {
        $loopbackListener.Stop()
    }

    $holderOut = Join-Path $root "peer-proxy-holder.out"
    $holderErr = Join-Path $root "peer-proxy-holder.err"
    $holder = Start-Process -FilePath $AxisBin -WindowStyle Hidden -PassThru `
        -WorkingDirectory $workspace -RedirectStandardInput $emptyInput `
        -RedirectStandardOutput $holderOut -RedirectStandardError $holderErr `
        -ArgumentList @("run", "--policy", $PolicyPath, "--", $probe, "hold", "30")
    try {
        $peerProxyPorts = @()
        $deadline = (Get-Date).AddSeconds(15)
        while ($peerProxyPorts.Count -eq 0 -and (Get-Date) -lt $deadline) {
            if ($holder.HasExited) {
                Exit-Fail "peer sandbox exited before its proxy was probed (exit $($holder.ExitCode))"
            }
            $peerProxyPorts = @(
                Get-NetTCPConnection -State Listen -OwningProcess $holder.Id -LocalAddress 127.0.0.1 -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty LocalPort -Unique
            )
            if ($peerProxyPorts.Count -eq 0) {
                Start-Sleep -Milliseconds 200
            }
        }
        if ($peerProxyPorts.Count -eq 0) {
            Exit-Fail "peer sandbox's AXIS proxy never listened on 127.0.0.1 from its axis.exe; run this suite without axisd so each sandbox hosts its own proxy"
        }
        foreach ($port in $peerProxyPorts) {
            $result = Invoke-Probe @("tcp-hold", "127.0.0.1", "$port")
            if ($result.ExitCode -eq 0 -or -not $result.Output.Contains("TCP_BLOCKED")) {
                Exit-Fail "sandbox reached another sandbox's AXIS proxy on port ${port}: $($result.Output)"
            }
        }
    } finally {
        if (-not $holder.HasExited) {
            $holder.Kill()
        }
        $holder.WaitForExit(10000) | Out-Null
    }

    # Per-container filters: tearing down one sandbox must not lift another's block.
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
        -ArgumentList @("run", "--policy", $PolicyPath, "--", $probe, "delay-tcp", "5", "1.1.1.1", "443")
    Start-Sleep -Seconds 2
    if ($first.HasExited) {
        Exit-Fail "first concurrent sandbox exited before it was stopped (exit $($first.ExitCode)), so its teardown was not tested"
    }
    $first.Kill()
    $first.WaitForExit(10000) | Out-Null
    if (-not $second.WaitForExit(30000)) {
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
        Exit-Fail "second sandbox bypassed its block after the first sandbox exited: $secondOutput"
    }

    Write-Host "PASS: AXIS Windows MXC strict proxy security checks"
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
