# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Gated BaseContainer scoped-SSH projection and CONNECT enforcement proof.
param(
    [string]$AxisBin = ".\target\release\axis.exe"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
function Exit-Fail([string]$Message) { throw "FAIL: $Message" }

if ($env:AXIS_RUN_WINDOWS_SSH_E2E -ne "1") {
    Write-Host "SKIP: AXIS_RUN_WINDOWS_SSH_E2E=1 not set"
    exit 0
}
if ($env:OS -ne "Windows_NT") { Exit-Fail "scoped SSH E2E requires Windows" }
$service = Get-Service -Name AxisWfpBroker -ErrorAction SilentlyContinue
if (-not $service -or $service.Status -ne "Running") { Exit-Fail "AxisWfpBroker must be running" }
foreach ($path in @($AxisBin, $env:AXIS_TEST_MXC_EXECUTOR, ".\target\release\axis-ssh-proxy.exe")) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Exit-Fail "required executable not found: $path"
    }
}

$AxisBin = (Resolve-Path -LiteralPath $AxisBin).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ("axis-ssh-e2e-" + [guid]::NewGuid().ToString("N"))
$workspace = Join-Path $root "workspace"
$probe = Join-Path $workspace "axis-ssh-probe.exe"
$privateKey = Join-Path $root "id_axis_test"
$requestFile = Join-Path $root "ssh-request.bin"
$providerOut = Join-Path $root "ssh-provider.out"
$providerErr = Join-Path $root "ssh-provider.err"
$policy = Join-Path $root "policy.yaml"
$fakeKeyscan = Join-Path $root "ssh-keyscan.cmd"
$policyName = "windows-mxc-ssh-e2e"
$managedSsh = Join-Path $env:USERPROFILE ".axis\agents\$policyName\home\.ssh"
$projectedHelper = Join-Path $managedSsh "axis-ssh-proxy.exe"
$savedPath = $env:PATH
$savedKeyscan = $env:AXIS_TEST_SSH_KEYSCAN
$provider = $null
$env:AXIS_RUN_MXC_BASECONTAINER_E2E = "1"

try {
    New-Item -ItemType Directory -Path $workspace -Force | Out-Null
    Set-Content -LiteralPath $privateKey -Encoding ASCII -Value "AXIS_TEST_PRIVATE_KEY"
    Set-Content -LiteralPath $fakeKeyscan -Encoding ASCII -Value @(
        "@echo off",
        "echo 127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAxisTestOnly"
    )
    $env:PATH = "$root;$savedPath"
    $env:AXIS_TEST_SSH_KEYSCAN = $fakeKeyscan
    & rustc -O (Join-Path $PSScriptRoot "helpers\ssh_probe.rs") -o $probe
    if ($LASTEXITCODE -ne 0) { Exit-Fail "failed to compile SSH probe" }

    $provider = Start-Process -FilePath $probe -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $providerOut -RedirectStandardError $providerErr `
        -ArgumentList @("server", $requestFile)
    $port = $null
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if (Test-Path -LiteralPath $providerOut) {
            $line = Get-Content -LiteralPath $providerOut -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($line -match '^PORT=(\d+)$') { $port = [int]$Matches[1]; break }
        }
        Start-Sleep -Milliseconds 50
    }
    if (-not $port) { $provider.Kill(); Exit-Fail "SSH mock server did not publish a port" }

    $yamlKey = $privateKey.Replace("'", "''")
    $policyText = @"
version: 1
name: $policyName
runtime:
  containment: process
  provider: mxc
filesystem:
  read_write:
    - "{workspace}"
  compatibility: hard_requirement
process:
  timeout_sec: 20
network:
  mode: proxy
  policies:
    - name: scoped-ssh
      endpoints:
        - host: "127.0.0.1"
          port: $port
          access: read-write
ssh:
  allowed_keys:
    - name: test
      private_key: '$yamlKey'
      allowed_hosts: ["127.0.0.1"]
  generate_known_hosts: true
  generate_config: true
"@
    Set-Content -LiteralPath $policy -Value $policyText -Encoding ASCII

    function Invoke-AxisProgram([string]$Program, [string[]]$Arguments, [string]$InputText) {
        Push-Location $workspace
        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $output = $InputText | & $AxisBin run --policy $policy -- $Program @Arguments 2>&1 | Out-String
            return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
        } finally {
            $ErrorActionPreference = $saved
            Pop-Location
        }
    }

    $inspect = Invoke-AxisProgram $probe @("inspect", "id_axis_test", $privateKey) ""
    if ($inspect.ExitCode -ne 0 -or -not $inspect.Output.Contains("SSH_PROJECTION=1")) {
        $provider.Kill()
        Exit-Fail "scoped SSH projection failed: $($inspect.Output)"
    }

    $allowed = Invoke-AxisProgram $projectedHelper @("127.0.0.1", "$port") "SSH_CLIENT_HELLO"
    if (-not $provider.WaitForExit(10000)) { $provider.Kill(); Exit-Fail "SSH mock server did not exit" }
    if ($allowed.ExitCode -ne 0 -or -not $allowed.Output.Contains("SSH_TUNNEL_OK")) {
        Exit-Fail "allowed SSH CONNECT tunnel failed: $($allowed.Output)"
    }
    if (-not ([IO.File]::ReadAllText($requestFile)).Contains("SSH_CLIENT_HELLO")) {
        Exit-Fail "SSH CONNECT tunnel did not relay client bytes"
    }

    $deniedPort = if ($port -lt 65535) { $port + 1 } else { $port - 1 }
    $denied = Invoke-AxisProgram $projectedHelper @("127.0.0.1", "$deniedPort") "DENIED"
    if ($denied.ExitCode -eq 0 -or -not $denied.Output.Contains("proxy rejected")) {
        Exit-Fail "out-of-scope SSH destination was not denied: $($denied.Output)"
    }

    Write-Host "PASS: AXIS Windows MXC scoped SSH projection and CONNECT checks"
} finally {
    $env:PATH = $savedPath
    if ($null -eq $savedKeyscan) {
        Remove-Item Env:\AXIS_TEST_SSH_KEYSCAN -ErrorAction SilentlyContinue
    } else {
        $env:AXIS_TEST_SSH_KEYSCAN = $savedKeyscan
    }
    if ($provider -and -not $provider.HasExited) { $provider.Kill() }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
