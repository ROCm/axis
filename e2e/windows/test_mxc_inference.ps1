# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Gated BaseContainer managed-inference, credential, and token-budget proof.
param(
    [string]$AxisBin = ".\target\release\axis.exe"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Exit-Fail([string]$Message) { throw "FAIL: $Message" }

if ($env:AXIS_RUN_WINDOWS_INFERENCE_E2E -ne "1") {
    Write-Host "SKIP: AXIS_RUN_WINDOWS_INFERENCE_E2E=1 not set"
    exit 0
}
if ($env:OS -ne "Windows_NT") { Exit-Fail "inference E2E requires Windows" }
$service = Get-Service -Name AxisWfpBroker -ErrorAction SilentlyContinue
if (-not $service -or $service.Status -ne "Running") {
    Exit-Fail "AxisWfpBroker must be installed and running"
}
foreach ($path in @($AxisBin, $env:AXIS_TEST_MXC_EXECUTOR)) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Exit-Fail "required executable not found: $path"
    }
}

$AxisBin = (Resolve-Path -LiteralPath $AxisBin).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ("axis-inference-e2e-" + [guid]::NewGuid().ToString("N"))
$workspace = Join-Path $root "workspace"
$probe = Join-Path $workspace "axis-inference-probe.exe"
$policy = Join-Path $root "policy.yaml"
$providerOut = Join-Path $root "provider.out"
$providerErr = Join-Path $root "provider.err"
$requestFile = Join-Path $root "provider-request.bin"
$savedSecret = $env:AXIS_TEST_WINDOWS_PROVIDER_KEY
$savedInferenceEndpoint = $env:AXIS_INFERENCE_ENDPOINT
$env:AXIS_RUN_MXC_BASECONTAINER_E2E = "1"

try {
    New-Item -ItemType Directory -Path $workspace -Force | Out-Null
    & rustc -O (Join-Path $PSScriptRoot "helpers\inference_probe.rs") -o $probe
    if ($LASTEXITCODE -ne 0) { Exit-Fail "failed to compile inference probe" }
    $env:AXIS_TEST_WINDOWS_PROVIDER_KEY = "axis-provider-secret-7f3a"

    function Start-Provider {
        Remove-Item -LiteralPath $providerOut, $providerErr, $requestFile -Force -ErrorAction SilentlyContinue
        $process = Start-Process -FilePath $probe -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $providerOut -RedirectStandardError $providerErr `
            -ArgumentList @("provider", $requestFile)
        $port = $null
        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            if (Test-Path -LiteralPath $providerOut) {
                $line = Get-Content -LiteralPath $providerOut -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($line -match '^PORT=(\d+)$') { $port = [int]$Matches[1]; break }
            }
            Start-Sleep -Milliseconds 50
        }
        if (-not $port) { $process.Kill(); Exit-Fail "mock provider did not publish its port" }
        return [pscustomobject]@{ Process = $process; Port = $port }
    }

    function Write-Policy([int]$Port) {
        $text = @"
version: 1
name: windows-mxc-inference-e2e
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
    - name: mock-provider
      endpoints:
        - host: "inference.local"
          port: $Port
          access: read-write
inference:
  routes:
    - name: mock-provider
      endpoint: "http://inference.local:$Port"
      api_key_env: AXIS_TEST_WINDOWS_PROVIDER_KEY
      protocols: ["openai-chat-stream"]
  token_budget:
    max_tokens_per_hour: 1000
    max_tokens_per_request: 200
    action_on_exhaust: reject
"@
        Set-Content -LiteralPath $policy -Value $text -Encoding ASCII
    }

    function Invoke-Inference([int]$Port, [int]$MaxTokens) {
        Push-Location $workspace
        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $output = "" | & $AxisBin run --policy $policy -- $probe client inference.local "$Port" "$MaxTokens" 2>&1 | Out-String
            return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
        } finally {
            $ErrorActionPreference = $saved
            Pop-Location
        }
    }

    $provider = Start-Provider
    Write-Policy $provider.Port
    $env:AXIS_INFERENCE_ENDPOINT = "127.0.0.1:$($provider.Port)"
    $allowed = Invoke-Inference $provider.Port 10
    if ($allowed.ExitCode -ne 0) {
        $provider.Process.Kill()
        Exit-Fail "allowed inference launch failed before the provider completed: $($allowed.Output)"
    }
    if (-not $provider.Process.WaitForExit(10000)) { $provider.Process.Kill(); Exit-Fail "provider did not exit" }
    if (-not $allowed.Output.Contains("SECRET_ENV=0") -or -not $allowed.Output.Contains("STREAMING=1")) {
        Exit-Fail "allowed inference request failed: $($allowed.Output)"
    }
    $request = [IO.File]::ReadAllText($requestFile)
    if (-not $request.Contains("Authorization: Bearer axis-provider-secret-7f3a")) {
        Exit-Fail "host credential was not injected at the proxy boundary: $request"
    }
    if ($request.Contains("AXIS_TEST_WINDOWS_PROVIDER_KEY")) {
        Exit-Fail "credential environment name leaked upstream"
    }
    if ($allowed.Output.Contains("axis-provider-secret-7f3a")) {
        Exit-Fail "provider credential leaked back into sandbox output"
    }

    $provider = Start-Provider
    Write-Policy $provider.Port
    $env:AXIS_INFERENCE_ENDPOINT = "127.0.0.1:$($provider.Port)"
    $denied = Invoke-Inference $provider.Port 201
    if (-not $provider.Process.WaitForExit(10000)) { $provider.Process.Kill(); Exit-Fail "denied provider connection did not close" }
    $deniedLength = if (Test-Path -LiteralPath $requestFile) { (Get-Item -LiteralPath $requestFile).Length } else { 0 }
    if ($denied.ExitCode -eq 0 -or $deniedLength -ne 0) {
        Exit-Fail "oversize token request was not denied before forwarding: $($denied.Output)"
    }

    Write-Host "PASS: AXIS Windows MXC managed inference, credentials, streaming, and token budget checks"
} finally {
    if ($null -eq $savedSecret) {
        Remove-Item Env:\AXIS_TEST_WINDOWS_PROVIDER_KEY -ErrorAction SilentlyContinue
    } else {
        $env:AXIS_TEST_WINDOWS_PROVIDER_KEY = $savedSecret
    }
    if ($null -eq $savedInferenceEndpoint) {
        Remove-Item Env:\AXIS_INFERENCE_ENDPOINT -ErrorAction SilentlyContinue
    } else {
        $env:AXIS_INFERENCE_ENDPOINT = $savedInferenceEndpoint
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
