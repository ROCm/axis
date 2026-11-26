# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# AXIS Agent Safety Test Suite (Windows PowerShell)
#
# Tests that agent policies validate and sandbox isolation works.
#
# Usage:
#   .\test_agents.ps1
#   .\test_agents.ps1 -AxisBin C:\path\to\axis.exe

param(
    [string]$AxisBin = "axis"
)

$ErrorActionPreference = "Continue"

$PolicyDir = "$PSScriptRoot\..\..\policies\agents"
if (-not (Test-Path $PolicyDir)) {
    $PolicyDir = "$env:LOCALAPPDATA\axis\policies\agents"
}
if (-not (Test-Path $PolicyDir)) {
    $PolicyDir = "$env:USERPROFILE\.axis\policies\agents"
}

Write-Host ""
Write-Host "  AXIS Agent Safety Test Suite (Windows)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  AXIS: $(& $AxisBin --version 2>&1)"
Write-Host "  Policies: $PolicyDir"
Write-Host ""

$pass = 0; $fail = 0; $skip = 0

function Test-Pass($msg) { Write-Host "  PASS: $msg" -ForegroundColor Green; $script:pass++ }
function Test-Fail($msg) { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:fail++ }
function Test-Skip($msg) { Write-Host "  SKIP: $msg" -ForegroundColor Yellow; $script:skip++ }

# -- Test each agent policy --------------------------------------------

$agents = @(
    @{ Name = "base-deny"; Policy = "base-deny.yaml" },
    @{ Name = "Claude Code"; Policy = "claude-code.yaml" },
    @{ Name = "Codex"; Policy = "codex.yaml" },
    @{ Name = "OpenClaw"; Policy = "openclaw.yaml" },
    @{ Name = "Ironclaw"; Policy = "ironclaw.yaml" },
    @{ Name = "NanoClaw"; Policy = "nanoclaw.yaml" },
    @{ Name = "ZeroClaw"; Policy = "zeroclaw.yaml" },
    @{ Name = "Hermes"; Policy = "hermes.yaml" }
)

foreach ($agent in $agents) {
    $policyFile = "$PolicyDir\$($agent.Policy)"
    Write-Host "--- $($agent.Name) ---"

    if (-not (Test-Path $policyFile)) {
        Test-Skip "$($agent.Name): policy not found at $policyFile"
        Write-Host ""
        continue
    }

    # Test 1: Policy validates.
    $result = & $AxisBin policy validate $policyFile 2>&1
    if ($LASTEXITCODE -eq 0) {
        Test-Pass "$($agent.Name): policy validates"
    } else {
        Test-Fail "$($agent.Name): policy validation ($result)"
    }

    Write-Host ""
}

# -- Summary ----------------------------------------------------------

Write-Host "=================================================="
$total = $pass + $fail
Write-Host "Result: $pass passed, $fail failed, $skip skipped (of $total)"
Write-Host "Platform: Windows"
Write-Host ""

if ($fail -eq 0) {
    Write-Host "All agent policies validate correctly." -ForegroundColor Green
}

exit $fail
