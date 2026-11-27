# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# AXIS Agent Installer for Windows (PowerShell)
#
# Installs agent runtimes into %LOCALAPPDATA%\axis\tools\.
# Creates wrapper scripts that route agents through AXIS when
# %LOCALAPPDATA%\axis\bin is first on PATH.
#
# Usage:
#   .\install_agents.ps1 -Agents aider,codex
#   .\install_agents.ps1 -All
#   .\install_agents.ps1 -List
#
# Agents are installed to %LOCALAPPDATA%\axis\tools\<agent>\ and wrapper
# scripts in %LOCALAPPDATA%\axis\bin\ route them through AXIS.

param(
    [string[]]$Agents,
    [switch]$All,
    [switch]$List
)

$ErrorActionPreference = "Continue"

$AxisRoot = "$env:LOCALAPPDATA\axis"
$ToolsDir = "$AxisRoot\tools"
$BinDir = "$AxisRoot\bin"
$PoliciesDir = "$AxisRoot\policies\agents"

New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
New-Item -ItemType Directory -Path $PoliciesDir -Force | Out-Null

# -- Agent definitions ----------------------------------------------------

$AgentDefs = @{
    "claude-code"  = @{ Binary = "claude";        Policy = "claude-code.yaml";  Install = "Install-ClaudeCode" }
    "codex"        = @{ Binary = "codex";         Policy = "codex.yaml";        Install = "Install-Codex" }
    "openclaw"     = @{ Binary = "openclaw";      Policy = "openclaw.yaml";     Install = "Install-OpenClaw" }
    "ironclaw"     = @{ Binary = "ironclaw";      Policy = "ironclaw.yaml";     Install = "Install-Ironclaw" }
    "aider"        = @{ Binary = "aider";         Policy = "hermes.yaml";       Install = "Install-Aider" }
    "goose"        = @{ Binary = "goose";         Policy = "hermes.yaml";       Install = "Install-Goose" }
    "gemini-cli"   = @{ Binary = "gemini";        Policy = "gemini-cli.yaml";   Install = "Install-GeminiCli" }
    "opencode"     = @{ Binary = "opencode";      Policy = "opencode.yaml";     Install = "Install-OpenCode" }
}

$AllAgents = @("claude-code", "codex", "openclaw", "ironclaw", "aider", "goose", "gemini-cli", "opencode")

# -- Install functions ----------------------------------------------------

function Install-ClaudeCode {
    $dir = "$ToolsDir\claude-code"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    # Check if already installed
    $bin = Get-Command claude -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    # Check common install locations
    foreach ($candidate in @(
        "$env:LOCALAPPDATA\Programs\claude\claude.exe",
        "$env:LOCALAPPDATA\.claude\bin\claude.exe",
        "$env:USERPROFILE\.local\bin\claude.exe",
        "$env:USERPROFILE\.local\bin\claude",
        "$env:USERPROFILE\.local\share\claude\claude.exe"
    )) {
        if ($candidate -and (Test-Path $candidate -ErrorAction SilentlyContinue)) {
            return $candidate
        }
    }

    # Try official installer
    try {
        Write-Host "  Downloading Claude Code installer..."
        $installer = "$env:TEMP\claude-install.ps1"
        Invoke-WebRequest -Uri "https://claude.ai/install.ps1" -OutFile $installer -UseBasicParsing
        & powershell -ExecutionPolicy Bypass -File $installer
        Remove-Item $installer -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  Installer failed: $_" -ForegroundColor Yellow
    }

    # Check again after install
    $bin = Get-Command claude -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    foreach ($candidate in @(
        "$env:LOCALAPPDATA\Programs\claude\claude.exe",
        "$env:LOCALAPPDATA\.claude\bin\claude.exe"
    )) {
        if ($candidate -and (Test-Path $candidate -ErrorAction SilentlyContinue)) {
            return $candidate
        }
    }

    return ""
}

function Install-Codex {
    $dir = "$ToolsDir\codex"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Write-Host "  Installing via npm..."
        & npm install --prefix $dir @openai/codex 2>&1 | Out-Null
        $bin = "$dir\node_modules\.bin\codex.cmd"
        if (Test-Path $bin) { return $bin }
    }

    $bin = Get-Command codex -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    return ""
}

function Install-OpenClaw {
    $dir = "$ToolsDir\openclaw"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Write-Host "  Installing via npm..."
        & npm install --prefix $dir openclaw@latest 2>&1 | Out-Null
        $bin = "$dir\node_modules\.bin\openclaw.cmd"
        if (Test-Path $bin) { return $bin }
    }

    $bin = Get-Command openclaw -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    return ""
}

function Install-Ironclaw {
    $dir = "$ToolsDir\ironclaw"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    # ironclaw is distributed via npm; --ignore-scripts avoids native opus build
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Write-Host "  Installing via npm..."
        & npm install --prefix $dir ironclaw@latest --ignore-scripts 2>&1 | Out-Null
        $bin = "$dir\node_modules\.bin\ironclaw.cmd"
        if (Test-Path $bin) { return $bin }
    }

    $bin = Get-Command ironclaw -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    return ""
}

function Install-Aider {
    $dir = "$ToolsDir\aider"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    $pythonCmd = if (Get-Command python -ErrorAction SilentlyContinue) { "python" }
                 elseif (Get-Command python3 -ErrorAction SilentlyContinue) { "python3" }
                 else { $null }

    if ($pythonCmd) {
        Write-Host "  Creating venv..."
        & $pythonCmd -m venv "$dir\venv" 2>&1 | Out-Null
        # Upgrade pip and install setuptools first - required for building native deps
        Write-Host "  Upgrading pip and installing build deps..."
        & "$dir\venv\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel 2>&1 | Out-Null
        Write-Host "  Installing aider-chat..."
        & "$dir\venv\Scripts\pip.exe" install aider-chat 2>&1 | Out-Null
        $bin = "$dir\venv\Scripts\aider.exe"
        if (Test-Path $bin) { return $bin }
    }

    # Try pipx as fallback
    if (Get-Command pipx -ErrorAction SilentlyContinue) {
        Write-Host "  Trying pipx..."
        & pipx install aider-chat 2>&1 | Out-Null
    }

    $bin = Get-Command aider -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    return ""
}

function Install-Goose {
    $dir = "$ToolsDir\goose"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    try {
        # Goose distributes a zip on Windows, not a standalone exe
        $zipUrl = "https://github.com/block/goose/releases/latest/download/goose-x86_64-pc-windows-msvc.zip"
        $zipPath = "$dir\goose.zip"
        Write-Host "  Downloading goose..."
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
        Write-Host "  Extracting..."
        Expand-Archive -Path $zipPath -DestinationPath $dir -Force
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        # The zip contains goose.exe at the top level or in a subdirectory
        $bin = Get-ChildItem -Path $dir -Filter "goose.exe" -Recurse | Select-Object -First 1
        if ($bin) { return $bin.FullName }
    } catch {
        Write-Host "  Download failed: $_" -ForegroundColor Yellow
    }

    $bin = Get-Command goose -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    return ""
}

function Install-GeminiCli {
    $dir = "$ToolsDir\gemini-cli"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Write-Host "  Installing via npm..."
        & npm install --prefix $dir @google/gemini-cli@latest 2>&1 | Out-Null
        $bin = "$dir\node_modules\.bin\gemini.cmd"
        if (Test-Path $bin) { return $bin }
    }

    $bin = Get-Command gemini -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    return ""
}

function Install-OpenCode {
    $dir = "$ToolsDir\opencode"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Write-Host "  Installing via npm..."
        & npm install --prefix $dir opencode-ai@latest 2>&1 | Out-Null
        $bin = "$dir\node_modules\.bin\opencode.cmd"
        if (Test-Path $bin) { return $bin }
    }

    # Try scoop as fallback
    if (Get-Command scoop -ErrorAction SilentlyContinue) {
        Write-Host "  Installing via scoop..."
        & scoop install opencode 2>&1 | Out-Null
    }

    $bin = Get-Command opencode -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    return ""
}

# -- Wrapper generator ----------------------------------------------------

function Get-AgentDefaultFlags {
    param([string]$AgentName)
    switch ($AgentName) {
        "claude-code" { return "--dangerously-skip-permissions" }
        "codex"       { return "--dangerously-bypass-approvals-and-sandbox" }
        default       { return "" }
    }
}

function New-AgentWrapper {
    param(
        [string]$AgentName,
        [string]$BinaryName,
        [string]$BinaryPath,
        [string]$PolicyFile
    )

    $defaultFlags = Get-AgentDefaultFlags $AgentName

    # Find axis binary.
    $axisBin = Get-Command axis -ErrorAction SilentlyContinue
    $axisPath = if ($axisBin) { $axisBin.Source } else { "axis" }

    # Create .cmd wrapper (works in cmd.exe and PowerShell).
    $cmdWrapper = "$BinDir\$BinaryName.cmd"
    @"
@echo off
REM AXIS-sandboxed $BinaryName
REM This wrapper routes execution through AXIS when it is selected on PATH.
REM Agent state: %LOCALAPPDATA%\axis\agents\
REM Policy:      $PolicyFile
REM Real binary: $BinaryPath
set "AXIS_BIN=%AXIS_BIN%"
if "%AXIS_BIN%"=="" set "AXIS_BIN=$axisPath"
if defined AXIS_NO_DEFAULT_FLAGS ("%AXIS_BIN%" run --policy "$PolicyFile" -- "$BinaryPath" %*) else ("%AXIS_BIN%" run --policy "$PolicyFile" -- "$BinaryPath" $defaultFlags %*)
"@ | Set-Content -Path $cmdWrapper -Encoding ASCII

    # Create .ps1 wrapper for PowerShell.
    $ps1Wrapper = "$BinDir\$BinaryName.ps1"
    @"
# AXIS-sandboxed $BinaryName
# Default flags: $defaultFlags
# Override: `$env:AXIS_NO_DEFAULT_FLAGS=1; $BinaryName [args...]
`$axisBin = if (`$env:AXIS_BIN) { `$env:AXIS_BIN } else { "$axisPath" }
if (`$env:AXIS_NO_DEFAULT_FLAGS) {
    & `$axisBin run --policy "$PolicyFile" -- "$BinaryPath" @args
} else {
    & `$axisBin run --policy "$PolicyFile" -- "$BinaryPath" $defaultFlags @args
}
"@ | Set-Content -Path $ps1Wrapper -Encoding UTF8

    Write-Host "  Wrapper: $cmdWrapper"
    Write-Host "  Wrapper: $ps1Wrapper"
}

# -- Main -----------------------------------------------------------------

if ($List) {
    Write-Host "Available agents:"
    foreach ($agent in $AllAgents) {
        $installed = if (Test-Path "$ToolsDir\$agent") { " [installed]" } else { "" }
        Write-Host "  $agent$installed"
    }
    exit 0
}

if (-not $All -and -not $Agents) {
    Write-Host "AXIS Agent Installer (Windows)"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\install_agents.ps1 -All"
    Write-Host "  .\install_agents.ps1 -List"
    Write-Host "  .\install_agents.ps1 -Agents aider,codex"
    Write-Host ""
    Write-Host "Available: $($AllAgents -join ', ')"
    Write-Host ""
    Write-Host "Agents install to $ToolsDir and run through AXIS sandbox."
    exit 0
}

$targetAgents = if ($All) { $AllAgents } else { $Agents }

Write-Host ""
Write-Host "  AXIS Agent Installer (Windows)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Install dir: $ToolsDir"
Write-Host "  Wrappers:    $BinDir"
Write-Host ""

$installed = 0
$failed = 0

foreach ($agent in $targetAgents) {
    Write-Host "--- Installing: $agent ---"

    $def = $AgentDefs[$agent]
    if (-not $def) {
        Write-Host "  Unknown agent: $agent" -ForegroundColor Red
        $failed++
        continue
    }

    $binaryPath = & $def.Install 2>&1 | Select-Object -Last 1

    if ($binaryPath -and ("$binaryPath" -ne "") -and (Test-Path "$binaryPath" -ErrorAction SilentlyContinue)) {
        Write-Host "  Binary: $binaryPath" -ForegroundColor Green

        $policyFile = "$PoliciesDir\$($def.Policy)"
        if (-not (Test-Path $policyFile)) {
            Write-Host "  Warning: policy not found, using base-deny"
            $policyFile = "$PoliciesDir\base-deny.yaml"
        }

        New-AgentWrapper -AgentName $agent -BinaryName $def.Binary `
            -BinaryPath $binaryPath -PolicyFile $policyFile
        $installed++
        Write-Host "  OK" -ForegroundColor Green
    } else {
        Write-Host "  Failed to install" -ForegroundColor Red
        $failed++
    }
    Write-Host ""
}

Write-Host "=================================================="
Write-Host "Installed: $installed  Failed: $failed"
Write-Host ""

if ($installed -gt 0) {
    # Check if BinDir is in PATH.
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$BinDir*") {
        Write-Host "Adding $BinDir to PATH..." -ForegroundColor Yellow
        [Environment]::SetEnvironmentVariable("Path", "$BinDir;$userPath", "User")
        $env:Path = "$BinDir;$env:Path"
    }

    Write-Host "Run agents through AXIS sandbox:" -ForegroundColor Cyan
    Write-Host ""
    foreach ($agent in $targetAgents) {
        $def = $AgentDefs[$agent]
        if ($def -and (Test-Path "$BinDir\$($def.Binary).cmd")) {
            Write-Host "  $($def.Binary) --version        # runs through AXIS sandbox"
            Write-Host "  axis $($def.Binary) --version   # same thing, explicit"
        }
    }
}
