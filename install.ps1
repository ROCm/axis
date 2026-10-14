# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# AXIS installer for PowerShell 7 on Windows
#
# Usage:
#   pwsh -c "irm 'https://raw.githubusercontent.com/ROCm/axis/main/install.ps1' | iex"
#
#   # Or with options:
#   $env:AXIS_CHANNEL = "nightly"
#   pwsh -c "irm 'https://raw.githubusercontent.com/ROCm/axis/main/install.ps1' | iex"
#
# Options (set as env vars before running):
#   AXIS_CHANNEL   "release" (default) or "nightly"
#   AXIS_VERSION   Specific version (e.g., "0.1.0")
#   AXIS_DIR       Install directory (default: %LOCALAPPDATA%\axis\bin)

$ErrorActionPreference = "Stop"

if (-not $PSVersionTable.PSVersion -or $PSVersionTable.PSVersion.Major -lt 7) {
    throw "AXIS installation requires PowerShell 7 or later (pwsh). Install it from https://aka.ms/powershell-release"
}

if (-not ("AxisInstaller.JobProcessRunner" -as [type])) {
    Add-Type -TypeDefinition @'
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace AxisInstaller
{
    public sealed class JobProcessResult
    {
        public string Stdout { get; set; }
        public string Stderr { get; set; }
        public int ExitCode { get; set; }
    }

    public static class JobProcessRunner
    {
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_TIMEOUT = 0x00000102;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            IntPtr job, int informationClass, IntPtr information, uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcess(
            string applicationName, StringBuilder commandLine, IntPtr processAttributes,
            IntPtr threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags, IntPtr environment, string currentDirectory,
            ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreatePipe(
            out IntPtr readPipe, out IntPtr writePipe,
            ref SECURITY_ATTRIBUTES attributes, uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        public static JobProcessResult Run(
            string executable, string[] arguments, int maximumOutput, int timeoutMilliseconds)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                throw new PlatformNotSupportedException("AXIS Windows installer requires Windows");
            if (maximumOutput <= 0 || timeoutMilliseconds <= 0)
                throw new ArgumentOutOfRangeException();

            IntPtr job = IntPtr.Zero;
            IntPtr stdoutRead = IntPtr.Zero, stdoutWrite = IntPtr.Zero;
            IntPtr stderrRead = IntPtr.Zero, stderrWrite = IntPtr.Zero;
            IntPtr stdinRead = IntPtr.Zero, stdinWrite = IntPtr.Zero;
            IntPtr environment = IntPtr.Zero;
            PROCESS_INFORMATION process = new PROCESS_INFORMATION();
            try
            {
                job = CreateKillOnCloseJob();
                CreateRedirectPipe(out stdoutRead, out stdoutWrite);
                CreateRedirectPipe(out stderrRead, out stderrWrite);
                CreateInputPipe(out stdinRead, out stdinWrite);

                STARTUPINFO startup = new STARTUPINFO();
                startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                startup.dwFlags = STARTF_USESTDHANDLES;
                startup.hStdInput = stdinRead;
                startup.hStdOutput = stdoutWrite;
                startup.hStdError = stderrWrite;
                environment = BuildEnvironment();
                StringBuilder commandLine = BuildCommandLine(executable, arguments);
                if (!CreateProcess(
                    executable, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                    environment, null, ref startup, out process))
                    ThrowLastWin32("CreateProcess");
                if (!AssignProcessToJobObject(job, process.hProcess))
                    ThrowLastWin32("AssignProcessToJobObject");

                Close(ref stdoutWrite);
                Close(ref stderrWrite);
                Close(ref stdinRead);
                Close(ref stdinWrite);
                if (ResumeThread(process.hThread) == UInt32.MaxValue)
                    ThrowLastWin32("ResumeThread");
                Close(ref process.hThread);

                Stopwatch timer = Stopwatch.StartNew();
                byte[][] output;
                using (FileStream stdout = new FileStream(
                    new SafeFileHandle(stdoutRead, true), FileAccess.Read, 65536, false))
                using (FileStream stderr = new FileStream(
                    new SafeFileHandle(stderrRead, true), FileAccess.Read, 65536, false))
                {
                    stdoutRead = IntPtr.Zero;
                    stderrRead = IntPtr.Zero;
                    Action terminate = delegate { TerminateJobObject(job, 1); };
                    Task<byte[]> stdoutTask = ReadBounded(stdout, maximumOutput, terminate);
                    Task<byte[]> stderrTask = ReadBounded(stderr, maximumOutput, terminate);
                    Task<byte[][]> allOutput = Task.WhenAll(stdoutTask, stderrTask);
                    Task completed = Task.WhenAny(
                        allOutput, Task.Delay(timeoutMilliseconds)).GetAwaiter().GetResult();
                    if (completed != allOutput)
                    {
                        TerminateJobObject(job, 1);
                        throw new TimeoutException("GitHub CLI command timed out");
                    }
                    try
                    {
                        output = allOutput.GetAwaiter().GetResult();
                    }
                    catch (InvalidDataException)
                    {
                        throw new InvalidOperationException(
                            "GitHub CLI output exceeds size limit");
                    }
                }

                long remaining = timeoutMilliseconds - timer.ElapsedMilliseconds;
                uint waitResult = remaining > 0
                    ? WaitForSingleObject(process.hProcess, (uint)remaining)
                    : WAIT_TIMEOUT;
                if (waitResult != WAIT_OBJECT_0)
                {
                    TerminateJobObject(job, 1);
                    throw new TimeoutException("GitHub CLI command timed out");
                }
                if (!GetExitCodeProcess(process.hProcess, out uint exitCode))
                    ThrowLastWin32("GetExitCodeProcess");
                return new JobProcessResult {
                    Stdout = Encoding.UTF8.GetString(output[0]).Trim(),
                    Stderr = Encoding.UTF8.GetString(output[1]),
                    ExitCode = unchecked((int)exitCode),
                };
            }
            catch
            {
                if (job != IntPtr.Zero) TerminateJobObject(job, 1);
                if (process.hProcess != IntPtr.Zero) TerminateProcess(process.hProcess, 1);
                throw;
            }
            finally
            {
                if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
                Close(ref process.hThread);
                Close(ref process.hProcess);
                Close(ref stdinRead);
                Close(ref stdinWrite);
                Close(ref stdoutRead);
                Close(ref stdoutWrite);
                Close(ref stderrRead);
                Close(ref stderrWrite);
                Close(ref job);
            }
        }

        private static async Task<byte[]> ReadBounded(
            FileStream stream, int maximumOutput, Action terminate)
        {
            using (MemoryStream output = new MemoryStream())
            {
                byte[] buffer = new byte[65536];
                while (true)
                {
                    int count = await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                    if (count == 0) break;
                    if (output.Length + count > maximumOutput)
                    {
                        terminate();
                        throw new InvalidDataException("output limit exceeded");
                    }
                    output.Write(buffer, 0, count);
                }
                return output.ToArray();
            }
        }

        private static IntPtr CreateKillOnCloseJob()
        {
            IntPtr job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) ThrowLastWin32("CreateJobObject");
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits =
                new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr pointer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(limits, pointer, false);
                if (!SetInformationJobObject(job, 9, pointer, (uint)size))
                    ThrowLastWin32("SetInformationJobObject");
            }
            catch
            {
                CloseHandle(job);
                throw;
            }
            finally
            {
                Marshal.FreeHGlobal(pointer);
            }
            return job;
        }

        private static void CreateRedirectPipe(out IntPtr read, out IntPtr write)
        {
            SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
            attributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            attributes.bInheritHandle = true;
            if (!CreatePipe(out read, out write, ref attributes, 0))
                ThrowLastWin32("CreatePipe");
            if (!SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0))
            {
                int error = Marshal.GetLastWin32Error();
                CloseHandle(read);
                CloseHandle(write);
                read = IntPtr.Zero;
                write = IntPtr.Zero;
                throw new System.ComponentModel.Win32Exception(
                    error, "SetHandleInformation failed");
            }
        }

        private static void CreateInputPipe(out IntPtr read, out IntPtr write)
        {
            SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
            attributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            attributes.bInheritHandle = true;
            if (!CreatePipe(out read, out write, ref attributes, 0))
                ThrowLastWin32("CreatePipe");
            if (!SetHandleInformation(write, HANDLE_FLAG_INHERIT, 0))
            {
                int error = Marshal.GetLastWin32Error();
                CloseHandle(read);
                CloseHandle(write);
                read = IntPtr.Zero;
                write = IntPtr.Zero;
                throw new System.ComponentModel.Win32Exception(
                    error, "SetHandleInformation failed");
            }
        }

        private static IntPtr BuildEnvironment()
        {
            SortedDictionary<string, string> values =
                new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
                values[(string)entry.Key] = (string)entry.Value;
            values["GH_PROMPT_DISABLED"] = "1";
            values["GH_NO_UPDATE_NOTIFIER"] = "1";
            StringBuilder block = new StringBuilder();
            foreach (KeyValuePair<string, string> entry in values)
                block.Append(entry.Key).Append('=').Append(entry.Value).Append('\0');
            block.Append('\0');
            return Marshal.StringToHGlobalUni(block.ToString());
        }

        private static StringBuilder BuildCommandLine(string executable, string[] arguments)
        {
            StringBuilder command = new StringBuilder(QuoteArgument(executable));
            foreach (string argument in arguments)
                command.Append(' ').Append(QuoteArgument(argument));
            return command;
        }

        private static string QuoteArgument(string argument)
        {
            if (argument.Length > 0 && argument.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0)
                return argument;
            StringBuilder quoted = new StringBuilder("\"");
            int backslashes = 0;
            foreach (char value in argument)
            {
                if (value == '\\')
                {
                    backslashes++;
                }
                else if (value == '"')
                {
                    quoted.Append('\\', backslashes * 2 + 1).Append('"');
                    backslashes = 0;
                }
                else
                {
                    quoted.Append('\\', backslashes).Append(value);
                    backslashes = 0;
                }
            }
            quoted.Append('\\', backslashes * 2).Append('"');
            return quoted.ToString();
        }

        private static void Close(ref IntPtr handle)
        {
            if (handle != IntPtr.Zero && handle.ToInt64() != -1) CloseHandle(handle);
            handle = IntPtr.Zero;
        }

        private static void ThrowLastWin32(string operation)
        {
            throw new System.ComponentModel.Win32Exception(
                Marshal.GetLastWin32Error(), operation + " failed");
        }
    }
}
'@
}

$Repo = "ROCm/axis"
$Channel = if ($env:AXIS_CHANNEL) { $env:AXIS_CHANNEL } else { "release" }
$Version = $env:AXIS_VERSION
$InstallDir = if ($env:AXIS_DIR) { $env:AXIS_DIR } else { "$env:LOCALAPPDATA\axis\bin" }
$LocalArchive = $env:AXIS_INSTALL_ARCHIVE
$LocalChecksum = $env:AXIS_INSTALL_SHA256
$GhVersion = "2.94.0"
$GhWindowsAmd64Sha256 = "c0766af54195dfa0bcd9a0cb63a45c313fbaffdebb9f736f666e9ba4be8c91e8"
$MaxAxisDownload = 1GB
$MaxToolDownload = 128MB
$MaxMetadataDownload = 1MB
$GhCommandTimeoutMilliseconds = 120000
$GhPath = $null
$Tag = $null
$LegacyRelease = $false
# Releases published before checksum sidecars and provenance attestations.
# Their archives are authenticated by these digests instead.
$LegacyReleaseSha256 = @{
    "v0.3.5:axis-windows-x86_64.zip" = "d8fba28841625387db62ae5fe80cc95e6b086a5e73205c13927b81d74af1e054"
}

function Receive-BoundedFile {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][long]$MaximumBytes
    )
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $true
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(5)
    $response = $null
    try {
        $response = $client.GetAsync(
            $Uri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
        ).GetAwaiter().GetResult()
        $response.EnsureSuccessStatusCode() | Out-Null
        if ($response.Content.Headers.ContentLength -gt $MaximumBytes) {
            throw "Download exceeds size limit: $Uri"
        }
        $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $output = [System.IO.File]::Create($Destination)
        try {
            $buffer = [byte[]]::new(65536)
            [long]$total = 0
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            while ($true) {
                $remaining = 300000 - $timer.ElapsedMilliseconds
                if ($remaining -le 0) { throw "Download timed out: $Uri" }
                $readTask = $inputStream.ReadAsync($buffer, 0, $buffer.Length)
                if (-not $readTask.Wait([int]$remaining)) {
                    throw "Download timed out: $Uri"
                }
                $count = $readTask.GetAwaiter().GetResult()
                if ($count -eq 0) { break }
                $total += $count
                if ($total -gt $MaximumBytes) {
                    throw "Download exceeds size limit: $Uri"
                }
                $output.Write($buffer, 0, $count)
            }
        } finally {
            $output.Dispose()
            $inputStream.Dispose()
        }
    } finally {
        if ($response) { $response.Dispose() }
        $client.Dispose()
        $handler.Dispose()
    }
}

function Invoke-Gh {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    try {
        $result = [AxisInstaller.JobProcessRunner]::Run(
            $GhPath, [string[]]$Arguments, 4MB, $GhCommandTimeoutMilliseconds
        )
        if ($result.ExitCode -ne 0) {
            throw "GitHub CLI failed: $($result.Stderr)"
        }
        return $result.Stdout
    } catch {
        throw $_.Exception.GetBaseException()
    }
}

function Initialize-Gh {
    $existing = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue
    if ($existing) {
        $script:GhPath = $existing.Source
        try {
            Invoke-Gh release verify-asset --help | Out-Null
            Invoke-Gh attestation verify --help | Out-Null
            return
        } catch {
            $script:GhPath = $null
        }
    }
    $archiveName = "gh_${GhVersion}_windows_amd64.zip"
    $archive = Join-Path $script:TmpDir $archiveName
    Receive-BoundedFile `
        -Uri "https://github.com/cli/cli/releases/download/v$GhVersion/$archiveName" `
        -Destination $archive -MaximumBytes $MaxToolDownload
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if (-not $actual.Equals($GhWindowsAmd64Sha256, [StringComparison]::OrdinalIgnoreCase)) {
        throw "GitHub CLI bootstrap checksum failed"
    }
    $destination = Join-Path $script:TmpDir "gh"
    Expand-Archive -LiteralPath $archive -DestinationPath $destination
    $script:GhPath = Join-Path $destination "gh_${GhVersion}_windows_amd64\bin\gh.exe"
    if (-not (Test-Path -LiteralPath $script:GhPath -PathType Leaf)) {
        throw "GitHub CLI bootstrap archive is invalid"
    }
}

function Get-Platform {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64"   { return "windows-x86_64" }
        default { throw "No AXIS release artifact is published for Windows $arch" }
    }
}

function Get-DownloadUrl {
    param([string]$Platform)

    if ($Channel -eq "nightly") {
        $tagValue = Invoke-Gh api "repos/$Repo/releases?per_page=100" --jq `
            'map(select(.prerelease and (.tag_name | test("^nightly-[0-9a-f]{40}$")))) | first | .tag_name // empty'
        if (-not $tagValue) {
            throw "Cannot determine latest nightly release"
        }
        $script:Tag = $tagValue
    } elseif ($Version) {
        if ($Version -notmatch '^[0-9A-Za-z.+-]+$') { throw "Invalid AXIS version" }
        $script:Tag = "v$Version"
    } else {
        $script:Tag = Invoke-Gh api "repos/$Repo/releases/latest" --jq '.tag_name'
        if (-not $script:Tag) {
            throw 'Cannot determine latest release. Try setting $env:AXIS_VERSION'
        }
    }
    if ($script:Tag -notmatch '^[0-9A-Za-z._+-]+$') { throw "Invalid release tag" }

    return "https://github.com/$Repo/releases/download/$script:Tag/axis-${Platform}.zip"
}

function Confirm-GitHubProvenance {
    param([string]$Archive)
    if ($LocalArchive) { return }
    if ($script:LegacyRelease) {
        Write-Host "Release $Tag predates provenance attestations; verified against the installer's pinned digest." -ForegroundColor Yellow
        return
    }
    Write-Host "Verifying immutable release provenance..." -ForegroundColor Yellow
    Invoke-Gh release verify-asset $Tag $Archive --repo $Repo | Out-Null
    $workflow = "$Repo/.github/workflows/release.yml"
    $sourceArgument = "--source-ref=refs/tags/$Tag"
    if ($Channel -eq "nightly") {
        $workflow = "$Repo/.github/workflows/nightly.yml"
        $sourceDigest = $Tag.Substring("nightly-".Length)
        if ($sourceDigest -notmatch '^[0-9a-f]{40}$') { throw "Invalid nightly source identity" }
        $sourceArgument = "--source-digest=$sourceDigest"
    }
    Invoke-Gh attestation verify $Archive --repo $Repo `
        --signer-workflow $workflow $sourceArgument --deny-self-hosted-runners | Out-Null
}

function Install-AXIS {
    $platform = Get-Platform

    Write-Host ""
    Write-Host "AXIS Installer" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Platform: $platform"
    Write-Host "  Channel:  $Channel"
    Write-Host "  Install:  $InstallDir"
    Write-Host ""

    $script:TmpDir = Join-Path $env:TEMP "axis-install-$([Guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:TmpDir | Out-Null
    try {
      if (-not $LocalArchive) { Initialize-Gh }

      if ($LocalArchive) {
          $sourceArchive = (Resolve-Path -LiteralPath $LocalArchive).Path
          $sourceChecksum = if ($LocalChecksum) {
              (Resolve-Path -LiteralPath $LocalChecksum).Path
          } else {
              (Resolve-Path -LiteralPath "$LocalArchive.sha256").Path
          }
          $archiveName = [System.IO.Path]::GetFileName($sourceArchive)
          Write-Host "  Archive:  $sourceArchive"
        } else {
          $url = Get-DownloadUrl $platform
          $archiveName = [System.IO.Path]::GetFileName($url)
          Write-Host "  Download: $url"
        }
        Write-Host ""

        $tmpDir = $script:TmpDir
        $archivePath = Join-Path $tmpDir "axis.zip"
        $checksumPath = Join-Path $tmpDir "axis.zip.sha256"

        if ($LocalArchive) {
            Copy-Item -LiteralPath $sourceArchive -Destination $archivePath
            Copy-Item -LiteralPath $sourceChecksum -Destination $checksumPath
        } else {
            Write-Host "Downloading..." -ForegroundColor Yellow
            try {
                Receive-BoundedFile -Uri $url -Destination $archivePath -MaximumBytes $MaxAxisDownload
            } catch {
                Write-Host ""
                Write-Host "Error: Download failed." -ForegroundColor Red
                Write-Host "  URL: $url"
                Write-Host ""
                Write-Host "If this is a new release, binaries may not be uploaded yet."
                Write-Host "Try: `$env:AXIS_CHANNEL = `"nightly`""
                throw
            }

            $legacyKey = "${Tag}:$archiveName"
            if ($LegacyReleaseSha256.ContainsKey($legacyKey)) {
                $script:LegacyRelease = $true
                [System.IO.File]::WriteAllText(
                    $checksumPath, "$($LegacyReleaseSha256[$legacyKey])  $archiveName`n"
                )
            } else {
                $checksumUrl = "$url.sha256"
                try {
                    Receive-BoundedFile -Uri $checksumUrl -Destination $checksumPath -MaximumBytes $MaxMetadataDownload
                } catch {
                    Write-Host "Error: Checksum download failed." -ForegroundColor Red
                    Write-Host "  URL: $checksumUrl"
                    throw
                }
            }
        }

        Write-Host "Verifying checksum..." -ForegroundColor Yellow
        $checksumLines = @(Get-Content -LiteralPath $checksumPath)
        $checksumPattern = '^(?<hash>[0-9A-Fa-f]{64})  ' + [regex]::Escape($archiveName) + '$'
        if ($checksumLines.Count -ne 1 -or $checksumLines[0] -notmatch $checksumPattern) {
            throw "Invalid checksum file for $archiveName"
        }
        $expectedHash = $Matches.hash
        $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
        if (-not $actualHash.Equals($expectedHash, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Checksum verification failed for $archiveName"
        }
        Confirm-GitHubProvenance -Archive $archivePath

        # Extract.
        Write-Host "Extracting..." -ForegroundColor Yellow
        $extractDir = Join-Path $tmpDir "extracted"
        Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force

        # Install binaries.
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

        $binaries = Get-ChildItem -Path $extractDir -Recurse -Filter "*.exe"
        foreach ($bin in $binaries) {
            $dest = Join-Path $InstallDir $bin.Name
            Copy-Item $bin.FullName $dest -Force
            Write-Host "  Installed: $dest" -ForegroundColor Green
        }

        # Copy policy files.
        $yamls = Get-ChildItem -Path $extractDir -Recurse -Filter "*.yaml"
        if ($yamls.Count -gt 0) {
            $policyDir = Join-Path (Join-Path $InstallDir "..") "policies"
            New-Item -ItemType Directory -Path $policyDir -Force | Out-Null
            foreach ($yaml in $yamls) {
                Copy-Item $yaml.FullName (Join-Path $policyDir $yaml.Name) -Force
            }
            Write-Host "  Policies:  $policyDir" -ForegroundColor Green
        }

        Write-Host ""

        # Check PATH.
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($userPath -notlike "*$InstallDir*") {
            Write-Host "Adding to PATH..." -ForegroundColor Yellow
            [Environment]::SetEnvironmentVariable("Path", "$InstallDir;$userPath", "User")
            $env:Path = "$InstallDir;$env:Path"
            Write-Host "  Added $InstallDir to user PATH" -ForegroundColor Green
            Write-Host ""
            Write-Host "  NOTE: Restart your terminal for PATH changes to take effect." -ForegroundColor Yellow
        }

        Write-Host ""
        Write-Host "AXIS installed successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "  axis --version"
        Write-Host ""

    } finally {
        # Cleanup.
        Remove-Item $script:TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Install-AXIS
