# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parent.parent


FAKE_GH = r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["INSTALLER_FIXTURE_ROOT"])
args = sys.argv[1:]
(root / "gh.log").open("a", encoding="utf-8").write(json.dumps(args) + "\n")
if args[:2] in (["release", "verify-asset"], ["attestation", "verify"]):
    if os.environ.get("FAIL_PROVENANCE") == "1" and args[:2] == ["release", "verify-asset"]:
        raise SystemExit(1)
elif args[:1] == ["api"]:
    endpoint = args[1]
    if endpoint.endswith("/releases/latest"):
        print(os.environ.get("INSTALLER_RELEASE_TAG", "v1.2.3"))
    else:
        raise SystemExit(2)
else:
    raise SystemExit(2)
"""


FAKE_CURL = r"""#!/usr/bin/env python3
import os
from pathlib import Path
import shutil
import sys

root = Path(os.environ["INSTALLER_FIXTURE_ROOT"])
args = sys.argv[1:]
destination = Path(args[args.index("--output") + 1])
url = args[-1]
checksum = url.endswith(".sha256")
if checksum and os.environ.get("CHECKSUM_HTTP_STATUS") == "404":
    sys.stderr.write("curl: (22) The requested URL returned error: 404\n")
    raise SystemExit(22)
if not checksum and os.environ.get("ARCHIVE_HTTP_STATUS") == "404":
    sys.stderr.write("curl: (22) The requested URL returned error: 404\n")
    raise SystemExit(22)
source = root / ("checksum" if checksum else "archive")
shutil.copyfile(source, destination)
"""


class UnixInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, content in (("gh", FAKE_GH), ("curl", FAKE_CURL)):
            path = self.bin / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o755)
        archive = self.root / "archive"
        with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as output:
            for name in ("axis", "axisd", "axis-seccomp-launcher", "lxc-exec"):
                info = tarfile.TarInfo(f"axis-linux-x86_64/{name}")
                info.mode = 0o755
                data = name.encode("ascii")
                info.size = len(data)
                output.addfile(info, io.BytesIO(data))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.root / "checksum").write_text(
            f"{digest}  axis-linux-x86_64.tar.gz\n", encoding="ascii"
        )
        self.environment = os.environ | {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.root / "home"),
            "INSTALLER_FIXTURE_ROOT": str(self.root),
        }

    def tearDown(self):
        self.temporary.cleanup()

    def run_installer(self, **environment: str) -> subprocess.CompletedProcess[str]:
        install = self.root / "installed"
        return subprocess.run(
            ["sh", str(ROOT / "install.sh"), "--prefix", str(install)],
            env=self.environment | environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
        )

    def test_remote_install_requires_release_and_workflow_provenance(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout)
        calls = [
            json.loads(line) for line in (self.root / "gh.log").read_text().splitlines()
        ]
        self.assertTrue(any(call[:2] == ["release", "verify-asset"] for call in calls))
        attestation = next(
            call
            for call in calls
            if call[:2] == ["attestation", "verify"] and "--help" not in call
        )
        self.assertIn("ROCm/axis/.github/workflows/release.yml", attestation)
        self.assertIn("--source-ref=refs/tags/v1.2.3", attestation)
        self.assertIn("--deny-self-hosted-runners", attestation)

    def test_provenance_failure_prevents_installation(self):
        result = self.run_installer(FAIL_PROVENANCE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "installed/axis").exists())

    def test_trusted_local_archive_skip_returns_success(self):
        local_archive = self.root / "axis-linux-x86_64.tar.gz"
        local_archive.write_bytes((self.root / "archive").read_bytes())
        local_checksum = self.root / "axis-linux-x86_64.tar.gz.sha256"
        local_checksum.write_bytes((self.root / "checksum").read_bytes())
        result = self.run_installer(
            AXIS_INSTALL_ARCHIVE=str(local_archive),
            AXIS_INSTALL_SHA256=str(local_checksum),
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue((self.root / "installed/axis").is_file())

    def test_oversized_checksum_download_fails_closed(self):
        (self.root / "checksum").write_bytes(b"x" * (1024 * 1024 + 1))
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exceeds size limit", result.stdout)

    def test_missing_checksum_sidecar_is_not_reported_as_a_size_limit(self):
        result = self.run_installer(CHECKSUM_HTTP_STATUS="404")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("checksum download failed", result.stdout)
        self.assertIn(
            "https://raw.githubusercontent.com/ROCm/axis/v1.2.3/install.sh",
            result.stdout,
        )
        self.assertNotIn("exceeds size limit", result.stdout)
        self.assertNotIn("Illegal number", result.stdout)
        self.assertFalse((self.root / "installed/axis").exists())

    def test_missing_archive_is_not_reported_as_a_size_limit(self):
        result = self.run_installer(ARCHIVE_HTTP_STATUS="404")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("download failed", result.stdout)
        self.assertNotIn("exceeds size limit", result.stdout)
        self.assertNotIn("Illegal number", result.stdout)
        self.assertFalse((self.root / "installed/axis").exists())

    def test_windows_installer_contains_equivalent_enforcement(self):
        source = (ROOT / "install.ps1").read_text(encoding="utf-8")
        self.assertIn("$PSVersionTable.PSVersion.Major -lt 7", source)
        self.assertIn("requires PowerShell 7 or later (pwsh)", source)
        self.assertNotIn('powershell -c "irm', source)
        self.assertIn("Receive-BoundedFile", source)
        self.assertIn("release verify-asset", source)
        self.assertIn("attestation verify", source)
        self.assertIn("--signer-workflow", source)
        self.assertIn("--deny-self-hosted-runners", source)
        self.assertNotIn("ReadToEndAsync", source)
        self.assertIn("ReadBounded", source)
        self.assertIn("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", source)
        self.assertIn("CREATE_SUSPENDED", source)
        self.assertIn("AssignProcessToJobObject", source)
        self.assertIn("TerminateJobObject", source)
        self.assertIn("Task.WhenAll(stdoutTask, stderrTask)", source)
        self.assertEqual(source.count("FileAccess.Read, 65536, false"), 2)
        self.assertNotIn("FileAccess.Read, 65536, true", source)
        self.assertNotIn("$Process.Kill", source)
        self.assertNotIn("taskkill.exe", source)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        setup = (ROOT / "docs/setup-and-install.md").read_text(encoding="utf-8")
        self.assertIn("PowerShell 7 or later", readme)
        self.assertIn("PowerShell 7 or later", setup)
        self.assertIn("https://aka.ms/powershell-release", setup)
        self.assertIn("has no $archiveName.sha256 sidecar", source)
        self.assertIn("axis/$Tag/install.ps1", source)


@unittest.skipUnless(
    shutil.which("pwsh") and sys.platform == "win32",
    "PowerShell 7 on Windows is unavailable",
)
class PowerShellInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        source = (ROOT / "install.ps1").read_text(encoding="utf-8")
        source, invocation = source.rsplit("\nInstall-AXIS", 1)
        self.assertEqual(invocation.strip(), "")
        self.fake_gh = self.root / "fake_gh.py"
        self.fake_gh.write_text(
            """import os
from pathlib import Path
import subprocess
import sys
import time

mode = sys.argv[1]
if mode in ('tree', 'orphan'):
    marker = sys.argv[2]
    subprocess.Popen([
        sys.executable,
        '-c',
        \"import time; from pathlib import Path; time.sleep(3); \"
        f\"Path({marker!r}).write_text('survived'); time.sleep(30)\",
    ], close_fds=False)
    if mode == 'orphan':
        raise SystemExit(0)
    mode = 'stdout'
descriptor = 1 if mode == 'stdout' else 2
while True:
    os.write(descriptor, b'x' * 65536)
""",
            encoding="utf-8",
        )
        harness = (
            source
            + r"""
$script:GhPath = $env:PYTHON_EXE
$script:GhCommandTimeoutMilliseconds = 2000
try {
    if ($env:GH_TEST_MODE -in @("tree", "orphan")) {
        Invoke-Gh $env:FAKE_GH $env:GH_TEST_MODE $env:SURVIVAL_MARKER | Out-Null
    } else {
        Invoke-Gh $env:FAKE_GH $env:GH_TEST_MODE | Out-Null
    }
    exit 90
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 42
}
"""
        )
        self.harness = self.root / "invoke-gh-test.ps1"
        self.harness.write_text(harness, encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def run_probe(self, mode: str) -> subprocess.CompletedProcess[str]:
        marker = self.root / "descendant-survived"
        environment = os.environ | {
            "PYTHON_EXE": sys.executable,
            "FAKE_GH": str(self.fake_gh),
            "GH_TEST_MODE": mode,
            "SURVIVAL_MARKER": str(marker),
        }
        return subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-File", str(self.harness)],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

    def test_caps_stdout_and_stderr_while_process_is_running(self):
        for mode in ("stdout", "stderr"):
            with self.subTest(mode=mode):
                result = self.run_probe(mode)
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertIn("output exceeds size limit", result.stderr)

    def test_output_cap_kills_the_process_tree_immediately(self):
        marker = self.root / "descendant-survived"
        result = self.run_probe("tree")
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertIn("output exceeds size limit", result.stderr)
        time.sleep(4)
        self.assertFalse(marker.exists(), "gh descendant survived output rejection")

    def test_timeout_kills_descendant_after_root_exits_with_inherited_handles(self):
        marker = self.root / "descendant-survived"
        result = self.run_probe("orphan")
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertIn("timed out", result.stderr)
        time.sleep(4)
        self.assertFalse(
            marker.exists(), "gh descendant survived root exit and timeout"
        )


if __name__ == "__main__":
    unittest.main()
