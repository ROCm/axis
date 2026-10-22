# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import quote


SOURCE_SHA = "4" * 40
PAYLOADS = (
    "axis-desktop-linux-x86_64.tar.gz",
    "axis-desktop-macos-aarch64.tar.gz",
    "axis-desktop-windows-x86_64.zip",
    "axis-linux-x86_64.tar.gz",
    "axis-macos-aarch64.tar.gz",
    "axis-windows-x86_64.zip",
    "axis_0.3.5-1_amd64.deb",
    "axis-daemon-0.3.5-1.x86_64.rpm",
)


class ReleaseAssetVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.assets = self.root / "assets"
        self.bin = self.root / "bin"
        self.assets.mkdir()
        self.bin.mkdir()
        for payload in PAYLOADS:
            artifact = self.assets / payload
            artifact.write_bytes(f"payload:{payload}\n".encode())
            self.write_sbom(artifact)
        self.write_tools()
        self.environment = os.environ.copy()
        self.environment["PATH"] = f"{self.bin}:{self.environment['PATH']}"

    def tearDown(self):
        self.temporary.cleanup()

    def write_sbom(self, artifact: Path) -> None:
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        root_id = f"SPDXRef-Artifact-{digest}"
        dependency_id = "SPDXRef-Package-test"
        document = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": artifact.name,
            "documentNamespace": (
                "https://github.com/ROCm/axis/sbom/"
                f"{quote(artifact.name, safe='')}/{digest}"
            ),
            "creationInfo": {
                "created": "1980-01-01T00:00:00Z",
                "creators": ["Tool: test"],
            },
            "dataLicense": "CC0-1.0",
            "packages": [
                {
                    "SPDXID": root_id,
                    "name": artifact.name,
                    "versionInfo": SOURCE_SHA,
                    "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                    "filesAnalyzed": False,
                },
                {
                    "SPDXID": dependency_id,
                    "name": "test-dependency",
                    "versionInfo": "1.0.0",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:cargo/test-dependency@1.0.0",
                        }
                    ],
                },
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": root_id,
                },
                {
                    "spdxElementId": root_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": dependency_id,
                },
            ],
        }
        sbom = self.assets / f"{artifact.name}.spdx.json"
        sbom.write_text(json.dumps(document), encoding="utf-8")
        for protected in (artifact, sbom):
            digest = hashlib.sha256(protected.read_bytes()).hexdigest()
            (self.assets / f"{protected.name}.sha256").write_text(
                f"{digest}  {protected.name}\n", encoding="utf-8"
            )

    def write_tools(self) -> None:
        dpkg = self.bin / "dpkg-deb"
        dpkg.write_text(
            "#!/bin/sh\n"
            'case "$*" in\n'
            "  *Recommends*) printf '%s\\n' \"${FAKE_DEB_RECOMMENDS-iptables, slirp4netns}\" ;;\n"
            "  *Depends*) printf '%s\\n' \"${FAKE_DEB_DEPENDS:-libc6, bubblewrap}\" ;;\n"
            "  *) printf 'Package: axis\\nVersion: %s\\nArchitecture: amd64\\n' "
            '"${FAKE_DEB_VERSION:-0.3.5-1}" ;;\n'
            "esac\n",
            encoding="utf-8",
        )
        dpkg.chmod(0o755)
        rpm = self.bin / "rpm"
        rpm.write_text(
            "#!/bin/sh\n"
            'case "$*" in\n'
            "  *--recommends*) printf '%s\\n' \"${FAKE_RPM_RECOMMENDS-iptables\nslirp4netns}\" ;;\n"
            "  *--requires*) printf '%s\\n' \"${FAKE_RPM_REQUIRES:-bubblewrap}\" ;;\n"
            "  *) printf 'axis-daemon %s x86_64' \"${FAKE_RPM_VERSION:-0.3.5-1}\" ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        rpm.chmod(0o755)

    def verify(self, **environment: str) -> subprocess.CompletedProcess[str]:
        merged = self.environment | environment
        return subprocess.run(
            [
                str(Path(__file__).with_name("verify_release_assets.sh")),
                "stable",
                str(self.assets),
                SOURCE_SHA,
            ],
            cwd=Path(__file__).resolve().parent.parent,
            env=merged,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_accepts_exact_names_metadata_sboms_and_checksums(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_debian_and_rpm_version_drift(self):
        for variable in ("FAKE_DEB_VERSION", "FAKE_RPM_VERSION"):
            with self.subTest(variable=variable):
                result = self.verify(**{variable: "9.9.9-1"})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("identity does not match", result.stderr)

    def test_rejects_missing_native_bubblewrap_dependency(self):
        for variable in ("FAKE_DEB_DEPENDS", "FAKE_RPM_REQUIRES"):
            with self.subTest(variable=variable):
                result = self.verify(**{variable: "libc6"})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("does not require bubblewrap", result.stderr)

    def test_requires_exactly_the_recommended_mxc_network_tools(self):
        accepted = {
            "FAKE_DEB_RECOMMENDS": ["iptables, slirp4netns"],
            "FAKE_RPM_RECOMMENDS": ["iptables\nslirp4netns", "slirp4netns\niptables"],
        }
        for variable, values in accepted.items():
            for value in values:
                with self.subTest(variable=variable, value=value):
                    result = self.verify(**{variable: value})
                    self.assertEqual(result.returncode, 0, result.stderr)

        # Missing, renamed, extra, or version-qualified entries do not match
        # what the packaging produces.
        rejected = {
            "FAKE_DEB_RECOMMENDS": [
                "",
                "iptables",
                "slirp4netns, iptables",
                "iptables-nft, slirp4netns",
                "iptables, slirp4netns-extra",
                "iptables (>= 1.8), slirp4netns",
                "iptables, slirp4netns, nftables",
            ],
            "FAKE_RPM_RECOMMENDS": [
                "",
                "iptables",
                "iptables-nft\nslirp4netns",
                "iptables\nslirp4netns-extra",
                "iptables >= 1.8\nslirp4netns",
                "iptables\nslirp4netns\nnftables",
            ],
        }
        package = {"FAKE_DEB_RECOMMENDS": "Debian", "FAKE_RPM_RECOMMENDS": "RPM"}
        for variable, values in rejected.items():
            for value in values:
                with self.subTest(variable=variable, value=value):
                    result = self.verify(**{variable: value})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"{package[variable]} package must recommend exactly",
                        result.stderr,
                    )

    def test_rejects_sbom_artifact_identity_drift(self):
        artifact = self.assets / "axis-linux-x86_64.tar.gz"
        artifact.write_bytes(b"changed")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        (self.assets / f"{artifact.name}.sha256").write_text(
            f"{digest}  {artifact.name}\n", encoding="utf-8"
        )
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SBOM identity does not match", result.stderr)

    def test_rejects_checksum_drift_and_unexpected_assets(self):
        sidecar = self.assets / "axis-linux-x86_64.tar.gz.sha256"
        original = sidecar.read_text()
        sidecar.write_text("invalid\n")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid checksum sidecar", result.stderr)
        sidecar.write_text(original)
        (self.assets / "unexpected.log").write_text("unexpected")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact expected asset set", result.stderr)

    def test_rejects_noncanonical_package_name(self):
        original = self.assets / "axis_0.3.5-1_amd64.deb"
        original.rename(self.assets / "axis_0.3.5_amd64.deb")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected Debian package name", result.stderr)


if __name__ == "__main__":
    unittest.main()
