# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
import xml.etree.ElementTree as ET
import zipfile

import generate_third_party_notices as notices


class Response:
    def __init__(self, data: bytes, status: int = 200):
        self.data = data
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit: int) -> bytes:
        return self.data


def metadata_fixture(dep_kinds=None):
    dep_kinds = [{"kind": None, "target": None}] if dep_kinds is None else dep_kinds
    return {
        "workspace_members": ["root"],
        "packages": [
            {"id": "root", "name": "root", "source": None},
            {
                "id": "dep",
                "name": "dep",
                "version": "1.0.0",
                "source": notices.CRATES_IO_SOURCE,
                "license": "MIT",
            },
        ],
        "resolve": {
            "nodes": [
                {"id": "root", "deps": [{"pkg": "dep", "dep_kinds": dep_kinds}]},
                {"id": "dep", "deps": []},
            ]
        },
    }


class NoticeGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write_lock(self, text: str) -> Path:
        path = self.root / "Cargo.lock"
        path.write_text(text, encoding="utf-8")
        return path

    def write_webview_lock(
        self, record: dict, *, additions: dict | None = None
    ) -> Path:
        additions = additions or {}
        path = self.root / "packages.lock.json"
        dependencies = {
            target: {notices.WEBVIEW_PACKAGE: record.copy(), **additions}
            for target in notices.WEBVIEW_TARGETS
        }
        path.write_text(
            json.dumps({"version": 1, "dependencies": dependencies}),
            encoding="utf-8",
        )
        return path

    def crate_archive(self, name="dep", version="1.0.0", files=None) -> Path:
        files = {"LICENSE": b"Exact license\n"} if files is None else files
        archive = self.root / f"{name}-{version}.crate"
        with tarfile.open(archive, "w:gz") as package:
            for relative, data in files.items():
                member = tarfile.TarInfo(f"{name}-{version}/{relative}")
                member.size = len(data)
                package.addfile(member, io.BytesIO(data))
        return archive

    def test_parse_cargo_lock_accepts_registry_and_skips_path_and_git_without_checksum(
        self,
    ):
        checksum = "1" * 64
        lock = self.write_lock(
            "version = 4\n"
            '[[package]]\nname = "local"\nversion = "1.0.0"\n'
            '[[package]]\nname = "git"\nversion = "1.0.0"\nsource = "git+https://example.test"\n'
            '[[package]]\nname = "dep"\nversion = "1.0.0"\n'
            f'source = "{notices.CRATES_IO_SOURCE}"\nchecksum = "{checksum}"\n'
        )
        self.assertEqual(
            notices.parse_cargo_lock(lock),
            {("dep", "1.0.0", notices.CRATES_IO_SOURCE): checksum},
        )

    def test_parse_cargo_lock_rejects_bad_version_checksum_duplicate_and_empty(self):
        cases = [
            ("version = 2\n", "unsupported"),
            (
                'version = 4\n[[package]]\nname="dep"\nversion="1"\nsource="registry+x"\nchecksum="bad"\n',
                "invalid checksum",
            ),
            (
                "version = 4\n"
                + "".join(
                    '[[package]]\nname="dep"\nversion="1"\nsource="registry+x"\nchecksum="'
                    + "1" * 64
                    + '"\n'
                    for _ in range(2)
                ),
                "duplicate",
            ),
            ('version = 4\n[[package]]\nname="local"\nversion="1"\n', "no external"),
        ]
        for text, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(notices.NoticeError, message):
                    notices.parse_cargo_lock(self.write_lock(text))

    def test_production_closure_includes_normal_and_build_but_not_dev(self):
        for kind, included in [(None, True), ("build", True), ("dev", False)]:
            with self.subTest(kind=kind):
                closure = notices.production_closure(
                    metadata_fixture([{"kind": kind, "target": None}])
                )
                self.assertEqual("dep" in closure, included)

    def test_production_closure_rejects_missing_ambiguous_and_malformed_graphs(self):
        with self.assertRaisesRegex(notices.NoticeError, "no root"):
            notices.production_closure(metadata_fixture(), root_package="missing")
        ambiguous = metadata_fixture()
        ambiguous["packages"].append({"id": "second", "name": "root", "source": None})
        with self.assertRaisesRegex(notices.NoticeError, "ambiguous"):
            notices.production_closure(ambiguous, root_package="root")
        malformed = metadata_fixture()
        malformed["resolve"]["nodes"][0]["deps"][0]["dep_kinds"] = None
        with self.assertRaisesRegex(notices.NoticeError, "malformed"):
            notices.production_closure(malformed)

    def test_validate_package_accepts_expression_or_declared_license_file(self):
        package = metadata_fixture()["packages"][1]
        self.assertEqual(notices.validate_package(package)[3], "MIT")
        package["license"] = None
        package["license_file"] = "LICENSE"
        self.assertEqual(notices.validate_package(package)[3], "License file: LICENSE")

    def test_validate_package_rejects_missing_unsafe_and_non_crates_io_metadata(self):
        package = metadata_fixture()["packages"][1]
        for update, message in [
            ({"license": None}, "no declared"),
            ({"name": "bad/name"}, "unsafe Cargo package name"),
            ({"version": "1\n2"}, "unsafe Cargo package version"),
            ({"license": "MIT\nApache"}, "unsafe Cargo license"),
            (
                {"source": "git+https://example.test"},
                "unsupported Cargo package source",
            ),
        ]:
            with self.subTest(update=update):
                candidate = package | update
                with self.assertRaisesRegex(notices.NoticeError, message):
                    notices.validate_package(candidate)
        candidate = package | {"license": None, "license_file": "../LICENSE"}
        with self.assertRaisesRegex(notices.NoticeError, "unsafe Cargo license file"):
            notices.validate_package(candidate)

    def test_locate_crate_archive_requires_lockfile_checksum(self):
        cargo_home = self.root / "cargo"
        cache = cargo_home / "registry/cache/index"
        cache.mkdir(parents=True)
        archive = self.crate_archive()
        target = cache / archive.name
        target.write_bytes(archive.read_bytes())
        checksum = hashlib.sha256(target.read_bytes()).hexdigest()
        with notices.locate_crate_archive(
            cargo_home, "dep", "1.0.0", checksum
        ) as authenticated:
            self.assertIsInstance(authenticated.name, int)
            self.assertEqual(authenticated.read(), target.read_bytes())
            authenticated.seek(0)
            self.assertEqual(
                notices.legal_files_from_crate(authenticated, "dep", "1.0.0"),
                [("LICENSE", "Exact license\n")],
            )
            with self.assertRaises(OSError):
                os.write(authenticated.fileno(), b"replacement")
        with self.assertRaisesRegex(notices.NoticeError, "checksum-verified"):
            notices.locate_crate_archive(
                cargo_home,
                "dep",
                "1.0.0",
                "0" * 64,
            )

    def test_sealed_crate_descriptor_is_immune_to_post_authentication_replacement(self):
        cargo_home = self.root / "cargo"
        cache = cargo_home / "registry/cache/index"
        cache.mkdir(parents=True)
        original = self.crate_archive(files={"LICENSE": b"Authenticated\n"})
        candidate = cache / original.name
        candidate.write_bytes(original.read_bytes())
        checksum = hashlib.sha256(candidate.read_bytes()).hexdigest()
        with notices.locate_crate_archive(
            cargo_home, "dep", "1.0.0", checksum
        ) as authenticated:
            descriptor_path = Path(f"/proc/self/fd/{authenticated.fileno()}")
            self.assertIn("memfd:axis-crate-dep-1.0.0", os.readlink(descriptor_path))

            replacement = self.crate_archive(files={"LICENSE": b"Replacement\n"})
            candidate.unlink()
            candidate.write_bytes(replacement.read_bytes())
            self.assertEqual(
                notices.legal_files_from_crate(authenticated, "dep", "1.0.0"),
                [("LICENSE", "Authenticated\n")],
            )

    def test_crate_reader_includes_all_nested_legal_files_in_sorted_order(self):
        archive = self.crate_archive(
            files={
                "third_party/NOTICE.txt": b"Notice\n",
                "LICENSE-MIT": b"MIT\n",
                "UNLICENSE": b"Unlicense\n",
                "LICENSES/Apache-2.0.txt": b"Apache\n",
                "src/licenses/not-project-license": b"ignored\n",
                "src/not-legal.txt": b"ignored\n",
            }
        )
        self.assertEqual(
            notices.legal_files_from_crate(archive, "dep", "1.0.0"),
            [
                ("LICENSE-MIT", "MIT\n"),
                ("LICENSES/Apache-2.0.txt", "Apache\n"),
                ("UNLICENSE", "Unlicense\n"),
                ("third_party/NOTICE.txt", "Notice\n"),
            ],
        )

    def test_legal_text_normalizes_line_endings_and_trailing_whitespace(self):
        self.assertEqual(
            notices.decode_legal_text(
                b"First line  \r\n\t \r\nSecond line\t\rThird line  ",
                "fixture",
            ),
            "First line\n\nSecond line\nThird line",
        )

    def test_crate_reader_rejects_invalid_archive_and_legal_text(self):
        invalid = self.root / "bad.crate"
        invalid.write_bytes(b"not a tar")
        with self.assertRaisesRegex(notices.NoticeError, "invalid crate"):
            notices.legal_files_from_crate(invalid, "dep", "1.0.0")
        archive = self.crate_archive(files={"LICENSE": b"bad\0text"})
        with self.assertRaisesRegex(notices.NoticeError, "invalid legal text"):
            notices.legal_files_from_crate(archive, "dep", "1.0.0")
        archive = self.crate_archive(files={"LICENSE": b"\xff"})
        with self.assertRaisesRegex(notices.NoticeError, "not UTF-8"):
            notices.legal_files_from_crate(archive, "dep", "1.0.0")

    def test_crate_reader_rejects_a_traversing_legal_file_path(self):
        archive = self.crate_archive(files={"../LICENSE": b"text"})
        with self.assertRaisesRegex(notices.NoticeError, "unsafe crate archive member"):
            notices.legal_files_from_crate(archive, "dep", "1.0.0")

    def test_crate_reader_enforces_compressed_member_count_member_and_total_limits(
        self,
    ):
        archive = self.crate_archive(
            files={"LICENSE": b"license", "src/lib.rs": b"source"}
        )
        cases = [
            ("MAX_CRATE_ARCHIVE_SIZE", archive.stat().st_size - 1, "compressed size"),
            ("MAX_CRATE_MEMBERS", 1, "too many members"),
            ("MAX_CRATE_MEMBER_SIZE", 5, "member size"),
            ("MAX_CRATE_CONTENT_SIZE", 10, "content exceeds"),
        ]
        for constant, limit, message in cases:
            with self.subTest(constant=constant), mock.patch.object(
                notices, constant, limit
            ), self.assertRaisesRegex(notices.NoticeError, message):
                notices.legal_files_from_crate(archive, "dep", "1.0.0")

    def test_crate_reader_rejects_duplicate_and_non_regular_metadata(self):
        duplicate = self.root / "duplicate.crate"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with tarfile.open(duplicate, "w:gz") as package:
                for data in (b"one", b"two"):
                    member = tarfile.TarInfo("dep-1.0.0/LICENSE")
                    member.size = len(data)
                    package.addfile(member, io.BytesIO(data))
        with self.assertRaisesRegex(notices.NoticeError, "duplicate crate"):
            notices.legal_files_from_crate(duplicate, "dep", "1.0.0")

        symlink = self.root / "symlink.crate"
        with tarfile.open(symlink, "w:gz") as package:
            member = tarfile.TarInfo("dep-1.0.0/LICENSE")
            member.type = tarfile.SYMTYPE
            member.linkname = "target"
            package.addfile(member)
        with self.assertRaisesRegex(notices.NoticeError, "unsupported archive"):
            notices.legal_files_from_crate(symlink, "dep", "1.0.0")

    def test_missing_legal_text_requires_reviewed_override_and_rejects_stale_override(
        self,
    ):
        empty = self.crate_archive(files={"src/lib.rs": b"source"})
        with self.assertRaisesRegex(notices.NoticeError, "no reviewed legal text"):
            notices.resolve_crate_legal_files(empty, "dep", "1.0.0", {})

        override = {("dep", "1.0.0"): ("https://example.test/LICENSE", "1" * 64)}
        with mock.patch.object(
            notices, "UPSTREAM_OVERRIDES", override
        ), mock.patch.object(
            notices, "download_verified", return_value=b"upstream text\n"
        ):
            cache = {}
            self.assertEqual(
                notices.resolve_crate_legal_files(empty, "dep", "1.0.0", cache),
                [
                    (
                        "upstream LICENSE (https://example.test/LICENSE)",
                        "upstream text\n",
                    )
                ],
            )
            with self.assertRaisesRegex(
                notices.NoticeError, "stale legal-text override"
            ):
                notices.resolve_crate_legal_files(
                    self.crate_archive(), "dep", "1.0.0", cache
                )

    def test_declared_cargo_license_file_must_be_included_exactly(self):
        package = {"license_file": "licenses/PROJECT"}
        notices.verify_declared_license_file(
            package, [("licenses/PROJECT", "text")], "dep", "1.0.0"
        )
        with self.assertRaisesRegex(notices.NoticeError, "absent from notices"):
            notices.verify_declared_license_file(
                package, [("LICENSE", "different")], "dep", "1.0.0"
            )

    def test_download_verified_enforces_transport_size_status_and_digest(self):
        data = b"reviewed"
        digest = hashlib.sha256(data).hexdigest()
        with mock.patch.object(
            notices.urllib.request, "urlopen", return_value=Response(data)
        ):
            self.assertEqual(
                notices.download_verified("https://example.test/LICENSE", digest), data
            )
        for url, expected, response, message in [
            ("http://example.test", digest, Response(data), "HTTPS"),
            ("https://example.test", "bad", Response(data), "lowercase SHA"),
            ("https://example.test", digest, Response(data, 404), "HTTP 404"),
            ("https://example.test", "0" * 64, Response(data), "SHA-256 mismatch"),
            (
                "https://example.test",
                hashlib.sha256(b"x" * (64 * 1024 * 1024 + 1)).hexdigest(),
                Response(b"x" * (64 * 1024 * 1024 + 1)),
                "size limit",
            ),
        ]:
            with self.subTest(message=message), mock.patch.object(
                notices.urllib.request, "urlopen", return_value=response
            ):
                with self.assertRaisesRegex(notices.NoticeError, message):
                    notices.download_verified(url, expected)

    def test_subprocess_timeout_terminates_without_network(self):
        with self.assertRaisesRegex(notices.NoticeError, "timed out"):
            notices.run(
                [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.05
            )

    def test_subprocess_errors_and_output_are_bounded(self):
        with mock.patch.object(notices, "MAX_COMMAND_ERROR_SIZE", 32):
            with self.assertRaisesRegex(notices.NoticeError, "exceeds 32") as error:
                notices.run(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.stderr.write('x' * 100); sys.exit(2)",
                    ],
                    timeout=5,
                )
            self.assertLess(len(str(error.exception)), 256)
        with mock.patch.object(notices, "MAX_COMMAND_OUTPUT_SIZE", 32):
            with self.assertRaisesRegex(notices.NoticeError, "stdout exceeds 32"):
                notices.run([sys.executable, "-c", "print('x' * 100)"], timeout=5)

    def test_checked_in_webview_release_and_runtime_targets_are_consistent(self):
        root = Path(__file__).resolve().parent.parent
        project_root = root / "gui/windows/AXIS"
        project = ET.parse(project_root / "AXIS.csproj").getroot()
        reference = project.find(
            f".//PackageReference[@Include='{notices.WEBVIEW_PACKAGE}']"
        )
        self.assertIsNotNone(reference)
        self.assertEqual(reference.get("Version"), notices.WEBVIEW_VERSION)
        self.assertEqual(project.findtext(".//RuntimeIdentifiers"), "win-x64")
        lock = json.loads((project_root / "packages.lock.json").read_text())
        self.assertEqual(set(lock["dependencies"]), notices.WEBVIEW_TARGETS)
        expected = {
            "type": "Direct",
            "requested": f"[{notices.WEBVIEW_VERSION}, )",
            "resolved": notices.WEBVIEW_VERSION,
            "contentHash": notices.WEBVIEW_CONTENT_HASH,
        }
        for target in notices.WEBVIEW_TARGETS:
            with self.subTest(target=target):
                self.assertEqual(
                    lock["dependencies"][target][notices.WEBVIEW_PACKAGE], expected
                )

    def test_webview_requires_exact_lock_records_and_exact_legal_files(self):
        license_text = b"license  \r\n\r\nterms\t\r\n"
        notice_text = b"notice\t\r\n"
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("LICENSE.txt", license_text)
            package.writestr("NOTICE.txt", notice_text)
        record = {
            "type": "Direct",
            "requested": f"[{notices.WEBVIEW_VERSION}, )",
            "resolved": notices.WEBVIEW_VERSION,
            "contentHash": notices.WEBVIEW_CONTENT_HASH,
        }
        lock = self.write_webview_lock(record)
        hashes = {
            "LICENSE.txt": hashlib.sha256(license_text).hexdigest(),
            "NOTICE.txt": hashlib.sha256(notice_text).hexdigest(),
        }
        with mock.patch.object(
            notices, "download_verified", return_value=archive.getvalue()
        ), mock.patch.object(notices, "WEBVIEW_FILE_HASHES", hashes):
            self.assertEqual(
                notices.webview_legal_files(lock),
                [
                    ("LICENSE.txt", "license\n\nterms\n"),
                    ("NOTICE.txt", "notice\n"),
                ],
            )
        record["resolved"] = "0.0.0"
        lock = self.write_webview_lock(record)
        with self.assertRaisesRegex(notices.NoticeError, "does not match reviewed"):
            notices.webview_legal_files(lock)

    def test_webview_rejects_missing_duplicate_tampered_and_invalid_archives(self):
        record = {
            "type": "Direct",
            "requested": f"[{notices.WEBVIEW_VERSION}, )",
            "resolved": notices.WEBVIEW_VERSION,
            "contentHash": notices.WEBVIEW_CONTENT_HASH,
        }
        lock = self.write_webview_lock(record)
        cases = []
        for entries in [
            [("LICENSE.txt", b"license")],
            [
                ("LICENSE.txt", b"license"),
                ("LICENSE.txt", b"again"),
                ("NOTICE.txt", b"notice"),
            ],
            [("LICENSE.txt", b"tampered"), ("NOTICE.txt", b"notice")],
        ]:
            output = io.BytesIO()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(output, "w") as package:
                    for name, data in entries:
                        package.writestr(name, data)
            cases.append(output.getvalue())
        cases.append(b"not a zip")
        hashes = {
            "LICENSE.txt": hashlib.sha256(b"license").hexdigest(),
            "NOTICE.txt": hashlib.sha256(b"notice").hexdigest(),
        }
        for archive in cases:
            with self.subTest(size=len(archive)), mock.patch.object(
                notices, "download_verified", return_value=archive
            ), mock.patch.object(notices, "WEBVIEW_FILE_HASHES", hashes):
                with self.assertRaises(notices.NoticeError):
                    notices.webview_legal_files(lock)

    def test_nuget_lock_rejects_unknown_direct_and_transitive_packages(self):
        record = {
            "type": "Direct",
            "requested": f"[{notices.WEBVIEW_VERSION}, )",
            "resolved": notices.WEBVIEW_VERSION,
            "contentHash": notices.WEBVIEW_CONTENT_HASH,
        }
        for package_type in ("Direct", "Transitive"):
            lock = self.write_webview_lock(
                record,
                additions={
                    "Unknown.Package": {
                        "type": package_type,
                        "resolved": "1.0.0",
                        "contentHash": "unreviewed",
                    }
                },
            )
            with self.subTest(package_type=package_type), self.assertRaisesRegex(
                notices.NoticeError, "unreviewed package"
            ):
                notices.webview_legal_files(lock)

    def test_nuget_lock_rejects_unknown_duplicate_and_version_drifted_targets(self):
        record = {
            "type": "Direct",
            "requested": f"[{notices.WEBVIEW_VERSION}, )",
            "resolved": notices.WEBVIEW_VERSION,
            "contentHash": notices.WEBVIEW_CONTENT_HASH,
        }
        lock = self.write_webview_lock(record)
        document = json.loads(lock.read_text(encoding="utf-8"))
        document["dependencies"]["unknown-target"] = {notices.WEBVIEW_PACKAGE: record}
        lock.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(notices.NoticeError, "target records"):
            notices.webview_legal_files(lock)

        lock = self.write_webview_lock(record)
        document = json.loads(lock.read_text(encoding="utf-8"))
        document["unreviewed"] = True
        lock.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(notices.NoticeError, "top-level records"):
            notices.webview_legal_files(lock)

        duplicate_target = next(iter(notices.WEBVIEW_TARGETS))
        duplicate_json = (
            '{"version":1,"dependencies":{'
            f'"{duplicate_target}":{{}},"{duplicate_target}":{{}}'
            "}}"
        )
        lock.write_text(duplicate_json, encoding="utf-8")
        with self.assertRaisesRegex(notices.NoticeError, "duplicate JSON key"):
            notices.webview_legal_files(lock)

        duplicate_package_target = next(iter(notices.WEBVIEW_TARGETS))
        other_target = next(iter(notices.WEBVIEW_TARGETS - {duplicate_package_target}))
        duplicate_package_json = (
            '{"version":1,"dependencies":{'
            f'"{duplicate_package_target}":{{'
            f'"{notices.WEBVIEW_PACKAGE}":{{}},'
            f'"{notices.WEBVIEW_PACKAGE}":{{}}}},'
            f'"{other_target}":{{}}'
            "}}"
        )
        lock.write_text(duplicate_package_json, encoding="utf-8")
        with self.assertRaisesRegex(notices.NoticeError, "duplicate JSON key"):
            notices.webview_legal_files(lock)

        lock = self.write_webview_lock(record)
        document = json.loads(lock.read_text(encoding="utf-8"))
        drift_target = next(iter(notices.WEBVIEW_TARGETS))
        document["dependencies"][drift_target][notices.WEBVIEW_PACKAGE][
            "resolved"
        ] = "0.0.0"
        lock.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(notices.NoticeError, "does not match reviewed"):
            notices.webview_legal_files(lock)

    def test_webview_archive_enforces_member_count_member_and_aggregate_limits(self):
        record = {
            "type": "Direct",
            "requested": f"[{notices.WEBVIEW_VERSION}, )",
            "resolved": notices.WEBVIEW_VERSION,
            "contentHash": notices.WEBVIEW_CONTENT_HASH,
        }
        lock = self.write_webview_lock(record)
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as package:
            package.writestr("LICENSE.txt", b"license")
            package.writestr("NOTICE.txt", b"notice")
            package.writestr("highly-compressible.bin", b"0" * 100_000)
        cases = [
            ("MAX_NUGET_MEMBERS", 2, "too many members"),
            ("MAX_NUGET_MEMBER_SIZE", 99_999, "member exceeds"),
            ("MAX_NUGET_CONTENT_SIZE", 100_012, "content exceeds"),
        ]
        for constant, limit, message in cases:
            with self.subTest(constant=constant), mock.patch.object(
                notices, "download_verified", return_value=output.getvalue()
            ), mock.patch.object(notices, constant, limit), self.assertRaisesRegex(
                notices.NoticeError, message
            ):
                notices.webview_legal_files(lock)

    def test_merge_rejects_inconsistent_material_and_combines_contexts(self):
        package = {
            "name": "dep",
            "version": "1",
            "license": "MIT",
            "contexts": {"A"},
            "files": [("LICENSE", "text")],
        }
        merged = notices.merge_cargo_packages(
            [{("dep", "1"): package}, {("dep", "1"): package | {"contexts": {"B"}}}]
        )
        self.assertEqual(merged[0]["contexts"], {"A", "B"})
        with self.assertRaisesRegex(notices.NoticeError, "inconsistent"):
            notices.merge_cargo_packages(
                [
                    {("dep", "1"): package},
                    {("dep", "1"): package | {"license": "Apache-2.0"}},
                ]
            )

    def test_render_maps_packages_to_exact_content_hash_catalog(self):
        package = {
            "name": "dep",
            "version": "1",
            "license": "MIT",
            "contexts": {"AXIS"},
            "files": [("LICENSE", "exact text  \r\n\r\nterms\t\r\n")],
        }
        rendered = notices.render_distribution_section(
            "MXC text\n",
            [package],
            [("LICENSE.txt", "webview license\n"), ("NOTICE.txt", "notice\n")],
        )
        digest = hashlib.sha256(b"exact text\n\nterms\n").hexdigest()
        self.assertIn(f"`LICENSE`: SHA-256 `{digest}`", rendered)
        self.assertEqual(rendered.count("exact text\n\nterms\n"), 1)
        self.assertNotIn("\r", rendered)
        self.assertFalse(
            any(line.endswith((" ", "\t")) for line in rendered.split("\n"))
        )
        self.assertIn(notices.DIST_BEGIN, rendered)
        self.assertIn(notices.DIST_END, rendered)

    def test_compose_document_preserves_only_the_single_npm_section(self):
        npm = notices.NPM_BEGIN + b"\nfrontend\n" + notices.NPM_END
        expected = notices.compose_document("distribution", npm)
        self.assertEqual(
            expected,
            b"# Third-Party Notices\n\ndistribution\n\n" + npm + b"\n",
        )
        for malformed in [b"", notices.NPM_BEGIN, notices.NPM_END, npm + npm]:
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(notices.NoticeError, "malformed"):
                    notices.compose_document("distribution", malformed)

    def test_compose_document_normalizes_frontend_notice_lines(self):
        npm = notices.NPM_BEGIN + b"\r\nfrontend  \r\n\r\ntext\t\r\n" + notices.NPM_END
        self.assertEqual(
            notices.compose_document("distribution  \r\n", npm),
            b"# Third-Party Notices\n\ndistribution\n\n\n"
            + notices.NPM_BEGIN
            + b"\nfrontend\n\ntext\n"
            + notices.NPM_END
            + b"\n",
        )

    def test_frontend_generator_output_must_be_exactly_one_generated_section(self):
        npm = notices.NPM_BEGIN + b"\nfrontend\n" + notices.NPM_END
        with mock.patch.object(notices, "run", return_value=(npm + b"\n").decode()):
            self.assertEqual(notices.generate_frontend_section(), npm)
        with mock.patch.object(
            notices, "run", return_value=(b"prefix" + npm + b"\n").decode()
        ):
            with self.assertRaisesRegex(notices.NoticeError, "unexpected output"):
                notices.generate_frontend_section()

    def test_verify_mxc_checkout_requires_commit_clean_tree_and_exact_license(self):
        license_data = b"license  \r\n\r\nterms\t\r\n"
        (self.root / "LICENSE.md").write_bytes(license_data)
        commands = iter([notices.MXC_REF + "\n", ""])
        with mock.patch.object(
            notices, "run", side_effect=lambda *_args, **_kwargs: next(commands)
        ), mock.patch.object(
            notices, "MXC_LICENSE_SHA256", hashlib.sha256(license_data).hexdigest()
        ):
            self.assertEqual(
                notices.verify_mxc_checkout(self.root), "license\n\nterms\n"
            )
        with mock.patch.object(notices, "run", return_value="wrong\n"):
            with self.assertRaisesRegex(notices.NoticeError, "must be at"):
                notices.verify_mxc_checkout(self.root)
        commands = iter([notices.MXC_REF + "\n", " M src/Cargo.toml\n"])
        with mock.patch.object(
            notices, "run", side_effect=lambda *_args, **_kwargs: next(commands)
        ):
            with self.assertRaisesRegex(notices.NoticeError, "tracked modifications"):
                notices.verify_mxc_checkout(self.root)

    def test_generate_rejects_a_release_ref_that_differs_from_notice_inputs(self):
        with self.assertRaisesRegex(notices.NoticeError, "does not match notice ref"):
            notices.generate(expected_mxc_ref="0" * 40)

    def test_check_mode_rejects_staleness_and_write_mode_repairs_it(self):
        path = self.root / "THIRD_PARTY_NOTICES.md"
        path.write_bytes(b"stale")
        with self.assertRaisesRegex(notices.NoticeError, "is stale"):
            notices.apply_generated_document(b"expected", check=True, path=path)
        notices.apply_generated_document(b"expected", check=False, path=path)
        modified = path.stat().st_mtime_ns
        for _ in range(2):
            notices.apply_generated_document(b"expected", check=True, path=path)
        self.assertEqual(path.read_bytes(), b"expected")
        self.assertEqual(path.stat().st_mtime_ns, modified)

    def test_write_mode_creates_an_absent_notice_file(self):
        path = self.root / "THIRD_PARTY_NOTICES.md"
        notices.apply_generated_document(b"expected", check=False, path=path)
        self.assertEqual(path.read_bytes(), b"expected")


if __name__ == "__main__":
    unittest.main()
