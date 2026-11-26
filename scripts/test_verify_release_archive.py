# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import binascii
import io
from pathlib import Path
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

import verify_release_archive as verifier


def newc_entry(
    name: str,
    data: bytes = b"",
    *,
    mode: int = stat.S_IFREG | 0o644,
    magic: bytes = b"070701",
    link_count: int = 1,
    checksum: int | None = None,
) -> bytes:
    encoded_name = name.encode("utf-8") + b"\0"
    checksum = sum(data) & 0xFFFFFFFF if checksum is None else checksum
    fields = [
        1,
        mode,
        0,
        0,
        link_count,
        0,
        len(data),
        0,
        0,
        0,
        0,
        len(encoded_name),
        checksum if magic == b"070702" else 0,
    ]
    header = magic + b"".join(f"{value:08x}".encode("ascii") for value in fields)
    name_padding = b"\0" * (-(len(header) + len(encoded_name)) % 4)
    data_padding = b"\0" * (-len(data) % 4)
    return header + encoded_name + name_padding + data + data_padding


def newc_archive(*entries: bytes) -> bytes:
    return b"".join(entries) + newc_entry("TRAILER!!!", mode=0) + b"\0" * 16


class ReleaseArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "LICENSE").write_bytes(b"project license\n")

    def tearDown(self):
        self.temporary.cleanup()

    def members(self):
        return {
            "axis-test/LICENSE": b"project license\n",
            "axis-test/axis": b"binary",
        }

    def write_tar(self, members=None, special=None, name="release.tar.gz"):
        archive = self.root / name
        with tarfile.open(archive, "w:gz") as package:
            for member_name, data in (
                self.members() if members is None else members
            ).items():
                member = tarfile.TarInfo(member_name)
                member.size = len(data)
                member.mode = 0o644
                package.addfile(member, io.BytesIO(data))
            if special is not None:
                package.addfile(special)
        return archive

    def write_zip(self, members=None, special=None, name="release.zip"):
        archive = self.root / name
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as package:
            for member_name, data in (
                self.members() if members is None else members
            ).items():
                package.writestr(member_name, data)
            if special is not None:
                package.writestr(special, b"target")
        return archive

    def forge_zip_declared_size_and_crc(
        self, archive: Path, member_name: str, declared_data: bytes
    ) -> None:
        data = bytearray(archive.read_bytes())
        encoded_name = member_name.encode("utf-8")
        local_name = data.find(encoded_name)
        central_name = data.rfind(encoded_name)
        local_header = data.rfind(b"PK\x03\x04", 0, local_name + 1)
        central_header = data.rfind(b"PK\x01\x02", 0, central_name + 1)
        self.assertGreaterEqual(local_header, 0)
        self.assertGreaterEqual(central_header, 0)
        crc = binascii.crc32(declared_data) & 0xFFFFFFFF
        struct.pack_into("<L", data, local_header + 14, crc)
        struct.pack_into("<L", data, local_header + 22, len(declared_data))
        struct.pack_into("<L", data, central_header + 16, crc)
        struct.pack_into("<L", data, central_header + 24, len(declared_data))
        archive.write_bytes(data)

    def test_accepts_tar_and_zip_with_byte_identical_legal_files(self):
        for archive in (self.write_tar(), self.write_zip()):
            with self.subTest(archive=archive.suffix):
                verifier.verify_archive(archive, "axis-test", ["axis"], self.root)

    def test_rejects_missing_required_member_and_directory_instead_of_file(self):
        members = self.members()
        del members["axis-test/axis"]
        with self.assertRaisesRegex(verifier.ArchiveError, "missing regular"):
            verifier.verify_archive(
                self.write_tar(members), "axis-test", ["axis"], self.root
            )
        members = self.members()
        members.pop("axis-test/LICENSE")
        archive = self.write_tar(members)
        with self.assertRaisesRegex(verifier.ArchiveError, "missing regular"):
            verifier.verify_archive(archive, "axis-test", [], self.root)

    def test_rejects_tampered_legal_material_for_both_formats(self):
        members = self.members()
        members["axis-test/LICENSE"] = b"tampered\n"
        for archive in (self.write_tar(members), self.write_zip(members)):
            with self.subTest(archive=archive.suffix), self.assertRaisesRegex(
                verifier.ArchiveError, "differs from repository"
            ):
                verifier.verify_archive(archive, "axis-test", ["axis"], self.root)

    def test_rejects_path_traversal_absolute_backslash_wrong_root_and_path_limits(self):
        for name in [
            "../escape",
            "/absolute",
            "axis-test/../escape",
            "axis-test\\file",
            "other/file",
            "axis-test/" + "/".join("x" for _ in range(verifier.MAX_PATH_PARTS)),
        ]:
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    verifier.ArchiveError, "unsafe|escapes|depth"
                ):
                    verifier.validate_member_name(name, "axis-test")
        with mock.patch.object(verifier, "MAX_PATH_BYTES", 4), self.assertRaisesRegex(
            verifier.ArchiveError, "length"
        ):
            verifier.validate_member_name("axis-test/file", "axis-test")

    def test_rejects_duplicate_tar_and_zip_members(self):
        tar_path = self.root / "duplicate.tar.gz"
        with tarfile.open(tar_path, "w:gz") as package:
            for _ in range(2):
                member = tarfile.TarInfo("axis-test/LICENSE")
                member.size = 1
                package.addfile(member, io.BytesIO(b"x"))
        with self.assertRaisesRegex(verifier.ArchiveError, "duplicate"):
            verifier.verify_archive(tar_path, "axis-test", [], self.root)

        zip_path = self.root / "duplicate.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(zip_path, "w") as package:
                package.writestr("axis-test/LICENSE", b"x")
                package.writestr("axis-test/LICENSE", b"x")
        with self.assertRaisesRegex(verifier.ArchiveError, "duplicate"):
            verifier.verify_archive(zip_path, "axis-test", [], self.root)

    def test_rejects_windows_path_aliases_and_invalid_components(self):
        cases = [
            ("axis-test/AXIS", "alias collision"),
            ("axis-test/axis.", "trailing dot or space"),
            ("axis-test/axis ", "trailing dot or space"),
            ("axis-test/axis.exe:payload", "invalid character"),
            ("axis-test/CON", "reserved name"),
            ("axis-test/nul.txt", "reserved name"),
        ]
        for index, (name, message) in enumerate(cases):
            members = self.members() | {name: b"shadow"}
            with self.subTest(name=name), self.assertRaisesRegex(
                verifier.ArchiveError, message
            ):
                verifier.verify_archive(
                    self.write_zip(members, name=f"windows-alias-{index}.zip"),
                    "axis-test",
                    ["axis"],
                    self.root,
                )

        members = self.members() | {
            "axis-test/Parent": b"file",
            "axis-test/parent/child": b"child",
        }
        with self.assertRaisesRegex(verifier.ArchiveError, "file parent"):
            verifier.verify_archive(
                self.write_zip(members, name="windows-parent-alias.zip"),
                "axis-test",
                ["axis"],
                self.root,
            )

        members = self.members() | {
            "axis-test/Mixed/one": b"one",
            "axis-test/mixed/two": b"two",
        }
        with self.assertRaisesRegex(verifier.ArchiveError, "alias collision"):
            verifier.verify_archive(
                self.write_zip(members, name="windows-parent-spelling.zip"),
                "axis-test",
                ["axis"],
                self.root,
            )

    def test_rejects_windows_components_changed_by_unicode_normalization(self):
        cases = [
            "axis-test/fullwidth\uff0fslash",
            "axis-test/fullwidth\uff3cbackslash",
            "axis-test/trailing\u2024",
        ]
        for index, name in enumerate(cases):
            members = self.members() | {name: b"confusable"}
            with self.subTest(name=name), self.assertRaisesRegex(
                verifier.ArchiveError, "normalization"
            ):
                verifier.verify_archive(
                    self.write_zip(members, name=f"windows-confusable-{index}.zip"),
                    "axis-test",
                    ["axis"],
                    self.root,
                )

    def test_rejects_special_mode_bits_in_release_archives(self):
        for index, special_bit in enumerate((stat.S_ISUID, stat.S_ISGID, stat.S_ISVTX)):
            tar_member = tarfile.TarInfo(f"axis-test/special-{index}")
            tar_member.mode = 0o644 | special_bit
            with self.subTest(
                format="tar", bit=oct(special_bit)
            ), self.assertRaisesRegex(verifier.ArchiveError, "special mode bits"):
                verifier.verify_archive(
                    self.write_tar(special=tar_member, name=f"special-{index}.tar.gz"),
                    "axis-test",
                    ["axis"],
                    self.root,
                )

            zip_member = zipfile.ZipInfo(f"axis-test/special-{index}")
            zip_member.external_attr = (stat.S_IFREG | 0o644 | special_bit) << 16
            with self.subTest(
                format="zip", bit=oct(special_bit)
            ), self.assertRaisesRegex(verifier.ArchiveError, "special mode bits"):
                verifier.verify_archive(
                    self.write_zip(special=zip_member, name=f"special-{index}.zip"),
                    "axis-test",
                    ["axis"],
                    self.root,
                )

    def test_rejects_tar_and_zip_symlinks(self):
        link = tarfile.TarInfo("axis-test/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "LICENSE"
        with self.assertRaisesRegex(
            verifier.ArchiveError, "unsupported archive member type"
        ):
            verifier.verify_archive(
                self.write_tar(special=link), "axis-test", ["axis"], self.root
            )
        zip_link = zipfile.ZipInfo("axis-test/link")
        zip_link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(
            verifier.ArchiveError, "unsupported archive member type"
        ):
            verifier.verify_archive(
                self.write_zip(special=zip_link),
                "axis-test",
                ["axis"],
                self.root,
            )

    def test_rejects_hierarchy_conflicts(self):
        for archive in (
            self.write_tar(
                {
                    "axis-test/LICENSE": b"x",
                    "axis-test/LICENSE/child": b"x",
                },
                name="hierarchy.tar.gz",
            ),
            self.write_zip(
                {
                    "axis-test/LICENSE": b"x",
                    "axis-test/LICENSE/child": b"x",
                },
                name="hierarchy.zip",
            ),
        ):
            with self.subTest(archive=archive), self.assertRaisesRegex(
                verifier.ArchiveError, "regular-file parent"
            ):
                verifier.verify_archive(archive, "axis-test", [], self.root)

    def test_rejects_invalid_archive_format_root_and_required_paths(self):
        unsupported = self.root / "release.bin"
        unsupported.write_bytes(b"data")
        with self.assertRaisesRegex(
            verifier.ArchiveError, "unsupported release archive format"
        ):
            verifier.verify_archive(unsupported, "axis-test", [], self.root)
        for root in ["", "a/b", "..", "a\\b"]:
            with self.subTest(root=root), self.assertRaisesRegex(
                verifier.ArchiveError, "invalid expected archive root"
            ):
                verifier.verify_archive(self.write_tar(), root, [], self.root)
        for required in ["../axis", "dir\\axis", ""]:
            with self.subTest(required=required), self.assertRaisesRegex(
                verifier.ArchiveError, "invalid required"
            ):
                verifier.verify_archive(
                    self.write_tar(), "axis-test", [required], self.root
                )

    def test_rejects_compressed_member_count_member_and_aggregate_limits(self):
        archives = (self.write_tar(), self.write_zip())
        cases = [
            (
                "MAX_COMPRESSED_ARCHIVE_SIZE",
                lambda path: path.stat().st_size - 1,
                "compressed",
            ),
            ("MAX_ARCHIVE_MEMBERS", lambda _path: 1, "too many"),
            ("MAX_ARCHIVE_MEMBER_SIZE", lambda _path: 5, r"member (?:size )?exceeds"),
            ("MAX_ARCHIVE_CONTENT_SIZE", lambda _path: 10, "aggregate"),
        ]
        for archive in archives:
            for constant, value, message in cases:
                with self.subTest(
                    archive=archive, constant=constant
                ), mock.patch.object(
                    verifier, constant, value(archive)
                ), self.assertRaisesRegex(
                    verifier.ArchiveError, message
                ):
                    verifier.verify_archive(archive, "axis-test", ["axis"], self.root)

    def test_accepts_exact_member_and_aggregate_boundaries(self):
        archive = self.write_zip()
        total = sum(len(value) for value in self.members().values())
        maximum = max(len(value) for value in self.members().values())
        with mock.patch.object(
            verifier, "MAX_COMPRESSED_ARCHIVE_SIZE", archive.stat().st_size
        ), mock.patch.object(
            verifier, "MAX_ARCHIVE_MEMBERS", len(self.members())
        ), mock.patch.object(
            verifier, "MAX_ARCHIVE_MEMBER_SIZE", maximum
        ), mock.patch.object(
            verifier, "MAX_ARCHIVE_CONTENT_SIZE", total
        ):
            verifier.verify_archive(archive, "axis-test", ["axis"], self.root)

    def test_rejects_highly_compressible_zip_bomb_metadata(self):
        archive = self.write_zip({"axis-test/bomb": b"0" * 100_000}, name="bomb.zip")
        self.assertLess(archive.stat().st_size, 100_000)
        with mock.patch.object(
            verifier, "MAX_ARCHIVE_CONTENT_SIZE", 99_999
        ), self.assertRaisesRegex(verifier.ArchiveError, "aggregate"):
            verifier.read_zip(archive, "axis-test")

    def test_rejects_unsupported_zip_compression(self):
        archive = self.root / "bzip2.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_BZIP2) as package:
            package.writestr("axis-test/LICENSE", b"license")
        with self.assertRaisesRegex(
            verifier.ArchiveError, "unsupported zip compression"
        ):
            verifier.read_zip(archive, "axis-test")

    def test_zip_preflight_rejects_zip64_and_oversized_directory_metadata(self):
        archive = self.write_zip()
        data = bytearray(archive.read_bytes())
        end = data.rfind(b"PK\x05\x06")
        self.assertGreaterEqual(end, 0)
        data[end + 8 : end + 12] = b"\xff\xff\xff\xff"
        zip64 = self.root / "zip64.zip"
        zip64.write_bytes(data)
        with self.assertRaisesRegex(verifier.ArchiveError, "ZIP64"):
            verifier.read_zip(zip64, "axis-test")

        with mock.patch.object(
            verifier, "MAX_ZIP_DIRECTORY_SIZE", 1
        ), self.assertRaisesRegex(verifier.ArchiveError, "central directory"):
            verifier.read_zip(archive, "axis-test")

    def test_rejects_tar_and_zip_directories_with_declared_data(self):
        tar_path = self.root / "directory-data.tar.gz"
        with tarfile.open(tar_path, "w:gz") as package:
            directory = tarfile.TarInfo("axis-test/directory")
            directory.type = tarfile.DIRTYPE
            directory.size = 1
            package.addfile(directory, io.BytesIO(b"x"))
        with self.assertRaisesRegex(verifier.ArchiveError, "directory contains"):
            verifier.read_tar(tar_path, "axis-test")

        zip_path = self.root / "directory-data.zip"
        with zipfile.ZipFile(zip_path, "w") as package:
            package.writestr("axis-test/directory/", b"x")
        with self.assertRaisesRegex(verifier.ArchiveError, "directory contains"):
            verifier.read_zip(zip_path, "axis-test")

    def test_rejects_corrupt_tar_and_zip(self):
        for name in ["bad.tar.gz", "bad.zip"]:
            archive = self.root / name
            archive.write_bytes(b"not an archive")
            with self.subTest(name=name), self.assertRaisesRegex(
                verifier.ArchiveError, "invalid"
            ):
                verifier.verify_archive(archive, "axis-test", [], self.root)

    def test_rejects_corrupt_nonlegal_zip_member_stream(self):
        members = self.members()
        members["axis-test/axis"] = b"A" * 4096
        archive = self.write_zip(members, name="corrupt-payload.zip")
        with zipfile.ZipFile(archive) as package:
            member = package.getinfo("axis-test/axis")
            offset = member.header_offset
        data = bytearray(archive.read_bytes())
        name_size, extra_size = struct.unpack_from("<HH", data, offset + 26)
        payload_offset = offset + 30 + name_size + extra_size
        data[payload_offset + 1] ^= 0xFF
        archive.write_bytes(data)

        with self.assertRaisesRegex(verifier.ArchiveError, "invalid zip archive"):
            verifier.verify_archive(archive, "axis-test", ["axis"], self.root)

    def test_rejects_forged_zip_size_and_prefix_crc_after_full_decompression(self):
        members = self.members() | {"axis-test/hidden-bomb": b"A" * 1_000_000}
        archive = self.write_zip(members, name="forged-size-crc.zip")
        self.forge_zip_declared_size_and_crc(archive, "axis-test/hidden-bomb", b"A")

        with self.assertRaisesRegex(verifier.ArchiveError, "actual size differs"):
            verifier.verify_archive(archive, "axis-test", ["axis"], self.root)

        for constant, limit, message in (
            ("MAX_ARCHIVE_MEMBER_SIZE", 100_000, "member exceeds size limit"),
            ("MAX_ARCHIVE_CONTENT_SIZE", 100_000, "aggregate size limit"),
        ):
            with self.subTest(constant=constant), mock.patch.object(
                verifier, constant, limit
            ), self.assertRaisesRegex(verifier.ArchiveError, message):
                verifier.verify_archive(archive, "axis-test", ["axis"], self.root)


class SafeExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def tar_archive(self, entries, name="payload.tar"):
        archive = self.root / name
        with tarfile.open(archive, "w") as package:
            for entry_name, data, mode in entries:
                member = tarfile.TarInfo(entry_name)
                member.size = len(data)
                member.mode = mode
                package.addfile(member, io.BytesIO(data))
        return archive

    def cpio_archive(self, *entries, name="payload.cpio"):
        archive = self.root / name
        archive.write_bytes(newc_archive(*entries))
        return archive

    def test_safely_extracts_tar_and_preserves_file_mode(self):
        destination = self.root / "tar-output"
        archive = self.tar_archive([("./usr/share/doc/axis/LICENSE", b"text", 0o640)])
        verifier.safe_extract_tar(archive, destination)
        extracted = destination / "usr/share/doc/axis/LICENSE"
        self.assertEqual(extracted.read_bytes(), b"text")
        self.assertEqual(stat.S_IMODE(extracted.stat().st_mode), 0o640)

    def test_tar_accepts_only_a_zero_size_directory_root_record(self):
        valid = self.root / "root.tar"
        with tarfile.open(valid, "w") as package:
            root = tarfile.TarInfo(".")
            root.type = tarfile.DIRTYPE
            package.addfile(root)
        verifier.safe_extract_tar(valid, self.root / "valid-root-output")

        invalid = self.root / "invalid-root.tar"
        with tarfile.open(invalid, "w") as package:
            root = tarfile.TarInfo(".")
            root.size = 1
            package.addfile(root, io.BytesIO(b"x"))
        with self.assertRaisesRegex(verifier.ArchiveError, "invalid tar root"):
            verifier.safe_extract_tar(invalid, self.root / "invalid-root-output")

    def test_tar_extraction_rejects_traversal_links_and_limits(self):
        traversal = self.tar_archive([("../escape", b"bad", 0o644)], "bad.tar")
        with self.assertRaisesRegex(verifier.ArchiveError, "unsafe"):
            verifier.safe_extract_tar(traversal, self.root / "traversal-output")

        link_archive = self.root / "link.tar"
        with tarfile.open(link_archive, "w") as package:
            link = tarfile.TarInfo("link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/tmp/target"
            package.addfile(link)
        with self.assertRaisesRegex(verifier.ArchiveError, "unsupported"):
            verifier.safe_extract_tar(link_archive, self.root / "link-output")

        archive = self.tar_archive([("large", b"1234", 0o644)], "large.tar")
        with mock.patch.object(
            verifier, "MAX_ARCHIVE_MEMBER_SIZE", 3
        ), self.assertRaisesRegex(verifier.ArchiveError, "size exceeds limit"):
            verifier.safe_extract_tar(archive, self.root / "large-output")

    def test_extraction_rejects_every_special_mode_bit(self):
        for index, special_bit in enumerate((stat.S_ISUID, stat.S_ISGID, stat.S_ISVTX)):
            tar_archive = self.tar_archive(
                [("file", b"tar", 0o640 | special_bit)],
                name=f"special-{index}.tar",
            )
            with self.subTest(
                format="tar", bit=oct(special_bit)
            ), self.assertRaisesRegex(verifier.ArchiveError, "special mode bits"):
                verifier.safe_extract_tar(
                    tar_archive, self.root / f"special-tar-output-{index}"
                )

            cpio_archive = self.cpio_archive(
                newc_entry(
                    "file",
                    b"cpio",
                    mode=stat.S_IFREG | 0o640 | special_bit,
                ),
                name=f"special-{index}.cpio",
            )
            with self.subTest(
                format="cpio", bit=oct(special_bit)
            ), self.assertRaisesRegex(verifier.ArchiveError, "special mode bits"):
                verifier.safe_extract_newc(
                    cpio_archive, self.root / f"special-cpio-output-{index}"
                )

    def test_safely_extracts_newc_and_validates_crc(self):
        archive = self.cpio_archive(
            newc_entry(
                "./usr/share/doc/axis/LICENSE",
                b"text",
                mode=stat.S_IFREG | 0o640,
                magic=b"070702",
            )
        )
        destination = self.root / "cpio-output"
        verifier.safe_extract_newc(archive, destination)
        extracted = destination / "usr/share/doc/axis/LICENSE"
        self.assertEqual(extracted.read_bytes(), b"text")
        self.assertEqual(stat.S_IMODE(extracted.stat().st_mode), 0o640)

        bad_crc = self.cpio_archive(
            newc_entry("file", b"text", magic=b"070702", checksum=1),
            name="bad-crc.cpio",
        )
        with self.assertRaisesRegex(verifier.ArchiveError, "checksum mismatch"):
            verifier.safe_extract_newc(bad_crc, self.root / "crc-output")

    def test_newc_rejects_traversal_duplicate_hardlink_and_unsupported_type(self):
        cases = [
            (newc_entry("../escape", b"x"), "unsafe"),
            (newc_entry("same", b"x") + newc_entry("same", b"y"), "duplicate"),
            (newc_entry("hard", b"x", link_count=2), "hard-linked"),
            (newc_entry("link", b"target", mode=stat.S_IFLNK | 0o777), "unsupported"),
        ]
        for index, (entry, message) in enumerate(cases):
            archive = self.cpio_archive(entry, name=f"bad-{index}.cpio")
            with self.subTest(message=message), self.assertRaisesRegex(
                verifier.ArchiveError, message
            ):
                verifier.safe_extract_newc(archive, self.root / f"bad-output-{index}")

    def test_newc_rejects_malformed_truncated_missing_trailer_and_padding(self):
        valid = newc_archive(newc_entry("file", b"text"))
        cases = [
            (b"bad", "magic|truncated"),
            (valid[:50], "truncated"),
            (newc_entry("file", b"text"), "missing its trailer"),
            (valid + b"x", "trailing padding"),
        ]
        for index, (data, message) in enumerate(cases):
            archive = self.root / f"malformed-{index}.cpio"
            archive.write_bytes(data)
            with self.subTest(message=message), self.assertRaisesRegex(
                verifier.ArchiveError, message
            ):
                verifier.safe_extract_newc(
                    archive, self.root / f"malformed-output-{index}"
                )

    def test_newc_enforces_member_count_member_and_aggregate_limits(self):
        archive = self.cpio_archive(
            newc_entry("one", b"1234"), newc_entry("two", b"5678")
        )
        cases = [
            ("MAX_ARCHIVE_MEMBERS", 1, "too many"),
            ("MAX_ARCHIVE_MEMBER_SIZE", 3, "size limit"),
            ("MAX_ARCHIVE_CONTENT_SIZE", 7, "aggregate"),
        ]
        for index, (constant, limit, message) in enumerate(cases):
            with self.subTest(constant=constant), mock.patch.object(
                verifier, constant, limit
            ), self.assertRaisesRegex(verifier.ArchiveError, message):
                verifier.safe_extract_newc(archive, self.root / f"limit-output-{index}")

    def test_newc_counts_root_records_toward_member_limit(self):
        root_entry = newc_entry(".", mode=stat.S_IFDIR | 0o755)
        archive = self.cpio_archive(root_entry, root_entry)
        with mock.patch.object(
            verifier, "MAX_ARCHIVE_MEMBERS", 1
        ), self.assertRaisesRegex(verifier.ArchiveError, "too many"):
            verifier.safe_extract_newc(archive, self.root / "root-limit-output")

    def test_converter_streams_bounded_tar_and_newc_payloads(self):
        tar_archive = self.tar_archive([("file", b"tar", 0o640)])
        tar_output = self.root / "converter-tar-output"
        verifier.extract_converter_output(
            "tar",
            tar_output,
            [
                sys.executable,
                "-c",
                f"import sys; sys.stdout.buffer.write(open({str(tar_archive)!r}, 'rb').read())",
            ],
        )
        self.assertEqual((tar_output / "file").read_bytes(), b"tar")

        cpio_archive = self.cpio_archive(newc_entry("file", b"cpio"))
        cpio_output = self.root / "converter-cpio-output"
        verifier.extract_converter_output(
            "newc",
            cpio_output,
            [
                sys.executable,
                "-c",
                f"import sys; sys.stdout.buffer.write(open({str(cpio_archive)!r}, 'rb').read())",
            ],
        )
        self.assertEqual((cpio_output / "file").read_bytes(), b"cpio")

    def test_converter_rejects_bomb_noise_error_and_hang_without_external_tools(self):
        cases = [
            (
                [
                    sys.executable,
                    "-c",
                    "import os\nwhile True: os.write(1, b'x' * 4096)",
                ],
                {"MAX_COMPRESSED_ARCHIVE_SIZE": 1024},
                "stdout exceeds",
            ),
            (
                [
                    sys.executable,
                    "-c",
                    "import os\nwhile True: os.write(2, b'x' * 4096)",
                ],
                {"MAX_PACKAGE_CONVERTER_ERROR_SIZE": 1024},
                "stderr exceeds",
            ),
            ([sys.executable, "-c", "import sys; sys.exit(7)"], {}, "status 7"),
            (
                [sys.executable, "-c", "import time; time.sleep(30)"],
                {"PACKAGE_CONVERTER_TIMEOUT_SECONDS": 0.05},
                "timed out",
            ),
        ]
        for index, (command, constants, message) in enumerate(cases):
            patches = [
                mock.patch.object(verifier, name, value)
                for name, value in constants.items()
            ]
            for patcher in patches:
                patcher.start()
            try:
                with self.subTest(message=message), self.assertRaisesRegex(
                    verifier.ArchiveError, message
                ):
                    verifier.extract_converter_output(
                        "tar", self.root / f"converter-failure-{index}", command
                    )
            finally:
                for patcher in reversed(patches):
                    patcher.stop()

    def test_converter_main_resolves_an_allowlisted_system_tool(self):
        trusted = Path("/trusted/usr/bin/rpm2archive")
        destination = self.root / "converter-output"
        with mock.patch.object(
            verifier, "trusted_package_tool", return_value=trusted
        ) as resolve, mock.patch.object(verifier, "extract_converter_output") as extract:
            self.assertEqual(
                verifier.converter_main(
                    [
                        "--extract-command-tar",
                        str(destination),
                        "rpm2archive",
                        "-n",
                        "package.rpm",
                    ]
                ),
                0,
            )
        resolve.assert_called_once_with("rpm2archive")
        extract.assert_called_once_with(
            "tar", destination, [str(trusted), "-n", "package.rpm"]
        )

    def test_trusted_package_tool_accepts_only_root_owned_nonwritable_paths(self):
        resolved = Path("/trusted/usr/bin/rpm2archive")
        regular = mock.Mock(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        directory = mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=0)

        def metadata(path):
            return regular if path == resolved else directory

        with mock.patch.object(
            verifier, "TRUSTED_PACKAGE_TOOL_DIRS", (Path("/candidate"),)
        ), mock.patch.object(
            Path, "resolve", autospec=True, return_value=resolved
        ), mock.patch.object(
            Path, "stat", autospec=True, side_effect=metadata
        ), mock.patch.object(verifier.os, "access", return_value=True):
            self.assertEqual(verifier.trusted_package_tool("rpm2archive"), resolved)

    def test_trusted_package_tool_rejects_every_unsafe_metadata_case(self):
        resolved = Path("/trusted/usr/bin/rpm2archive")
        safe_file = mock.Mock(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        safe_directory = mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        unsafe_cases = [
            (mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=0), safe_directory, True),
            (mock.Mock(st_mode=stat.S_IFREG | 0o755, st_uid=1000), safe_directory, True),
            (mock.Mock(st_mode=stat.S_IFREG | 0o775, st_uid=0), safe_directory, True),
            (safe_file, safe_directory, False),
            (safe_file, mock.Mock(st_mode=stat.S_IFDIR | 0o777, st_uid=0), True),
            (safe_file, mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=1000), True),
        ]
        for file_metadata, parent_metadata, executable in unsafe_cases:
            with self.subTest(
                file_mode=file_metadata.st_mode,
                file_uid=file_metadata.st_uid,
                parent_mode=parent_metadata.st_mode,
                parent_uid=parent_metadata.st_uid,
                executable=executable,
            ), mock.patch.object(
                verifier, "TRUSTED_PACKAGE_TOOL_DIRS", (Path("/candidate"),)
            ), mock.patch.object(
                Path, "resolve", autospec=True, return_value=resolved
            ), mock.patch.object(
                Path,
                "stat",
                autospec=True,
                side_effect=lambda path: (
                    # B023 is a false positive: the lambda runs inside this
                    # loop iteration, so it sees the current values.
                    file_metadata if path == resolved else parent_metadata  # noqa: B023
                ),
            ), mock.patch.object(verifier.os, "access", return_value=executable):
                with self.assertRaisesRegex(
                    verifier.ArchiveError, "trusted system package converter"
                ):
                    verifier.trusted_package_tool("rpm2archive")

    def test_trusted_package_tool_rejects_unknown_and_missing_tools(self):
        with self.assertRaisesRegex(verifier.ArchiveError, "unsupported"):
            verifier.trusted_package_tool("attacker-controlled")
        with mock.patch.object(
            verifier, "TRUSTED_PACKAGE_TOOL_DIRS", (Path("/missing"),)
        ), mock.patch.object(Path, "resolve", autospec=True, side_effect=OSError):
            with self.assertRaisesRegex(
                verifier.ArchiveError, "trusted system package converter"
            ):
                verifier.trusted_package_tool("rpm2archive")

    def test_trusted_package_tool_rejects_an_unsafe_candidate_symlink_directory(self):
        candidate_directory = Path("/candidate")
        resolved = Path("/trusted/usr/bin/rpm2archive")
        safe_file = mock.Mock(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        safe_directory = mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        unsafe_directory = mock.Mock(st_mode=stat.S_IFDIR | 0o777, st_uid=0)

        def metadata(path):
            if path == resolved:
                return safe_file
            if path == candidate_directory:
                return unsafe_directory
            return safe_directory

        with mock.patch.object(
            verifier, "TRUSTED_PACKAGE_TOOL_DIRS", (candidate_directory,)
        ), mock.patch.object(
            Path, "resolve", autospec=True, return_value=resolved
        ), mock.patch.object(
            Path, "stat", autospec=True, side_effect=metadata
        ), mock.patch.object(verifier.os, "access", return_value=True):
            with self.assertRaisesRegex(
                verifier.ArchiveError, "trusted system package converter"
            ):
                verifier.trusted_package_tool("rpm2archive")


if __name__ == "__main__":
    unittest.main()
