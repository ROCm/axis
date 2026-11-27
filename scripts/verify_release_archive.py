#!/usr/bin/env python3
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Verify release archives and safely extract native package payloads."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
import tarfile
import tempfile
from typing import BinaryIO
import unicodedata
import zipfile
import zlib

from bounded_subprocess import BoundedProcessError, run_bounded
from bounded_tar import (
    TarLimits,
    TarValidationError,
    open_validated_tar,
    validated_tar_members,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
LEGAL_FILES = ("LICENSE",)
MAX_COMPRESSED_ARCHIVE_SIZE = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_ARCHIVE_MEMBER_SIZE = 128 * 1024 * 1024
MAX_ARCHIVE_CONTENT_SIZE = 512 * 1024 * 1024
MAX_TAR_STREAM_SIZE = 544 * 1024 * 1024
MAX_LEGAL_FILE_SIZE = 8 * 1024 * 1024
MAX_ZIP_DIRECTORY_SIZE = 32 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_PATH_PARTS = 64
MAX_CPIO_NAME_SIZE = MAX_PATH_BYTES + 1
MAX_CPIO_TRAILING_PADDING = 4096
STREAM_CHUNK_SIZE = 64 * 1024
SUPPORTED_ZIP_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
ZIP_LOCAL_HEADER = struct.Struct("<4s5H3L2H")
ZIP_LOCAL_HEADER_SIGNATURE = b"PK\x03\x04"
ZIP_DATA_DESCRIPTOR_FLAG = 0x08
ZIP_UTF8_FLAG = 0x800
SPECIAL_MODE_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
WINDOWS_INVALID_CHARACTERS = set('<>:"|?*')
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{suffix}" for suffix in "123456789\u00b9\u00b2\u00b3"),
    *(f"LPT{suffix}" for suffix in "123456789\u00b9\u00b2\u00b3"),
}
PACKAGE_CONVERTER_TIMEOUT_SECONDS = 120
MAX_PACKAGE_CONVERTER_ERROR_SIZE = 64 * 1024
TRUSTED_PACKAGE_TOOL_DIRS = (Path("/usr/bin"), Path("/bin"))
TRUSTED_PACKAGE_TOOLS = frozenset({"dpkg-deb", "rpm2archive"})


class ArchiveError(RuntimeError):
    """A release or package archive is malformed or exceeds safety limits."""


@dataclass
class ArchiveIndex:
    """Validated archive metadata and the bounded legal material needed by callers."""

    entries: set[str] = field(default_factory=set)
    files: set[str] = field(default_factory=set)
    directories: set[str] = field(default_factory=set)
    required_directories: set[str] = field(default_factory=set)
    legal_files: dict[str, bytes] = field(default_factory=dict)
    member_count: int = 0
    content_size: int = 0
    windows_entries: dict[str, str] = field(default_factory=dict)
    windows_files: set[str] = field(default_factory=set)
    windows_directories: set[str] = field(default_factory=set)
    windows_required_directories: set[str] = field(default_factory=set)
    windows_directory_spellings: dict[str, str] = field(default_factory=dict)

    def add(
        self,
        path: PurePosixPath,
        *,
        is_directory: bool,
        size: int,
        enforce_windows_paths: bool = False,
    ) -> None:
        name = str(path)
        self.member_count += 1
        if self.member_count > MAX_ARCHIVE_MEMBERS:
            raise ArchiveError("archive contains too many members")
        if name in self.entries:
            raise ArchiveError(f"duplicate archive member: {name}")
        self.entries.add(name)

        parents = [str(parent) for parent in path.parents if str(parent) != "."]
        if any(parent in self.files for parent in parents):
            raise ArchiveError(f"archive member has a regular-file parent: {name}")
        if is_directory:
            if name in self.files:
                raise ArchiveError(f"archive path changes type: {name}")
            self.directories.add(name)
        else:
            if name in self.directories or name in self.required_directories:
                raise ArchiveError(f"archive path changes type: {name}")
            if size < 0 or size > MAX_ARCHIVE_MEMBER_SIZE:
                raise ArchiveError(f"archive member exceeds size limit: {name}")
            self.content_size += size
            if self.content_size > MAX_ARCHIVE_CONTENT_SIZE:
                raise ArchiveError("archive content exceeds aggregate size limit")
            self.files.add(name)
        self.required_directories.update(parents)
        if enforce_windows_paths:
            self.add_windows_path(path, is_directory=is_directory)

    def add_windows_path(self, path: PurePosixPath, *, is_directory: bool) -> None:
        canonical = windows_canonical_path(path)
        name = str(path)
        existing = self.windows_entries.get(canonical)
        if existing is not None:
            raise ArchiveError(
                f"Windows archive path alias collision: {existing!r} and {name!r}"
            )
        self.windows_entries[canonical] = name
        canonical_path = PurePosixPath(canonical)
        parents = [
            str(parent) for parent in canonical_path.parents if str(parent) != "."
        ]
        original_prefixes = [
            str(PurePosixPath(*path.parts[:index]))
            for index in range(1, len(path.parts) + int(is_directory))
        ]
        canonical_prefixes = [
            str(PurePosixPath(*canonical_path.parts[:index]))
            for index in range(1, len(canonical_path.parts) + int(is_directory))
        ]
        for canonical_prefix, original_prefix in zip(
            canonical_prefixes, original_prefixes, strict=True
        ):
            existing_spelling = self.windows_directory_spellings.get(canonical_prefix)
            if existing_spelling is not None and existing_spelling != original_prefix:
                raise ArchiveError(
                    "Windows archive path alias collision: "
                    f"{existing_spelling!r} and {original_prefix!r}"
                )
            self.windows_directory_spellings[canonical_prefix] = original_prefix
        if any(parent in self.windows_files for parent in parents):
            raise ArchiveError(f"Windows archive member has a file parent: {name}")
        if is_directory:
            if canonical in self.windows_files:
                raise ArchiveError(f"Windows archive path changes type: {name}")
            self.windows_directories.add(canonical)
        else:
            if (
                canonical in self.windows_directories
                or canonical in self.windows_required_directories
            ):
                raise ArchiveError(f"Windows archive path changes type: {name}")
            self.windows_files.add(canonical)
        self.windows_required_directories.update(parents)


def check_archive_file(archive: Path) -> None:
    try:
        size = archive.stat().st_size
    except OSError as error:
        raise ArchiveError(f"failed to inspect archive: {archive}") from error
    if size <= 0 or size > MAX_COMPRESSED_ARCHIVE_SIZE:
        raise ArchiveError(f"archive compressed size exceeds limit: {archive}")


def normalize_member_name(name: str, root: str | None = None) -> PurePosixPath:
    if not name or "\\" in name or "\0" in name:
        raise ArchiveError(f"unsafe archive member name: {name!r}")
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if not name or name == ".":
        raise ArchiveError(f"unsafe archive member name: {name!r}")
    if len(name.encode("utf-8")) > MAX_PATH_BYTES:
        raise ArchiveError("archive member path exceeds length limit")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ArchiveError(f"unsafe archive member name: {name!r}")
    if len(path.parts) > MAX_PATH_PARTS:
        raise ArchiveError(f"archive member path exceeds depth limit: {name!r}")
    if root is not None and path.parts[0] != root:
        raise ArchiveError(f"archive member escapes expected root {root!r}: {name!r}")
    return path


def windows_canonical_path(path: PurePosixPath) -> str:
    canonical_parts = []
    for part in path.parts:
        if part.rstrip(" .") != part:
            raise ArchiveError(
                f"Windows archive path has trailing dot or space: {path}"
            )
        if any(ord(character) < 0x20 for character in part) or any(
            character in WINDOWS_INVALID_CHARACTERS for character in part
        ):
            raise ArchiveError(
                f"Windows archive path contains an invalid character: {path}"
            )
        normalized = unicodedata.normalize("NFKC", part)
        if (
            not normalized
            or normalized in (".", "..")
            or "/" in normalized
            or "\\" in normalized
            or "\0" in normalized
        ):
            raise ArchiveError(
                f"Windows archive path normalization changes a component: {path}"
            )
        if normalized.rstrip(" .") != normalized:
            raise ArchiveError(
                f"Windows archive path normalization adds a trailing dot or space: {path}"
            )
        if any(ord(character) < 0x20 for character in normalized) or any(
            character in WINDOWS_INVALID_CHARACTERS for character in normalized
        ):
            raise ArchiveError(
                f"Windows archive path normalization adds an invalid character: {path}"
            )
        reserved_stem = normalized.split(".", 1)[0].upper()
        if reserved_stem in WINDOWS_RESERVED_NAMES:
            raise ArchiveError(f"Windows archive path uses a reserved name: {path}")
        canonical_parts.append(normalized.casefold())
    return "/".join(canonical_parts)


def validated_permissions(mode: int, path: str | PurePosixPath) -> int:
    if mode & SPECIAL_MODE_BITS:
        raise ArchiveError(f"archive member has forbidden special mode bits: {path}")
    return mode & 0o777


def validate_member_name(name: str, root: str) -> PurePosixPath:
    """Validate a release archive member under its single expected root."""

    return normalize_member_name(name, root)


def read_stream_bounded(source: BinaryIO, declared_size: int, limit: int) -> bytes:
    if declared_size < 0 or declared_size > limit:
        raise ArchiveError("archive member exceeds bounded read limit")
    remaining = declared_size
    chunks: list[bytes] = []
    while remaining:
        chunk = source.read(min(STREAM_CHUNK_SIZE, remaining))
        if not chunk:
            raise ArchiveError("archive member ended before its declared size")
        chunks.append(chunk)
        remaining -= len(chunk)
    if source.read(1):
        raise ArchiveError("archive member exceeds its declared size")
    return b"".join(chunks)


def drain_stream_bounded(source: BinaryIO, declared_size: int) -> None:
    remaining = declared_size
    while remaining:
        chunk = source.read(min(STREAM_CHUNK_SIZE, remaining))
        if not chunk:
            raise ArchiveError("archive member ended before its declared size")
        remaining -= len(chunk)
    if source.read(1):
        raise ArchiveError("archive member exceeds its declared size")


def copy_stream_bounded(
    source: BinaryIO,
    destination: BinaryIO,
    declared_size: int,
    *,
    calculate_checksum: bool = False,
) -> int:
    remaining = declared_size
    checksum = 0
    while remaining:
        chunk = source.read(min(STREAM_CHUNK_SIZE, remaining))
        if not chunk:
            raise ArchiveError("archive member ended before its declared size")
        destination.write(chunk)
        if calculate_checksum:
            checksum = (checksum + sum(chunk)) & 0xFFFFFFFF
        remaining -= len(chunk)
    return checksum


def legal_member_names(root: str) -> set[str]:
    return {str(PurePosixPath(root) / name) for name in LEGAL_FILES}


def tar_limits() -> TarLimits:
    return TarLimits(
        compressed_size=MAX_COMPRESSED_ARCHIVE_SIZE,
        decompressed_size=MAX_TAR_STREAM_SIZE,
        raw_members=MAX_ARCHIVE_MEMBERS,
        member_size=MAX_ARCHIVE_MEMBER_SIZE,
        content_size=MAX_ARCHIVE_CONTENT_SIZE,
    )


def read_tar(archive: Path, root: str) -> ArchiveIndex:
    result = ArchiveIndex()
    legal_names = legal_member_names(root)
    try:
        with open_validated_tar(archive, tar_limits()) as (package, raw_records):
            for member in validated_tar_members(package, raw_records):
                validated_permissions(member.mode, member.name)
                path = validate_member_name(member.name, root)
                if member.isdir():
                    if member.size != 0:
                        raise ArchiveError(
                            f"archive directory contains declared data: {path}"
                        )
                    result.add(path, is_directory=True, size=0)
                    continue
                if not member.isfile() or member.sparse:
                    raise ArchiveError(f"unsupported archive member type: {path}")
                result.add(path, is_directory=False, size=member.size)
                name = str(path)
                if name in legal_names:
                    source = package.extractfile(member)
                    if source is None:
                        raise ArchiveError(f"unreadable archive member: {path}")
                    with source:
                        result.legal_files[name] = read_stream_bounded(
                            source, member.size, MAX_LEGAL_FILE_SIZE
                        )
    except ArchiveError:
        raise
    except TarValidationError as error:
        raise ArchiveError(f"invalid raw tar archive: {archive}: {error}") from error
    except (OSError, tarfile.TarError, EOFError) as error:
        raise ArchiveError(f"invalid tar archive: {archive}") from error
    return result


def validate_zip_member(member: zipfile.ZipInfo) -> None:
    if member.flag_bits & 0x1:
        raise ArchiveError(f"encrypted zip member is unsupported: {member.filename}")
    if member.compress_type not in SUPPORTED_ZIP_COMPRESSION:
        raise ArchiveError(f"unsupported zip compression for member: {member.filename}")
    if member.flag_bits & ZIP_DATA_DESCRIPTOR_FLAG:
        raise ArchiveError(f"zip data descriptors are unsupported: {member.filename}")
    mode = member.external_attr >> 16
    validated_permissions(mode, member.filename)
    file_type = stat.S_IFMT(mode)
    if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise ArchiveError(f"unsupported archive member type: {member.filename}")
    if member.is_dir() and file_type == stat.S_IFREG:
        raise ArchiveError(
            f"zip directory has regular-file metadata: {member.filename}"
        )
    if not member.is_dir() and file_type == stat.S_IFDIR:
        raise ArchiveError(f"zip file has directory metadata: {member.filename}")
    if member.is_dir() and (member.file_size != 0 or member.compress_size != 0):
        raise ArchiveError(f"zip directory contains declared data: {member.filename}")


def preflight_zip(archive: Path) -> tuple[int, int]:
    """Bound central-directory resources before ZipFile creates member objects."""

    check_archive_file(archive)
    try:
        size = archive.stat().st_size
        search_size = min(size, 22 + 65_535)
        with archive.open("rb") as source:
            source.seek(size - search_size)
            tail = source.read(search_size)
    except OSError as error:
        raise ArchiveError(f"failed to inspect zip archive: {archive}") from error

    signature = b"PK\x05\x06"
    search_end = len(tail)
    fields = None
    end_offset = -1
    while True:
        offset = tail.rfind(signature, 0, search_end)
        if offset < 0:
            break
        if len(tail) - offset >= 22:
            candidate = struct.unpack("<4s4H2LH", tail[offset : offset + 22])
            if offset + 22 + candidate[-1] == len(tail):
                fields = candidate
                end_offset = size - search_size + offset
                break
        search_end = offset
    if fields is None:
        raise ArchiveError(f"invalid zip end-of-central-directory record: {archive}")

    (
        _signature,
        disk_number,
        directory_disk,
        disk_entries,
        total_entries,
        directory_size,
        directory_offset,
        _comment_size,
    ) = fields
    if disk_number != 0 or directory_disk != 0 or disk_entries != total_entries:
        raise ArchiveError("multi-disk zip archives are unsupported")
    if (
        total_entries == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
    ):
        raise ArchiveError("ZIP64 release archives are unsupported")
    if total_entries > MAX_ARCHIVE_MEMBERS:
        raise ArchiveError("archive contains too many members")
    if directory_size > MAX_ZIP_DIRECTORY_SIZE:
        raise ArchiveError("zip central directory exceeds size limit")
    if directory_offset + directory_size != end_offset:
        raise ArchiveError("zip central-directory bounds are inconsistent")
    return directory_offset, total_entries


def read_zip_local_header(
    source: BinaryIO, member: zipfile.ZipInfo, next_offset: int
) -> int:
    try:
        source.seek(member.header_offset)
    except OSError as error:
        raise ArchiveError(
            f"failed to seek to zip member: {member.filename}"
        ) from error
    header = source.read(ZIP_LOCAL_HEADER.size)
    if len(header) != ZIP_LOCAL_HEADER.size:
        raise ArchiveError(f"truncated zip local header: {member.filename}")
    (
        signature,
        _version,
        flags,
        compression,
        _modified_time,
        _modified_date,
        crc,
        compressed_size,
        file_size,
        name_size,
        extra_size,
    ) = ZIP_LOCAL_HEADER.unpack(header)
    if signature != ZIP_LOCAL_HEADER_SIGNATURE:
        raise ArchiveError(f"invalid zip local header: {member.filename}")
    encoded_name = source.read(name_size)
    extra = source.read(extra_size)
    if len(encoded_name) != name_size or len(extra) != extra_size:
        raise ArchiveError(f"truncated zip local metadata: {member.filename}")
    try:
        local_name = encoded_name.decode("utf-8" if flags & ZIP_UTF8_FLAG else "cp437")
    except UnicodeDecodeError as error:
        raise ArchiveError(
            f"invalid zip local member name: {member.filename}"
        ) from error
    if (
        local_name != member.orig_filename
        or flags != member.flag_bits
        or compression != member.compress_type
        or crc != member.CRC
        or compressed_size != member.compress_size
        or file_size != member.file_size
    ):
        raise ArchiveError(
            f"zip local metadata differs from directory: {member.filename}"
        )
    data_offset = source.tell()
    if data_offset + compressed_size != next_offset:
        raise ArchiveError(
            f"zip member stream bounds are inconsistent: {member.filename}"
        )
    return data_offset


def consume_zip_member(
    source: BinaryIO,
    member: zipfile.ZipInfo,
    *,
    aggregate_size: int,
    capture: bool,
) -> tuple[int, bytes | None]:
    actual_size = 0
    crc = 0
    captured: list[bytes] | None = [] if capture else None

    def account(data: bytes) -> None:
        nonlocal actual_size, crc
        if actual_size + len(data) > MAX_ARCHIVE_MEMBER_SIZE:
            raise ArchiveError(f"archive member exceeds size limit: {member.filename}")
        if aggregate_size + actual_size + len(data) > MAX_ARCHIVE_CONTENT_SIZE:
            raise ArchiveError("archive content exceeds aggregate size limit")
        if captured is not None and actual_size + len(data) > MAX_LEGAL_FILE_SIZE:
            raise ArchiveError(
                f"legal archive member exceeds size limit: {member.filename}"
            )
        actual_size += len(data)
        crc = zlib.crc32(data, crc)
        if captured is not None:
            captured.append(data)

    remaining = member.compress_size
    if member.compress_type == zipfile.ZIP_STORED:
        while remaining:
            chunk = source.read(min(STREAM_CHUNK_SIZE, remaining))
            if not chunk:
                raise ArchiveError(f"truncated zip member stream: {member.filename}")
            remaining -= len(chunk)
            account(chunk)
    else:
        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        while remaining:
            compressed = source.read(min(STREAM_CHUNK_SIZE, remaining))
            if not compressed:
                raise ArchiveError(f"truncated zip member stream: {member.filename}")
            remaining -= len(compressed)
            while compressed:
                output = decompressor.decompress(compressed, STREAM_CHUNK_SIZE)
                account(output)
                compressed = decompressor.unconsumed_tail
            if decompressor.eof and (remaining or decompressor.unused_data):
                raise ArchiveError(
                    f"trailing data in zip member stream: {member.filename}"
                )
        if (
            not decompressor.eof
            or decompressor.unused_data
            or decompressor.unconsumed_tail
        ):
            raise ArchiveError(f"incomplete zip member stream: {member.filename}")
        account(decompressor.flush())

    if actual_size != member.file_size:
        raise ArchiveError(
            f"zip member actual size differs from directory: {member.filename}"
        )
    if crc & 0xFFFFFFFF != member.CRC:
        raise ArchiveError(f"zip member CRC mismatch: {member.filename}")
    return actual_size, b"".join(captured) if captured is not None else None


def read_zip(archive: Path, root: str) -> ArchiveIndex:
    directory_offset, total_entries = preflight_zip(archive)
    result = ArchiveIndex()
    legal_names = legal_member_names(root)
    try:
        with zipfile.ZipFile(archive) as package, archive.open("rb") as source:
            members = package.infolist()
            if package.start_dir != directory_offset:
                raise ArchiveError(
                    "zip central-directory offset changed during parsing"
                )
            if len(members) != total_entries:
                raise ArchiveError("zip central-directory member count is inconsistent")
            ordered = sorted(members, key=lambda member: member.header_offset)
            if len({member.header_offset for member in ordered}) != len(ordered):
                raise ArchiveError("duplicate zip local header offset")
            next_offsets = [
                *(member.header_offset for member in ordered[1:]),
                directory_offset,
            ]
            for member, next_offset in zip(ordered, next_offsets, strict=True):
                validate_zip_member(member)
                path = validate_member_name(member.filename, root)
                is_directory = member.is_dir()
                read_zip_local_header(source, member, next_offset)
                name = str(path)
                actual_size, captured = consume_zip_member(
                    source,
                    member,
                    aggregate_size=result.content_size,
                    capture=name in legal_names and not is_directory,
                )
                result.add(
                    path,
                    is_directory=is_directory,
                    size=actual_size,
                    enforce_windows_paths=True,
                )
                if captured is not None:
                    result.legal_files[name] = captured
    except ArchiveError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError, zlib.error) as error:
        raise ArchiveError(f"invalid zip archive: {archive}") from error
    return result


def validate_relative_requirement(relative: str) -> PurePosixPath:
    if not relative or "\\" in relative or "\0" in relative:
        raise ArchiveError(f"invalid required archive path: {relative!r}")
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ArchiveError(f"invalid required archive path: {relative!r}")
    if (
        len(relative.encode("utf-8")) > MAX_PATH_BYTES
        or len(path.parts) > MAX_PATH_PARTS
    ):
        raise ArchiveError(f"invalid required archive path: {relative!r}")
    return path


def verify_archive(
    archive: Path,
    root: str,
    required: list[str],
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    if not root or "/" in root or "\\" in root or root in (".", ".."):
        raise ArchiveError(f"invalid expected archive root: {root!r}")
    if len(root.encode("utf-8")) > MAX_PATH_BYTES:
        raise ArchiveError(f"invalid expected archive root: {root!r}")
    suffixes = archive.suffixes
    if suffixes[-2:] in ([".tar", ".gz"], [".tar", ".xz"]):
        members = read_tar(archive, root)
    elif archive.suffix == ".zip":
        members = read_zip(archive, root)
    else:
        raise ArchiveError(f"unsupported release archive format: {archive}")

    for relative in [*LEGAL_FILES, *required]:
        path = validate_relative_requirement(relative)
        archived_name = str(PurePosixPath(root) / path)
        if archived_name not in members.files:
            raise ArchiveError(f"missing regular archive member: {root}/{relative}")
        if relative in LEGAL_FILES:
            archived = members.legal_files.get(archived_name)
            if archived is None:
                raise ArchiveError(
                    f"legal archive member was not read: {root}/{relative}"
                )
            try:
                expected_path = repository_root / relative
                if expected_path.stat().st_size > MAX_LEGAL_FILE_SIZE:
                    raise ArchiveError(
                        f"repository legal file exceeds size limit: {relative}"
                    )
                expected = expected_path.read_bytes()
            except ArchiveError:
                raise
            except OSError as error:
                raise ArchiveError(
                    f"failed to read repository legal file: {relative}"
                ) from error
            if archived != expected:
                raise ArchiveError(
                    f"archive legal file differs from repository: {relative}"
                )


def destination_path(destination: Path, path: PurePosixPath) -> Path:
    return destination.joinpath(*path.parts)


def prepare_extraction_destination(destination: Path) -> None:
    try:
        destination.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        raise ArchiveError(
            f"failed to create extraction destination: {destination}"
        ) from error


def create_parent_directories(destination: Path, path: PurePosixPath) -> None:
    current = destination
    for part in path.parts[:-1]:
        current /= part
        try:
            current.mkdir(mode=0o755)
        except FileExistsError:
            if not current.is_dir() or current.is_symlink():
                raise ArchiveError(f"unsafe extraction parent: {path}") from None
        except OSError as error:
            raise ArchiveError(f"failed to create extraction parent: {path}") from error


def create_directory(destination: Path, path: PurePosixPath) -> None:
    create_parent_directories(destination, path / "placeholder")
    target = destination_path(destination, path)
    try:
        target.mkdir(mode=0o755)
    except FileExistsError:
        if not target.is_dir() or target.is_symlink():
            raise ArchiveError(f"unsafe extraction directory: {path}") from None
    except OSError as error:
        raise ArchiveError(f"failed to create extraction directory: {path}") from error


def open_extracted_file(destination: Path, path: PurePosixPath) -> BinaryIO:
    create_parent_directories(destination, path)
    target = destination_path(destination, path)
    try:
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        return os.fdopen(descriptor, "wb")
    except OSError as error:
        raise ArchiveError(f"failed to create extracted file: {path}") from error


def safe_extract_tar(archive: Path, destination: Path) -> None:
    prepare_extraction_destination(destination)
    index = ArchiveIndex()
    directory_modes: dict[Path, int] = {}
    try:
        with open_validated_tar(archive, tar_limits()) as (package, raw_records):
            for member in validated_tar_members(package, raw_records):
                permissions = validated_permissions(member.mode, member.name)
                if member.name in (".", "./"):
                    if not member.isdir() or member.size != 0:
                        raise ArchiveError("invalid tar root entry")
                    continue
                path = normalize_member_name(member.name)
                if member.isdir():
                    if member.size != 0:
                        raise ArchiveError(
                            f"archive directory contains declared data: {path}"
                        )
                    index.add(path, is_directory=True, size=0)
                    create_directory(destination, path)
                    directory_modes[destination_path(destination, path)] = permissions
                    continue
                if not member.isfile() or member.sparse:
                    raise ArchiveError(f"unsupported archive member type: {path}")
                index.add(path, is_directory=False, size=member.size)
                source = package.extractfile(member)
                if source is None:
                    raise ArchiveError(f"unreadable archive member: {path}")
                with source, open_extracted_file(destination, path) as target:
                    copy_stream_bounded(source, target, member.size)
                destination_path(destination, path).chmod(permissions)
        for path, mode in sorted(
            directory_modes.items(), key=lambda item: len(item[0].parts), reverse=True
        ):
            path.chmod(mode)
    except ArchiveError:
        raise
    except TarValidationError as error:
        raise ArchiveError(f"invalid raw tar archive: {archive}: {error}") from error
    except (OSError, tarfile.TarError, EOFError) as error:
        raise ArchiveError(f"invalid tar archive: {archive}") from error


def read_exact(source: BinaryIO, size: int, description: str) -> bytes:
    data = source.read(size)
    if len(data) != size:
        raise ArchiveError(f"truncated cpio {description}")
    return data


def parse_hex_field(value: bytes, description: str) -> int:
    try:
        return int(value, 16)
    except ValueError as error:
        raise ArchiveError(f"invalid cpio {description}") from error


def consume_padding(source: BinaryIO, size: int, description: str) -> None:
    padding = (-size) % 4
    if padding and any(read_exact(source, padding, description)):
        raise ArchiveError(f"nonzero cpio {description}")


def safe_extract_newc(archive: Path, destination: Path) -> None:
    check_archive_file(archive)
    prepare_extraction_destination(destination)
    index = ArchiveIndex()
    directory_modes: dict[Path, int] = {}
    trailer_seen = False
    raw_member_count = 0
    try:
        with archive.open("rb") as source:
            while True:
                magic = source.read(6)
                if not magic:
                    break
                if magic not in (b"070701", b"070702"):
                    raise ArchiveError("invalid cpio magic")
                raw_member_count += 1
                if raw_member_count > MAX_ARCHIVE_MEMBERS:
                    raise ArchiveError("archive contains too many members")
                fields = [
                    parse_hex_field(read_exact(source, 8, "header"), "header")
                    for _ in range(13)
                ]
                mode = fields[1]
                link_count = fields[4]
                file_size = fields[6]
                name_size = fields[11]
                expected_checksum = fields[12]
                if name_size <= 1 or name_size > MAX_CPIO_NAME_SIZE:
                    raise ArchiveError("invalid cpio member name size")
                raw_name = read_exact(source, name_size, "member name")
                if raw_name[-1:] != b"\0" or b"\0" in raw_name[:-1]:
                    raise ArchiveError("invalid cpio member name termination")
                try:
                    name = raw_name[:-1].decode("utf-8")
                except UnicodeDecodeError as error:
                    raise ArchiveError("cpio member name is not UTF-8") from error
                consume_padding(source, 110 + name_size, "header padding")
                permissions = validated_permissions(mode, name)
                if name == "TRAILER!!!":
                    if file_size != 0:
                        raise ArchiveError("cpio trailer contains data")
                    trailer_seen = True
                    break

                if name in (".", "./"):
                    if stat.S_IFMT(mode) != stat.S_IFDIR or file_size != 0:
                        raise ArchiveError("invalid cpio root entry")
                    continue
                path = normalize_member_name(name)
                file_type = stat.S_IFMT(mode)
                if file_type == stat.S_IFDIR:
                    if file_size != 0:
                        raise ArchiveError(f"cpio directory contains data: {path}")
                    index.add(path, is_directory=True, size=0)
                    create_directory(destination, path)
                    directory_modes[destination_path(destination, path)] = permissions
                elif file_type == stat.S_IFREG:
                    if link_count != 1:
                        raise ArchiveError(
                            f"cpio hard-linked file is unsupported: {path}"
                        )
                    index.add(path, is_directory=False, size=file_size)
                    with open_extracted_file(destination, path) as target:
                        checksum = copy_stream_bounded(
                            source,
                            target,
                            file_size,
                            calculate_checksum=magic == b"070702",
                        )
                    if magic == b"070702" and checksum != expected_checksum:
                        raise ArchiveError(f"cpio checksum mismatch: {path}")
                    destination_path(destination, path).chmod(permissions)
                else:
                    raise ArchiveError(f"unsupported cpio member type: {path}")
                consume_padding(source, file_size, "file padding")

            if not trailer_seen:
                raise ArchiveError("cpio archive is missing its trailer")
            trailing = source.read(MAX_CPIO_TRAILING_PADDING + 1)
            if len(trailing) > MAX_CPIO_TRAILING_PADDING or any(trailing):
                raise ArchiveError("invalid cpio trailing padding")
            if source.read(1):
                raise ArchiveError("cpio trailing padding exceeds limit")
        for path, mode in sorted(
            directory_modes.items(), key=lambda item: len(item[0].parts), reverse=True
        ):
            path.chmod(mode)
    except ArchiveError:
        raise
    except OSError as error:
        raise ArchiveError(f"invalid cpio archive: {archive}") from error


def extract_converter_output(
    archive_kind: str, destination: Path, command: list[str]
) -> None:
    if archive_kind not in ("tar", "newc") or not command:
        raise ArchiveError("package converter kind and command are required")
    with tempfile.TemporaryDirectory(prefix="axis-package-converter-") as temporary:
        archive = Path(temporary) / f"payload.{archive_kind}"
        try:
            with archive.open("xb") as sink:
                run_bounded(
                    command,
                    timeout=PACKAGE_CONVERTER_TIMEOUT_SECONDS,
                    stdout_limit=MAX_COMPRESSED_ARCHIVE_SIZE,
                    stderr_limit=MAX_PACKAGE_CONVERTER_ERROR_SIZE,
                    stdout_sink=sink,
                    retain_stdout=False,
                )
        except (OSError, BoundedProcessError) as error:
            raise ArchiveError(f"package converter failed: {error}") from error
        if archive_kind == "tar":
            safe_extract_tar(archive, destination)
        else:
            safe_extract_newc(archive, destination)


def trusted_package_tool(name: str) -> Path:
    def has_trusted_parents(path: Path) -> bool:
        for parent in path.parents:
            try:
                metadata = parent.stat()
            except OSError:
                return False
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                return False
        return True

    if name not in TRUSTED_PACKAGE_TOOLS:
        raise ArchiveError(f"unsupported package converter: {name}")
    for directory in TRUSTED_PACKAGE_TOOL_DIRS:
        candidate = directory / name
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or not os.access(resolved, os.X_OK)
            or not has_trusted_parents(candidate)
            or not has_trusted_parents(resolved)
        ):
            continue
        return resolved
    raise ArchiveError(f"trusted system package converter is required: {name}")


def extraction_main(arguments: list[str]) -> int:
    mode = arguments[0]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    parsed = parser.parse_args(arguments[1:])
    if mode == "--extract-tar":
        safe_extract_tar(parsed.archive, parsed.destination)
    else:
        safe_extract_newc(parsed.archive, parsed.destination)
    return 0


def converter_main(arguments: list[str]) -> int:
    mode = arguments[0]
    if len(arguments) < 3:
        raise ArchiveError("package converter command is required")
    archive_kind = "tar" if mode == "--extract-command-tar" else "newc"
    tool = trusted_package_tool(arguments[2])
    command = [str(tool), *arguments[3:]]
    extract_converter_output(archive_kind, Path(arguments[1]), command)
    return 0


def verification_main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("root")
    parser.add_argument("--require", action="append", default=[])
    parsed = parser.parse_args(arguments)
    verify_archive(parsed.archive, parsed.root, parsed.require)
    return 0


def main() -> int:
    try:
        if sys.argv[1:2] in (["--extract-command-tar"], ["--extract-command-newc"]):
            return converter_main(sys.argv[1:])
        if sys.argv[1:2] in (["--extract-tar"], ["--extract-newc"]):
            return extraction_main(sys.argv[1:])
        return verification_main(sys.argv[1:])
    except ArchiveError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
