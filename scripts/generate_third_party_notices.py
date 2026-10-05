#!/usr/bin/env python3
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Generate complete distribution notices from authenticated dependency inputs."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile
import tomllib
from typing import BinaryIO, Iterable, Iterator
import urllib.error
import urllib.request
import zipfile

try:
    import fcntl
except ImportError:  # pragma: no cover - generation already requires Linux containment
    fcntl = None

from bounded_subprocess import BoundedProcessError, run_bounded
from bounded_tar import (
    BoundedCompressedReader,
    PrefixedReader,
    SPOOL_MEMORY_LIMIT,
    TarLimits,
    TarRecord,
    TarValidationError,
    copy_plain,
    decompress_gzip,
    decompress_xz,
    open_validated_tar,
    validate_uncompressed_tar,
    validated_tar_members,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
NOTICES_PATH = REPOSITORY_ROOT / "THIRD_PARTY_NOTICES.md"
NPM_BEGIN = b"<!-- BEGIN GENERATED GUI FRONTEND NOTICES -->"
NPM_END = b"<!-- END GENERATED GUI FRONTEND NOTICES -->"
DIST_BEGIN = "<!-- BEGIN GENERATED DISTRIBUTION NOTICES -->"
DIST_END = "<!-- END GENERATED DISTRIBUTION NOTICES -->"

SUPPORTED_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
)
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
MXC_REPOSITORY = "https://github.com/microsoft/mxc"
MXC_REF = "1736b48398c3fe4d1315b2311c0951cc893eb3ae"
MXC_LICENSE_SHA256 = "d9a1b1e30d633d5732ea18e3cba9538d293ebc53e1a9e4e96ab739e0c5c4f1cb"

WEBVIEW_PACKAGE = "Microsoft.Web.WebView2"
WEBVIEW_VERSION = "1.0.4258.31"
WEBVIEW_CONTENT_HASH = (
    "sHVZ2MQrHT1J3q5/6csn0fIP27rzpTO/RRC+wPQDrZheB7T4t2n+"
    "vVbY6SdCKr4WRV9s/gmBM3PPMWWJtoDzMg=="
)
WEBVIEW_URL = (
    "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/"
    "1.0.4258.31/microsoft.web.webview2.1.0.4258.31.nupkg"
)
WEBVIEW_ARCHIVE_SHA256 = (
    "56f7f4b8bf9aee4b8efefbbdd4f67d5f74ebd1b100ed0806da71bf76af481aa9"
)
WEBVIEW_FILE_HASHES = {
    "LICENSE.txt": "0af8f1b807512aae39c2ac1aa4d0cae65cabecb6fd554b8439a5162a0d6eca55",
    "NOTICE.txt": "106423785c5b7eba0a8e61d1837f2132e9c828e20ad530f565d981c1df60dd90",
}

LEGAL_FILE_RE = re.compile(
    r"^(?:licen[cs]e|unlicense|copying|notice|copyright|patents)(?:[-._].*)?$",
    re.IGNORECASE,
)
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
PACKAGE_VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]+$")
MAX_LEGAL_FILE_SIZE = 4 * 1024 * 1024
MAX_CRATE_ARCHIVE_SIZE = 16 * 1024 * 1024
MAX_CRATE_MEMBERS = 4096
MAX_CRATE_MEMBER_SIZE = 16 * 1024 * 1024
MAX_CRATE_CONTENT_SIZE = 160 * 1024 * 1024
MAX_CRATE_TAR_STREAM_SIZE = 168 * 1024 * 1024
MAX_ARCHIVE_PATH_BYTES = 4096
MAX_ARCHIVE_PATH_DEPTH = 64
MAX_NUGET_MEMBERS = 4096
MAX_NUGET_MEMBER_SIZE = 64 * 1024 * 1024
MAX_NUGET_CONTENT_SIZE = 256 * 1024 * 1024
MAX_COMMAND_OUTPUT_SIZE = 64 * 1024 * 1024
MAX_COMMAND_ERROR_SIZE = 64 * 1024
CARGO_TIMEOUT_SECONDS = 300
GIT_TIMEOUT_SECONDS = 120
NODE_TIMEOUT_SECONDS = 60

WEBVIEW_TARGETS = {
    "net8.0-windows7.0",
    "net8.0-windows7.0/win-x64",
}

# These crates declare MIT but omit the workspace-level LICENSE from their
# published archives. Each replacement is tied to the release's source commit.
UPSTREAM_OVERRIDES = {
    ("jsonschema", "0.26.2"): (
        "https://raw.githubusercontent.com/Stranger6667/jsonschema/"
        "b8eef873017a4ce84eb3281965ce7a2791f95e51/LICENSE",
        "0f614c290631feb320f6c0d54c72fc0f85b17ca6d6dc0b5a3383ea7de3e9dc69",
    ),
    ("referencing", "0.26.2"): (
        "https://raw.githubusercontent.com/Stranger6667/jsonschema/"
        "b8eef873017a4ce84eb3281965ce7a2791f95e51/LICENSE",
        "0f614c290631feb320f6c0d54c72fc0f85b17ca6d6dc0b5a3383ea7de3e9dc69",
    ),
    ("uuid-simd", "0.8.0"): (
        "https://raw.githubusercontent.com/Nugine/simd/"
        "d74c030d9dc4f3cae02146d1f497ff62726ef09a/LICENSE",
        "71674605ec4c087fe9eb534e3e4f9e26eb2e4aabcd76a29fd156c6a844d44b3d",
    ),
    ("vsimd", "0.8.0"): (
        "https://raw.githubusercontent.com/Nugine/simd/"
        "d74c030d9dc4f3cae02146d1f497ff62726ef09a/LICENSE",
        "71674605ec4c087fe9eb534e3e4f9e26eb2e4aabcd76a29fd156c6a844d44b3d",
    ),
    ("javascriptcore6", "0.4.0"): (
        "https://gitlab.gnome.org/World/Rust/webkit6-rs/-/raw/"
        "a3b7abac6d52dc82424ad16e70d429d6d6ecab10/LICENSE",
        "44dad7b2e199b0d355adf4437df5c9bb18633d47804242f24dab5a633faba5f7",
    ),
    ("javascriptcore6-sys", "0.4.0"): (
        "https://gitlab.gnome.org/World/Rust/webkit6-rs/-/raw/"
        "a3b7abac6d52dc82424ad16e70d429d6d6ecab10/LICENSE",
        "44dad7b2e199b0d355adf4437df5c9bb18633d47804242f24dab5a633faba5f7",
    ),
    ("webkit6", "0.4.0"): (
        "https://gitlab.gnome.org/World/Rust/webkit6-rs/-/raw/"
        "a3b7abac6d52dc82424ad16e70d429d6d6ecab10/LICENSE",
        "44dad7b2e199b0d355adf4437df5c9bb18633d47804242f24dab5a633faba5f7",
    ),
    ("webkit6-sys", "0.4.0"): (
        "https://gitlab.gnome.org/World/Rust/webkit6-rs/-/raw/"
        "a3b7abac6d52dc82424ad16e70d429d6d6ecab10/LICENSE",
        "44dad7b2e199b0d355adf4437df5c9bb18633d47804242f24dab5a633faba5f7",
    ),
}


class NoticeError(RuntimeError):
    """An authenticated notice input is missing, malformed, or inconsistent."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_notice_text(text: str) -> str:
    """Use stable line endings without changing line or paragraph boundaries."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip(" \t") for line in text.split("\n"))


def run(command: list[str], *, cwd: Path | None = None, timeout: int | float) -> str:
    try:
        result = run_bounded(
            command,
            cwd=cwd,
            timeout=timeout,
            stdout_limit=MAX_COMMAND_OUTPUT_SIZE,
            stderr_limit=MAX_COMMAND_ERROR_SIZE,
        )
    except BoundedProcessError as error:
        raise NoticeError(str(error)) from error
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise NoticeError(f"command returned non-UTF-8 output: {command[0]}") from error


def download_verified(url: str, expected_sha256: str) -> bytes:
    if not url.startswith("https://") or not re.fullmatch(
        r"[0-9a-f]{64}", expected_sha256
    ):
        raise NoticeError("download source must use HTTPS and a lowercase SHA-256")
    request = urllib.request.Request(
        url, headers={"User-Agent": "axis-notice-generator/1"}
    )
    try:
        # The source is restricted to HTTPS above and authenticated by SHA-256 below.
        with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310
            if response.status != 200:
                raise NoticeError(f"download returned HTTP {response.status}: {url}")
            data = response.read(64 * 1024 * 1024 + 1)
    except (OSError, urllib.error.URLError) as error:
        raise NoticeError(
            f"failed to download authenticated notice input: {url}"
        ) from error
    if len(data) > 64 * 1024 * 1024:
        raise NoticeError(f"download exceeds size limit: {url}")
    actual = sha256(data)
    if actual != expected_sha256:
        raise NoticeError(
            f"SHA-256 mismatch for {url}: expected {expected_sha256}, got {actual}"
        )
    return data


def parse_cargo_lock(lockfile: Path) -> dict[tuple[str, str, str], str]:
    try:
        document = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise NoticeError(f"failed to parse Cargo lockfile: {lockfile}") from error
    if document.get("version") not in (3, 4):
        raise NoticeError(f"unsupported Cargo lockfile version: {lockfile}")
    result: dict[tuple[str, str, str], str] = {}
    for package in document.get("package", []):
        source = package.get("source")
        if source is None:
            continue
        name = package.get("name")
        version = package.get("version")
        checksum = package.get("checksum")
        if not all(isinstance(value, str) for value in (name, version, source)):
            raise NoticeError(f"incomplete external package record in {lockfile}")
        if checksum is None:
            continue
        if not isinstance(checksum, str):
            raise NoticeError(f"invalid checksum for {name}@{version} in {lockfile}")
        if not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise NoticeError(f"invalid checksum for {name}@{version} in {lockfile}")
        key = (name, version, source)
        if key in result:
            raise NoticeError(
                f"duplicate package record for {name}@{version} in {lockfile}"
            )
        result[key] = checksum
    if not result:
        raise NoticeError(f"no external package records in {lockfile}")
    return result


def cargo_metadata(manifest: Path, target: str, extra: Iterable[str] = ()) -> dict:
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--manifest-path",
        str(manifest),
        "--filter-platform",
        target,
        *extra,
    ]
    try:
        document = json.loads(run(command, timeout=CARGO_TIMEOUT_SECONDS))
    except json.JSONDecodeError as error:
        raise NoticeError(
            f"cargo metadata returned invalid JSON for {manifest}"
        ) from error
    if not isinstance(document.get("packages"), list) or not isinstance(
        document.get("resolve", {}).get("nodes"), list
    ):
        raise NoticeError(f"cargo metadata omitted the resolved graph for {manifest}")
    return document


def production_closure(
    metadata: dict, root_package: str | None = None
) -> dict[str, dict]:
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    if len(packages) != len(metadata["packages"]) or len(nodes) != len(
        metadata["resolve"]["nodes"]
    ):
        raise NoticeError(
            "cargo metadata contains duplicate package or node identifiers"
        )
    if root_package is None:
        roots = metadata.get("workspace_members")
    else:
        roots = [
            package_id
            for package_id, package in packages.items()
            if package.get("name") == root_package and package.get("source") is None
        ]
    if not isinstance(roots, list) or not roots:
        raise NoticeError(
            f"cargo metadata contains no root package {root_package or 'members'}"
        )
    if root_package is not None and len(roots) != 1:
        raise NoticeError(f"cargo metadata root package is ambiguous: {root_package}")

    visited = set(roots)
    pending = list(roots)
    while pending:
        package_id = pending.pop()
        if package_id not in nodes or package_id not in packages:
            raise NoticeError(f"cargo metadata has an unresolved node: {package_id}")
        for dependency in nodes[package_id].get("deps", []):
            dependency_id = dependency.get("pkg")
            kinds = dependency.get("dep_kinds")
            if not isinstance(kinds, list):
                raise NoticeError(
                    f"cargo metadata has malformed dependency kinds: {package_id}"
                )
            include = any(kind.get("kind") in (None, "build") for kind in kinds)
            if include and dependency_id not in visited:
                if dependency_id not in packages:
                    raise NoticeError(
                        f"cargo metadata references an unknown package: {dependency_id}"
                    )
                visited.add(dependency_id)
                pending.append(dependency_id)
    return {
        package_id: packages[package_id]
        for package_id in visited
        if packages[package_id].get("source") is not None
    }


def validate_package(package: dict) -> tuple[str, str, str, str]:
    values = tuple(package.get(key) for key in ("name", "version", "source"))
    if not all(isinstance(value, str) and value for value in values):
        raise NoticeError("external Cargo package is missing name, version, or source")
    name, version, source = values
    license_expression = package.get("license")
    if not isinstance(license_expression, str) or not license_expression:
        license_file = package.get("license_file")
        if not isinstance(license_file, str) or not license_file:
            raise NoticeError(
                f"external Cargo package has no declared license: {name}@{version}"
            )
        license_path = PurePosixPath(license_file)
        if (
            license_path.is_absolute()
            or ".." in license_path.parts
            or "\\" in license_file
            or "`" in license_file
            or any(ord(character) < 0x20 for character in license_file)
        ):
            raise NoticeError(f"unsafe Cargo license file: {name}@{version}")
        license_expression = f"License file: {license_file}"
    if not PACKAGE_NAME_RE.fullmatch(name):
        raise NoticeError(f"unsafe Cargo package name: {name!r}")
    if not PACKAGE_VERSION_RE.fullmatch(version):
        raise NoticeError(f"unsafe Cargo package version: {name}@{version!r}")
    if any(character in "\r\n\0" for character in license_expression):
        raise NoticeError(f"unsafe Cargo license expression: {name}@{version}")
    if source != CRATES_IO_SOURCE:
        raise NoticeError(
            f"unsupported Cargo package source for {name}@{version}: {source}"
        )
    return name, version, source, license_expression


def locate_crate_archive(
    cargo_home: Path,
    name: str,
    version: str,
    checksum: str,
) -> BinaryIO:
    candidates = sorted(
        (cargo_home / "registry" / "cache").glob(f"*/{name}-{version}.crate")
    )
    authenticated_data: bytes | None = None
    for candidate in candidates:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            with os.fdopen(os.open(candidate, flags), "rb") as source:
                metadata = os.fstat(source.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    continue
                if metadata.st_size <= 0 or metadata.st_size > MAX_CRATE_ARCHIVE_SIZE:
                    continue
                data = source.read(MAX_CRATE_ARCHIVE_SIZE + 1)
        except OSError as error:
            raise NoticeError(f"failed to read crate archive: {candidate}") from error
        if not data or len(data) > MAX_CRATE_ARCHIVE_SIZE:
            continue
        if sha256(data) == checksum:
            if authenticated_data is not None and authenticated_data != data:
                raise NoticeError(
                    f"SHA-256 collision between crate archives: {name}@{version}"
                )
            authenticated_data = data
    if authenticated_data is None:
        raise NoticeError(
            f"checksum-verified crate archive not found: {name}@{version}"
        )
    if (
        fcntl is None
        or not hasattr(os, "memfd_create")
        or not hasattr(os, "MFD_ALLOW_SEALING")
    ):
        raise NoticeError(
            "sealed anonymous files are required for crate authentication"
        )
    descriptor = -1
    try:
        descriptor = os.memfd_create(
            f"axis-crate-{name}-{version}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        )
        offset = 0
        while offset < len(authenticated_data):
            written = os.write(descriptor, authenticated_data[offset:])
            if written <= 0:
                raise OSError("failed to write authenticated crate bytes")
            offset += written
        os.lseek(descriptor, 0, os.SEEK_SET)
        seals = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != seals:
            raise OSError("authenticated crate descriptor was not fully sealed")
        archive = os.fdopen(descriptor, "rb")
        descriptor = -1
    except OSError as error:
        raise NoticeError(
            f"failed to preserve authenticated crate archive: {name}@{version}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return archive


@contextmanager
def open_validated_crate_descriptor(
    source: BinaryIO, label: str, limits: TarLimits
) -> Iterator[tuple[tarfile.TarFile, list[TarRecord]]]:
    try:
        source.seek(0)
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise TarValidationError("crate archive input is not a regular file")
        if metadata.st_size <= 0 or metadata.st_size > limits.compressed_size:
            raise TarValidationError("TAR compressed size exceeds limit")
        spool_limit = max(1, min(SPOOL_MEMORY_LIMIT, limits.decompressed_size))
        with tempfile.SpooledTemporaryFile(max_size=spool_limit, mode="w+b") as spool:
            counted = BoundedCompressedReader(source, limits.compressed_size)
            magic = counted.read(6)
            prefixed = PrefixedReader(magic, counted)
            if magic.startswith(b"\x1f\x8b"):
                decompress_gzip(prefixed, spool, limits.decompressed_size)
            elif magic == b"\xfd7zXZ\x00":
                decompress_xz(prefixed, spool, limits.decompressed_size)
            else:
                copy_plain(prefixed, spool, limits.decompressed_size)
            spool.flush()
            spool.seek(0)
            records = validate_uncompressed_tar(spool, limits)
            spool.seek(0)
            package = tarfile.open(fileobj=spool, mode="r:")
            try:
                yield package, records
            finally:
                package.close()
    except TarValidationError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise TarValidationError(
            f"failed to decode authenticated crate: {label}"
        ) from error


def decode_legal_text(data: bytes, label: str) -> str:
    if not data or len(data) > MAX_LEGAL_FILE_SIZE or b"\0" in data:
        raise NoticeError(f"invalid legal text size or content: {label}")
    try:
        return normalize_notice_text(data.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise NoticeError(f"legal text is not UTF-8: {label}") from error


def read_stream_bounded(stream, declared_size: int, limit: int, label: str) -> bytes:
    if declared_size < 0 or declared_size > limit:
        raise NoticeError(f"declared size exceeds limit: {label}")
    chunks = []
    remaining = declared_size
    while remaining:
        chunk = stream.read(min(64 * 1024, remaining))
        if not chunk:
            raise NoticeError(f"archive member ended before its declared size: {label}")
        chunks.append(chunk)
        remaining -= len(chunk)
    if stream.read(1):
        raise NoticeError(f"archive member exceeds its declared size: {label}")
    return b"".join(chunks)


def validate_crate_member_path(member_name: str, expected_root: str) -> PurePosixPath:
    if (
        not member_name
        or "\\" in member_name
        or "\0" in member_name
        or len(member_name.encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES
    ):
        raise NoticeError(f"unsafe crate archive member path: {member_name!r}")
    path = PurePosixPath(member_name)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or path.parts[0] != expected_root
        or len(path.parts) > MAX_ARCHIVE_PATH_DEPTH
    ):
        raise NoticeError(f"unsafe crate archive member path: {member_name!r}")
    return path


def legal_files_from_crate(
    archive: Path | BinaryIO, name: str, version: str
) -> list[tuple[str, str]]:
    expected_root = f"{name}-{version}"
    try:
        limits = TarLimits(
            compressed_size=MAX_CRATE_ARCHIVE_SIZE,
            decompressed_size=MAX_CRATE_TAR_STREAM_SIZE,
            raw_members=MAX_CRATE_MEMBERS,
            member_size=MAX_CRATE_MEMBER_SIZE,
            content_size=MAX_CRATE_CONTENT_SIZE,
        )
        validated = (
            open_validated_tar(archive, limits)
            if isinstance(archive, Path)
            else open_validated_crate_descriptor(archive, f"{name}@{version}", limits)
        )
        with validated as (crate, raw_records):
            legal_files = []
            seen_paths = set()
            member_count = 0
            total_size = 0
            for member in validated_tar_members(crate, raw_records):
                member_count += 1
                if member_count > MAX_CRATE_MEMBERS:
                    raise NoticeError(
                        f"crate archive has too many members: {name}@{version}"
                    )
                path = validate_crate_member_path(member.name, expected_root)
                normalized = str(path)
                if normalized in seen_paths:
                    raise NoticeError(
                        f"duplicate crate archive member: {name}@{version}/{normalized}"
                    )
                seen_paths.add(normalized)
                if not member.isfile() or member.sparse is not None:
                    raise NoticeError(
                        f"unsupported crate archive member type: {name}@{version}/{normalized}"
                    )
                if member.size < 0 or member.size > MAX_CRATE_MEMBER_SIZE:
                    raise NoticeError(
                        f"crate archive member size exceeds limit: {name}@{version}/{normalized}"
                    )
                total_size += member.size
                if total_size > MAX_CRATE_CONTENT_SIZE:
                    raise NoticeError(
                        f"crate archive content exceeds limit: {name}@{version}"
                    )
                relative_parts = path.parts[1:]
                in_top_level_legal_directory = len(
                    relative_parts
                ) > 1 and relative_parts[0].lower() in ("license", "licenses")
                if LEGAL_FILE_RE.fullmatch(path.name) or in_top_level_legal_directory:
                    source = crate.extractfile(member)
                    if source is None:
                        raise NoticeError(
                            f"failed to read legal file in {name}@{version}: {normalized}"
                        )
                    relative = str(path.relative_to(expected_root))
                    if "`" in relative or any(
                        ord(character) < 0x20 for character in relative
                    ):
                        raise NoticeError(
                            f"unsafe legal file name in {name}@{version}: {relative!r}"
                        )
                    data = read_stream_bounded(
                        source,
                        member.size,
                        MAX_LEGAL_FILE_SIZE,
                        f"{name}@{version}/{relative}",
                    )
                    legal_files.append(
                        (
                            relative,
                            decode_legal_text(data, f"{name}@{version}/{relative}"),
                        )
                    )
            if member_count == 0:
                raise NoticeError(
                    f"crate archive contains no members: {name}@{version}"
                )
            legal_files.sort(key=lambda item: item[0])
            return legal_files
    except TarValidationError as error:
        raise NoticeError(
            f"invalid crate archive for {name}@{version}: {error}"
        ) from error
    except (OSError, tarfile.TarError) as error:
        raise NoticeError(f"invalid crate archive: {archive}") from error


def resolve_crate_legal_files(
    archive: Path | BinaryIO,
    name: str,
    version: str,
    override_cache: dict[str, str],
) -> list[tuple[str, str]]:
    legal_files = legal_files_from_crate(archive, name, version)
    override = UPSTREAM_OVERRIDES.get((name, version))
    if legal_files and override is not None:
        raise NoticeError(f"stale legal-text override for {name}@{version}")
    if legal_files:
        return legal_files
    if override is None:
        raise NoticeError(f"crate contains no reviewed legal text: {name}@{version}")
    url, expected_hash = override
    if url not in override_cache:
        override_cache[url] = decode_legal_text(
            download_verified(url, expected_hash), f"{name}@{version} upstream LICENSE"
        )
    return [(f"upstream LICENSE ({url})", override_cache[url])]


def verify_declared_license_file(
    package: dict, legal_files: list[tuple[str, str]], name: str, version: str
) -> None:
    declared = package.get("license_file")
    if declared is not None and declared not in {label for label, _text in legal_files}:
        raise NoticeError(
            f"declared Cargo license file is absent from notices: "
            f"{name}@{version}/{declared}"
        )


def collect_cargo_packages(
    manifest: Path,
    targets: Iterable[str],
    context: str,
    cargo_home: Path,
    *,
    root_package: str | None = None,
    metadata_extra: Iterable[str] = (),
    override_cache: dict[str, str],
) -> dict[tuple[str, str], dict]:
    run(
        ["cargo", "fetch", "--locked", "--manifest-path", str(manifest)],
        timeout=CARGO_TIMEOUT_SECONDS,
    )
    lock = parse_cargo_lock(manifest.parent / "Cargo.lock")
    closure: dict[str, dict] = {}
    for target in targets:
        closure.update(
            production_closure(
                cargo_metadata(manifest, target, metadata_extra),
                root_package=root_package,
            )
        )
    if not closure:
        raise NoticeError(f"empty production/build dependency closure: {manifest}")

    result = {}
    for package_id in sorted(closure):
        package = closure[package_id]
        name, version, source, license_expression = validate_package(package)
        checksum = lock.get((name, version, source))
        if checksum is None:
            raise NoticeError(
                f"resolved package is absent from lockfile: {name}@{version}"
            )
        with locate_crate_archive(cargo_home, name, version, checksum) as archive:
            legal_files = resolve_crate_legal_files(
                archive, name, version, override_cache
            )
        verify_declared_license_file(package, legal_files, name, version)
        result[(name, version)] = {
            "name": name,
            "version": version,
            "license": license_expression,
            "contexts": {context},
            "files": legal_files,
        }
    return result


def merge_cargo_packages(groups: Iterable[dict[tuple[str, str], dict]]) -> list[dict]:
    merged: dict[tuple[str, str], dict] = {}
    for group in groups:
        for key, package in group.items():
            existing = merged.get(key)
            if existing is None:
                merged[key] = package
            elif (
                existing["license"] != package["license"]
                or existing["files"] != package["files"]
            ):
                raise NoticeError(
                    f"inconsistent Cargo package material: {key[0]}@{key[1]}"
                )
            else:
                existing["contexts"].update(package["contexts"])
    return [merged[key] for key in sorted(merged)]


def verify_mxc_checkout(mxc_dir: Path) -> str:
    if (
        run(
            ["git", "rev-parse", "HEAD"], cwd=mxc_dir, timeout=GIT_TIMEOUT_SECONDS
        ).strip()
        != MXC_REF
    ):
        raise NoticeError(f"MXC checkout must be at {MXC_REF}")
    if run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=mxc_dir,
        timeout=GIT_TIMEOUT_SECONDS,
    ).strip():
        raise NoticeError("MXC checkout has tracked modifications")
    license_path = mxc_dir / "LICENSE.md"
    try:
        license_data = license_path.read_bytes()
    except OSError as error:
        raise NoticeError("MXC checkout is missing LICENSE.md") from error
    if sha256(license_data) != MXC_LICENSE_SHA256:
        raise NoticeError("MXC LICENSE.md does not match the pinned commit")
    return decode_legal_text(license_data, "MXC LICENSE.md")


def prepare_mxc_checkout(provided: Path | None, temporary_root: Path) -> Path:
    if provided is not None:
        return provided.resolve()
    destination = temporary_root / "mxc"
    run(
        [
            "git",
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            MXC_REPOSITORY,
            str(destination),
        ],
        timeout=GIT_TIMEOUT_SECONDS,
    )
    run(
        ["git", "checkout", "--detach", MXC_REF],
        cwd=destination,
        timeout=GIT_TIMEOUT_SECONDS,
    )
    return destination


def parse_json_without_duplicates(text: str, label: str) -> dict:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise NoticeError(f"duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    try:
        document = json.loads(text, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise NoticeError(f"failed to parse JSON: {label}") from error
    if not isinstance(document, dict):
        raise NoticeError(f"expected a JSON object: {label}")
    return document


def validate_zip_member(member: zipfile.ZipInfo, label: str) -> PurePosixPath:
    name = member.filename.rstrip("/")
    if (
        not name
        or "\\" in name
        or "\0" in name
        or len(name.encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES
    ):
        raise NoticeError(f"unsafe zip member path in {label}: {member.filename!r}")
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or ".." in path.parts
        or len(path.parts) > MAX_ARCHIVE_PATH_DEPTH
    ):
        raise NoticeError(f"unsafe zip member path in {label}: {member.filename!r}")
    mode = member.external_attr >> 16
    if mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise NoticeError(f"unsupported zip member type in {label}: {member.filename}")
    if member.flag_bits & 0x1:
        raise NoticeError(f"encrypted zip member in {label}: {member.filename}")
    if member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise NoticeError(f"unsupported zip compression in {label}: {member.filename}")
    return path


def webview_legal_files(lockfile: Path) -> list[tuple[str, str]]:
    try:
        document = parse_json_without_duplicates(
            lockfile.read_text(encoding="utf-8"), str(lockfile)
        )
    except (OSError, UnicodeError) as error:
        raise NoticeError(f"failed to parse NuGet lockfile: {lockfile}") from error
    if document.get("version") != 1 or not isinstance(
        document.get("dependencies"), dict
    ):
        raise NoticeError(
            "expected a NuGet packages.lock.json version 1 dependency map"
        )
    if set(document) != {"version", "dependencies"}:
        raise NoticeError("NuGet lockfile contains unreviewed top-level records")
    if set(document["dependencies"]) != WEBVIEW_TARGETS:
        raise NoticeError(
            "NuGet lockfile contains unreviewed or missing target records"
        )
    records = []
    for target, dependencies in document["dependencies"].items():
        if not isinstance(dependencies, dict):
            raise NoticeError(f"malformed NuGet target dependency map: {target}")
        if set(dependencies) != {WEBVIEW_PACKAGE}:
            raise NoticeError(
                f"NuGet target contains unreviewed package records: {target}"
            )
        records.append(dependencies[WEBVIEW_PACKAGE])
    expected = {
        "type": "Direct",
        "requested": f"[{WEBVIEW_VERSION}, )",
        "resolved": WEBVIEW_VERSION,
        "contentHash": WEBVIEW_CONTENT_HASH,
    }
    if any(record != expected for record in records):
        raise NoticeError(
            f"NuGet lockfile does not match reviewed {WEBVIEW_PACKAGE} metadata"
        )

    archive = download_verified(WEBVIEW_URL, WEBVIEW_ARCHIVE_SHA256)
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            members = package.infolist()
            if len(members) > MAX_NUGET_MEMBERS:
                raise NoticeError("WebView2 NuGet package has too many members")
            seen_paths = set()
            legal_members = {}
            total_size = 0
            for member in members:
                path = validate_zip_member(member, "WebView2 NuGet package")
                normalized = str(path)
                if normalized in seen_paths:
                    raise NoticeError("WebView2 NuGet package contains duplicate paths")
                seen_paths.add(normalized)
                if member.file_size < 0 or member.file_size > MAX_NUGET_MEMBER_SIZE:
                    raise NoticeError(
                        "WebView2 NuGet package member exceeds size limit"
                    )
                total_size += member.file_size
                if total_size > MAX_NUGET_CONTENT_SIZE:
                    raise NoticeError(
                        "WebView2 NuGet package content exceeds size limit"
                    )
                if not member.is_dir() and normalized in WEBVIEW_FILE_HASHES:
                    legal_members[normalized] = member
            legal_names = set(legal_members)
            if legal_names != set(WEBVIEW_FILE_HASHES):
                raise NoticeError(
                    "WebView2 NuGet package is missing required legal files"
                )
            result = []
            for name in WEBVIEW_FILE_HASHES:
                member = legal_members[name]
                with package.open(member) as source:
                    data = read_stream_bounded(
                        source,
                        member.file_size,
                        MAX_LEGAL_FILE_SIZE,
                        f"WebView2 {name}",
                    )
                if sha256(data) != WEBVIEW_FILE_HASHES[name]:
                    raise NoticeError(
                        f"WebView2 {name} does not match the reviewed package"
                    )
                result.append((name, decode_legal_text(data, f"WebView2 {name}")))
            return result
    except zipfile.BadZipFile as error:
        raise NoticeError("WebView2 download is not a valid NuGet package") from error


def render_legal_file(label: str, text: str) -> str:
    text = normalize_notice_text(text)
    suffix = "" if text.endswith("\n") else "\n"
    return f"#### `{label}`\n\n{text}{suffix}"


def render_distribution_section(
    mxc_license: str, cargo_packages: list[dict], webview_files: list[tuple[str, str]]
) -> str:
    mxc_license = normalize_notice_text(mxc_license)
    package_entries = []
    legal_texts: dict[str, str] = {}
    legal_references: dict[str, list[str]] = {}
    for package in cargo_packages:
        contexts = ", ".join(sorted(package["contexts"]))
        mappings = []
        for label, text in package["files"]:
            text = normalize_notice_text(text)
            digest = sha256(text.encode("utf-8"))
            if digest in legal_texts and legal_texts[digest] != text:
                raise NoticeError("SHA-256 collision between Rust legal texts")
            legal_texts[digest] = text
            legal_references.setdefault(digest, []).append(
                f"{package['name']}@{package['version']}/{label}"
            )
            mappings.append(f"- `{label}`: SHA-256 `{digest}`")
        package_entries.append(
            f"### {package['name']} {package['version']}\n\n"
            f"Used by: {contexts}\n\n"
            f"Declared license: {package['license']}\n\n"
            f"Legal texts:\n\n" + "\n".join(mappings)
        )
    text_entries = []
    for digest in sorted(legal_texts):
        references = "\n".join(
            f"- `{reference}`" for reference in sorted(legal_references[digest])
        )
        text_entries.append(
            f"### SHA-256 `{digest}`\n\nReferenced by:\n\n{references}\n\n"
            + render_legal_file("Exact text", legal_texts[digest])
        )
    webview_text = "\n".join(
        render_legal_file(label, text) for label, text in webview_files
    )
    mxc_suffix = "" if mxc_license.endswith("\n") else "\n"
    return "\n".join(
        [
            DIST_BEGIN,
            "## Microsoft Execution Containers (MXC)",
            "",
            f"AXIS Linux release artifacts include `lxc-exec` from MXC commit `{MXC_REF}`.",
            "The following is the exact project license from that revision.",
            "",
            mxc_license + mxc_suffix,
            "---",
            "",
            "## Rust Dependencies",
            "",
            "This section covers the locked normal and build dependency closures for AXIS",
            "release targets, the Linux desktop GUI, and the pinned MXC `lxc-exec` build.",
            "",
            "\n\n---\n\n".join(package_entries),
            "",
            "---",
            "",
            "## Rust Legal Text Catalog",
            "",
            "Each exact text is stored once and referenced by content hash above.",
            "",
            "\n\n---\n\n".join(text_entries),
            "",
            "---",
            "",
            f"## {WEBVIEW_PACKAGE} {WEBVIEW_VERSION}",
            "",
            "The Windows desktop archive redistributes WebView2 components from the locked",
            "official NuGet package. Its required legal files follow exactly.",
            "",
            webview_text,
            DIST_END,
        ]
    )


def extract_single_section(document: bytes, begin: bytes, end: bytes) -> bytes:
    if document.count(begin) != 1 or document.count(end) != 1:
        raise NoticeError(
            "THIRD_PARTY_NOTICES.md has malformed generated section markers"
        )
    start = document.index(begin)
    finish = document.index(end)
    if finish < start:
        raise NoticeError(
            "THIRD_PARTY_NOTICES.md has reversed generated section markers"
        )
    return document[start : finish + len(end)]


def generate_frontend_section() -> bytes:
    output = run(
        [
            "node",
            str(
                REPOSITORY_ROOT / "gui/shared/scripts/generate-third-party-notices.mjs"
            ),
            "--print",
        ],
        timeout=NODE_TIMEOUT_SECONDS,
    ).encode("utf-8")
    section = extract_single_section(output, NPM_BEGIN, NPM_END)
    if output != section + b"\n":
        raise NoticeError("frontend notice generator returned unexpected output")
    return section


def compose_document(distribution_section: str, npm_section: bytes) -> bytes:
    if extract_single_section(npm_section, NPM_BEGIN, NPM_END) != npm_section:
        raise NoticeError("frontend notice section has unexpected surrounding content")
    document = (
        b"# Third-Party Notices\n\n"
        + distribution_section.encode("utf-8")
        + b"\n\n"
        + npm_section
        + b"\n"
    )
    try:
        return normalize_notice_text(document.decode("utf-8")).encode("utf-8")
    except UnicodeDecodeError as error:
        raise NoticeError("generated frontend notices are not UTF-8") from error


def generate(mxc_dir: Path | None = None, expected_mxc_ref: str | None = None) -> bytes:
    if expected_mxc_ref is not None and expected_mxc_ref != MXC_REF:
        raise NoticeError(
            f"release MXC ref {expected_mxc_ref} does not match notice ref {MXC_REF}"
        )
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
    override_cache: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="axis-notices-") as temporary:
        checkout = prepare_mxc_checkout(mxc_dir, Path(temporary))
        mxc_license = verify_mxc_checkout(checkout)
        groups = [
            collect_cargo_packages(
                REPOSITORY_ROOT / "Cargo.toml",
                SUPPORTED_TARGETS,
                "AXIS",
                cargo_home,
                override_cache=override_cache,
            ),
            collect_cargo_packages(
                REPOSITORY_ROOT / "gui/linux/Cargo.toml",
                ("x86_64-unknown-linux-gnu",),
                "Linux desktop GUI",
                cargo_home,
                override_cache=override_cache,
            ),
            collect_cargo_packages(
                checkout / "src/Cargo.toml",
                ("x86_64-unknown-linux-gnu",),
                "MXC lxc-exec",
                cargo_home,
                root_package="lxc",
                metadata_extra=("--no-default-features",),
                override_cache=override_cache,
            ),
        ]
        used_overrides = {
            key
            for group in groups
            for key, package in group.items()
            if package["files"][0][0].startswith("upstream LICENSE")
        }
        if used_overrides != set(UPSTREAM_OVERRIDES):
            unused = sorted(set(UPSTREAM_OVERRIDES) - used_overrides)
            raise NoticeError(f"stale or unused legal-text overrides: {unused}")
        cargo_packages = merge_cargo_packages(groups)
        webview_files = webview_legal_files(
            REPOSITORY_ROOT / "gui/windows/AXIS/packages.lock.json"
        )
        distribution = render_distribution_section(
            mxc_license, cargo_packages, webview_files
        )
        return compose_document(distribution, generate_frontend_section())


def apply_generated_document(
    expected: bytes, *, check: bool, path: Path = NOTICES_PATH
) -> None:
    if check:
        try:
            current = path.read_bytes()
        except OSError as error:
            raise NoticeError(f"failed to read {path}") from error
        if current != expected:
            raise NoticeError(
                "THIRD_PARTY_NOTICES.md is stale; run "
                "python3 scripts/generate_third_party_notices.py --write"
            )
        return
    try:
        path.write_bytes(expected)
    except OSError as error:
        raise NoticeError(f"failed to write {path}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail if notices are stale")
    mode.add_argument(
        "--write", action="store_true", help="replace the generated notices"
    )
    parser.add_argument(
        "--mxc-dir", type=Path, help="use an existing clean pinned MXC checkout"
    )
    parser.add_argument(
        "--expected-mxc-ref",
        help="fail unless a release workflow's MXC ref matches the reviewed notice ref",
    )
    arguments = parser.parse_args()
    try:
        expected = generate(arguments.mxc_dir, arguments.expected_mxc_ref)
        apply_generated_document(expected, check=arguments.check)
    except (NoticeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
