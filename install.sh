#!/bin/sh
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# AXIS installer — downloads pre-built binaries from GitHub releases.
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/ROCm/axis/main/install.sh | sh
#   curl -sSf https://raw.githubusercontent.com/ROCm/axis/main/install.sh | sh -s -- --nightly
#
# Options:
#   --nightly     Install latest nightly build instead of stable release
#   --prefix DIR  Install to DIR (default: ~/.local/bin on Linux/macOS)
#   --version VER Install specific version (e.g., 0.1.0)
#   --with-netns-helper
#                 Linux only: install the optional setuid netns helper for proxy mode
#   --with-cap-net-admin
#                 Linux only: grant CAP_NET_ADMIN to axis/axisd (advanced)

set -e

REPO="ROCm/axis"
INSTALL_DIR="${HOME}/.local/bin"
INSTALL_DIR_EXPLICIT=0
CHANNEL="release"
VERSION=""
LOCAL_ARCHIVE="${AXIS_INSTALL_ARCHIVE:-}"
LOCAL_CHECKSUM="${AXIS_INSTALL_SHA256:-}"
GH_VERSION="2.94.0"
GH_BIN=""
LEGACY_RELEASE=0
MAX_AXIS_DOWNLOAD=$((1024 * 1024 * 1024))
MAX_TOOL_DOWNLOAD=$((128 * 1024 * 1024))
MAX_METADATA_DOWNLOAD=$((1024 * 1024))
INSTALL_NETNS_HELPER=0
ENABLE_CAP_NET_ADMIN=0
HELPER_INSTALL_PATH="/usr/libexec/axis/axis-netns-helper"
HELPER_MXC_EXECUTOR_PATH="/usr/local/bin/lxc-exec"

# Parse args.
while [ $# -gt 0 ]; do
    case "$1" in
        --nightly) CHANNEL="nightly"; shift ;;
        --prefix)  [ "$#" -ge 2 ] || { echo "Error: --prefix requires a value"; exit 1; }; INSTALL_DIR="$2"; INSTALL_DIR_EXPLICIT=1; shift 2 ;;
        --version) [ "$#" -ge 2 ] || { echo "Error: --version requires a value"; exit 1; }; VERSION="$2"; shift 2 ;;
        --with-netns-helper) INSTALL_NETNS_HELPER=1; shift ;;
        --with-cap-net-admin) ENABLE_CAP_NET_ADMIN=1; shift ;;
        --help|-h)
            echo "AXIS installer"
            echo ""
            echo "Usage: curl -sSf https://raw.githubusercontent.com/ROCm/axis/main/install.sh | sh"
            echo ""
            echo "Options:"
            echo "  --nightly              Install nightly build"
            echo "  --prefix DIR           Install directory (default: ~/.local/bin)"
            echo "  --version VER          Specific version"
            echo "  --with-netns-helper    Linux only: install optional proxy-mode helper"
            echo "  --with-cap-net-admin   Linux only: grant CAP_NET_ADMIN to axis/axisd"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Detect OS and architecture.
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="macos" ;;
        mingw*|msys*|cygwin*) OS="windows" ;;
        *)
            echo "Error: unsupported OS: $OS"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *)
            echo "Error: unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
    case "$PLATFORM" in
        linux-x86_64|macos-aarch64) ;;
        *)
            echo "Error: no AXIS release artifact is published for ${PLATFORM}"
            exit 1
            ;;
    esac
}

# Releases published before checksum sidecars and provenance attestations.
# Their archives are authenticated by these digests instead.
legacy_release_sha256() {
    case "$1:$2" in
        v0.3.5:axis-linux-x86_64.tar.gz) echo "34ba6c10377690108d878b7236e758c2e91353f97cc975f4be4bb5abf5d689c5" ;;
        v0.3.5:axis-macos-aarch64.tar.gz) echo "e3d59c280d8ace8722ef59a37ff7d70938b2b9166b545990b1be45de46b37812" ;;
        *) return 1 ;;
    esac
}

file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print tolower($1)}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print tolower($1)}'
    else
        echo "Error: sha256sum or shasum is required" >&2
        exit 1
    fi
}

download_file() {
    download_url="$1"
    download_destination="$2"
    download_limit="$3"
    # Return the downloader status explicitly. This function is called from
    # `if`, and dash disables set -e for the whole function in that case, so a
    # failed curl would otherwise fall through to the size check below.
    if command -v curl >/dev/null 2>&1; then
        curl --fail --silent --show-error --location \
            --connect-timeout 15 --max-time 300 --retry 2 --retry-max-time 300 \
            --max-filesize "$download_limit" \
            --output "$download_destination" "$download_url" || return $?
    elif command -v wget >/dev/null 2>&1; then
        wget --quiet --timeout=15 --tries=2 --quota="$download_limit" \
            --output-document="$download_destination" "$download_url" || return $?
    else
        echo "Error: curl or wget required" >&2
        exit 1
    fi
    download_size=$(wc -c <"$download_destination") || return 1
    if [ "$download_size" -gt "$download_limit" ]; then
        echo "Error: download exceeds size limit: $download_url" >&2
        exit 1
    fi
}

run_gh() {
    set +e
    GH_PROMPT_DISABLED=1 GH_NO_UPDATE_NOTIFIER=1 "$GH_BIN" "$@" &
    command_pid=$!
    (
        sleep 120
        kill -TERM "$command_pid" 2>/dev/null || true
        sleep 2
        kill -KILL "$command_pid" 2>/dev/null || true
    ) </dev/null >/dev/null 2>&1 &
    timer_pid=$!
    wait "$command_pid"
    command_status=$?
    kill "$timer_pid" 2>/dev/null || true
    wait "$timer_pid" 2>/dev/null || true
    set -e
    return "$command_status"
}

ensure_gh() {
    if command -v gh >/dev/null 2>&1; then
        GH_BIN=$(command -v gh)
        if "$GH_BIN" release verify-asset --help >/dev/null 2>&1 && \
            "$GH_BIN" attestation verify --help >/dev/null 2>&1; then
            return
        fi
    fi
    case "$PLATFORM" in
        linux-x86_64)
            gh_archive="gh_${GH_VERSION}_linux_amd64.tar.gz"
            gh_hash="a757f1ba6db18f4de8cbadb244843a5f89bc75b5e7c6fc127d2bd77fbd12ed62"
            ;;
        macos-aarch64)
            gh_archive="gh_${GH_VERSION}_macOS_arm64.zip"
            gh_hash="4f9bc1a5e77500737290a307b40b4c396a4d23729f55340f2a83f414410165a1"
            ;;
        *) echo "Error: cannot bootstrap GitHub CLI for $PLATFORM"; exit 1 ;;
    esac
    gh_path="$TMPDIR/$gh_archive"
    download_file "https://github.com/cli/cli/releases/download/v${GH_VERSION}/${gh_archive}" \
        "$gh_path" "$MAX_TOOL_DOWNLOAD"
    [ "$(file_sha256 "$gh_path")" = "$gh_hash" ] || {
        echo "Error: GitHub CLI bootstrap checksum failed" >&2
        exit 1
    }
    mkdir -p "$TMPDIR/gh"
    if [ "$OS" = "macos" ]; then
        ditto -x -k "$gh_path" "$TMPDIR/gh"
    else
        tar xzf "$gh_path" -C "$TMPDIR/gh"
    fi
    GH_BIN="$TMPDIR/gh/gh_${GH_VERSION}_$( [ "$OS" = macos ] && printf macOS_arm64 || printf linux_amd64 )/bin/gh"
    [ -x "$GH_BIN" ] || { echo "Error: GitHub CLI bootstrap archive is invalid"; exit 1; }
}

need_privilege() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo "Error: this install option requires root or sudo"
        exit 1
    fi
}

require_linux_privilege_options() {
    if [ "$INSTALL_NETNS_HELPER" -eq 1 ] || [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        if [ "$OS" != "linux" ]; then
            echo "Error: privileged network install options are Linux-only"
            exit 1
        fi
    fi

    if [ "$INSTALL_NETNS_HELPER" -eq 1 ] && [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        echo "Error: choose either --with-netns-helper or --with-cap-net-admin, not both"
        exit 1
    fi

    if [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ] && [ "$INSTALL_DIR_EXPLICIT" -eq 0 ]; then
        INSTALL_DIR="/usr/local/bin"
    fi

    if [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        case "$INSTALL_DIR" in
            "$HOME"|"$HOME"/*)
                echo "Error: --with-cap-net-admin requires a root-owned install prefix"
                echo "Try: curl -sSf https://raw.githubusercontent.com/ROCm/axis/main/install.sh | sh -s -- --with-cap-net-admin --prefix /usr/local/bin"
                exit 1
                ;;
        esac
    fi
}

find_extracted_binary() {
    find "${TMPDIR}/extracted" -name "$1" -type f | head -1
}

install_user_binary() {
    SRC="$1"
    DEST="$2"
    if [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        need_privilege install -o root -g root -m 0755 "$SRC" "$DEST"
    else
        cp "$SRC" "$DEST"
        chmod +x "$DEST"
    fi
}

install_netns_helper() {
    HELPER_SRC=$(find_extracted_binary axis-netns-helper)
    MXC_EXECUTOR_SRC=$(find_extracted_binary lxc-exec)
    if [ -z "$HELPER_SRC" ]; then
        echo "Error: archive does not contain axis-netns-helper"
        echo "Install without --with-netns-helper or use a release that ships the helper."
        exit 1
    fi
    if [ -z "$MXC_EXECUTOR_SRC" ]; then
        echo "Error: archive does not contain lxc-exec"
        exit 1
    fi

    echo "Installing optional netns helper and trusted MXC executor..."
    need_privilege install -d -o root -g root -m 0755 "$(dirname "$HELPER_INSTALL_PATH")"
    need_privilege install -d -o root -g root -m 0755 "$(dirname "$HELPER_MXC_EXECUTOR_PATH")"
    need_privilege install -o root -g root -m 4755 "$HELPER_SRC" "$HELPER_INSTALL_PATH"
    need_privilege install -o root -g root -m 0755 "$MXC_EXECUTOR_SRC" "$HELPER_MXC_EXECUTOR_PATH"
    echo "  Installed: ${HELPER_INSTALL_PATH} (root-owned, setuid)"
    echo "  Installed: ${HELPER_MXC_EXECUTOR_PATH} (root-owned)"
}

enable_cap_net_admin() {
    if command -v setcap >/dev/null 2>&1; then
        SETCAP=$(command -v setcap)
    elif [ -x /usr/sbin/setcap ]; then
        SETCAP=/usr/sbin/setcap
    elif [ -x /sbin/setcap ]; then
        SETCAP=/sbin/setcap
    else
        echo "Error: --with-cap-net-admin requires setcap"
        exit 1
    fi

    echo "Granting CAP_NET_ADMIN to AXIS binaries..."
    need_privilege "$SETCAP" cap_net_admin+ep "${INSTALL_DIR}/axis"
    need_privilege "$SETCAP" cap_net_admin+ep "${INSTALL_DIR}/axisd"
    echo "  CAP_NET_ADMIN: ${INSTALL_DIR}/axis"
    echo "  CAP_NET_ADMIN: ${INSTALL_DIR}/axisd"
}

# Get the download URL for the latest release.
get_download_url() {
    if [ -n "$LOCAL_ARCHIVE" ]; then
        if [ ! -f "$LOCAL_ARCHIVE" ]; then
            echo "Error: AXIS_INSTALL_ARCHIVE does not exist: $LOCAL_ARCHIVE"
            exit 1
        fi
        ARCHIVE_NAME=$(basename "$LOCAL_ARCHIVE")
        if [ -z "$LOCAL_CHECKSUM" ]; then
            LOCAL_CHECKSUM="${LOCAL_ARCHIVE}.sha256"
        fi
        if [ ! -f "$LOCAL_CHECKSUM" ]; then
            echo "Error: checksum file not found: $LOCAL_CHECKSUM"
            exit 1
        fi
        URL="$LOCAL_ARCHIVE"
        CHECKSUM_URL="$LOCAL_CHECKSUM"
        return
    fi

    if [ "$CHANNEL" = "nightly" ]; then
        TAG=$(run_gh api "repos/${REPO}/releases?per_page=100" --jq \
            '.[] | select(.prerelease and (.tag_name | test("^nightly-[0-9a-f]{40}$"))) | .tag_name' | sed -n '1p')
        if [ -z "$TAG" ]; then
            echo "Error: cannot determine latest nightly release"
            exit 1
        fi
    elif [ -n "$VERSION" ]; then
        case "$VERSION" in *[!0-9A-Za-z.+-]*|'') echo "Error: invalid version"; exit 1 ;; esac
        TAG="v${VERSION}"
    else
        # Get latest release tag.
        TAG=$(run_gh api "repos/${REPO}/releases/latest" --jq '.tag_name')
        if [ -z "$TAG" ]; then
            echo "Error: cannot determine latest release"
            exit 1
        fi
    fi
    case "$TAG" in *[!0-9A-Za-z._+-]*|'') echo "Error: invalid release tag"; exit 1 ;; esac

    EXT="tar.gz"
    if [ "$OS" = "windows" ]; then
        EXT="zip"
    fi

    ARCHIVE_NAME="axis-${PLATFORM}.${EXT}"
    URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE_NAME}"
    CHECKSUM_URL="${URL}.sha256"
}

download_archive() {
    if [ -n "$LOCAL_ARCHIVE" ]; then
        cp "$LOCAL_ARCHIVE" "${TMPDIR}/axis-archive"
        cp "$LOCAL_CHECKSUM" "${TMPDIR}/axis-archive.sha256"
        return
    fi

    if ! download_file "$URL" "${TMPDIR}/axis-archive" "$MAX_AXIS_DOWNLOAD"; then
            echo ""
            echo "Error: download failed. URL: $URL"
            echo ""
            echo "If this is a new release, binaries may not be uploaded yet."
            echo "Try: --nightly or --version <version>"
            exit 1
    fi
    if LEGACY_SHA256=$(legacy_release_sha256 "$TAG" "$ARCHIVE_NAME"); then
        LEGACY_RELEASE=1
        printf '%s  %s\n' "$LEGACY_SHA256" "$ARCHIVE_NAME" >"${TMPDIR}/axis-archive.sha256"
        return
    fi
    if ! download_file "$CHECKSUM_URL" "${TMPDIR}/axis-archive.sha256" "$MAX_METADATA_DOWNLOAD"; then
            echo "Error: checksum download failed. URL: $CHECKSUM_URL"
            exit 1
    fi
}

verify_archive() {
    EXPECTED_SHA256=$(awk -v archive="$ARCHIVE_NAME" '
        {
            sub(/\r$/, "")
            if (NR != 1 || length($1) != 64 || $1 !~ /^[0-9A-Fa-f]+$/ ||
                $0 != $1 "  " archive) {
                exit 1
            }
            hash = tolower($1)
        }
        END {
            if (NR != 1 || hash == "") {
                exit 1
            }
            print hash
        }
    ' "${TMPDIR}/axis-archive.sha256") || {
        echo "Error: invalid checksum file for ${ARCHIVE_NAME}"
        exit 1
    }

    ACTUAL_SHA256=$(file_sha256 "${TMPDIR}/axis-archive")

    if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
        echo "Error: checksum verification failed for ${ARCHIVE_NAME}"
        exit 1
    fi
}

verify_github_provenance() {
    if [ -n "$LOCAL_ARCHIVE" ]; then
        return 0
    fi
    if [ "$LEGACY_RELEASE" -eq 1 ]; then
        echo "Release ${TAG} predates provenance attestations; verified against the installer's pinned digest."
        return 0
    fi
    echo "Verifying immutable release provenance..."
    run_gh release verify-asset "$TAG" "${TMPDIR}/axis-archive" --repo "$REPO"
    signer_workflow="$REPO/.github/workflows/release.yml"
    source_identity="--source-ref=refs/tags/$TAG"
    if [ "$CHANNEL" = "nightly" ]; then
        signer_workflow="$REPO/.github/workflows/nightly.yml"
        source_sha=${TAG#nightly-}
        [ ${#source_sha} -eq 40 ] || { echo "Error: invalid nightly source identity"; exit 1; }
        source_identity="--source-digest=$source_sha"
    fi
    run_gh attestation verify "${TMPDIR}/axis-archive" \
        --repo "$REPO" \
        --signer-workflow "$signer_workflow" \
        "$source_identity" \
        --deny-self-hosted-runners
}

# Download and install.
install() {
    require_linux_privilege_options

    echo "AXIS installer"
    echo ""
    echo "  Platform: ${PLATFORM}"
    echo "  Channel:  ${CHANNEL}"
    echo "  Install:  ${INSTALL_DIR}"
    if [ "$INSTALL_NETNS_HELPER" -eq 1 ]; then
        echo "  Netns:    helper (${HELPER_INSTALL_PATH})"
    elif [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        echo "  Netns:    CAP_NET_ADMIN on axis/axisd"
    fi
    echo ""

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    if [ -z "$LOCAL_ARCHIVE" ]; then
        ensure_gh
    fi
    get_download_url

    if [ -n "$LOCAL_ARCHIVE" ]; then
        echo "  Archive:  ${URL}"
    else
        echo "  Download: ${URL}"
    fi
    echo ""

    # Download.
    echo "Downloading..."
    download_archive

    echo "Verifying checksum..."
    verify_archive
    verify_github_provenance

    # Extract.
    echo "Extracting..."
    if [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        need_privilege install -d -o root -g root -m 0755 "${INSTALL_DIR}"
    else
        mkdir -p "${INSTALL_DIR}"
    fi

    mkdir -p "${TMPDIR}/extracted"
    if [ "$OS" = "windows" ]; then
        unzip -q "${TMPDIR}/axis-archive" -d "${TMPDIR}/extracted"
    else
        tar xzf "${TMPDIR}/axis-archive" -C "${TMPDIR}/extracted" 2>/dev/null || \
        tar xf "${TMPDIR}/axis-archive" -C "${TMPDIR}/extracted"
    fi

    # Install binaries. Linux MXC-backed sandboxing uses ordinary unprivileged
    # runtime helpers that must be available from stable, safe executable paths.
    # User-prefix installs keep them beside axis/axisd; package installs place
    # them in system paths through package metadata.
    INSTALL_BINS="axis axisd"
    if [ "$OS" = "linux" ] && [ "$LEGACY_RELEASE" -eq 0 ]; then
        INSTALL_BINS="$INSTALL_BINS axis-seccomp-launcher lxc-exec"
    fi
    for bin in $INSTALL_BINS; do
        if [ "$OS" = "windows" ]; then
            BIN_NAME="${bin}.exe"
        else
            BIN_NAME="${bin}"
        fi

        SRC=$(find_extracted_binary "$BIN_NAME")
        if [ -n "$SRC" ]; then
            install_user_binary "$SRC" "${INSTALL_DIR}/${BIN_NAME}"
            echo "  Installed: ${INSTALL_DIR}/${BIN_NAME}"
        elif [ "$OS" = "linux" ] && { [ "$bin" = "axis-seccomp-launcher" ] || [ "$bin" = "lxc-exec" ]; }; then
            echo "Error: archive does not contain ${bin}"
            echo "Use a Linux release archive that ships the MXC runtime helpers."
            exit 1
        fi
    done

    if [ "$INSTALL_NETNS_HELPER" -eq 1 ]; then
        install_netns_helper
    fi

    if [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        enable_cap_net_admin
    fi

    echo ""

    # Check PATH.
    case ":$PATH:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            echo "Add to your PATH:"
            echo ""
            echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
            echo ""
            SHELL_RC=""
            if [ -f "$HOME/.zshrc" ]; then
                SHELL_RC="$HOME/.zshrc"
            elif [ -f "$HOME/.bashrc" ]; then
                SHELL_RC="$HOME/.bashrc"
            fi
            if [ -n "$SHELL_RC" ]; then
                echo "Or run:"
                echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ${SHELL_RC}"
                echo ""
            fi
            ;;
    esac

    echo "AXIS installed successfully!"
    echo ""
    echo "  axis --version"
    echo "  axis run -- echo 'Hello from sandbox'"
}

detect_platform
install
