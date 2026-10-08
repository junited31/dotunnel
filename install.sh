#!/bin/sh
set -eu

WHEEL_VERSION='0.1.5'
WHEEL_URL='https://github.com/junited31/dotunnel/releases/download/v0.1.5/dotunnel-0.1.5-py3-none-any.whl'
WHEEL_SHA256='5b617552d1d9dbaabd4209a99f42c4a25e7757fad8c3e9a0e684d9f01a949810'
WHEEL_BYTES=123908

usage() {
    cat <<EOF
Usage: install.sh [--help]

Install the verified dotunnel $WHEEL_VERSION wheel into a dedicated Python virtualenv at
\$HOME/.local/share/dotunnel/venv and expose it as \$HOME/.local/bin/dotunnel.

Requirements: Linux, a non-root user, Python 3.11 or newer with venv/ensurepip,
curl, and sha256sum. The installer does not install the separate official
tunnel-client or run setup. After installation, run:
  dotunnel setup --directory "\$HOME/.dotunnel-setup"
EOF
}

fail() {
    printf 'dotunnel installer: %s\n' "$*" >&2
    exit 1
}

if [ "$#" -gt 0 ]; then
    if [ "$#" -eq 1 ] && [ "$1" = '--help' ]; then
        usage
        exit 0
    fi
    usage >&2
    exit 2
fi

system=$(uname -s 2>/dev/null) || fail 'Unable to identify the operating system.'
[ "$system" = 'Linux' ] || fail 'This installer supports Linux only.'
uid=$(id -u 2>/dev/null) || fail 'Unable to identify the current user.'
[ "$uid" -ne 0 ] || fail 'Running as root is not supported; install as a normal user.'

for tool in curl sha256sum python3 mktemp wc tr mkdir rmdir rm; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required command is missing: $tool"
done

PYTHON3=$(command -v python3)
"$PYTHON3" -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
    >/dev/null 2>&1 || fail 'Python 3.11 or newer is required.'
"$PYTHON3" -I -c 'import ensurepip, venv' >/dev/null 2>&1 || \
    fail 'Python venv and ensurepip support are required.'

[ -n "${HOME:-}" ] || fail 'HOME must name an existing trusted home directory.'
case "$HOME" in
    /*) ;;
    *) fail 'HOME must be an absolute path.' ;;
esac

LOCAL_DIR="$HOME/.local"
SHARE_DIR="$LOCAL_DIR/share"
INSTALL_PARENT="$SHARE_DIR/dotunnel"
VENV_PATH="$INSTALL_PARENT/venv"
BIN_DIR="$LOCAL_DIR/bin"
LAUNCHER_PATH="$BIN_DIR/dotunnel"
TEMP_DIR=
ENV_CREATED=0
LAUNCHER_CREATED=0
LOCAL_CREATED=0
SHARE_CREATED=0
INSTALL_PARENT_CREATED=0
BIN_CREATED=0

cleanup() {
    status=$?
    trap - 0
    if [ "$status" -ne 0 ]; then
        if [ "$LAUNCHER_CREATED" -eq 1 ]; then
            rm -f "$LAUNCHER_PATH" 2>/dev/null || :
        fi
        if [ "$ENV_CREATED" -eq 1 ]; then
            rm -rf "$VENV_PATH" 2>/dev/null || :
        fi
        if [ "$BIN_CREATED" -eq 1 ]; then
            rmdir "$BIN_DIR" 2>/dev/null || :
        fi
        if [ "$INSTALL_PARENT_CREATED" -eq 1 ]; then
            rmdir "$INSTALL_PARENT" 2>/dev/null || :
        fi
        if [ "$SHARE_CREATED" -eq 1 ]; then
            rmdir "$SHARE_DIR" 2>/dev/null || :
        fi
        if [ "$LOCAL_CREATED" -eq 1 ]; then
            rmdir "$LOCAL_DIR" 2>/dev/null || :
        fi
    fi
    if [ -n "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR" 2>/dev/null || :
    fi
    exit "$status"
}
trap cleanup 0
trap 'exit 130' HUP INT TERM

check_trusted_paths() {
    "$PYTHON3" -I - "$HOME" "$INSTALL_PARENT" "$BIN_DIR" /tmp <<'PY'
import os
import stat
import sys


def reject(message):
    print("dotunnel installer: " + message, file=sys.stderr)
    raise SystemExit(1)


def check_directory(path):
    if not os.path.isabs(path) or ".." in path.split("/"):
        reject("trusted paths must be absolute and must not contain '..': " + path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        fd = os.open("/", flags)
    except OSError:
        reject("unable to inspect trusted path parents")
    try:
        for component in path.split("/"):
            if not component or component == ".":
                continue
            try:
                child = os.open(component, flags, dir_fd=fd)
            except FileNotFoundError:
                break
            except OSError:
                reject("trusted path contains a symlink or non-directory component: " + path)
            info = os.fstat(child)
            if info.st_uid not in (0, os.getuid()) or (
                info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX
            ):
                os.close(child)
                reject("trusted path has a shared-writable or untrusted parent: " + path)
            os.close(fd)
            fd = child
    finally:
        os.close(fd)


for candidate in sys.argv[1:]:
    check_directory(candidate)
PY
}

check_trusted_paths || fail 'HOME or an install path parent is not trusted; refusing symlinks and shared-writable directories.'
if [ -e "$VENV_PATH" ] || [ -L "$VENV_PATH" ]; then
    fail "Install path already exists: $VENV_PATH. Existing users should run dotunnel update."
fi
if [ -e "$LAUNCHER_PATH" ] || [ -L "$LAUNCHER_PATH" ]; then
    fail "Launcher already exists: $LAUNCHER_PATH. It was left unchanged; remove it yourself only if you know it is safe."
fi

umask 077
TEMP_DIR=$(mktemp -d /tmp/dotunnel-install.XXXXXXXX) || fail 'Unable to create a private temporary directory under /tmp.'
WHEEL_FILE="$TEMP_DIR/dotunnel-${WHEEL_VERSION}-py3-none-any.whl"
if ! curl --disable --fail --location --silent --show-error --connect-timeout 15 --max-time 120 --max-filesize "$WHEEL_BYTES" --output "$WHEEL_FILE" "$WHEEL_URL"; then
    fail 'Unable to download the pinned dotunnel wheel.'
fi
wheel_bytes=$(wc -c < "$WHEEL_FILE" | tr -d '[:space:]') || fail 'Unable to check the downloaded wheel size.'
[ "$wheel_bytes" = "$WHEEL_BYTES" ] || fail 'Downloaded wheel length did not match the pinned release; nothing was installed.'
sha_result=$(sha256sum "$WHEEL_FILE") || fail 'Unable to calculate the downloaded wheel SHA-256.'
wheel_sha256=${sha_result%% *}
[ "$wheel_sha256" = "$WHEEL_SHA256" ] || fail 'Downloaded wheel SHA-256 did not match the pinned release; nothing was installed.'

check_trusted_paths || fail 'HOME or an install path parent changed or is not trusted; refusing installation.'

ensure_directory() {
    path=$1
    if [ -d "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    if [ -e "$path" ] || [ -L "$path" ]; then
        fail "Install parent is not a real directory: $path"
    fi
    mkdir -m 700 "$path" || fail "Unable to create install directory: $path"
    case "$path" in
        "$LOCAL_DIR") LOCAL_CREATED=1 ;;
        "$SHARE_DIR") SHARE_CREATED=1 ;;
        "$INSTALL_PARENT") INSTALL_PARENT_CREATED=1 ;;
        "$BIN_DIR") BIN_CREATED=1 ;;
    esac
}

ensure_directory "$LOCAL_DIR"
ensure_directory "$SHARE_DIR"
ensure_directory "$INSTALL_PARENT"
check_trusted_paths || fail 'Install parents changed or are not trusted; refusing installation.'
if [ -e "$VENV_PATH" ] || [ -L "$VENV_PATH" ]; then
    fail "Install path already exists: $VENV_PATH. Existing users should run dotunnel update."
fi
mkdir -m 700 "$VENV_PATH" || fail "Install path appeared or could not be created: $VENV_PATH"
ENV_CREATED=1

"$PYTHON3" -I -m venv "$VENV_PATH" || fail 'Python could not create the isolated virtual environment.'
"$VENV_PATH/bin/python" -I -m pip --version >/dev/null 2>&1 || fail 'The new virtual environment does not provide pip.'
"$VENV_PATH/bin/python" -I -m pip --isolated install --no-input --disable-pip-version-check \
    --prefix "$VENV_PATH" --no-cache-dir --only-binary=:all: "$WHEEL_FILE" || \
    fail 'Binary-only installation failed; the newly created environment was removed.'
"$VENV_PATH/bin/python" -I -c 'import importlib.metadata as m, sys; raise SystemExit(0 if m.version("dotunnel") == sys.argv[1] else 1)' "$WHEEL_VERSION" \
    >/dev/null 2>&1 || fail "The requested dotunnel $WHEEL_VERSION package was not installed."
[ -x "$VENV_PATH/bin/dotunnel" ] || fail 'The installed package did not expose its dotunnel command.'

check_trusted_paths || fail 'Install parents changed or are not trusted; refusing to expose the launcher.'
ensure_directory "$BIN_DIR"
if [ -e "$LAUNCHER_PATH" ] || [ -L "$LAUNCHER_PATH" ]; then
    fail "Launcher already exists: $LAUNCHER_PATH. It was left unchanged."
fi
"$PYTHON3" -I - "$VENV_PATH/bin/dotunnel" "$LAUNCHER_PATH" <<'PY'
import os
import sys

try:
    os.symlink(sys.argv[1], sys.argv[2])
except OSError as error:
    print("dotunnel installer: unable to create launcher: " + error.strerror, file=sys.stderr)
    raise SystemExit(1)
PY
LAUNCHER_CREATED=1
ENV_CREATED=0 LAUNCHER_CREATED=0

printf 'Installed dotunnel %s in %s\n' "$WHEEL_VERSION" "$VENV_PATH"
printf 'The official tunnel-client remains separate and was not installed or changed.\n'
case ":${PATH:-}:" in
    *":$BIN_DIR:"*)
        printf 'Next: dotunnel setup --directory "$HOME/.dotunnel-setup"\n'
        ;;
    *)
        printf 'Add %s to PATH in your current shell; this installer does not edit shell startup files.\n' "$BIN_DIR"
        printf 'Next: "%s" setup --directory "$HOME/.dotunnel-setup"\n' "$LAUNCHER_PATH"
        ;;
esac
