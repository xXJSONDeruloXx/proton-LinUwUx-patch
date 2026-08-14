#!/bin/sh
# Copyright (C) 2026 brcly
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# install.sh -- fetches the latest liblinuwux.so release and installs it.
# No git clone, no gcc, no compiler toolchain required. Run via:
#   curl -fsSL https://raw.githubusercontent.com/brcly/linuwux-runtime/main/install.sh | sh
#
# Building from source instead (build.sh) stays fully supported -- this
# is just a faster path for anyone who doesn't need or want to compile.

set -eu

REPO="brcly/linuwux-runtime"
BASE_URL="https://github.com/${REPO}/releases/latest/download"
LIBDIR="${HOME}/.local/lib"
BINDIR="${HOME}/.local/bin"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "install.sh: '$1' is required but not found" >&2; exit 1; }
}
need curl
need sha256sum

arch=$(uname -m)
if [ "$arch" != "x86_64" ]; then
    echo "install.sh: liblinuwux.so is x86_64-only (detected: $arch)" >&2
    exit 1
fi

echo "==> Downloading latest liblinuwux release..."
curl -fsSL -o "${TMPDIR}/liblinuwux.so" "${BASE_URL}/liblinuwux.so"
curl -fsSL -o "${TMPDIR}/liblinuwux-legacy.so" "${BASE_URL}/liblinuwux-legacy.so"
curl -fsSL -o "${TMPDIR}/linuwux.sh" "${BASE_URL}/linuwux.sh"
curl -fsSL -o "${TMPDIR}/SHA256SUMS" "${BASE_URL}/SHA256SUMS"

echo "==> Verifying checksums..."
if ! (cd "$TMPDIR" && sha256sum -c SHA256SUMS >/dev/null); then
    echo "install.sh: checksum verification failed -- aborting" >&2
    exit 1
fi

mkdir -p "$LIBDIR" "$BINDIR"
cp -f "${TMPDIR}/liblinuwux.so" "${LIBDIR}/liblinuwux.so"
cp -f "${TMPDIR}/liblinuwux-legacy.so" "${LIBDIR}/liblinuwux-legacy.so"
cp -f "${TMPDIR}/linuwux.sh" "${BINDIR}/linuwux"
cp -f "${TMPDIR}/linuwux.sh" "${BINDIR}/linuwux-legacy"
chmod 0755 "${BINDIR}/linuwux"
chmod 0755 "${BINDIR}/linuwux-legacy"

echo
echo "============================================================"
echo "  INSTALL SUCCESSFUL"
echo "============================================================"
echo "  Library  : ${LIBDIR}/liblinuwux.so"
echo "  Wrapper  : ${BINDIR}/linuwux"
echo "============================================================"
echo
echo "Steam launch options for any GE-Proton / CachyOS game:"
echo "  ${BINDIR}/linuwux %command%"
echo
case ":$PATH:" in
    *":${BINDIR}:"*)
        echo "${BINDIR} is already on your PATH, so this also works from a terminal"
        echo "(Lutris, Heroic, bare umu-run, etc.):"
        echo "  linuwux %command%"
        ;;
    *)
        echo "${BINDIR} is not on your PATH yet. That only matters for a terminal,"
        echo "Lutris, or Heroic -- Steam uses the absolute path above regardless."
        echo "To get the plain 'linuwux' command elsewhere, add this to ~/.bashrc"
        echo "(or equivalent) and open a new terminal:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
        ;;
esac
echo
echo "LINUWUX_PRELOAD=/other/path overrides the library the wrapper loads."
echo "Check what's installed any time with: linuwux --version"
echo
