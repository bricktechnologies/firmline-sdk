#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test install script: `install-ok.sh <file> <version> <release>` installs and exits 0, so the new
# version is the installed one. It keeps its marks next to itself (the tests run a copy per
# component): runs (one line per run: file, version, release, working folder), installed.bin
# (a copy of the file) and version (the version source of the component).
set -eu
here=$(dirname "$0")
printf '%s %s %s %s\n' "$1" "$2" "$3" "$(pwd)" >>"$here/runs"
cp "$1" "$here/installed.bin"
printf '%s\n' "$2" >"$here/version"
echo "installing version $2"
