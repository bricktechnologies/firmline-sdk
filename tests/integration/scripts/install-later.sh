#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test install script: prepares the update and exits 10 (installed at the next start). The new
# version is what the component reports from now on, as after a successful reboot.
set -eu
here=$(dirname "$0")
printf '%s %s %s %s\n' "$1" "$2" "$3" "$(pwd)" >>"$here/runs"
printf '%s\n' "$2" >"$here/version"
echo "version $2 is installed at the next start"
exit 10
