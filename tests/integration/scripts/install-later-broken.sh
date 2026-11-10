#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test install script: exits 10 (installed at the next start) but the version never changes, as
# when the new image does not boot and the old one comes back.
set -eu
here=$(dirname "$0")
printf '%s %s %s %s\n' "$1" "$2" "$3" "$(pwd)" >>"$here/runs"
exit 10
