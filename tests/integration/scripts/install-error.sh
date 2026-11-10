#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test install script: fails with exit 1 and a message on stderr.
here=$(dirname "$0")
printf '%s %s %s %s\n' "$1" "$2" "$3" "$(pwd)" >>"$here/runs"
echo "cannot write the flash" >&2
exit 1
