#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test install script: sleeps `sleep` seconds (a file next to it), then installs and exits with
# the code in `exit` (0 or 10 write the new version first). For stopping the agent while it runs.
here=$(dirname "$0")
printf '%s %s %s %s\n' "$1" "$2" "$3" "$(pwd)" >>"$here/runs"
code=$(cat "$here/exit")
echo "sleeping before the installation"
sleep "$(cat "$here/sleep")"
if [ "$code" = 0 ] || [ "$code" = 10 ]; then
    printf '%s\n' "$2" >"$here/version"
fi
exit "$code"
