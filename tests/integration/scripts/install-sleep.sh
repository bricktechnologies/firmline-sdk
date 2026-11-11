#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test install script: sleeps `sleep` seconds (a file next to it), then installs and exits with
# the code in `exit` (0 or 10 write the new version first). With a file `early` next to it, the
# new version is written before the sleep (already in place when a signal ends the script). Its
# pid (= its process group) goes to `pid`. For stopping the agent while it runs.
here=$(dirname "$0")
printf '%s %s %s %s\n' "$1" "$2" "$3" "$(pwd)" >>"$here/runs"
echo $$ >"$here/pid"
code=$(cat "$here/exit")
if [ -f "$here/early" ]; then
    printf '%s\n' "$2" >"$here/version"
fi
echo "sleeping before the installation"
sleep "$(cat "$here/sleep")"
if [ "$code" = 0 ] || [ "$code" = 10 ]; then
    printf '%s\n' "$2" >"$here/version"
fi
exit "$code"
