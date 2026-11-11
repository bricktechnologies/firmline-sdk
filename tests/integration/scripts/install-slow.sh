#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test install script: never ends by itself. A child of its own (sleep) records its pid, so the
# test can check that the whole process group is gone after the timeout.
here=$(dirname "$0")
printf '%s %s %s %s\n' "$1" "$2" "$3" "$(pwd)" >>"$here/runs"
echo "installing slowly"
sleep 300 &
echo $! >"$here/sleep.pid"
wait
