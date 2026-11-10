#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test reboot command: records its arguments in `rebooted` next to itself and exits 0.
printf '%s\n' "$*" >"$(dirname "$0")/rebooted"
