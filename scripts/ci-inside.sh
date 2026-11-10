#!/usr/bin/env bash
# Runs inside the dev container (see scripts/check.sh), from the repository root.
set -euo pipefail
cd "$(dirname "$0")/.."

dirs=(core)
[ -d linux ] && dirs+=(linux)
find "${dirs[@]}" -path core/third_party -prune -o \( -name '*.c' -o -name '*.h' \) -print0 \
    | xargs -0 clang-format --dry-run --Werror

# The guide documents every configuration key of the agent. The key table is KEY_NAMES in
# linux/src/config.c (one "section.key" string per line, as fa_config_keys returns it); the guide
# must name each key as written in the INI file: the key without its section, in backticks.
if [ -f linux/src/config.c ]; then
    mapfile -t config_keys < <(sed -n '/^static const char \*const KEY_NAMES/,/^};/p' linux/src/config.c \
        | grep -oE '^[[:space:]]+"(platform|component)\.[a-z_]+",' | tr -d ' ",')
    declared=$(grep -cE '^[[:space:]]+K_[A-Z_]+,$' linux/src/config.c)
    # K_COUNT closes the enum without a comma, so the count of "K_x," lines is the number of keys.
    if [ "${#config_keys[@]}" -eq 0 ] || [ "${#config_keys[@]}" -ne "$declared" ]; then
        echo "check: cannot read the key table of linux/src/config.c (${#config_keys[@]} names, $declared enum entries)" >&2
        exit 1
    fi
    missing=0
    for key in "${config_keys[@]}"; do
        if ! grep -qF "\`${key#*.}\`" docs/integration.md 2>/dev/null; then
            echo "docs/integration.md does not document the configuration key [${key%%.*}] \`${key#*.}\`" >&2
            missing=1
        fi
    done
    [ "$missing" -eq 0 ] || exit 1
    echo "guide documents all ${#config_keys[@]} configuration keys"
fi

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DFIRMLINE_SANITIZE=ON
cmake --build build -j2
ctest --test-dir build --output-on-failure

if [ -d tests/integration ]; then
    python3 -m unittest discover -s tests/integration -v
fi
