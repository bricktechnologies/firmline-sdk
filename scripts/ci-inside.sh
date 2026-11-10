#!/usr/bin/env bash
# Runs inside the dev container (see scripts/check.sh), from the repository root.
set -euo pipefail
cd "$(dirname "$0")/.."

dirs=(core)
[ -d linux ] && dirs+=(linux)
find "${dirs[@]}" \( -name '*.c' -o -name '*.h' \) -print0 \
    | xargs -0 clang-format --dry-run --Werror

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DFIRMLINE_SANITIZE=ON
cmake --build build -j2
ctest --test-dir build --output-on-failure

if [ -d tests/integration ]; then
    python3 -m unittest discover -s tests/integration -v
fi
