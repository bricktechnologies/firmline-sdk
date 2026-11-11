#!/usr/bin/env bash
# The one check every change and the CI run: builds the dev image, then runs scripts/ci-inside.sh
# in it with the repository mounted. The build directory lives in a named Docker volume, so Mbed TLS
# is compiled once and reruns are quick (remove it with: docker volume rm firmline-build). A 1 MiB
# tmpfs at /tmp/firmline-small is the small disk of test_not_enough_space_sends_no_space.
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1   # Git Bash on Windows must not rewrite the Linux paths below

docker build -q -t firmline-dev -f docker/dev.Dockerfile docker >/dev/null
docker run --rm \
    -v "$(pwd):/work" \
    -v firmline-build:/work/build \
    --tmpfs /tmp/firmline-small:size=1m \
    firmline-dev bash scripts/ci-inside.sh
