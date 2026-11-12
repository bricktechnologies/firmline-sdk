FROM debian:trixie-slim
# docker.io, docker-cli, docker-compose and busybox-static: the Docker daemon of the integration
# tests (tests/integration/docker_host.py) and what its test images are made of.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential cmake ninja-build clang-format libssl-dev libcurl4-openssl-dev \
       libmosquitto-dev mosquitto python3 python3-cryptography python3-paho-mqtt \
       ca-certificates git jq \
       docker.io docker-cli docker-compose busybox-static \
    && rm -rf /var/lib/apt/lists/*
# The container runs privileged (scripts/check.sh), so it is not confined by AppArmor, and a host
# AppArmor profile for /usr/sbin/mosquitto (as on the Ubuntu runners of GitHub) attaches to the
# broker by its path: it may read only /etc/mosquitto, not the configuration the tests write in
# /tmp. A copy at another path, first in PATH, is the broker of the tests.
RUN cp /usr/sbin/mosquitto /usr/local/sbin/mosquitto
WORKDIR /work
