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
WORKDIR /work
