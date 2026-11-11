FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential cmake ninja-build clang-format libssl-dev libcurl4-openssl-dev \
       libmosquitto-dev mosquitto python3 python3-cryptography python3-paho-mqtt \
       ca-certificates git jq \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
