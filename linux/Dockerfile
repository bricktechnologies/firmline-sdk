# SPDX-License-Identifier: Apache-2.0
# The Linux agent image (amd64, arm64, armv7). Build from the repository root:
#   docker build -f linux/Dockerfile --build-arg VERSION=1.2.3 -t firmline-agent .
FROM debian:trixie-slim AS build
ARG VERSION=0.0.0-dev
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential cmake ninja-build libssl-dev libcurl4-openssl-dev libmosquitto-dev \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY cmake cmake
COPY core core
COPY linux linux
# Release build, no sanitizers, no tests; Mbed TLS is fetched with its pinned hash (cmake/mbedtls.cmake).
RUN cmake -S . -B /out -G Ninja -DCMAKE_BUILD_TYPE=Release -DFIRMLINE_BUILD_TESTS=OFF \
          -DFIRMLINE_BUILD_AGENT=ON -DFIRMLINE_AGENT_VERSION="${VERSION}" \
    && cmake --build /out -j2 --target firmline-agent \
    && strip -o /firmline-agent /out/linux/firmline-agent

FROM debian:trixie-slim AS runtime
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="firmline-agent" \
      org.opencontainers.image.description="Firmline Linux agent: registers the device, reports its status and applies signed updates" \
      org.opencontainers.image.source="https://github.com/bricktechnologies/firmline-sdk" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3t64 libcurl4t64 libmosquitto1 \
       docker-cli docker-compose \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /firmline-agent /usr/bin/firmline-agent
VOLUME /var/lib/firmline
ENTRYPOINT ["firmline-agent"]
CMD ["run", "--wait-registration"]
