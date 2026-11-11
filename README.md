# Firmline SDK

Reference SDK for devices that talk to the Firmline platform. It helps a manufacturer of connected
devices register its devices, report their state and apply signed updates.

It has two parts:

- **core** (`core/`): a small C library without allocation, I/O or clock access (time is a
  parameter): JSON, offer checks (signature, tenant, family, component, version), the download
  check, the update queue, and the status and result messages. It builds with Mbed TLS and is meant
  to run on a microcontroller as well as on Linux.
- **Linux agent** (`linux/`): `firmline-agent`, a program built on the core that registers the
  device, keeps the broker connection, reports the status, downloads and installs signed updates
  with a script of yours, and renews the device certificate.

## Status

| Component | State |
| --- | --- |
| Core library | ready |
| Linux agent for generic Linux (install script) | ready |
| Docker and Torizon (`install = docker-compose`) | planned (T179) |
| Zephyr | planned (T180) |

## Start here

The guide for generic Linux is [docs/integration.md](docs/integration.md): build or image,
configuration, registration, the install script contract, renewal, relay, data folder, logs and a
check list for a trial on a real device. An example for a Debian device is in
[examples/debian-script](examples/debian-script), and a systemd unit in
[linux/systemd/firmline-agent.service](linux/systemd/firmline-agent.service).

## Build and test

Everything builds and is tested in a container, so the same steps work on any workstation with
Docker:

```
scripts/check.sh
```

It builds the development image, checks the formatting, builds with the sanitizers, and runs the
unit and integration tests. The agent image is built from `linux/Dockerfile`.

## Licence

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
