# Firmline agent for generic Linux: integration guide

This guide is for the engineer who puts the Firmline agent on a Linux device. It covers what the
agent does, how to build or get it, every configuration key, how a device is registered at the
end-of-line test station, how updates are installed, and what is left on the device.

The agent helps a manufacturer deliver signed updates and report the state of a device to the
Firmline platform. It prepares the data the platform needs; it does not make a product compliant
with any regulation, and what an update does on your device is decided by your install script.

## What the agent does and does not do

The agent (`firmline-agent`) is one program with four commands: `register`, `run`, `status` and
`endpoint`.

It does:

- create the device key on the device and register the device with the platform, using a one-time
  token (`register`);
- keep an MQTT 5 connection to the platform's broker with the device certificate (`run`), publish
  a status message (installed versions, time, uptime) at start and every `status_interval`
  seconds, and again after an update;
- receive update offers, check each one (signature with your update key, tenant, device family,
  component, version), download the file, check its size and SHA-256 against the signed manifest,
  and run your install script with the verified file;
- send exactly one result per release, stored on the device before it is sent, so that a lost
  connection or a reboot never loses it: `installed`, `rejected_signature` (the signature, the key
  identifier, the size or the SHA-256 do not match) or `failed` (anything else), each refusal with
  a detail (see "Results");
- renew the device certificate before it expires.

It does not:

- install anything by itself: how a file is put in place is your script's job;
- decide when to update: the platform offers, the agent applies one release at a time, in arrival
  order;
- run a file that was not completely downloaded and verified;
- change its trust anchor: the platform root received at registration is never replaced, not even
  by a renewal;
- write secrets to its log (see "Logs").

## Requirements, build and image

To build from source:

- a Linux host (the agent uses `posix_spawn`, `/proc` and POSIX file APIs), glibc 2.34 or later;
- CMake 3.24 or later, Ninja or Make, a C99 compiler;
- OpenSSL 3, libcurl 7.85 or later, libmosquitto (with MQTT 5), each with its
  development files (on Debian: `libssl-dev libcurl4-openssl-dev libmosquitto-dev`).

Mbed TLS (used by the core library for signature checks) is fetched and built by CMake at a pinned
version and hash; the machine that builds therefore needs network access the first time.

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DFIRMLINE_BUILD_TESTS=OFF \
      -DFIRMLINE_AGENT_VERSION=1.0.0
cmake --build build --target firmline-agent
```

The result is `build/linux/firmline-agent`. Copy it to the device (for example to
`/usr/bin/firmline-agent`, the path `linux/systemd/firmline-agent.service` uses). `--version`
prints `firmline-agent <version>`, `--help` the commands.

A container image, `ghcr.io/bricktechnologies/firmline-agent` (linux/amd64, linux/arm64 and
linux/arm/v7), is built from `linux/Dockerfile` and published at each release; until the first
release is published, build it yourself with `docker build -f linux/Dockerfile .`. It runs
`firmline-agent run` and keeps its data in the volume `/var/lib/firmline`. Inside the image an
install script runs inside the container; updating the host or other containers is the subject of
the Docker and Torizon support, which is planned and not part of this release.

The image contains no configuration: mount the folder with `agent.conf` and the update key at
`/etc/firmline` (the default path). `run` exits with code 1 on a device that is not registered,
so a container started with a restart policy before registration restarts in a loop, and
`docker exec … register` cannot be used. Register first, with a one-off container on the same
volume (the image's entry point is `firmline-agent`, so the command follows the image name); put
the token file in a folder of its own, mounted writable, because the agent deletes the file:

```
docker run --rm \
    -v firmline-data:/var/lib/firmline \
    -v /etc/firmline:/etc/firmline:ro \
    -v /run/firmline-token:/run/firmline-token \
    ghcr.io/bricktechnologies/firmline-agent \
    register --token-file /run/firmline-token/token --serial SN-000123
```

Then start the long-running container, which runs `run` by default:

```
docker run -d --name firmline-agent --restart unless-stopped \
    -v firmline-data:/var/lib/firmline \
    -v /etc/firmline:/etc/firmline:ro \
    ghcr.io/bricktechnologies/firmline-agent
```

The exit codes and the standard output of `register` are those of "Registration at the end-of-line
test station".

## Set-up in short

1. Build or install the agent and `examples/debian-script/install.sh` (adapted).
2. Write `/etc/firmline/agent.conf` (see `examples/debian-script/agent.conf`) and the update key
   in `/etc/firmline/update.pem`, taken from the «OTA releases» page of your account.
3. At the end-of-line test station, register the device with a one-time token.
4. Enable the service (`linux/systemd/firmline-agent.service`).
5. Run the check list at the end of this guide on a real device.

## Configuration

The file is `/etc/firmline/agent.conf` (`--config <path>` on every command chooses another). It is
an INI file: a `[platform]` section and one `[component <code>]` section for each component. A
line is `key = value`; blank lines and lines starting with `#` or `;` are ignored. The agent
refuses, with the line number, an unknown section or key, a key given twice in a section, a value
it cannot use, a line longer than 1023 bytes and a file with a NUL byte. Write the file when the
image is built; the agent never changes it.

### `[platform]`

| Key | Default | Meaning |
| --- | --- | --- |
| `url` | required | Base address of the platform's HTTPS API. Must start with `https://`. |
| `broker` | required | Host name of the MQTT broker. |
| `broker_port` | `8883` | Port of the broker, 1 to 65535. |
| `ca_file` | system authorities | PEM file with the authorities for the platform's HTTPS (`url`). Only for a platform behind a private authority. The broker is always verified with the root received at registration, not with this file. |
| `update_key` | required | Absolute path of the PEM file with the public key (ECDSA P-256) that signs your releases. Copy it from the «OTA releases» page. The agent does not start with a file that is not a P-256 public key. |
| `family` | none | The device family (UUID). Only for a device registered before the platform sent the family; see "Device family". |
| `serial` | none | Where the agent reads the serial number at registration: `devicetree`, `file:<absolute path>` or `command:<absolute path>`. Without it, `register` needs `--serial`. See "Serial number". |
| `data_dir` | `/var/lib/firmline` | The data folder (see "Data folder"). |
| `os_release` | `/etc/os-release` | The file a version source `os-release:<KEY>` reads. |
| `reboot_command` | none | Program run after an install script exits 10: an absolute path and its arguments separated by spaces, started without a shell, with a limit of 60 seconds. Without it, the install script reboots the device itself. |
| `status_interval` | `3600` | Seconds between two status messages, 1 to 86400. |

### `[component <code>]`

A component is something the platform tracks and updates: the firmware or operating system image,
an application, a configuration package. The code is 1 to 64 characters of `a-z 0-9 . _ -`,
starting with a letter or a digit, and it is the code of the component in the platform. There can be
up to 16 components, and exactly one has `main = true`.

| Key | Default | Meaning |
| --- | --- | --- |
| `main` | `false` | `true` for the one component whose version is the firmware version (`fw`) of the status. |
| `version` | required | Where the installed version is read. `fixed:<version>`, `os-release:<KEY>` (the value of `<KEY>`, upper case, in the `os_release` file), `file:<absolute path>` (first line of the file) or `command:<absolute path>` (first line of its output; run without a shell, with a limit of 10 seconds). A version is 1 to 64 characters. |
| `install` | `none` | `script:<absolute path>` or `none`. |
| `timeout` | `600` | Seconds the install script may run, 1 to 86400. After that the agent kills it and the result is `failed install_failed`. |

`install = docker-compose` is refused for now (Docker support is planned).

The version is read every time the agent needs it (for each status, and to settle an update), not
once at start. A `fixed:` version never changes: use it only for a component the agent does not
update, or for a first trial.

## Serial number

`register` sends the serial number of the device (1 to 64 bytes: the first line of what is read,
without spaces at the sides). It comes from one of three places, never two at once:

- `--serial <serial>` on the command line, when the configuration has no `serial`;
- `serial = devicetree`: the file `/proc/device-tree/serial-number` (a device tree string ends with
  a NUL byte; the agent stops at it);
- `serial = file:<path>`: the first line of a file, for a serial written at the end-of-line test;
- `serial = command:<path>`: the first line of the output of a program (no shell, 10 seconds).

When the configuration gives a source and `--serial` is given too, `register` refuses with exit
code 1.

## Registration at the end-of-line test station

The platform issues a one-time registration token for a device (see the registration page of your
account). At the test station, as root, on the device:

```
firmline-agent register --token-file /run/firmline-token --serial SN-000123
```

The agent creates the device key (ECDSA P-256) and a certificate signing request on the device,
sends the request with the token and the serial number to the platform, and writes the identity
in the data folder: `device.pem`, `chain.pem`, `root.pem`, `device.key` and, last, `device.json`.
A device is registered when `device.json` exists; a crash in between leaves a device that is not
registered. After a refusal or a network error that did not reach the platform's answer, `register` can run again (with the same token when the file was kept, see the table). After a successful `register`, start the service: `systemctl start firmline-agent` (or reboot); a unit enabled before registration is skipped at boot (see "The systemd unit").

Prefer `--token-file <path>` to `--token <token>`: an argument is visible to every user in the
process list. The first line of the file is the token. The agent deletes the file after a
successful registration and after a final refusal of the platform; it keeps it when you can retry
with the same token (a network error, or the answer 429).

Registration always goes to the platform's address in the configuration, directly: the platform
refuses a registration that comes through a relay (see "Relay").

Exit codes and standard output:

| Exit | Standard output | Meaning |
| --- | --- | --- |
| `0` | the `deviceId` | Registered. |
| `1` | empty, or `already_registered` | Usage error, configuration error or a local failure (the message is on the log, standard error). `already_registered` when `device.json` already exists: the agent never registers twice. If the platform answered 200 but the data folder cannot be written, the token is used up and deleted: revoke the device on the platform and register again with a new token. |
| `2` | the platform's error code (`http_<status>` when the answer has no readable code) | The platform refused. The token file is deleted, except after the answer 429 (too many requests), when it is kept. |
| `3` | `network_error` | A network or TLS error, or a platform error (5xx): the request did not get an answer, the token file is kept, try again with the same token. Also when a 200 cannot be read: the token is probably already used, so a retry gets `provisioning_token_invalid`; revoke the device on the platform and register again with a new token. |

A test station reads standard output and the exit code; it never has to parse the log.

## Components, updates and the install script

### The update path

An offer arrives on the device's offer topic. For each offer the agent:

1. checks the signed manifest: signature (ES256) with the `update_key`, key identifier, tenant,
   device family, component, version, `notBefore` and, unless the manifest allows a rollback, that
   the version is not older than the installed one; a refused offer gets its result at once;
2. queues it (up to 8 releases, oldest first) and works on one release at a time;
3. downloads the file from the link in the offer, keeps it as a partial file, hashes it while it
   arrives, and resumes after an interruption or a restart (the bytes already on disk are hashed
   again). The answer 429 is retried after 60 seconds, a server error or a network error after 5
   to 60 seconds, for up to one hour after the agent received the link (a new offer brings a new
   link and a new hour; after a restart of the agent the hour counts from the restart). Whether
   the link is still valid is the server's answer, not the device clock's: the agent always tries
   the link, so a wrong device clock does not block updates (it only logs a warning that the
   device clock may be wrong). A network error or an expired link (the platform answers 404) is
   not a result: the platform offers the release again;
4. checks size and SHA-256 against the manifest; a wrong file is `rejected_signature` with
   `size_mismatch` or `hash_mismatch` and is never installed;
5. runs the install script of the component with the verified file;
6. sends the result and stores it (the 32 most recent are kept); an offer for a release that
   already has a result gets that result again, nothing else.

If there is not enough free space in the data folder for the file, the result is
`failed no_space`.

### Results

A release gets one of three results:

| Result | When | Detail |
| --- | --- | --- |
| `installed` | The install script succeeded (see "The script contract"). | none; `fw` is the new version |
| `rejected_signature` | The signature or the key identifier of the manifest is not valid, or the downloaded file differs from the manifest in size or SHA-256. | `signature_invalid`, `kid_mismatch`, `size_mismatch`, `hash_mismatch` |
| `failed` | Any other refusal or error. | `format_unknown`, `tenant_mismatch`, `family_mismatch`, `family_unknown`, `component_mismatch`, `older_version`, `no_space`, `install_failed`, `boot_failed` |

On the platform the first `rejected_signature` of a release pauses the whole release, for every
device. A site proxy or cache that alters downloaded files therefore pauses the rollout: let the
download links through unchanged. `failed` closes the release for that device only: a new release
is needed for it to try again.

### The script contract

For a component with `install = script:<path>` the agent runs

```
<script> <file> <version> <release>
```

- `<file>` is the verified file (in the data folder, `download-<release>.bin`; the agent removes it
  after the script ends), `<version>` the version of the manifest and `<release>` the release
  identifier;
- the script runs without a shell from the agent's side (so the file must be executable and start
  with `#!` if it is a script), with the working folder `/`, standard input on `/dev/null`, and
  only the descriptors 0, 1 and 2 open. The environment of the agent is passed on;
- its standard output and standard error are read line by line into the agent's log, each line
  prefixed with `script: `. Do not print secrets;
- it runs in a process group of its own, in the background: the agent keeps its broker connection
  while the script runs;
- the exit code decides:

| Exit | Result |
| --- | --- |
| `0` | Installed. The agent sends `installed` with the manifest version. The version source of the component should now report that version. |
| `10` | Installed, effective at the next boot. The agent writes `install.json` (release, component, version and the boot identifier), runs `reboot_command` if the configuration has one, and sends no result yet. Otherwise the script must reboot the device itself. After the boot the agent reads the version: the one of the manifest is `installed`, any other (or none) is `failed boot_failed`. If only the agent restarts in the same boot, it keeps waiting and, when `reboot_command` is set, runs it again. |
| any other, or ended by a signal | `failed install_failed`. |
| no exit within `timeout` | The agent kills the process group: `failed install_failed`. |

A script that the agent's own stop ended (the agent got SIGTERM while it ran) is not a verdict: the
next start of the agent reads the version of the component and reports `installed` when it is the
new one, `failed install_failed` otherwise.

The same holds after a power loss, or a stop of the device, while the script runs: at the next
start the agent reads the version of the component: the new one is `installed`, any other (or
none) is `failed install_failed`, and the platform does not offer that release to the device
again: the device needs a new release. So the script should leave the device in a working state
when it is interrupted at any point: `examples/debian-script/install.sh` copies the file into
place with a rename, writes the version file last, and exits 0.

### Components with `install = none`

A component with `install = none` (the default) is only reported: its version is in each status
message, but the agent never installs it. An offer for it is answered `failed component_mismatch`.
Use it for a component updated by another means that you still want to see on the platform.

### Device family

An offer is for a device family, and the agent refuses an offer for another one (`failed
family_mismatch`). The family comes from the platform, in the answer to the registration and to a
certificate renewal; it is stored in `device.json`. The `family` key of the configuration is only
for devices registered before the platform sent it, until the first renewal brings it. With
neither, the agent answers every offer `failed family_unknown` and says so in its log.

## Certificate renewal

The device certificate is renewed automatically, from 60 days before it expires: the agent checks
at start and after each status message, and tries at most once a day. It creates a new key,
sends a request with a proof made with the current key, and receives the new certificate and chain.

The new certificate has to chain to the root received at registration: the agent never changes its
trust root. The new key and the exact request are saved before the request goes out, so a lost
answer is recovered by sending the same request again. The swap of the files is made so that a
crash at any moment leaves a device that can connect (the old pair stays until the new one is
complete). The new certificate is presented at the next broker connection.

If the clock is past the expiry of the certificate, nothing is sent (a clock that jumped forward
comes back). `firmline-agent status` shows `certificateNotAfter`.

### Registering again

A device whose certificate has expired cannot renew it: for example a device kept in a store for
more than two years, or one that never reached the platform in its last 60 days. The log then
says `the device certificate expired on <date> and cannot be renewed: register the device again
with a new token` (or, for an identity with missing files, `the identity in <folder> is
incomplete`). `register` refuses with `already_registered` while `device.json` exists, so:

1. Stop the agent: `systemctl stop firmline-agent` (or stop its container).
2. In the data folder, remove the old identity and everything that belongs to it, and nothing
   else:

   ```
   cd /var/lib/firmline
   rm -f device.json device.key device.pem chain.pem root.pem device-chain.pem register.key \
         connection.json renewal.json renewal-* \
         offer-*.json download-* install.json result-*.json
   ```

   These are the identity that `register` checks and writes, the renewal state of the old
   certificate (a renewal left half-way would otherwise put the old certificate back), the time
   of the last connection, and the offers, downloads, install state and results of the old
   identity (the new device on the platform has releases of its own). `endpoint.json` stays: the
   relay is a setting of the site, not of the identity; remove it too (or run `firmline-agent
   endpoint --direct`) if the device moves to another site.
3. Get a new one-time registration token from the registration page of your account.
4. Run `register` as in "Registration at the end-of-line test station" (with the container image,
   as in "Requirements, build and image").
5. Start the agent again: `systemctl start firmline-agent` (or start the container).

## Relay

A site can reach the platform through a relay of the company. On the device:

```
firmline-agent endpoint --relay relay.example [--https-port 443] [--broker-port 8883]
firmline-agent endpoint --direct
```

`--relay` writes `endpoint.json` in the data folder (the default ports are 443 for HTTPS and 8883
for the broker); `--direct` removes it, and the addresses of the configuration apply again. Through
the relay every HTTPS request (renewal, downloads) and the broker connection are verified with the
root received at registration (`root.pem`), because the relay's certificates are issued by the
company's intermediate authority; `ca_file` does not apply. The relay name given to `--relay` is
a host name or an IP address, used for the broker and the renewal. Download links, however, are
written by the relay with its download name (set on the relay as `FIRMLINE_RELAY_DOWNLOAD_NAME`,
by default the first of its local names), so the device must be able to resolve and reach that
name too: with `--relay 192.168.1.10` the broker and the renewal work, but a link to
`https://relay.plant.local/…` fails if the device cannot resolve `relay.plant.local`. The
simplest set-up is to give `--relay` the relay's download name.

A running agent reads `endpoint.json` before each connection to the broker, so the change takes
effect at its next connection; restart the service to apply it at once. Registration never goes
through a relay.

## `status`

`firmline-agent status` prints one JSON object from the files of the data folder and does not use
the network or run any command: `registered`, `deviceId`, `familyId`, `certificateNotAfter`,
`endpoint` (`direct` or `relay`), `lastConnection`, `queue` (the stored offers: release, component,
version) and `pendingInstall` (an install running, or waiting for a restart). A value that is not
known is `null`. It is meant for the test station and for support.

## Data folder

The data folder (`data_dir`, `/var/lib/firmline` by default) is created with mode `0700`. Every
file is written atomically (a temporary file in the same folder, `fsync`, rename, `fsync` of the
folder), so a power loss leaves the old file or the new one, never half of one; temporary files
left by an interrupted write are removed at the next start. Do not edit anything by hand while the
agent runs. Back it up with the device only if you want the identity to follow a replaced disk;
never copy it to a second device.

| File | What it is |
| --- | --- |
| `device.json` | The identity: `deviceId`, `familyId`, client identifier, topic root and offer topic. Written last at registration; its existence is what "registered" means. |
| `device.key` | The device private key (PKCS#8, mode `0600`). Never leaves the device. |
| `device.pem` | The device certificate. |
| `chain.pem` | The certificate chain: the intermediate authority, then the root. |
| `root.pem` | The platform root received at registration. The trust anchor for the broker, the relay and the renewal; never replaced. |
| `device-chain.pem` | `device.pem` followed by the intermediate: what is presented to the broker. Made by the agent. |
| `connection.json` | The time of the last connection to the broker, for `status`. |
| `endpoint.json` | The relay, while one is set. |
| `renewal.json` | The time of the last renewal attempt (at most one a day). |
| `renewal-new.key`, `renewal-request.json` | A renewal in progress: the new key and the exact request. Removed after the swap or a final refusal. |
| `renewal-device.pem`, `renewal-chain.pem`, `renewal-device.json`, `renewal-commit` | The files of the swap after a renewal, until it is complete. |
| `register.key` | The new key during `register`, until the identity is saved. |
| `offer-<release>.json` | An offer as received, while its release is queued. |
| `download-<release>.part` | The bytes of a download so far; `.bin` is the verified file while its script runs. |
| `install.json` | An install in progress (release, component, version, state, boot identifier): present while a script runs or waits for the restart. |
| `result-<release>.json` | The result of a release as it is (or was) sent, and whether the broker confirmed it. The 32 most recent are kept. |

The release in a file name is the release identifier in lower case. Free disk space for the data
folder: the largest file you ship plus 1 MiB.

## Logs

The agent writes one line per event to standard error, `<level> <text>` with the level `info`,
`warning` or `error` and no time (journald adds one). Under systemd, read it with
`journalctl -u firmline-agent`. A line is at most 1024 bytes, and line breaks in a value are
replaced with spaces. The output of install scripts is in the same log, prefixed with `script: `.

The agent never writes to its log: the registration token, a download link, the private key,
certificates, the contents of a file it downloaded. It names the `deviceId`, a release, a result
code and the platform's error code. What your scripts print is logged as is: do not print secrets.

libcurl does the HTTPS requests (registration, renewal, downloads) and honours the standard proxy
environment variables: `https_proxy`, `no_proxy` and their upper-case forms. Set them in the
service environment (`Environment=` in the unit) when the device is behind a proxy. The MQTT
connection to the broker does not use a proxy: for a site that only has a proxy, use a relay.

## Security notes

- `device.key` is mode `0600`, owned by the user that runs the agent. The data folder is `0700`.
- The agent runs as root, because install scripts normally need to write to the system. That also
  means anyone who can write the configuration, the update key or the install script can run code
  as root: keep `/etc/firmline`, the script and its folder writable by root only.
- Keep the `update_key` from the «OTA releases» page; it is the public key that signs your releases.
  The agent refuses every offer whose signature or key identifier does not match it. If the key on
  the platform is replaced, put the new public key on the devices before releases are signed with it.
- The registration token is a secret until it is used: use `--token-file`, in a folder only root can
  read (`/run` is a memory file system), and do not put it in the image.
- The broker and the platform are verified on every connection (TLS 1.2 or later). There is no
  option to switch verification off.
- `FIRMLINE_BOOT_ID_FILE` is an environment variable used by the automated tests to play a reboot
  without rebooting. Never set it in production: it changes how the agent decides that a reboot
  happened.

## The systemd unit

`linux/systemd/firmline-agent.service` runs `firmline-agent run`:

- `Restart=always` and `RestartSec=5`: a crash is retried after 5 seconds. Do not make this
  shorter: the broker bans a device that disconnects more than 15 times a minute, and a crash loop
  would do it.
- `KillMode=mixed`: at a stop only the agent gets SIGTERM. An install script must not receive it
  together with the agent; the agent deals with the script itself.
- `TimeoutStopSec=30`: a stop during an install can take about 11 seconds (up to 5 seconds for a
  script that is ending, then SIGTERM and SIGKILL to the script).
- `ConditionPathExists=/var/lib/firmline/device.json`: the service does not start on a device that
  is not registered yet, which avoids a restart loop. A unit enabled in the image and booted before registration is skipped, and nothing starts it after `register`: run `systemctl start firmline-agent` (or reboot). If you change `data_dir`, change this line too.

## Check list for a trial on a real device

1. `firmline-agent --version` works on the device, and `agent.conf` loads: `firmline-agent status
   --config /etc/firmline/agent.conf` prints `registered` as false and does not complain.
2. The update key is the one of the «OTA releases» page, and the install script is executable.
3. `register` at the test station prints a `deviceId` and exits 0; then run `systemctl start firmline-agent` (or reboot); `status` shows
   `registered` as true, a `certificateNotAfter` date and the `familyId`.
4. After `systemctl start firmline-agent`, the log shows the connection and `status sent`, and the
   platform shows the device with its last contact and version.
5. Release a new version to a test device: the log shows the download, `script:` lines and the
   result, and the version on the platform changes.
6. Try the failure paths that matter for your device: a script that exits 1 (`install_failed`),
   a release for another family (`family_mismatch`), power loss during the download (it resumes),
   and, if you use exit 10, a reboot (`installed`) and a boot that comes back with the old version
   (`boot_failed`).
7. `systemctl stop firmline-agent` during an install stops within 30 seconds, and the next start
   reports the right result.
8. Check the log for the token, a link or a key: there must be none.

## Releases of the SDK (for maintainers)

A tag `vX.Y.Z` on `main` publishes the image `ghcr.io/bricktechnologies/firmline-agent` with the
tags `X.Y.Z` and `X` (a tag with a suffix such as `-rc.1` gets only its own), and attaches the SBOMs
(CycloneDX JSON) of the image and of the source to the GitHub release. The SBOM of the image
describes the platform of the runner that builds it (amd64). Syft finds the Debian packages and
the Actions; `scripts/sbom-components.sh` adds to both SBOMs what is compiled in: the agent itself,
Mbed TLS (version read from `cmake/mbedtls.cmake`, with its CPE) and jsmn (version in
`core/third_party/jsmn/VERSION`); when you update either, keep those files readable by the script
(`tests/integration/test_sbom.py` fails otherwise). The workflow first runs `scripts/check.sh`, and
a tag whose commit is not on `main` publishes nothing. Nothing is published on a pull request or
by running the workflow by hand (that builds the three architectures after the tests).

On the first tag, the GHCR package is created private: make it public in the package settings once.
The organisation must also allow `GITHUB_TOKEN` to create packages.
