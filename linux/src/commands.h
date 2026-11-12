/* SPDX-License-Identifier: Apache-2.0 */
/* The commands of firmline-agent. Each takes the arguments after its name and returns the exit
 * code of the process. */
#ifndef FIRMLINE_AGENT_COMMANDS_H
#define FIRMLINE_AGENT_COMMANDS_H

#define FA_DEFAULT_CONFIG "/etc/firmline/agent.conf"

/* register (--token <t> | --token-file <path>) [--serial <s>] [--config <path>].
 * Exit 0 and the deviceId on stdout; 2 and the platform's code when it refuses; 3 and
 * network_error on a network or TLS error (also a 5xx or an answer that cannot be read); 1 on a
 * usage or configuration error, already_registered on stdout when device.json exists. */
int fa_cmd_register(int argc, char **argv);

/* run [--config <path>]: the service (broker connection, status, offers, renewal) until SIGTERM
 * or SIGINT, then exit 0. Exit 1 when it cannot start (usage, configuration, not registered,
 * update_key not a P-256 public key, device.key not the key of device.pem). */
int fa_cmd_run(int argc, char **argv);

/* status [--config <path>]: one JSON object on stdout from the files of the data folder (no
 * network): registered, deviceId, familyId, certificateNotAfter, endpoint, lastConnection,
 * queue, pendingInstall. Exit 0; 1 on a usage or configuration error. */
int fa_cmd_status(int argc, char **argv);

/* endpoint (--relay <host> [--https-port <p>] [--broker-port <p>] | --direct) [--config <path>]:
 * writes or removes endpoint.json in the data folder. Exit 0, or 1 on any error. */
int fa_cmd_endpoint(int argc, char **argv);

/* pack --compose <file> --version <v> --output <file.tar>: the package of a Docker Compose
 * application (cmd_pack.c), built with the docker CLI of this machine. Exit 0; 1 with one error
 * line on stderr and no output file (a file already there is left as it was). */
int fa_cmd_pack(int argc, char **argv);

/* apply --release <id> [--config <path>]: installs the package of the release that run left in
 * the data folder for the docker-compose component (cmd_apply.c, apply.h); the outcome in
 * apply.json. Exit 0 when installed; 1 when failed (apply.json says why) or on a usage or
 * configuration error (no apply.json). */
int fa_cmd_apply(int argc, char **argv);

#endif
