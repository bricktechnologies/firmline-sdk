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
 * update_key not a P-256 public key). */
int fa_cmd_run(int argc, char **argv);

#endif
