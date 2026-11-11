/* SPDX-License-Identifier: Apache-2.0 */
/* The version of the agent, set by the build (-DFIRMLINE_AGENT_VERSION, the image build argument
 * VERSION) and printed by --version. FA_AGENT_NAME_VERSION is what the platform gets of it: the
 * sdk field of each status and the User-Agent of each request. */
#ifndef FIRMLINE_AGENT_VERSION_H
#define FIRMLINE_AGENT_VERSION_H

#ifndef FIRMLINE_AGENT_VERSION
#define FIRMLINE_AGENT_VERSION "0.0.0-dev"
#endif

#define FA_AGENT_NAME_VERSION "firmline-agent/" FIRMLINE_AGENT_VERSION

#endif
