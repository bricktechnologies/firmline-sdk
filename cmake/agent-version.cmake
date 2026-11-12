# SPDX-License-Identifier: Apache-2.0
# The agent version is sent to the platform in the sdk field of every status ("firmline-agent/" and
# this value, at most 64 bytes) and in the User-Agent. A value the platform refuses would stop all
# status messages without a sign, so the configure step refuses it: 1 to 49 bytes of letters,
# digits and . _ + ~ - (a release version, X.Y.Z or X.Y.Z-pre), no "/", space or control character.
# Included by linux/CMakeLists.txt; also runnable alone (cmake -DFIRMLINE_AGENT_VERSION=x -P).
set(_fl_version_rule "1 to 49 bytes of letters, digits and . _ + ~ -")
string(LENGTH "${FIRMLINE_AGENT_VERSION}" _fl_version_length)
if(_fl_version_length LESS 1 OR _fl_version_length GREATER 49
   OR NOT FIRMLINE_AGENT_VERSION MATCHES "^[A-Za-z0-9._+~-]+$")
  message(FATAL_ERROR
    "FIRMLINE_AGENT_VERSION '${FIRMLINE_AGENT_VERSION}' is not valid: it must be "
    "${_fl_version_rule}, because the platform refuses any other sdk value")
endif()
