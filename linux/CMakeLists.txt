# SPDX-License-Identifier: Apache-2.0
# The agent's modules live in a static library so that the unit tests link the same code as the
# executable.
find_package(OpenSSL 3.0 REQUIRED)
find_package(CURL REQUIRED)
# libmosquitto 2.0 installs no CMake package: its header and library are looked up directly.
find_path(MOSQUITTO_INCLUDE_DIR mosquitto.h REQUIRED)
find_library(MOSQUITTO_LIBRARY mosquitto REQUIRED)

add_library(firmline_agent_lib STATIC
  src/config.c
  src/store.c
  src/log.c
  src/components.c
  src/keys.c
  src/http.c
  src/mqtt.c
  src/service.c
  src/ota.c
  src/renewal.c
  src/install_script.c)
target_include_directories(firmline_agent_lib PUBLIC src)
target_include_directories(firmline_agent_lib SYSTEM PRIVATE ${MOSQUITTO_INCLUDE_DIR})
target_link_libraries(firmline_agent_lib PUBLIC firmline_core OpenSSL::Crypto CURL::libcurl
                                                ${MOSQUITTO_LIBRARY})
# OpenSSL 3 APIs only: what OpenSSL deprecated (EC_KEY and the like) does not even compile.
target_compile_definitions(firmline_agent_lib PUBLIC OPENSSL_API_COMPAT=30000 OPENSSL_NO_DEPRECATED)
target_compile_options(firmline_agent_lib PRIVATE ${FIRMLINE_WARNINGS})

add_executable(firmline-agent src/main.c src/cmd_register.c src/cmd_run.c src/cmd_status.c
                              src/cmd_endpoint.c)
target_link_libraries(firmline-agent PRIVATE firmline_agent_lib)
target_compile_options(firmline-agent PRIVATE ${FIRMLINE_WARNINGS})

if(FIRMLINE_BUILD_TESTS)
  # One executable and one CTest test per linux/tests/test_*.c; the helpers come from the core.
  file(GLOB FIRMLINE_AGENT_TESTS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_*.c")
  foreach(test_source IN LISTS FIRMLINE_AGENT_TESTS)
    get_filename_component(test_name "${test_source}" NAME_WE)
    add_executable(${test_name} "${test_source}")
    target_link_libraries(${test_name} PRIVATE firmline_agent_lib)
    target_include_directories(${test_name} PRIVATE "${PROJECT_SOURCE_DIR}/core/tests")
    target_compile_options(${test_name} PRIVATE ${FIRMLINE_WARNINGS})
    add_test(NAME ${test_name} COMMAND ${test_name})
  endforeach()
endif()
