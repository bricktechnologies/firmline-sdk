# SPDX-License-Identifier: Apache-2.0
# The agent's modules live in a static library so that the unit tests link the same code as the
# executable. OpenSSL, libcurl and libmosquitto are linked by the task that first uses each one.
add_library(firmline_agent_lib STATIC
  src/config.c
  src/store.c
  src/log.c
  src/components.c)
target_include_directories(firmline_agent_lib PUBLIC src)
target_link_libraries(firmline_agent_lib PUBLIC firmline_core)
target_compile_options(firmline_agent_lib PRIVATE ${FIRMLINE_WARNINGS})

add_executable(firmline-agent src/main.c)
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
