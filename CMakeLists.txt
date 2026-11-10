# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20)
project(firmline VERSION 0.1.0 LANGUAGES C)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(_agent_default ON)
else()
  set(_agent_default OFF)
endif()
option(FIRMLINE_BUILD_AGENT "Build the Linux agent" ${_agent_default})
option(FIRMLINE_BUILD_TESTS "Build the unit tests" ON)
option(FIRMLINE_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(FIRMLINE_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

include(cmake/mbedtls.cmake)

# Warnings as errors apply to the SDK's own targets only, never to Mbed TLS.
set(FIRMLINE_WARNINGS -Wall -Wextra -Werror)

if(FIRMLINE_BUILD_TESTS)
  enable_testing()
endif()

add_subdirectory(core)

if(FIRMLINE_BUILD_AGENT AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/linux/CMakeLists.txt")
  add_subdirectory(linux)
endif()
