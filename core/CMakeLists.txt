# SPDX-License-Identifier: Apache-2.0
file(GLOB FIRMLINE_CORE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

add_library(firmline_core STATIC ${FIRMLINE_CORE_SOURCES})
target_include_directories(firmline_core PUBLIC include)
target_link_libraries(firmline_core PUBLIC mbedcrypto)
target_compile_options(firmline_core PRIVATE ${FIRMLINE_WARNINGS})

if(FIRMLINE_BUILD_TESTS)
  # One executable and one CTest test per core/tests/test_*.c.
  file(GLOB FIRMLINE_CORE_TESTS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_*.c")
  foreach(test_source IN LISTS FIRMLINE_CORE_TESTS)
    get_filename_component(test_name "${test_source}" NAME_WE)
    add_executable(${test_name} "${test_source}")
    target_link_libraries(${test_name} PRIVATE firmline_core)
    target_compile_options(${test_name} PRIVATE ${FIRMLINE_WARNINGS})
    target_compile_definitions(${test_name}
                               PRIVATE FL_VECTOR_DIR="${PROJECT_SOURCE_DIR}/tests/vector")
    add_test(NAME ${test_name} COMMAND ${test_name})
  endforeach()
endif()
