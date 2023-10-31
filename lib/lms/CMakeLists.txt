# SPDX-License-Identifier: Apache-2.0

zephyr_interface_library_named(lms)

target_include_directories(lms INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(lms INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/../../modules/crypto/mbedtls/include/)

zephyr_library(lms)

zephyr_library_sources(lmots.c lms.c psa_util.c lms_shell.c)

zephyr_library_link_libraries(lms)
