# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.13.1)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(preload-fw VERSION 02.00 LANGUAGES C)

set(PROJECT_VERSION_MAJOR ${CMAKE_PROJECT_VERSION_MAJOR})
set(PROJECT_VERSION_MINOR ${CMAKE_PROJECT_VERSION_MINOR})

configure_file(build_config.h.in build_config.h)
set(PRELOAD_FW_ROOT ${CMAKE_CURRENT_LIST_DIR})

add_subdirectory(src)

zephyr_link_libraries(mbedTLS)
zephyr_include_directories(.)
target_include_directories(
	app
	PRIVATE
	${PRELOAD_FW_ROOT}/src
	${ZEPHYR_BASE}/include
	${PROJECT_BINARY_DIR}/include/generated
	${CMAKE_CURRENT_BINARY_DIR}
)

