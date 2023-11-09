# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.13.1)

find_package(Zephyr HINTS $ENV{ZEPHYR_BASE})
project(aspeed-pfr VERSION 01.07 LANGUAGES C)

set(PROJECT_VERSION_MAJOR ${CMAKE_PROJECT_VERSION_MAJOR})
set(PROJECT_VERSION_MINOR ${CMAKE_PROJECT_VERSION_MINOR})

configure_file(build_config.h.in build_config.h)
set(ASPEED_PFR_ROOT ${CMAKE_CURRENT_LIST_DIR})

add_subdirectory(src)

set(CERBERUS_ROOT $ENV{ZEPHYR_BASE}/../middlewares/cerberus)

zephyr_link_libraries(hrot_hal)
zephyr_link_libraries(hrot_wrapper)
zephyr_link_libraries(smf)
zephyr_link_libraries(cerberus)
zephyr_link_libraries(mbedTLS)
zephyr_include_directories(mbedTLS)
zephyr_include_directories(.)
target_include_directories(
	app
	PRIVATE
	${CERBERUS_ROOT}/core
	${CERBERUS_ROOT}/projects/zephyr
	${ASPEED_PFR_ROOT}/src
	${ASPEED_PFR_ROOT}/src/state_machine
	${ZEPHYR_BASE}/include
	${PROJECT_BINARY_DIR}/include/generated
	${CMAKE_CURRENT_BINARY_DIR}
)

