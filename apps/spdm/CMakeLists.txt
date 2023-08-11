# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.13.1)

find_package(Zephyr HINTS $ENV{ZEPHYR_BASE})

project(ast1030_spdm)

zephyr_link_libraries(dmtf_libspdm)
zephyr_include_directories(dmtf_libspdm)
add_subdirectory(src)
