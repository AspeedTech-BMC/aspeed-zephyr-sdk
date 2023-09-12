# Copyright (c) 2023 Aspeed
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_PINMUX_ASPEED)
    zephyr_include_directories(.)
endif()
zephyr_library_sources(board.c)
