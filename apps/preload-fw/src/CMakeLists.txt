# Copyright (c) 2023 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT
target_sources(app PRIVATE main.c)

# Common layer
add_subdirectory(gpio)
add_subdirectory(otp)

add_subdirectory_ifdef(CONFIG_AST10X0_PROGRAMMER_MP mp)

add_subdirectory_ifdef(CONFIG_BOARD_AST1060_DCSCM_DICE fw_update)
add_subdirectory_ifdef(CONFIG_BOARD_AST1060_DCSCM_DICE sw_mailbox)
add_subdirectory_ifdef(CONFIG_BOARD_AST1060_DCSCM_DICE certificate)
