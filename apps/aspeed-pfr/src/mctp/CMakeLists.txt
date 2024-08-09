# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT
target_sources(app PRIVATE
	cmd_channel_mctp.c
	mctp.c
	mctp_smbus.c
	mctp_task.c
	plat_mctp.c
	)

target_sources_ifdef(CONFIG_PFR_MCTP_I3C app PRIVATE mctp_i3c.c)
target_sources_ifdef(CONFIG_PFR_MCTP_I3C_5_0 app PRIVATE mctp_i3c_target.c)

if(CONFIG_SHELL)
	target_sources(app PRIVATE test_mctp_shell.c)
endif()
