/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <zephyr.h>
#include <build_config.h>
#include <shell/shell.h>
#include <drivers/gpio.h>
#if defined(CONFIG_AST10X0_PROGRAMMER_MP)
#include "mp/mp_util.h"
#else
#include "certificate/cert_prov.h"
#endif
#include "gpio/gpio_ctrl.h"

LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

extern void aspeed_print_sysrst_info(void);

void main(void)
{
	init_mp_status_gpios();

	LOG_INF("*** ASPEED Preload FW version v%02d.%02d Board:%s ***", PROJECT_VERSION_MAJOR, PROJECT_VERSION_MINOR, CONFIG_BOARD);
	aspeed_print_sysrst_info();
#if defined(CONFIG_AST10X0_PROGRAMMER_MP)
	int ret;
	uint32_t time_start, time_end;
	time_start = k_uptime_get_32();
	ret = prog_otp_and_rot();
	if (ret == 0) {
		LOG_INF("OTP and firmware image have been programmed successfully");
		time_end = k_uptime_get_32();
		LOG_INF("MP flow completed, elapsed time = %u milliseconds",
				(time_end - time_start));
	} else {
		LOG_ERR("Failed to update OTP and firmware image");
	}
#else
#if defined(CONFIG_BOARD_AST1060_DCSCM_DICE)
	PROV_STATUS ret;
	BMCBootHold();
	PCHBootHold();

	ret = cert_provision();

	if (ret == PROV_ROT_UPDATE) {
		BMCBootRelease();
		PCHBootRelease();
	}
#endif
#endif
}

static int do_mp_inject(const struct shell *shell, size_t argc, char **argv)
{
	init_mp_status_gpios();
	if (!strcmp(argv[1], "inprog"))
		set_mp_status(0, 0);
	else if (!strcmp(argv[1], "otp"))
		set_mp_status(0, 1);
	else if (!strcmp(argv[1], "fw"))
		set_mp_status(1, 0);
	else if (!strcmp(argv[1], "done"))
		set_mp_status(1, 1);

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(mp_cmds,
		SHELL_CMD_ARG(inject_state, NULL, "inject state: <inprog|fw|otp|done>", do_mp_inject, 2, 0),
		SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(mp, &mp_cmds, "Test MP flow Commands", NULL);
