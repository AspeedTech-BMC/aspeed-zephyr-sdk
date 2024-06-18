/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include "plat_mctp.h"

LOG_MODULE_REGISTER(mctp, CONFIG_LOG_DEFAULT_LEVEL);

void init_pfr_mctp(void)
{
	plat_mctp_init();
}

