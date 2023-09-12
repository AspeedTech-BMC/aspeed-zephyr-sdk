/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <init.h>
#include <zephyr.h>
#include <drivers/gpio.h>

static int ast10x0_dcscm_post_init(const struct device *arg)
{
	return 0;
}

static int ast10x0_dcscm_init(const struct device *arg)
{
	return 0;
}

SYS_INIT(ast10x0_dcscm_post_init, POST_KERNEL,0);
SYS_INIT(ast10x0_dcscm_init, APPLICATION,0);
