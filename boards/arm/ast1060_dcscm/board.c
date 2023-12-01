/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>

static int ast1060_dcscm_post_init(void)
{
	// Enable flash power by GPIOL2 and GPIOL3
	const struct device *dev;
	dev = device_get_binding("gpio0_i_l");
	gpio_pin_configure(dev, 26, GPIO_OUTPUT_ACTIVE);
	gpio_pin_configure(dev, 27, GPIO_OUTPUT_ACTIVE);
	k_busy_wait(10000);
	return 0;
}

static int ast1060_dcscm_init(void)
{
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	const struct device *dev;
	dev = device_get_binding("gpio0_e_h");
	gpio_pin_configure(dev, 27, GPIO_OUTPUT_ACTIVE);
#endif
	return 0;
}

SYS_INIT(ast1060_dcscm_post_init, POST_KERNEL, 60);
SYS_INIT(ast1060_dcscm_init, APPLICATION, 0);
