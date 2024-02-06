/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/gpio.h>

LOG_MODULE_REGISTER(board);

static int ast2700_dcscm_post_init(void)
{
	// SMB Mux set to OE_N and Selet 0
	const struct device *dev;
	dev = device_get_binding("gpio0_i_l");
	gpio_pin_configure(dev, 26, GPIO_OUTPUT);
	gpio_pin_set_raw(dev, 26, 0);
	gpio_pin_configure(dev, 27, GPIO_OUTPUT);
	gpio_pin_set_raw(dev, 27, 0);
	return 0;
}

static int ast2700_dcscm_init(void)
{
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	const struct device *dev;
	dev = device_get_binding("gpio0_e_h");
	gpio_pin_configure(dev, 27, GPIO_OUTPUT_ACTIVE);
#endif
	return 0;
}

static void sgpio_passthrough_workaround(struct k_timer *timer_id) {
	const struct device *dev = NULL;
	uint32_t mask = 0;

	/* Bit 31:0 */
	dev = device_get_binding("sgpiom_a_d");
	mask = 0x00000000;
	if (dev && mask) {
		LOG_DBG("PASSTHROUGH [%s %08x]", dev->name, mask);
		sgpio_passthrough(dev, mask);
	}

	/* Bit 63:32 */
	dev = device_get_binding("sgpiom_e_h");
	mask = 0xFFFF0000;
	if (dev && mask) {
		LOG_DBG("PASSTHROUGH [%s %08x]", dev->name, mask);
		sgpio_passthrough(dev, mask);
	}

	/* Bit 95:64 */
	dev = device_get_binding("sgpiom_i_l");
	mask = 0xFFFFFFFF;
	if (dev && mask) {
		LOG_DBG("PASSTHROUGH [%s %08x]", dev->name, mask);
		sgpio_passthrough(dev, mask);
	}

	/* Bit 127:96 */
	dev = device_get_binding("sgpiom_m_p");
	mask = 0xFFFFFFFF;
	if (dev && mask) {
		LOG_DBG("PASSTHROUGH [%s %08x]", dev->name, mask);
		sgpio_passthrough(dev, mask);
	}
}

K_TIMER_DEFINE(dcscm_sgpio_passthrough_workaround,
		sgpio_passthrough_workaround,
		NULL);

static int ast2700_sgpio_workaround_init(void)
{
	// I don't have a good value here, so let's starts the workaround
	// after 200ms and runs every 50ms period
	LOG_WRN("AST2700-A0 SGPIO Passthrough Workaround");
	k_timer_start(&dcscm_sgpio_passthrough_workaround, K_MSEC(200), K_MSEC(50));
	return 0;
}

SYS_INIT(ast2700_sgpio_workaround_init, POST_KERNEL, 45);
SYS_INIT(ast2700_dcscm_post_init, POST_KERNEL, 60);
SYS_INIT(ast2700_dcscm_init, APPLICATION, 0);
