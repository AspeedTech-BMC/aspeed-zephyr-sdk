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
	const struct device *dev;
	dev = device_get_binding("sgpiom_a_d");
	if (dev) {
		LOG_INF("SGPIOM_A_D PIN[3,4,5,18,19,20(RTC_CPU0),23(RTC_CPU1),24] to 1");
		gpio_pin_set_raw(dev, 3, 1);
		gpio_pin_set_raw(dev, 4, 1);
		gpio_pin_set_raw(dev, 5, 1);
		gpio_pin_set_raw(dev, 18, 1);
		gpio_pin_set_raw(dev, 19, 1);
		gpio_pin_set_raw(dev, 20, 1); // RTCRST CPU0
		gpio_pin_set_raw(dev, 24, 1);
		gpio_pin_set_raw(dev, 23, 1); // RTCRST CPU1
	}

	dev = device_get_binding("sgpiom_e_h");
	if (dev) {
		LOG_INF("SGPIOM_E_H PIN[16,17,18,19,20] to 1");
		gpio_pin_set_raw(dev, 16, 1);
		gpio_pin_set_raw(dev, 17, 1);
		gpio_pin_set_raw(dev, 18, 1);
		gpio_pin_set_raw(dev, 19, 1);
		gpio_pin_set_raw(dev, 20, 1);
	}

	dev = device_get_binding("sgpiom_i_l");
	if (dev) {
		LOG_INF("SGPIOM_I_L PIN[2,6,7] to 1");
		gpio_pin_set_raw(dev, 2, 1);
		gpio_pin_set_raw(dev, 6, 1);
		gpio_pin_set_raw(dev, 7, 1);
	}

	return 0;
}

static void sgpio_passthrough_workaround(struct k_timer *timer_id)
{
	const struct device *dev = NULL;
	extern struct k_event pfr_system_event;
	static bool printed = false;

	if (k_event_wait(&pfr_system_event, BIT(0), false, K_NO_WAIT)) {
		LOG_DBG("SGPIO Passthrough");
		uint32_t mask = 0;

		/* Bit 31:0 */
		dev = device_get_binding("sgpiom_a_d");
		mask = 0x00000000;
		if (dev && mask) {
			if (printed == false)
				LOG_WRN("PASSTHROUGH [%s %08x]", dev->name, mask);
			sgpio_passthrough(dev, mask);
		}

		/* Bit 63:32 */
		dev = device_get_binding("sgpiom_e_h");
		mask = 0xFFFFFF00;
		if (dev && mask) {
			if (printed == false)
				LOG_WRN("PASSTHROUGH [%s %08x]", dev->name, mask);
			sgpio_passthrough(dev, mask);
		}

		/* Bit 95:64 */
		dev = device_get_binding("sgpiom_i_l");
		mask = 0xFFFFFFFF;
		if (dev && mask) {
			if (printed == false)
				LOG_WRN("PASSTHROUGH [%s %08x]", dev->name, mask);
			sgpio_passthrough(dev, mask);
		}

		/* Bit 127:96 */
		dev = device_get_binding("sgpiom_m_p");
		mask = 0xFFFFFFFF;
		if (dev && mask) {
			if (printed == false)
				LOG_WRN("PASSTHROUGH [%s %08x]", dev->name, mask);
			sgpio_passthrough(dev, mask);
		}
		if (printed == false)
			printed = true;
	} else {
		static uint32_t count = 0;
		if ((++count & 0xFF) == 0) {
			/* Do not flood the console log */
			LOG_WRN("SGPIO Passthrough wait for BMC Boot complete flag");
		}
	}
}

K_TIMER_DEFINE(dcscm_sgpio_passthrough_workaround,
		sgpio_passthrough_workaround,
		NULL);

static int ast2700_sgpio_workaround_init(void)
{
#define SCU_PIN_CTRL4      0x7e6e241c
	uint32_t pinctrl_val = sys_read32(SCU_PIN_CTRL4);
	pinctrl_val &= ~BIT(12);
	sys_write32(pinctrl_val, SCU_PIN_CTRL4);

	const struct device *dev = device_get_binding("gpio0_m_p");
	if (dev) {
		int ret = gpio_pin_configure(dev, 12, GPIO_OUTPUT);
		ret = gpio_pin_set_raw(dev, 12, 1);
	}

	// I don't have a good value here, so let's starts the workaround
	// after 200ms and runs every 50ms period
	LOG_WRN("AST2700-A0 SGPIO Passthrough Workaround");
	k_timer_start(&dcscm_sgpio_passthrough_workaround, K_MSEC(200), K_MSEC(50));
	return 0;
}

SYS_INIT(ast2700_sgpio_workaround_init, POST_KERNEL, 45);
SYS_INIT(ast2700_dcscm_post_init, POST_KERNEL, 60);
SYS_INIT(ast2700_dcscm_init, APPLICATION, 0);
