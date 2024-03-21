/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>

static int ast1060_dcscm_post_init(const struct device *arg)
{
	// Enable flash power by GPIOL2 and GPIOL3
	const struct device *dev;
	dev = device_get_binding("gpio0_i_l");
	gpio_pin_configure(dev, 26, GPIO_OUTPUT_ACTIVE);
	gpio_pin_configure(dev, 27, GPIO_OUTPUT_ACTIVE);
	k_busy_wait(10000);
	return 0;
}

static int ast1060_dcscm_init(const struct device *arg)
{
	// Workaround:
	// Will be removed if zephyr sdk supports changing pin function to GPI Tx when ADC engine
	// is disabled.
#define ADC_ENGINE_CTRL    0x7e6e9000
#define SCU_PIN_CTRL5      0x7e6e2430

	uint32_t pinctrl_val = sys_read32(SCU_PIN_CTRL5);
	uint32_t adc_engine_en = sys_read32(ADC_ENGINE_CTRL);
	if (!(adc_engine_en & 1)) {
		// Enable GPI T0 - T7
		pinctrl_val |= 0xff000000;
		sys_write32(pinctrl_val, SCU_PIN_CTRL5);
	}

	return 0;
}

SYS_INIT(ast1060_dcscm_post_init, POST_KERNEL, 60);
SYS_INIT(ast1060_dcscm_init, APPLICATION, 0);
