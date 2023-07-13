/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <init.h>
#include <zephyr.h>
#include <logging/log.h>
#include <drivers/gpio.h>
#include <sys/sys_io.h>

#define LOG_MODULE_NAME board
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

// SPI2 Timing Compensation
#if DT_NODE_HAS_STATUS(DT_NODELABEL(spi2), okay)
#define DEV_SPI_2
#define SPI94_CE0_TIMING_CTRL (0x0094)
#define SPI98_CE1_TIMING_CTRL (0x0098)
// HCLK/4(50MHz)
#define SPI2_50MHZ_HCYCLE 3
#define SPI2_50MHZ_DELAY_NS 7
// HCLK/5(40MHz)
#define SPI2_40MHZ_HCYCLE 2
#define SPI2_40MHZ_DELAY_NS 7
#endif

/*
 * If the data distribution is too monotonous(ex: flash data all 0xff),
 * the calibration operation cannot be executed.
 * To support qspi 50MHz or 40MHz for spi2,
 * adds fixed calibration value if spi drivers do auto-calibration failed.
 * The calibration value is provided by spi drivers,
 * please see aspeed_spi_timing_calibration function for detail to get the hcycle and delay_ns.
 * The calibration value may be difference in the different board.
 * So, strongly suggests users to update hcycle and delay_ns at the development stage
 * for users PROT module.
 */
static int ast1060_prot_post_init(const struct device *arg)
{
#ifdef DEV_SPI_2
	mm_reg_t spi2_ctrl_base = DT_REG_ADDR_BY_NAME(DT_NODELABEL(spi2), ctrl_reg);
	uint32_t final_delay = 0;
	uint32_t calib_val = 0;
	uint32_t delay_ns = 0;
	uint32_t hcycle = 0;
	uint32_t reg_addr;
	uint32_t reg_val;

	// 50MHZ
	hcycle = SPI2_50MHZ_HCYCLE;
	delay_ns = SPI2_50MHZ_DELAY_NS;
	final_delay = (BIT(3) | hcycle | (delay_ns << 4));
	reg_addr = spi2_ctrl_base + SPI94_CE0_TIMING_CTRL;
	reg_val = sys_read32(reg_addr);
	calib_val = sys_read32(reg_addr) & 0x00ff0000;
	if (!calib_val) {
		LOG_INF("set fixed calibration value(%x) for spi2_cs0 50MHz", final_delay);
		sys_write32((reg_val | (final_delay << 16)), reg_addr);
	}

	reg_addr = spi2_ctrl_base + SPI98_CE1_TIMING_CTRL;
	reg_val = sys_read32(reg_addr);
	calib_val = sys_read32(reg_addr) & 0x00ff0000;
	if (!calib_val) {
		LOG_INF("set fixed calibration value(%x) for spi2_cs1 50MHz", final_delay);
		sys_write32((reg_val | (final_delay << 16)), reg_addr);
	}

	// 40MHZ
	final_delay = 0;
	hcycle = SPI2_40MHZ_HCYCLE;
	delay_ns = SPI2_40MHZ_DELAY_NS;
	final_delay = (BIT(3) | hcycle | (delay_ns << 4));
	reg_addr = spi2_ctrl_base + SPI94_CE0_TIMING_CTRL;
	reg_val = sys_read32(reg_addr);
	calib_val = sys_read32(reg_addr) & 0xff000000;
	if (!calib_val) {
		LOG_INF("set fixed calibration value(%x) for spi2_cs0 40MHz", final_delay);
		sys_write32((reg_val | (final_delay << 24)), reg_addr);
	}

	reg_addr = spi2_ctrl_base + SPI98_CE1_TIMING_CTRL;
	reg_val = sys_read32(reg_addr);
	calib_val = sys_read32(reg_addr) & 0xff000000;
	if (!calib_val) {
		LOG_INF("set fixed calibration value(%x) for spi2_cs1 40MHz", final_delay);
		sys_write32((reg_val | (final_delay << 24)), reg_addr);
	}
#endif

	return 0;
}

static int ast1060_prot_init(const struct device *arg)
{
	return 0;
}

SYS_INIT(ast1060_prot_post_init, POST_KERNEL, 85);
SYS_INIT(ast1060_prot_init, APPLICATION, 0);
