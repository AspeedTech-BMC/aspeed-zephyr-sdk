/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <zephyr/drivers/misc/aspeed/pfr_aspeed.h>

#if defined(CONFIG_SPI_MUX_INVERSE)
#define SPIM_EXT_MUX_BMC_PCH        SPIM_EXT_MUX_SEL_1
#define SPIM_EXT_MUX_ROT            SPIM_EXT_MUX_SEL_0
#else
#define SPIM_EXT_MUX_BMC_PCH        SPIM_EXT_MUX_SEL_0
#define SPIM_EXT_MUX_ROT            SPIM_EXT_MUX_SEL_1
#endif

#define BMC_SPI_MONITOR   "spim@1"
#define BMC_SPI_MONITOR_2 "spim@2"
#define PCH_SPI_MONITOR   "spim@3"
#define PCH_SPI_MONITOR_2 "spim@4"

#define CPU0_RST 1  //refer to ASPEED Datasheet V0.8 p.41
#define BMC_SRST 5

enum {
	GPIO_APP_CMD_NOOP  = 0x00,				/**< No-op */
};

int BMCBootHold(void);
int PCHBootHold(void);
int BMCBootRelease(void);
int PCHBootRelease(void);

#if defined(CONFIG_PFR_MCTP_I3C)
#define I3C_MNG_OWNER_BMC     0
#define I3C_MNG_OWNER_ROT     1
void switch_i3c_mng_owner(int owner);
int get_i3c_mng_owner(void);
void RSTPlatformReset(bool assert);
#endif
