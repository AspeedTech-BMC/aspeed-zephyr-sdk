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

int BMCBootHold(void);
int PCHBootHold(void);
int BMCBootRelease(void);
int PCHBootRelease(void);

void BMCSPIHold(uint8_t ext_mux_level);
void BMCSPIRelease(uint8_t ext_mux_level);
void init_mp_status_gpios(void);
void set_mp_status(uint8_t status1, uint8_t status2);
