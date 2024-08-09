/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <zephyr/types.h>
#include <stddef.h>
#include <zephyr/device.h>
#include <zephyr/drivers/misc/aspeed/pfr_aspeed.h>

#define SPI_FILTER_READ_PRIV 0
#define SPI_FILTER_WRITE_PRIV 1

#define SPI_FILTER_PRIV_ENABLE 0
#define SPI_FILTER_PRIV_DISABLE 1

void SPI_Monitor_Enable(const char *dev_name, bool enabled);
int Set_SPI_Filter_RW_Region(const char *dev_name, enum addr_priv_rw_select rw_select, enum addr_priv_op op, mm_reg_t addr, uint32_t len);

