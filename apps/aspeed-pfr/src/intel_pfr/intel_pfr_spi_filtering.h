/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <zephyr/kernel.h>

void apply_pfm_protection(int spi_device_id);
void apply_fvm_spi_protection(uint32_t fvm_addr, int offset);

