/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <zephyr/kernel.h>

#if !DT_NODE_HAS_STATUS(DT_INST(0, aspeed_pfr_gpio_common), okay)
#error "no correct pfr gpio device"
#endif

#if DT_NODE_HAS_STATUS(DT_INST(0, aspeed_pfr_gpio_bhs), okay)
#define SUPPORT_PLTRST
#define INTEL_BHS
#endif

#if DT_NODE_HAS_STATUS(DT_INST(0, aspeed_pfr_gpio_egs), okay)
#define SUPPORT_ME
#define SUPPORT_PLTRST
#define INTEL_EGS
#endif

#if DT_NODE_HAS_STATUS(DT_INST(0, aspeed_pfr_gpio_genoa), okay)
#define SUPPORT_PLTRST
#define AMD_GENOA
#endif

void bmc_reset_monitor_init(void);
void bmc_reset_monitor_remove(void);
void power_sequence(void);
void platform_monitor_init(void);
void platform_monitor_remove(void);
void power_btn(bool enable);
void pltrst_sync_monitor_init(void);
