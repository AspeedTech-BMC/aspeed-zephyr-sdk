/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include "platform_monitor/platform_monitor.h"

#define WDT_BMC_TIMER_MAXTIMEOUT CONFIG_BMC_CHECKPOINT_EXPIRE_TIME
#define WDT_ACM_TIMER_MAXTIMEOUT CONFIG_PCH_CHECKPOINT_EXPIRE_TIME
#define WDT_BIOS_TIMER_MAXTIMEOUT CONFIG_PCH_CHECKPOINT_EXPIRE_TIME
#define WDT_ME_TIMER_MAXTIMEOUT CONFIG_PCH_CHECKPOINT_EXPIRE_TIME

// When there's BTG (ACM) authentication failure, ACM will pass that information to ME firmware.
// After ME performs clean up, it shuts down the system. Then ROT can perform the WDT recovery.
// This 2s timeout value is the time needs for ACM/ME communication and ME's clean up
#define WDT_ACM_AUTH_FAILURE_WAIT_TIME_MS 2000

/*
 * Watchdog timer boot progress tracking
 */
#define WDT_BMC_BOOT_DONE_MASK      0b00001
#define WDT_ME_BOOT_DONE_MASK       0b00010
#define WDT_ACM_BOOT_DONE_MASK      0b00100
#define WDT_IBB_BOOT_DONE_MASK      0b01000
#define WDT_OBB_BOOT_DONE_MASK      0b10000
#if defined(CONFIG_INTEL_PFR)
#define WDT_ACM_BIOS_BOOT_DONE_MASK (WDT_ACM_BOOT_DONE_MASK | WDT_IBB_BOOT_DONE_MASK | WDT_OBB_BOOT_DONE_MASK)
#ifdef SUPPORT_ME
#define WDT_PCH_BOOT_DONE_MASK      (WDT_ME_BOOT_DONE_MASK | WDT_ACM_BIOS_BOOT_DONE_MASK)
#else
#define WDT_PCH_BOOT_DONE_MASK      (WDT_ACM_BIOS_BOOT_DONE_MASK)
#endif
#else
#define WDT_PCH_BOOT_DONE_MASK      (WDT_IBB_BOOT_DONE_MASK)
#endif
#define WDT_ALL_BOOT_DONE_MASK      (WDT_BMC_BOOT_DONE_MASK | WDT_PCH_BOOT_DONE_MASK)

enum _pfr_timer {
	BMC_TIMER = 1,
	ACM_TIMER,
	BIOS_TIMER,
	ME_TIMER,
};

uint8_t is_timed_boot_done(void);
void pfr_start_timer(int type, uint32_t ms_timeout);
void pfr_stop_timer(int type);
uint32_t pfr_timer_remaining_get(int type);

