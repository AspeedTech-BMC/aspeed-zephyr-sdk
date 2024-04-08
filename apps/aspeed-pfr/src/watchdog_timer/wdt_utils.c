/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include "include/SmbusMailBoxCom.h"
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "wdt_utils.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);
uint8_t gWdtBootStatus = 0;

static void wdt_callback_bmc_timeout(struct k_timer *tmr)
{
	union aspeed_event_data data = {0};

	data.bit8[0] = BMC_EVENT;
	LOG_ERR("BMC Boot WDT Timeout");
	LogWatchdogRecovery(BMC_LAUNCH_FAIL, BMC_WDT_EXPIRE);
	GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
	ARG_UNUSED(tmr);
}
#if defined(CONFIG_INTEL_PFR)
static void wdt_callback_acm_timeout(struct k_timer *tmr)
{
	union aspeed_event_data data = {0};

	data.bit8[0] = PCH_EVENT;
	LOG_ERR("ACM Boot WDT Timeout");
	LogWatchdogRecovery(ACM_LAUNCH_FAIL, ACM_WDT_EXPIRE);
	GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
	ARG_UNUSED(tmr);

}

static void wdt_callback_bios_timeout(struct k_timer *tmr)
{
	union aspeed_event_data data = {0};

	data.bit8[0] = PCH_EVENT;
	if (gWdtBootStatus & WDT_IBB_BOOT_DONE_MASK) {
		LOG_ERR("OBB Boot WDT Timeout");
		LogWatchdogRecovery(OBB_LAUNCH_FAIL, OBB_WDT_EXPIRE);
	} else {
		LOG_ERR("IBB Boot WDT Timeout");
		LogWatchdogRecovery(IBB_LAUNCH_FAIL, IBB_WDT_EXPIRE);
	}
	GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
	ARG_UNUSED(tmr);
}

#ifdef SUPPORT_ME
static void wdt_callback_me_timeout(struct k_timer *tmr)
{
	union aspeed_event_data data = {0};

	data.bit8[0] = PCH_EVENT;
	LOG_ERR("ME Boot WDT Timeout");
	LogWatchdogRecovery(ME_LAUNCH_FAIL, ME_WDT_EXPIRE);
	GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
	ARG_UNUSED(tmr);
}
#endif
#else
static void wdt_callback_bios_timeout(struct k_timer *tmr)
{
	union aspeed_event_data data = {0};

	data.bit8[0] = PCH_EVENT;
	LOG_ERR("BIOS Boot WDT Timeout");
	LogWatchdogRecovery(IBB_LAUNCH_FAIL, IBB_WDT_EXPIRE);
	GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
	ARG_UNUSED(tmr);
}
#endif

// init boot timer
K_TIMER_DEFINE(pfr_bmc_timer, wdt_callback_bmc_timeout, NULL);
#if defined(CONFIG_INTEL_PFR)
K_TIMER_DEFINE(pfr_acm_timer, wdt_callback_acm_timeout, NULL);
#ifdef SUPPORT_ME
K_TIMER_DEFINE(pfr_me_timer, wdt_callback_me_timeout, NULL);
#endif
#endif
K_TIMER_DEFINE(pfr_bios_timer, wdt_callback_bios_timeout, NULL);

/**
 * Check if all components (BMC/ME/ACM/BIOS) have completed boot.
 *
 * @return 1 if all components have completed boot. 0, otherwise.
 */
uint8_t is_timed_boot_done(void)
{
	return gWdtBootStatus == WDT_ALL_BOOT_DONE_MASK;
}

void pfr_start_timer(int type, uint32_t ms_timeout)
{
	if (type == BMC_TIMER) {
		LOG_INF("Start BMC Timer");
		k_timer_start(&pfr_bmc_timer, K_MSEC(ms_timeout), K_NO_WAIT);
	}
#if defined(CONFIG_INTEL_PFR)
	else if (type == ACM_TIMER) {
		LOG_INF("Start ACM Timer");
		k_timer_start(&pfr_acm_timer, K_MSEC(ms_timeout), K_NO_WAIT);
	}
#ifdef SUPPORT_ME
	else if (type == ME_TIMER) {
		LOG_INF("Start ME Timer");
		k_timer_start(&pfr_me_timer, K_MSEC(ms_timeout), K_NO_WAIT);
	}
#endif
#endif
	else if (type == BIOS_TIMER) {
		LOG_INF("Start BIOS Timer");
		k_timer_start(&pfr_bios_timer, K_MSEC(ms_timeout), K_NO_WAIT);
	}
}

void pfr_stop_timer(int type)
{
	if (type == BMC_TIMER) {
		LOG_INF("Stop BMC Timer");
		k_timer_stop(&pfr_bmc_timer);
	}
#if defined(CONFIG_INTEL_PFR)
	else if (type == ACM_TIMER) {
		LOG_INF("Stop ACM Timer");
		k_timer_stop(&pfr_acm_timer);
	}
#ifdef SUPPORT_ME
	else if (type == ME_TIMER) {
		LOG_INF("Stop ME Timer");
		k_timer_stop(&pfr_me_timer);
	}
#endif
#endif
	else if (type == BIOS_TIMER) {
		LOG_INF("Stop BIOS Timer");
		k_timer_stop(&pfr_bios_timer);
	}
}

