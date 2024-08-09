/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include "flash/flash_aspeed.h"
#include "gpio/gpio_aspeed.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "wdt_utils.h"
#include "wdt_handler.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

extern uint8_t gWdtBootStatus;
/**
 * Monitor the boot progress for BMC firmware with the BMC checkpoint message.
 *
 * A single watchdog timer is used for tracking BMC boot progress.
 *
 * When BMC WDT is actively counting down, BMC checkpoint register is monitored for
 * START/DONE/PAUSE/RESUME/AUTH_FAIL checkpoint messages.
 *
 */
void bmc_wdt_handler(uint8_t cmd)
{
	uint32_t ms_timeout = WDT_BMC_TIMER_MAXTIMEOUT;
	union aspeed_event_data data = {0};
	int type = BMC_TIMER;

	data.bit8[0] = BMC_EVENT;

	if (cmd == ExecutionBlockStrat) {
		pfr_start_timer(type, ms_timeout);
	} else if (cmd == PausingExecutionBlock) {
		pfr_stop_timer(type);
		// BMC stays in uboot or in FFUJ(Force Firmware Update Jumper (FFUJ)) mode
		// Take over i3c MNG
#if defined(CONFIG_PFR_MCTP_I3C)
		SetPfrActivityInfo1(PFR_ACT1_I3C_MUX_TAKEOVER);
		switch_i3c_mng_owner(I3C_MNG_OWNER_ROT);
#endif
	} else if (cmd == ResumedExecutionBlock) {
		pfr_start_timer(type, ms_timeout);
	} else if (cmd == NextExeBlockAuthenticationFail) {
		pfr_stop_timer(type);
		LogWatchdogRecovery(BMC_LAUNCH_FAIL, BMC_WDT_EXPIRE);
		GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
	} else if (cmd == CompletingExecutionBlock || cmd == ReadyToBootOS) {
		// BMC has completed boot
		pfr_stop_timer(type);
		gWdtBootStatus |= WDT_BMC_BOOT_DONE_MASK;
#if defined(CONFIG_BMC_CHECKPOINT_RECOVERY) && defined(CONFIG_INTEL_PFR)
		// Clear the fw recovery level upon successful boot
		reset_recovery_level(BMC_SPI);
#endif
		SetPfrActivityInfo2(PFR_ACT2_BMC_BOOT_DONE);
		log_t0_timed_boot_complete_if_ready(T0_BMC_BOOTED);
	}
}

#if defined(CONFIG_INTEL_PFR)
#ifdef SUPPORT_ME
/**
 * Monitor the boot progress for ME firmware with the ME GPIO
 */
void me_wdt_timer_handler(uint8_t cmd)
{
	union aspeed_event_data data = {0};
	int type = ME_TIMER;

	data.bit8[0] = PCH_EVENT;

	if (cmd == AUTHENTICATION_FAILED) {
		LOG_ERR("ME authentication failed");
		// Stop ME watchdog timer
		pfr_stop_timer(type);
		// Clear previous boot done status
		gWdtBootStatus &= ~WDT_ME_BOOT_DONE_MASK;
		LogWatchdogRecovery(ME_LAUNCH_FAIL, ME_WDT_EXPIRE);
		GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
	} else if (cmd == EXECUTION_BLOCK_COMPLETED) {
		// Stop ME watchdog timer
		pfr_stop_timer(type);
		// When ME firmware booted and authentication pass
		gWdtBootStatus |= WDT_ME_BOOT_DONE_MASK;
		// Clear the fw recovery level upon successful boot of BIOS and ME
#if defined(CONFIG_PCH_CHECKPOINT_RECOVERY) && defined(CONFIG_INTEL_PFR)
		if (gWdtBootStatus & WDT_OBB_BOOT_DONE_MASK)
			reset_recovery_level(PCH_SPI);
#endif
		// Log boot progress
		log_t0_timed_boot_complete_if_ready(T0_ME_BOOTED);
	}
}
#endif

/**
 * Monitor the boot progress of ACM firmware with the ACM checkpoint messages.
 *
 * A single watchdog timer is used for tracking ACM boot progress, because of the ACM ->
 * IBB -> OBB multi-level secure boot flow.
 *
 * ROT arms the ACM watchdog timer upon PLTRST# de-assertion (i.e. on a rising edge). ACM WDT is turned off
 * when BIOS IBB starts to boot (i.e. ROT receives START checkpoint in BIOS checkpoint register). ROT does
 * not process START/DONE message from ACM checkpoint register. ACM may not sends these checkpoint messages in some
 * BootGuard (BtG) profiles. When ACM WDT is actively counting down, ACM checkpoint register is monitored for
 * PAUSE/RESUME/AUTH_FAIL checkpoint messages.
 *
 */
void acm_wdt_handler(uint8_t cmd)
{
	uint32_t ms_timeout = WDT_ACM_TIMER_MAXTIMEOUT;
	union aspeed_event_data data = {0};
	int type = ACM_TIMER;

	data.bit8[0] = PCH_EVENT;

	// Booting ACM
	// Process PAUSE/RESUME/AUTH_FAIL checkpoint message
	if (cmd == EXECUTION_BLOCK_PAUSED) {
		pfr_stop_timer(type);
	} else if (cmd == EXECUTION_BLOCK_RESUMED) {
		pfr_start_timer(type, ms_timeout);
	} else if (cmd == AUTHENTICATION_FAILED) {
		LOG_ERR("ACM authentication failed");
		pfr_stop_timer(type);
		// When there's ACM BtG authentication failure, ACM will pass that information to ME firmware.
		// Wait for ME firmware to clean up and shutdown system.
		k_sleep(K_MSEC(WDT_ACM_AUTH_FAILURE_WAIT_TIME_MS));
		LogWatchdogRecovery(ACM_LAUNCH_FAIL, ACM_IBB_0BB_AUTH_FAIL);
		GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
	}
}

/**
 * Monitor the boot progress of BIOS firmware with the BIOS checkpoint messages.
 *
 * A single watchdog timer is used for tracking BIOS boot progress, because of the ACM ->
 * IBB -> OBB multi-level secure boot flow.
 *
 * Once BIOS IBB sends START checkpoint message, ROT turns off ACM WDT and turns on BIOS IBB WDT. Then, when
 * IBB completes boot, ROT turns off BIOS IBB WDT and turns on BIOS OBB WDT. BIOS boot is considered complete after
 * ROT receives another boot DONE checkpoint message. ROT supports START/DONE/PAUSE/RESUME/AUTH_FAIL checkpoint messages
 * from BIOS.
 *
 */
void bios_wdt_handler(uint8_t cmd)
{
	uint32_t ms_timeout = WDT_BIOS_TIMER_MAXTIMEOUT;
	union aspeed_event_data data = {0};
	int type = BIOS_TIMER;

	data.bit8[0] = PCH_EVENT;

	// Three-stage boot: ACM -> IBB -> OBB
	if (gWdtBootStatus & WDT_IBB_BOOT_DONE_MASK) {
		// Both ACM and IBB have booted. Tracking OBB boot progress now
		if (cmd == EXECUTION_BLOCK_STARTED)
			// Restart OBB timer (initially started after IBB booted)
			pfr_start_timer(type, ms_timeout);
		else if (cmd == EXECUTION_BLOCK_COMPLETED) {
			LOG_INF("OBB boot done");
			// BIOS OBB boot has completed
			gWdtBootStatus |= WDT_OBB_BOOT_DONE_MASK;
			pfr_stop_timer(type);
#if defined(CONFIG_PCH_CHECKPOINT_RECOVERY) && defined(CONFIG_INTEL_PFR)
			// Clear the fw recovery level upon successful boot of BIOS and ME
			if (gWdtBootStatus & WDT_ME_BOOT_DONE_MASK)
				reset_recovery_level(PCH_SPI);
#endif
			// Log boot progress
			SetPfrActivityInfo2(PFR_ACT2_OBB_BOOT_DONE);
			log_t0_timed_boot_complete_if_ready(T0_BIOS_BOOTED);
		} else if (cmd == AUTHENTICATION_FAILED) {
			LOG_ERR("OBB authentication failed");
			pfr_stop_timer(type);
			LogWatchdogRecovery(OBB_LAUNCH_FAIL, ACM_IBB_0BB_AUTH_FAIL);
			GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
		}
	} else {
		// Booting BIOS IBB
		if (cmd == EXECUTION_BLOCK_STARTED) {
			LOG_INF("ACM boot done");
			// ACM has completed booting
			gWdtBootStatus |= WDT_ACM_BOOT_DONE_MASK;
			// Stop ACM timer
			pfr_stop_timer(ACM_TIMER);
			// Log boot progress
			SetPlatformState(T0_ACM_BOOTED);
			// Start the BIOS IBB timer.
			pfr_start_timer(type, ms_timeout);
		} else if (cmd == EXECUTION_BLOCK_COMPLETED) {
			LOG_INF("IBB boot done");
			// BIOS IBB boot has completed
			gWdtBootStatus |= WDT_IBB_BOOT_DONE_MASK;
			// Start the BIOS OBB timer.
			pfr_start_timer(type, ms_timeout);
			SetPfrActivityInfo2(PFR_ACT2_IBB_BOOT_DONE);
		} else if (cmd == AUTHENTICATION_FAILED) {
			LOG_ERR("IBB authentication failed");
			pfr_stop_timer(type);
			LogWatchdogRecovery(IBB_LAUNCH_FAIL, ACM_IBB_0BB_AUTH_FAIL);
			GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
		}
	}

	// Process PAUSE/RESUME
	if (cmd == EXECUTION_BLOCK_PAUSED)
		pfr_stop_timer(type);
	else if (cmd == EXECUTION_BLOCK_RESUMED)
		pfr_start_timer(type, ms_timeout);
}
#else
void bios_wdt_handler(uint8_t cmd)
{
	uint32_t ms_timeout = WDT_BIOS_TIMER_MAXTIMEOUT;
	union aspeed_event_data data = {0};
	int type = BIOS_TIMER;

	data.bit8[0] = PCH_EVENT;

	if (cmd == ExecutionBlockStrat) {
		pfr_start_timer(type, ms_timeout);
	} else if (cmd == PausingExecutionBlock) {
		pfr_stop_timer(type);
	} else if (cmd == ResumedExecutionBlock) {
		pfr_start_timer(type, ms_timeout);
	} else if (cmd == NextExeBlockAuthenticationFail) {
		pfr_stop_timer(type);
		LogWatchdogRecovery(IBB_LAUNCH_FAIL, IBB_WDT_EXPIRE);
		GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
	} else if (cmd == CompletingExecutionBlock || cmd == ReadyToBootOS) {
		// BIOS has completed boot
		pfr_stop_timer(type);
		gWdtBootStatus |= WDT_PCH_BOOT_DONE_MASK;
		log_t0_timed_boot_complete_if_ready(T0_BIOS_BOOTED);
	}
}
#endif // CONFIG_INTEL_PFR
