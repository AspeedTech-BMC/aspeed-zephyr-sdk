/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once
#include <zephyr/smf.h>
#include <zephyr/kernel.h>

#define PRIMARY_FLASH_REGION    1
#define SECONDARY_FLASH_REGION  2

enum aspeed_pfr_state {
	BOOT,
	INIT,
	UNPROVISIONED,
	ROT_RECOVERY,
	TMIN1,
	TZERO,
	FIRMWARE_VERIFY,
	FIRMWARE_RECOVERY,
	FIRMWARE_UPDATE,
	RUNTIME,
	SYSTEM_LOCKDOWN,
	SYSTEM_REBOOT,
#if defined(CONFIG_SEAMLESS_UPDATE)
	SEAMLESS_UPDATE,
	SEAMLESS_VERIFY,
#endif
};

enum aspeed_pfr_event {
	START_STATE_MACHINE,
	INIT_DONE,
	INIT_ROT_SECONDARY_BOOTED,
	VERIFY_UNPROVISIONED,
	VERIFY_FAILED,
	VERIFY_DONE,
	RECOVERY_FAILED,
	RECOVERY_DONE,
	RESET_DETECTED,
	UPDATE_REQUESTED,
	WDT_CHECKPOINT,
	WDT_TIMEOUT,
	UPDATE_DONE,
	UPDATE_FAILED,
	PROVISION_CMD,
	UPDATE_INTENT_2_REQUESTED,
#if defined(CONFIG_SEAMLESS_UPDATE)
	SEAMLESS_UPDATE_DONE,
	SEAMLESS_UPDATE_FAILED,
	SEAMLESS_VERIFY_DONE,
	SEAMLESS_VERIFY_FAILED,
#endif
#if defined(CONFIG_PIT_PROTECTION)
	SEAL_FIRMWARE,
#endif
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	ATTESTATION_FAILED,
#endif
	HANDSHAKE_FAILED,
};

enum OPERATIONS {
	NONE = 0,
	VERIFY_ACTIVE,
	VERIFY_BACKUP,
	RECOVER_ACTIVE,
	RECOVER_BACKUP_IMAGE,
	UPDATE_BACKUP,
#if defined(CONFIG_SEAMLESS_UPDATE)
	SEAMLESS_UPDATE_OP,
#endif
	RELEASE_HOLD,
	I2C_HANDLE
};

#pragma pack(1)
typedef struct _EVENT_CONTEXT {
	/* Operation being Performed*/
	unsigned int operation;
	/* Number Of Retries*/
	unsigned char retries;
	/* BMC image or PCH Image*/
	unsigned int image;
	// Active or Backup Region to Verify.
	// 1 - Active
	// 2 - Backup
	// Identifies region to recover
	// 0 - primary->secondary
	// 1 - secondary->primary
	unsigned int flash;
	unsigned int flag;
} EVENT_CONTEXT;

typedef struct _AO_DATA {
	int type;
	union {
		struct {
			unsigned int ActiveImageVerified : 1;
			unsigned int RecoveryImageVerified : 1;
			unsigned int StagingImageVerified : 1;
			unsigned int InLockdown : 1;
			unsigned int ActiveImageStatus : 1;
			unsigned int RecoveryImageStatus : 1;
			unsigned int RestrictActiveUpdate : 1;
			unsigned int PreviousState : 2;
			unsigned int BootPlatform : 1;
			unsigned int ProcessNewCommand : 1;
			unsigned int processOnce : 1;
		};
		unsigned int flag;
	};
} AO_DATA;
#pragma pack()

union aspeed_event_data {
	/* Data in-place */
	uint32_t bit32;
	uint8_t bit8[4];

	/* Data somewhere else */
	uint8_t *ptr_u8;
	uint32_t *ptr_u32;
	void *ptr;
};

struct event_context {
	/* Reserved for FIFO */
	void *fifo_reserved;

	/* User Defined Event */
	enum aspeed_pfr_event event;
	union aspeed_event_data data;
};

struct smf_context {
	/* Context data for smf */
	struct smf_ctx ctx;

	/* User Define State Data */

	/* Input event, malloc by generator, release by state machine */
	struct event_context *event_ctx;

	/* Firmware state */
	AO_DATA bmc_active_object;
	AO_DATA pch_active_object;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	AO_DATA afm_active_object;
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	AO_DATA cpld_active_object;
#endif
};

extern struct k_fifo aspeed_sm_fifo;
extern enum aspeed_pfr_event event_log[128];
extern size_t event_log_idx;

void GenerateStateMachineEvent(enum aspeed_pfr_event evt, void *data);
void AspeedStateMachine(void);
int is_afm_ready(void);
int is_pltrst_sync(void);
