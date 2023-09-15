/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>
#include <storage/flash_map.h>
#include <drivers/i2c.h>
#include <drivers/i2c/pfr/swmbx.h>
#include <drivers/spi_nor.h>
#include <logging/log.h>
#include <drivers/gpio.h>
#include <build_config.h>
#include "Smbus_mailbox.h"
#include "common/common.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_svn.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#include "cerberus_pfr/cerberus_pfr_provision.h"
#include "cerberus_pfr/cerberus_pfr_svn.h"
#endif
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_util.h"

#include "AspeedStateMachine/AspeedStateMachine.h"
#include "watchdog_timer/wdt_utils.h"
#include "watchdog_timer/wdt_handler.h"

LOG_MODULE_REGISTER(mailbox, CONFIG_LOG_DEFAULT_LEVEL);

static uint32_t gFailedUpdateAttempts = 0;
const struct device *gSwMbxDev = NULL;

uint8_t gUfmFifoData[64];
uint8_t gReadFifoData[64];
uint8_t gRootKeyHash[SHA384_DIGEST_LENGTH];
uint8_t gPchOffsets[12];
uint8_t gBmcOffsets[12];
#if defined(CONFIG_PIT_PROTECTION)
uint8_t gPitPassword[8];
#endif

uint8_t gFifoData = 0;
uint8_t gProvisionData = 0;
CPLD_STATUS cpld_update_status;

extern uint8_t gWdtBootStatus;

void ResetMailBox(void)
{
	SetUfmStatusValue(COMMAND_DONE);   // reset ufm status
	SetUfmCmdTriggerValue(0x00);
}

/**
 * Function to Erase th UFM, Key Manifest and State
 * @Param  NULL
 * @retval NULL
 **/
int erase_provision_flash(void)
{
	uint32_t region_size;

	// Erasing provisioned data
	region_size = pfr_spi_get_device_size(ROT_INTERNAL_INTEL_STATE);
	if (pfr_spi_erase_region(ROT_INTERNAL_INTEL_STATE, true, 0, region_size)) {
		LOG_ERR("Erase the provisioned UFM data failed");
		return Failure;
	}

	// Erasing key manifest data
	region_size = pfr_spi_get_device_size(ROT_INTERNAL_KEY);
	if (pfr_spi_erase_region(ROT_INTERNAL_KEY, true, 0, region_size)) {
		LOG_ERR("Erase the key manifest data failed");
		return Failure;
	}

	// Erasing state data
	region_size = pfr_spi_get_device_size(ROT_INTERNAL_STATE);
	if (pfr_spi_erase_region(ROT_INTERNAL_STATE, true, 0, region_size)) {
		LOG_ERR("Erase the state data failed");
		return Failure;
	}

	return Success;
}

/**
 * Function to Erase th UFM
 * @Param  NULL
 * @retval NULL
 **/
int erase_provision_ufm_flash(void)
{
	uint32_t region_size = pfr_spi_get_device_size(ROT_INTERNAL_INTEL_STATE);
	if (pfr_spi_erase_region(ROT_INTERNAL_INTEL_STATE, true, 0, region_size)) {
		LOG_ERR("Erase the provisioned UFM data failed");
		return Failure;
	}

	return Success;
}

/**
 * Function to Initialize Smbus Mailbox with default value
 * @Param  NULL
 * @retval NULL
 **/
int get_provision_data_in_flash(uint32_t addr, uint8_t *DataBuffer, uint32_t length)
{
	int status = pfr_spi_read(ROT_INTERNAL_INTEL_STATE, addr, length, DataBuffer);

	return status;
}

int set_provision_data_in_flash(uint32_t addr, uint8_t *DataBuffer, uint32_t length)
{
	int status;
	uint8_t buffer[PROVISION_UFM_SIZE];

	if (addr + length > ARRAY_SIZE(buffer)) {
		LOG_ERR("offset(0x%x) exceeds UFM max size(%ld)",  addr + length, ARRAY_SIZE(buffer));
		return Failure;
	}

	status = get_provision_data_in_flash(0, buffer, ARRAY_SIZE(buffer));
	if (status != Success)
		return Failure;

	status = erase_provision_ufm_flash();
	if (status != Success)
		return Failure;

	memcpy(buffer + addr, DataBuffer, length);
	pfr_spi_write(ROT_INTERNAL_INTEL_STATE, 0, ARRAY_SIZE(buffer), buffer);

	return status;
}

#define SWMBX_NOTIFYEE_STACK_SIZE 1024

#define TOTAL_MBOX_EVENT 10

struct k_thread swmbx_notifyee_thread;
K_THREAD_STACK_DEFINE(swmbx_notifyee_stack, SWMBX_NOTIFYEE_STACK_SIZE);
K_SEM_DEFINE(ufm_write_fifo_state_sem, 0, 1);
K_SEM_DEFINE(ufm_write_fifo_data_sem, 0, 1);
K_SEM_DEFINE(ufm_read_fifo_state_sem, 0, 1);
K_SEM_DEFINE(ufm_provision_trigger_sem, 0, 1);
K_SEM_DEFINE(bmc_update_intent_sem, 0, 1);
K_SEM_DEFINE(pch_update_intent_sem, 0, 1);
K_SEM_DEFINE(bmc_checkpoint_sem, 0, 1);
K_SEM_DEFINE(acm_checkpoint_sem, 0, 1);
K_SEM_DEFINE(bios_checkpoint_sem, 0, 1);
K_SEM_DEFINE(bmc_update_intent2_sem, 0, 1);
K_SEM_DEFINE(pch_update_intent2_sem, 0, 1);

struct k_mutex write_fifo_mutex;

int swmbx_mctp_i3c_doe_msg_read_handler(uint8_t addr, uint8_t data_len, uint8_t *swmbx_data)
{
	if (data_len > sizeof(gReadFifoData))
		return -1;

	if (addr == UfmReadFIFO) {
		for (int i = 0; i < data_len; i++) {
			if (swmbx_read(gSwMbxDev, true, UfmReadFIFO, &swmbx_data[i]))
				goto error;
		}
	} else {
		if (swmbx_read(gSwMbxDev, false, addr, swmbx_data))
			goto error;
	}

	return 0;

error:
	LOG_ERR("Failed to read mailbox");
	return -1;
}

int swmbx_mctp_i3c_doe_msg_write_handler(uint8_t addr, uint8_t data_len, uint8_t *swmbx_data)
{
	int status;
	union aspeed_event_data data = {0};
	data.bit8[0] = addr;
	data.bit8[1] = *swmbx_data;

	switch(addr) {
	case UfmCommand:
		if (swmbx_write(gSwMbxDev, false, addr, swmbx_data))
			goto error;
		break;
	case UfmCmdTriggerValue:
		data.bit8[0] = UfmCmdTriggerValue;
		if (swmbx_write(gSwMbxDev, false, addr, swmbx_data))
			goto error;
		GenerateStateMachineEvent(PROVISION_CMD, data.ptr);
		break;
	case UfmWriteFIFO:
		status = k_mutex_lock(&write_fifo_mutex, K_MSEC(1000));
		if (status) {
			LOG_ERR("Get write_fifo_mutex timeout, ret %d", status);
			return -1;
		}
		for (int i = 0; i < data_len; i++) {
			if (swmbx_write(gSwMbxDev, true, addr, &swmbx_data[i]))
				goto error;
			gUfmFifoData[gFifoData++] = swmbx_data[i];
		}
		status = k_mutex_unlock(&write_fifo_mutex);
		if (status) {
			LOG_ERR("Release write_fifo_mutex failed, ret %d", status);
			return -1;
		}
		break;
	case BmcCheckpoint:
	case AcmCheckpoint:
	case BiosCheckpoint:
		if (swmbx_write(gSwMbxDev, false, addr, swmbx_data))
			goto error;
		GenerateStateMachineEvent(WDT_CHECKPOINT, data.ptr);
		break;
	case BmcUpdateIntent:
		if (swmbx_write(gSwMbxDev, false, addr, swmbx_data))
			goto error;
		GenerateStateMachineEvent(UPDATE_REQUESTED, data.ptr);
		break;
	case BmcUpdateIntent2:
	case PchUpdateIntent2:
		if (swmbx_write(gSwMbxDev, false, addr, swmbx_data))
			goto error;
		GenerateStateMachineEvent(UPDATE_INTENT_2_REQUESTED, data.ptr);
		break;
	default:
		LOG_ERR("Unsupported mailbox command");
		goto error;
	}

	return 0;

error:
	LOG_ERR("Failed to write mailbox");
	return -1;
}

void swmbx_notifyee_main(void *a, void *b, void *c)
{
	struct k_poll_event events[TOTAL_MBOX_EVENT];

	k_poll_event_init(&events[0], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &ufm_write_fifo_data_sem);
	k_poll_event_init(&events[1], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &ufm_read_fifo_state_sem);
	k_poll_event_init(&events[2], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &ufm_provision_trigger_sem);
	k_poll_event_init(&events[3], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &bmc_update_intent_sem);
	k_poll_event_init(&events[4], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &pch_update_intent_sem);
	k_poll_event_init(&events[5], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &bmc_checkpoint_sem);
	k_poll_event_init(&events[6], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &acm_checkpoint_sem);
	k_poll_event_init(&events[7], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &bios_checkpoint_sem);
	k_poll_event_init(&events[8], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &bmc_update_intent2_sem);
	k_poll_event_init(&events[9], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &pch_update_intent2_sem);

	int ret, status;

	while (1) {
		ret = k_poll(events, TOTAL_MBOX_EVENT, K_FOREVER);

		union aspeed_event_data data = {0};
		if (ret < 0) {
			LOG_ERR("k_poll error ret=%d", ret);
			continue;
		}

		if (events[0].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* UFM Write FIFO from BMC/PCH */
			k_sem_take(events[0].sem, K_NO_WAIT);
			status = k_mutex_lock(&write_fifo_mutex, K_MSEC(1000));
			if (status) {
				LOG_ERR("Get write_fifo_mutex timeout, ret %d", status);
				continue;
			}

			do {
				uint8_t c;

				ret = swmbx_read(gSwMbxDev, true, UfmWriteFIFO, &c);
				if (!ret) {
					gUfmFifoData[gFifoData++] = c;
				}
			} while (!ret && (gFifoData < sizeof(gUfmFifoData)));
			status = k_mutex_unlock(&write_fifo_mutex);
			if (status) {
				LOG_ERR("Release write_fifo_mutex failed, ret %d", status);
				continue;
			}
		} else if (events[1].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* UFM Read FIFO empty prepare next data */
			k_sem_take(events[1].sem, K_NO_WAIT);
		} else if (events[2].state == K_POLL_STATE_SEM_AVAILABLE) {

			/* UFM Provision Trigger */
			k_sem_take(events[2].sem, K_NO_WAIT);
			data.bit8[0] = UfmCmdTriggerValue;
			swmbx_get_msg(0, UfmCmdTriggerValue, &data.bit8[1]);

			GenerateStateMachineEvent(PROVISION_CMD, data.ptr);
		} else if (events[3].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* BMC Update Intent */
			k_sem_take(events[3].sem, K_NO_WAIT);
			data.bit8[0] = BmcUpdateIntent;
			swmbx_get_msg(0, BmcUpdateIntent, &data.bit8[1]);

			GenerateStateMachineEvent(UPDATE_REQUESTED, data.ptr);
		} else if (events[4].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* PCH Update Intent */
			k_sem_take(events[4].sem, K_NO_WAIT);
			data.bit8[0] = PchUpdateIntent;
			swmbx_get_msg(0, PchUpdateIntent, &data.bit8[1]);

			// Only Bit[1:0] and Bit[7:6] have R/W access to PCH/CPU. Other bits are
			// read only.
			data.bit8[1] &= PchActiveRecoveryDynamicUpdateAtReset;
			swmbx_write(gSwMbxDev, false, PchUpdateIntent, &data.bit8[1]);

			if (data.bit8[1] & PchActiveRecoveryDynamicUpdateAtReset)
				GenerateStateMachineEvent(UPDATE_REQUESTED, data.ptr);
		} else if (events[5].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* BMC Checkpoint */
			k_sem_take(events[5].sem, K_NO_WAIT);
			data.bit8[0] = BmcCheckpoint;
			swmbx_get_msg(0, BmcCheckpoint, &data.bit8[1]);

			GenerateStateMachineEvent(WDT_CHECKPOINT, data.ptr);
		} else if (events[6].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* ACM Checkpoint */
			k_sem_take(events[6].sem, K_NO_WAIT);
			data.bit8[0] = AcmCheckpoint;
			swmbx_get_msg(0, AcmCheckpoint, &data.bit8[1]);

			GenerateStateMachineEvent(WDT_CHECKPOINT, data.ptr);
		} else if (events[7].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* BIOS Checkpoint */
			k_sem_take(events[7].sem, K_NO_WAIT);
			data.bit8[0] = BiosCheckpoint;
			swmbx_get_msg(0, BiosCheckpoint, &data.bit8[1]);

			GenerateStateMachineEvent(WDT_CHECKPOINT, data.ptr);
		}
		else if (events[8].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* BMC Update Intent 2 */
			k_sem_take(events[8].sem, K_NO_WAIT);
			data.bit8[0] = BmcUpdateIntent2;
			swmbx_get_msg(0, BmcUpdateIntent2, &data.bit8[1]);

			GenerateStateMachineEvent(UPDATE_INTENT_2_REQUESTED, data.ptr);
		} else if (events[9].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* PCH Update Intent 2 */
			k_sem_take(events[9].sem, K_NO_WAIT);
			data.bit8[0] = PchUpdateIntent2;
			swmbx_get_msg(0, PchUpdateIntent2, &data.bit8[1]);

			GenerateStateMachineEvent(UPDATE_INTENT_2_REQUESTED, data.ptr);
		}

		for (size_t i = 0; i < TOTAL_MBOX_EVENT; ++i)
			events[i].state = K_POLL_STATE_NOT_READY;
	}
}

void InitializeSoftwareMailbox(void)
{
	/* Top level mailbox device driver */
	const struct device *swmbx_dev = NULL;

	int status;

	swmbx_dev = device_get_binding("SWMBX");
	if (swmbx_dev == NULL) {
		LOG_ERR("%s: fail to bind %s", __func__, "SWMBX");
		return;
	}
	gSwMbxDev = swmbx_dev;

	status = k_mutex_init(&write_fifo_mutex);
	if (status) {
		LOG_ERR("%s: fail to init write fifo mutex", __func__);
		return;
	}

	/* Enable mailbox read/write notifiaction and FIFO */
	swmbx_enable_behavior(swmbx_dev, SWMBX_PROTECT | SWMBX_NOTIFY | SWMBX_FIFO, 1);

	/* Register mailbox notification semphore */
	swmbx_update_fifo(swmbx_dev, &ufm_write_fifo_state_sem, 0, UfmWriteFIFO, 0x40, SWMBX_FIFO_NOTIFY_STOP, true);
	swmbx_update_fifo(swmbx_dev, &ufm_read_fifo_state_sem, 1, UfmReadFIFO, 0x40, SWMBX_FIFO_NOTIFY_STOP, true);

	/* swmbx_update_notify(dev, port, sem, addr, enable) */
	/* From BMC */
	swmbx_update_notify(swmbx_dev, 0x0, &ufm_write_fifo_data_sem, UfmWriteFIFO, true);
	swmbx_update_notify(swmbx_dev, 0x0, &ufm_provision_trigger_sem, UfmCmdTriggerValue, true);
	swmbx_update_notify(swmbx_dev, 0x0, &bmc_update_intent_sem, BmcUpdateIntent, true);
	swmbx_update_notify(swmbx_dev, 0x0, &bmc_checkpoint_sem, BmcCheckpoint, true);
	swmbx_update_notify(swmbx_dev, 0x0, &bmc_update_intent2_sem,
			BmcUpdateIntent2, true);

	/* From PCH */
	swmbx_update_notify(swmbx_dev, 0x1, &ufm_write_fifo_data_sem, UfmWriteFIFO, true);
	swmbx_update_notify(swmbx_dev, 0x1, &ufm_provision_trigger_sem, UfmCmdTriggerValue, true);
	swmbx_update_notify(swmbx_dev, 0x1, &pch_update_intent_sem, PchUpdateIntent, true);
	swmbx_update_notify(swmbx_dev, 0x1, &acm_checkpoint_sem, AcmCheckpoint, true);
	swmbx_update_notify(swmbx_dev, 0x1, &bios_checkpoint_sem, BiosCheckpoint, true);
	swmbx_update_notify(swmbx_dev, 0x1, &pch_update_intent2_sem, PchUpdateIntent2, true);

	/* Protect bit:
	 * 0 means readable/writable
	 * 1 means read-only
	 *
	 * Port and access_control[]:
	 * 0 for BMC
	 * 1 for PCH
	 */
	uint32_t access_control[2][8] = {
		/* BMC */
		{
			0xfff704ff, // 1fh ~ 00h
			0xffffffff, // 3fh ~ 20h CPLD RoT Hash
			0xffffffff, // 5fh ~ 40h CPLD RoT Hash
			0xfffffffa, // 7fh ~ 60h
			0xffffffff, // 9fh ~ 80h ACM/BIOS Scrachpad
			0xffffffff, // bfh ~ a0h ACM/BIOS Scrachpad
			0x00000000, // dfh ~ c0h BMC scrachpad
			0x00000000, // ffh ~ e0h BMC scrachpad
		},
		/* PCH */
		{
			0xfff884ff, // 1fh ~ 00h
			0xffffffff, // 3fh ~ 20h CPLD RoT Hash
			0xffffffff, // 5fh ~ 40h CPLD RoT Hash
			0xfffffff5, // 7fh ~ 60h
			0x00000000, // 9fh ~ 80h ACM/BIOS Scrachpad
			0x00000000, // bfh ~ a0h ACM/BIOS Scrachpad
			0xffffffff, // dfh ~ c0h BMC scrachpad
			0xffffffff, // ffh ~ e0h BMC scrachpad
		},
	};
	swmbx_apply_protect(swmbx_dev, 0, access_control[0], 0, 8);
	swmbx_apply_protect(swmbx_dev, 1, access_control[1], 0, 8);

	/* Register slave device to bus device */
	const struct device *dev = NULL;

	dev = device_get_binding("SWMBX_SLAVE_BMC");
	if (dev)
		i2c_slave_driver_register(dev);

	/* TODO: CPU0 */
	dev = device_get_binding("SWMBX_SLAVE_CPU");
	if (dev)
		i2c_slave_driver_register(dev);

	k_tid_t swmbx_tid = k_thread_create(
		&swmbx_notifyee_thread,
		swmbx_notifyee_stack,
		SWMBX_NOTIFYEE_STACK_SIZE,
		swmbx_notifyee_main,
		NULL, NULL, NULL,
		5, 0, K_NO_WAIT);
	k_thread_name_set(swmbx_tid, "Software Mailbox Handler");

}

void InitializeSmbusMailbox(void)
{
	struct pfr_manifest *pfr_manifest = get_pfr_manifest();
	uint8_t sha_buffer[SHA384_DIGEST_LENGTH];
	uint8_t policy_svn;
	int status;
	int i;

	InitializeSoftwareMailbox();
	ResetMailBox();

	SetCpldIdentifier(0xDE);
	SetCpldReleaseVersion((PROJECT_VERSION_MAJOR << 4) | PROJECT_VERSION_MINOR);
	policy_svn = get_ufm_svn(SVN_POLICY_FOR_CPLD_UPDATE);
	SetCpldRotSvn(policy_svn);

	// Generate hash of rot active image
	// default hashing algorithm sha384
	pfr_manifest->flash->state->device_id[0] = ROT_INTERNAL_ACTIVE;
	pfr_manifest->image_type = ROT_INTERNAL_ACTIVE;
	pfr_manifest->pfr_hash->type = HASH_TYPE_SHA384;
	pfr_manifest->pfr_hash->start_address = 0;
	pfr_manifest->pfr_hash->length = pfr_spi_get_device_size(ROT_INTERNAL_ACTIVE);
	status = pfr_manifest->base->get_hash((struct manifest *)pfr_manifest, pfr_manifest->hash, sha_buffer, SHA384_DIGEST_LENGTH);
	if (status != Success)
		LOG_ERR("Get rot hash failed");
	else {
		LOG_HEXDUMP_DBG(sha_buffer, sizeof(sha_buffer), "rot hash:");
		// set rot hash to mailbox
		for (i = 0; i < SHA384_DIGEST_LENGTH; i++)
			swmbx_write(gSwMbxDev, false, CpldFPGARoTHash + i, &sha_buffer[i]);
	}
}

#define MBX_REG_SETTER(REG) \
	void Set##REG(byte Data) \
	{ \
		swmbx_write(gSwMbxDev, false, REG, &Data); \
	}

#define MBX_REG_INC(REG) \
	void Inc##REG() \
	{ \
		byte data; \
		swmbx_read(gSwMbxDev, false, REG, &data); \
		++data; \
		swmbx_write(gSwMbxDev, false, REG, &data); \
	}

#define MBX_REG_GETTER(REG) \
	byte Get##REG(void) \
	{ \
		byte data; \
		swmbx_read(gSwMbxDev, false, REG, &data); \
		return data; \
	}

#define MBX_REG_SETTER_GETTER(REG) \
	MBX_REG_SETTER(REG) \
	MBX_REG_GETTER(REG)

#define MBX_REG_INC_GETTER(REG) \
	MBX_REG_INC(REG) \
	MBX_REG_GETTER(REG)

MBX_REG_SETTER_GETTER(CpldIdentifier);
MBX_REG_SETTER_GETTER(CpldReleaseVersion);
MBX_REG_SETTER_GETTER(CpldRotSvn);
MBX_REG_GETTER(PlatformState);
MBX_REG_INC_GETTER(RecoveryCount);
MBX_REG_SETTER_GETTER(LastRecoveryReason);
MBX_REG_INC_GETTER(PanicEventCount);
MBX_REG_SETTER_GETTER(LastPanicReason);
MBX_REG_SETTER_GETTER(MajorErrorCode);
MBX_REG_SETTER_GETTER(MinorErrorCode);
MBX_REG_GETTER(UfmCommand);
MBX_REG_SETTER_GETTER(UfmCmdTriggerValue);
MBX_REG_SETTER_GETTER(BmcCheckpoint);
MBX_REG_SETTER_GETTER(AcmCheckpoint);
MBX_REG_SETTER_GETTER(BiosCheckpoint);
MBX_REG_SETTER_GETTER(BmcUpdateIntent);
MBX_REG_SETTER_GETTER(PchPfmActiveSvn);
MBX_REG_SETTER_GETTER(PchPfmActiveMajorVersion);
MBX_REG_SETTER_GETTER(PchPfmActiveMinorVersion);
MBX_REG_SETTER_GETTER(BmcPfmActiveSvn);
MBX_REG_SETTER_GETTER(BmcPfmActiveMajorVersion);
MBX_REG_SETTER_GETTER(BmcPfmActiveMinorVersion);
MBX_REG_SETTER_GETTER(PchPfmRecoverSvn);
MBX_REG_SETTER_GETTER(PchPfmRecoverMajorVersion);
MBX_REG_SETTER_GETTER(PchPfmRecoverMinorVersion);
MBX_REG_SETTER_GETTER(BmcPfmRecoverSvn);
MBX_REG_SETTER_GETTER(BmcPfmRecoverMajorVersion);
MBX_REG_SETTER_GETTER(BmcPfmRecoverMinorVersion);
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
MBX_REG_SETTER_GETTER(AfmActiveSvn);
MBX_REG_SETTER_GETTER(AfmActiveMajorVersion);
MBX_REG_SETTER_GETTER(AfmActiveMinorVersion);
MBX_REG_SETTER_GETTER(AfmRecoverSvn);
MBX_REG_SETTER_GETTER(AfmRecoverMajorVersion);
MBX_REG_SETTER_GETTER(AfmRecoverMinorVersion);
MBX_REG_SETTER_GETTER(ProvisionStatus2);
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
MBX_REG_SETTER_GETTER(IntelCpldActiveSvn);
MBX_REG_SETTER_GETTER(IntelCpldActiveMajorVersion);
MBX_REG_SETTER_GETTER(IntelCpldActiveMinorVersion);
#endif

#if defined(CONFIG_FRONT_PANEL_LED)
#include <drivers/timer/aspeed_timer.h>
#include <drivers/led.h>

#define GPIO_SPEC(node_id) GPIO_DT_SPEC_GET_OR(node_id, gpios, {0})
#define LED_DEVICE "leds"
#define TIMER_DEVICE "TIMER0"

static struct aspeed_timer_user_config timer_conf;
static const struct device *led_dev = NULL;
static const struct device *led_timer_dev = NULL;
static const struct device *bmc_fp_green_in = NULL;
static const struct device *bmc_fp_amber_in = NULL;
static bool fp_green_on;
static bool fp_amber_on;
static bool bypass_bmc_fp_signal;

static const struct gpio_dt_spec bmc_fp_green = GPIO_SPEC(DT_ALIAS(fp_input0));
static const struct gpio_dt_spec bmc_fp_amber = GPIO_SPEC(DT_ALIAS(fp_input1));

static struct gpio_callback bmc_fp_green_cb_data;
static struct gpio_callback bmc_fp_amber_cb_data;

enum {
	FP_GREEN_LED  = 0x00,
	FP_AMBER_LED,
};

enum {
	ONE_SHOT_TIMER = 0x00,
	PERIOD_TIMER,
};

void fp_amber_led_ctrl_callback()
{
	fp_amber_on ? led_off(led_dev, FP_AMBER_LED) : led_on(led_dev, FP_AMBER_LED);
	fp_amber_on = !fp_amber_on;
}

void bmc_fp_led_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	int led_id;
	if (bypass_bmc_fp_signal)
		return;

	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	if (gpio_pin == bmc_fp_green.pin)
		led_id = FP_GREEN_LED;
	else if (gpio_pin == bmc_fp_amber.pin)
		led_id = FP_AMBER_LED;
	else
		return;

	int ret = gpio_pin_get(dev, gpio_pin);
	if (ret < 0) {
		LOG_ERR("Failed to get BMC_FP_GREEN_LED status");
		return;
	}

	ret ? led_on(led_dev, led_id) : led_off(led_dev, led_id);
	if (led_id == FP_GREEN_LED)
		fp_green_on = (bool)ret;
	else
		fp_amber_on = (bool)ret;
}

void initializeFPLEDs(void)
{
	// init led
	led_dev = device_get_binding(LED_DEVICE);
	led_off(led_dev, FP_GREEN_LED);
	fp_green_on = false;
	led_off(led_dev, FP_AMBER_LED);
	fp_amber_on = false;

	// init timer
	led_timer_dev = device_get_binding(TIMER_DEVICE);
	timer_conf.millisec = 500;
	timer_conf.timer_type = PERIOD_TIMER;
	timer_conf.user_data = NULL;
	timer_conf.callback = fp_amber_led_ctrl_callback;

	// init bmc_fp_green_led
	bmc_fp_green_in = device_get_binding(DT_GPIO_LABEL(DT_ALIAS(fp_input0), gpios));
	gpio_pin_configure(bmc_fp_green_in, DT_GPIO_PIN(DT_ALIAS(fp_input0), gpios),
			DT_GPIO_FLAGS(DT_ALIAS(fp_input0), gpios) | GPIO_INPUT);
	gpio_pin_interrupt_configure(bmc_fp_green_in, DT_GPIO_PIN(DT_ALIAS(fp_input0), gpios),
			GPIO_INT_EDGE_BOTH);
	gpio_init_callback(&bmc_fp_green_cb_data, bmc_fp_led_handler,
			BIT(DT_GPIO_PIN(DT_ALIAS(fp_input0), gpios)));
	gpio_add_callback(bmc_fp_green_in, &bmc_fp_green_cb_data);

	// init bmc_fp_amber_led
	bmc_fp_amber_in = device_get_binding(DT_GPIO_LABEL(DT_ALIAS(fp_input1), gpios));
	gpio_pin_configure(bmc_fp_amber_in, DT_GPIO_PIN(DT_ALIAS(fp_input1), gpios),
			DT_GPIO_FLAGS(DT_ALIAS(fp_input1), gpios) | GPIO_INPUT);
	gpio_pin_interrupt_configure(bmc_fp_amber_in, DT_GPIO_PIN(DT_ALIAS(fp_input1), gpios),
			GPIO_INT_EDGE_BOTH);
	gpio_init_callback(&bmc_fp_amber_cb_data, bmc_fp_led_handler,
			BIT(DT_GPIO_PIN(DT_ALIAS(fp_input1), gpios)));
	gpio_add_callback(bmc_fp_amber_in, &bmc_fp_amber_cb_data);
}

void SetFPLEDState(byte PlatformStateData)
{
	// FP LED behavior
	//
	// |  Green  |  Amber  | State    |
	// --------------------------------
	// |   Lit   |  Off    | Verify   |
	// |   Off   |  Blink  | Recovery |
	// |   Off   |  Lit    | Update   |
	// | PassThr | PassThr | Tzero    |
	if (PlatformStateData == PCH_FW_UPDATE ||
	    PlatformStateData == BMC_FW_UPDATE ||
	    PlatformStateData == CPLD_FW_UPDATE) {
		bypass_bmc_fp_signal = true;
		timer_aspeed_stop(led_timer_dev);
		led_off(led_dev, FP_GREEN_LED);
		fp_green_on = false;
		led_on(led_dev, FP_AMBER_LED);
		fp_amber_on = true;
	} else if (PlatformStateData == T_MINUS_1_FW_RECOVERY) {
		bypass_bmc_fp_signal = true;
		led_off(led_dev, FP_GREEN_LED);
		fp_green_on = false;
		timer_aspeed_start(led_timer_dev, &timer_conf);
	} else if (PlatformStateData == ENTER_T_MINUS_1) {
		bypass_bmc_fp_signal = true;
		timer_aspeed_stop(led_timer_dev);
		led_on(led_dev, FP_GREEN_LED);
		fp_green_on = true;
		led_off(led_dev, FP_AMBER_LED);
		fp_amber_on = false;
	} else if (PlatformStateData == ENTER_T0) {
		timer_aspeed_stop(led_timer_dev);
		bypass_bmc_fp_signal = false;
		int pin_state = gpio_pin_get(bmc_fp_green_in, bmc_fp_green.pin);
		if (pin_state < 0) {
			LOG_ERR("Failed to get BMC_FP_GREEN_LED");
			return;
		}
		pin_state ? led_on(led_dev, FP_GREEN_LED) : led_off(led_dev, FP_GREEN_LED);
		fp_green_on = pin_state;

		pin_state = gpio_pin_get(bmc_fp_amber_in, bmc_fp_amber.pin);
		if (pin_state < 0) {
			LOG_ERR("Failed to get BMC_FP_AMBER_LED");
			return;
		}
		pin_state ? led_on(led_dev, FP_AMBER_LED) : led_off(led_dev, FP_AMBER_LED);
		fp_amber_on = pin_state;
	}
}
#endif

void SetPlatformState(byte PlatformStateData)
{
#if defined(CONFIG_PLATFORM_STATE_LED)
	// Per RSU IP, platform state should be bit reversed.
	static const struct gpio_dt_spec leds[] = {
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common), platform_state_out_gpios, 7),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common), platform_state_out_gpios, 6),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common), platform_state_out_gpios, 5),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common), platform_state_out_gpios, 4),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common), platform_state_out_gpios, 3),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common), platform_state_out_gpios, 2),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common), platform_state_out_gpios, 1),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common), platform_state_out_gpios, 0)};

	for (uint8_t bit = 0; bit < 8; ++bit) {
		gpio_pin_configure_dt(&leds[bit], GPIO_OUTPUT);
		gpio_pin_set(leds[bit].port, leds[bit].pin, !(PlatformStateData & BIT(bit)));
	}
#endif

#if defined(CONFIG_FRONT_PANEL_LED)
	SetFPLEDState(PlatformStateData);
#endif
	swmbx_write(gSwMbxDev, false, PlatformState, &PlatformStateData);
}

int getFailedUpdateAttemptsCount(void)
{
	return gFailedUpdateAttempts;
}

void LogErrorCodes(uint8_t major_err, uint8_t minor_err)
{
	SetMajorErrorCode(major_err);
	SetMinorErrorCode(minor_err);
}

void LogUpdateFailure(uint8_t minor_err, uint32_t failed_count)
{
	LogErrorCodes(FW_UPDATE_FAIL, minor_err);
	gFailedUpdateAttempts += failed_count;
}

void ClearUpdateFailure(void)
{
	if (GetMajorErrorCode() == FW_UPDATE_FAIL)
		LogErrorCodes(0, 0);
	gFailedUpdateAttempts = 0;
}

void LogLastPanic(uint8_t panic)
{
	SetLastPanicReason(panic);
	IncPanicEventCount();
}

void LogRecovery(uint8_t reason)
{
	SetLastRecoveryReason(reason);
	IncRecoveryCount();
}

void LogWatchdogRecovery(uint8_t recovery_reason, uint8_t panic_reason)
{
	LogRecovery(recovery_reason);
	LogLastPanic(panic_reason);
}

/**
 * Log boot complete status in T0 mode
 *
 * @param current_boot_state the status for the component that has just completed boot
 */
void log_t0_timed_boot_complete_if_ready(const PLATFORM_STATE_VALUE current_boot_state)
{
	CPLD_STATUS cpld_update_status;
	union aspeed_event_data data = {0};
	uint8_t intent = 0;
	uint8_t update_intent_src = BmcUpdateIntent;

	if (is_timed_boot_done()) {
		// If other components have finished booting, log timed boot complete status.
		SetPlatformState(T0_BOOT_COMPLETED);
		ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS,
				(uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
		if (cpld_update_status.Region[BMC_REGION].Recoveryregion == BMC_INTENT_RECOVERY_PENDING) {
			intent = BmcRecoveryUpdate;
		} else if (cpld_update_status.Region[PCH_REGION].Recoveryregion == BMC_INTENT_RECOVERY_PENDING) {
			intent = PchRecoveryUpdate;
		} else if (cpld_update_status.Region[PCH_REGION].Recoveryregion == PCH_INTENT_RECOVERY_PENDING) {
			intent = PchRecoveryUpdate;
			update_intent_src = PchUpdateIntent;
		} else if (cpld_update_status.Region[ROT_REGION].Recoveryregion == BMC_INTENT_RECOVERY_PENDING) {
			intent = HROTRecoveryUpdate;
		}

		if (intent) {
			data.bit8[0] = update_intent_src;
			data.bit8[1] = intent;
			data.bit8[2] |= BootDoneRecovery;
			GenerateStateMachineEvent(UPDATE_REQUESTED, data.ptr);
		}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
		if (cpld_update_status.Region[AFM_REGION].Recoveryregion == BMC_INTENT2_AFM_RECOVERY_PENDING) {
			data.bit8[0] = BmcUpdateIntent2;
			data.bit8[1] = AfmRecoveryUpdate;
			data.bit8[2] |= BootDoneRecovery;
			GenerateStateMachineEvent(UPDATE_REQUESTED, data.ptr);
		}
#endif
	} else {
		// Otherwise, just log the this boot complete status
		SetPlatformState(current_boot_state);
	}
}

// UFM Status
uint8_t GetUfmStatusValue(void)
{
	uint32_t UfmStatus;
	uint8_t data;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));
	swmbx_read(gSwMbxDev, false, UfmStatusValue, &data);

	// set bit4 ~ bit7 status from UFM flash status
	data = data & 0x0f;

	if (CheckUfmStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK))
		data |= UFM_LOCKED;

	if (CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_ROOT_KEY_HASH_BIT_MASK |
			   UFM_STATUS_PROVISIONED_PCH_OFFSETS_BIT_MASK |
			   UFM_STATUS_PROVISIONED_BMC_OFFSETS_BIT_MASK))
		data |= UFM_PROVISIONED;

#if defined(CONFIG_PIT_PROTECTION)
	if (CheckUfmStatus(UfmStatus, UFM_STATUS_PIT_L1_ENABLE_BIT_MASK))
		data |= PIT_LEVEL_1_ENFORCED;

	if (CheckUfmStatus(UfmStatus, UFM_STATUS_PIT_L2_PASSED_BIT_MASK))
		data |= PIT_L2_COMPLETE_SUCCESSFUL;
#endif

	return data;
}

void SetUfmStatusValue(uint8_t UfmStatusBitMask)
{
	uint8_t status = GetUfmStatusValue();

	// only set bit0 ~ bit2
	UfmStatusBitMask &= 0x07;
	status |= UfmStatusBitMask;
	swmbx_write(gSwMbxDev, false, UfmStatusValue, &status);
}

void ClearUfmStatusValue(uint8_t UfmStatusBitMask)
{
	uint8_t status = GetUfmStatusValue();

	// only clear bit0 ~ bit2
	UfmStatusBitMask &= 0x07;
	status &= ~UfmStatusBitMask;
	swmbx_write(gSwMbxDev, false, UfmStatusValue, &status);
}

void SetUfmFlashStatus(uint32_t UfmStatus, uint32_t UfmStatusBitMask)
{
	UfmStatus &= ~UfmStatusBitMask;
	set_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, 4);
}

int CheckUfmStatus(uint32_t UfmStatus, uint32_t UfmStatusBitMask)
{
	return ((~UfmStatus & UfmStatusBitMask) == UfmStatusBitMask);
}

int ProvisionRootKeyHash(uint8_t *DataBuffer, uint32_t length)
{
	uint32_t UfmStatus;
	int Status;

	if (!DataBuffer)
		return Failure;

	Status = get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));
	if (Status != Success) {
		LOG_ERR("Failed to get UFM status");
		return Failure;
	}

	if (!CheckUfmStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK) && !CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_ROOT_KEY_HASH_BIT_MASK)) {
		Status = set_provision_data_in_flash(ROOT_KEY_HASH, DataBuffer, length);
		if (Status == Success) {
			LOG_INF("Root key provisioned");
			SetUfmFlashStatus(UfmStatus, UFM_STATUS_PROVISIONED_ROOT_KEY_HASH_BIT_MASK);
			return Success;
		}

		LOG_ERR("Root key provision failed...");
		erase_provision_ufm_flash();
		return Failure;
	}

	LOG_WRN("%s, Provisioned or UFM Locked", __func__);

	return UnSupported;
}

int ProvisionPchOffsets(uint8_t *DataBuffer, uint32_t length)
{
	uint32_t UfmStatus;
	int Status;

	if (!DataBuffer)
		return Failure;

	Status = get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));
	if (Status != Success) {
		LOG_ERR("Failed to get UFM status");
		return Failure;
	}

	if (!CheckUfmStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK) && !CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_PCH_OFFSETS_BIT_MASK)) {
		Status = set_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, DataBuffer, length);
		if (Status == Success) {
			LOG_INF("PCH offsets provisioned");
			SetUfmFlashStatus(UfmStatus, UFM_STATUS_PROVISIONED_PCH_OFFSETS_BIT_MASK);
			return Success;
		}

		LOG_ERR("PCH offsets provision failed...");
		erase_provision_ufm_flash();
		return Failure;
	}

	LOG_WRN("%s, Provisioned or UFM Locked", __func__);
	return UnSupported;
}

int ProvisionBmcOffsets(uint8_t *DataBuffer, uint32_t length)
{
	uint32_t UfmStatus;
	int Status;

	if (!DataBuffer)
		return Failure;

	Status = get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));
	if (Status != Success) {
		LOG_ERR("Failed to get UFM status");
		return Failure;
	}

	if (!CheckUfmStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK) && !CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_BMC_OFFSETS_BIT_MASK)) {
		Status = set_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, DataBuffer, length);
		if (Status == Success) {
			SetUfmFlashStatus(UfmStatus, UFM_STATUS_PROVISIONED_BMC_OFFSETS_BIT_MASK);
			LOG_INF("BMC offsets provisioned");
			return Success;
		}

		LOG_ERR("BMC offsets provision failed...");
		erase_provision_ufm_flash();
		return Failure;
	}

	LOG_WRN("%s, Provisioned or UFM Locked", __func__);
	return UnSupported;
}

#if defined(CONFIG_PIT_PROTECTION)
void ProvisionPitKey(void)
{
	uint32_t UfmStatus;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));
	if (CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_PIT_ID_BIT_MASK)) {
		LOG_ERR("PIT password has been provisioned");
		SetUfmStatusValue(COMMAND_ERROR);
		return;
	}

	set_provision_data_in_flash(PIT_PASSWORD, (uint8_t *)gPitPassword, sizeof(gPitPassword));
	SetUfmFlashStatus(UfmStatus, UFM_STATUS_PROVISIONED_PIT_ID_BIT_MASK);
}

void EnablePitLevel1(void)
{
	uint32_t UfmStatus;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));

	if (CheckUfmStatus(UfmStatus, UFM_STATUS_PIT_L1_ENABLE_BIT_MASK)) {
		LOG_ERR("PIT L1 check has been enabled");
		return;
	}

	if (CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_PIT_ID_BIT_MASK)) {
		SetUfmFlashStatus(UfmStatus, UFM_STATUS_PIT_L1_ENABLE_BIT_MASK);
	} else {
		LOG_ERR("PIT ID is not configured");
		SetUfmStatusValue(COMMAND_ERROR);
	}
}

void EnablePitLevel2(void)
{
	uint32_t UfmStatus;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));

	if (CheckUfmStatus(UfmStatus, UFM_STATUS_PIT_L2_ENABLE_BIT_MASK)) {
		LOG_ERR("PIT L2 check has been enabled");
		return;
	}

	if (!CheckUfmStatus(UfmStatus, UFM_STATUS_PIT_L1_ENABLE_BIT_MASK)) {
		LOG_ERR("PIT L1 check should be enabled");
		return;
	}

	SetUfmFlashStatus(UfmStatus, UFM_STATUS_PIT_L2_ENABLE_BIT_MASK);
}
#endif

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
bool IsSpdmAttestationEnabled()
{
	// This setting will active/deactive SPDM attestation on next boot.
	CPLD_STATUS cpld_status;
	ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS,
			(uint8_t *)&cpld_status, sizeof(CPLD_STATUS));
	return cpld_status.AttestationFlag == 0x00 ? true : false;
}

void EnableSpdmAttestation(bool enable)
{
	// This setting will active/deactive SPDM attestation on next boot.
	CPLD_STATUS cpld_status;
	ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS,
			(uint8_t *)&cpld_status, sizeof(CPLD_STATUS));
	if (enable) {
		cpld_status.AttestationFlag = 0x00;
	} else {
		cpld_status.AttestationFlag = 0xFF;
	}
	ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS,
			(uint8_t *)&cpld_status, sizeof(CPLD_STATUS));
}

void ReadDeviceIdPublicKey(void)
{

}
#endif

void lock_provision_flash(void)
{
	uint32_t UfmStatus;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));

	if (!CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_BIT_MASK)) {
		LOG_ERR("Cannot lock UFM unless root key hash and offsets are provisioned");
		SetUfmStatusValue(COMMAND_ERROR);
	} else
		SetUfmFlashStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK);
}

void ReadRootKey(void)
{
	get_provision_data_in_flash(ROOT_KEY_HASH, gRootKeyHash, SHA384_DIGEST_LENGTH);
	memcpy(gReadFifoData, gRootKeyHash, SHA384_DIGEST_LENGTH);
	for (size_t i = 0; i < SHA384_DIGEST_LENGTH; ++i)
		swmbx_write(gSwMbxDev, true, UfmReadFIFO, gRootKeyHash + i);
}

void ReadPchOfsets(void)
{
	get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, gPchOffsets, sizeof(gPchOffsets));
	memcpy(gReadFifoData, gPchOffsets, sizeof(gPchOffsets));
	for (size_t i = 0; i < sizeof(gPchOffsets); ++i)
		swmbx_write(gSwMbxDev, true, UfmReadFIFO, gPchOffsets + i);
}

void ReadBmcOffets(void)
{
	get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, gBmcOffsets, sizeof(gBmcOffsets));
	memcpy(gReadFifoData, gBmcOffsets, sizeof(gBmcOffsets));
	for (size_t i = 0; i < sizeof(gBmcOffsets); ++i)
		swmbx_write(gSwMbxDev, true, UfmReadFIFO, gBmcOffsets + i);
}

/**
 * Function to process th UFM command operations
 * @Param  NULL
 * @retval NULL
 **/
void process_provision_command(void)
{
	uint32_t UfmFlashStatus;
	byte UfmCommandData;
	byte Status = 0;

	UfmCommandData = GetUfmCommand();

#if defined(CONFIG_CERBERUS_PFR)
	if ((UfmCommandData == PROVISION_ROOT_KEY) || (UfmCommandData == PROVISION_PCH_OFFSET) ||
	    (UfmCommandData == PROVISION_BMC_OFFSET)) {
		LOG_WRN("Unsupported command: 0x%x", UfmCommandData);
		SetUfmStatusValue(COMMAND_ERROR);
		return;
	}
#endif
	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmFlashStatus, sizeof(UfmFlashStatus));

	if (CheckUfmStatus(UfmFlashStatus, UFM_STATUS_LOCK_BIT_MASK)) {
		if ((UfmCommandData < READ_ROOT_KEY) || (UfmCommandData > READ_BMC_OFFSET)) {
			// Ufm locked
			LOG_WRN("UFM Locked and Dropped Write Command: 0x%x", UfmCommandData);
			SetUfmStatusValue(COMMAND_ERROR);
			return;
		}
	}

	switch (UfmCommandData) {
	case ERASE_CURRENT:
		Status = erase_provision_flash();
		if (Status != Success)
			SetUfmStatusValue(COMMAND_ERROR);
		break;
	case PROVISION_ROOT_KEY:
		memcpy(gRootKeyHash, gUfmFifoData, SHA384_DIGEST_LENGTH);
		Status = ProvisionRootKeyHash(gRootKeyHash, sizeof(gRootKeyHash));
		if (Status != Success) {
			SetUfmStatusValue(COMMAND_ERROR);
			return;
		}
		gProvisionData = 1;
		break;
#if defined(CONFIG_PIT_PROTECTION)
	case PROVISION_PIT_KEY:
		memcpy(gPitPassword, gUfmFifoData, sizeof(gPitPassword));
		ProvisionPitKey();
		break;
#endif
	case PROVISION_PCH_OFFSET:
		memcpy(gPchOffsets, gUfmFifoData, sizeof(gPchOffsets));
		Status = ProvisionPchOffsets(gPchOffsets, sizeof(gPchOffsets));
		if (Status != Success) {
			SetUfmStatusValue(COMMAND_ERROR);
			return;
		}
		gProvisionData = 1;
		break;
	case PROVISION_BMC_OFFSET:
		memcpy(gBmcOffsets, gUfmFifoData, sizeof(gBmcOffsets));
		Status = ProvisionBmcOffsets(gBmcOffsets, sizeof(gBmcOffsets));
		if (Status != Success) {
			SetUfmStatusValue(COMMAND_ERROR);
			return;
		}
		gProvisionData = 1;
		break;
	case LOCK_UFM:
		// lock ufm
		lock_provision_flash();
		break;
	case READ_ROOT_KEY:
		ReadRootKey();
		break;
	case READ_PCH_OFFSET:
		ReadPchOfsets();
		break;
	case READ_BMC_OFFSET:
		ReadBmcOffets();
		break;
#if defined(CONFIG_PIT_PROTECTION)
	case ENABLE_PIT_LEVEL_1_PROTECTION:
		EnablePitLevel1();
		break;
	case ENABLE_PIT_LEVEL_2_PROTECTION:
		EnablePitLevel2();
		break;
#endif
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	case ENABLE_DEVICE_ATTESTATION_REQUESTS:
		LOG_INF("Enable SPDM Attestation");
		EnableSpdmAttestation(true);
		break;
	case READ_DEVICE_ID_PUBLIC_KEY:
		ReadDeviceIdPublicKey();
		break;
	case DISABLE_DEVICE_ATTESTATION_REQUESTS:
		LOG_INF("Disable SPDM Attestation");
		EnableSpdmAttestation(false);
		break;
#endif
	default:
		LOG_ERR("Unsupported provision command 0x%02x", UfmCommandData);
		break;
	}

	if (gProvisionData) {
		gProvisionData = 0;
		get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmFlashStatus, sizeof(UfmFlashStatus));
		if (CheckUfmStatus(UfmFlashStatus, UFM_STATUS_PROVISIONED_ROOT_KEY_HASH_BIT_MASK |
			   UFM_STATUS_PROVISIONED_PCH_OFFSETS_BIT_MASK |
			   UFM_STATUS_PROVISIONED_BMC_OFFSETS_BIT_MASK)) {
			CPLD_STATUS cpld_status;

			ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_status, sizeof(CPLD_STATUS));
			if (cpld_status.DecommissionFlag) {
				cpld_status.DecommissionFlag = 0;
				ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_status, sizeof(CPLD_STATUS));
			}
		}
	}
}

/**
 * Function to update the BMC Checkpoint
 *
 * @Param  Data checkpoint command
 * @retval NULL
 **/
void UpdateBmcCheckpoint(byte Data)
{
	if (gWdtBootStatus == WDT_BMC_BOOT_DONE_MASK) {
		SetBmcCheckpoint(CompletingExecutionBlock);
	} else {
		SetBmcCheckpoint(Data);
		bmc_wdt_handler(Data);
	}
}

#if defined(CONFIG_INTEL_PFR)
/**
 * Function to update the ACM Checkpoint
 *
 * @Param  Data checkpoint command
 * @retval NULL
 **/
void UpdateAcmCheckpoint(byte Data)
{
	if (gWdtBootStatus == WDT_ACM_BOOT_DONE_MASK) {
		SetAcmCheckpoint(CompletingExecutionBlock);
	} else {
		SetAcmCheckpoint(Data);
		acm_wdt_handler(Data);
	}
}
#endif

/**
 * Function to update the BIOS Checkpoint
 *
 * @Param  Data checkpoint command
 * @retval NULL
 **/
void UpdateBiosCheckpoint(byte Data)
{
#if defined(CONFIG_INTEL_PFR)
	if (gWdtBootStatus & WDT_OBB_BOOT_DONE_MASK) {
#else
	if (gWdtBootStatus & WDT_PCH_BOOT_DONE_MASK) {
#endif
		SetBiosCheckpoint(CompletingExecutionBlock);
	} else {
		SetBiosCheckpoint(Data);
		bios_wdt_handler(Data);
	}
}
