/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>

#include "pfr_recovery.h"
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "common/common.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "pfr/pfr_recovery.h"
#include "flash/flash_aspeed.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_recovery.h"
#include "intel_pfr/intel_pfr_provision.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#include "cerberus_pfr/cerberus_pfr_recovery.h"
#include "cerberus_pfr/cerberus_pfr_svn.h"
#include "cerberus_pfr/cerberus_pfr_provision.h"
#endif

#include "include/SmbusMailBoxCom.h"
#include "Smbus_mailbox/Smbus_mailbox.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int recover_image(void *AoData, void *EventContext)
{
	int status = 0;
	AO_DATA *ActiveObjectData = (AO_DATA *) AoData;
	EVENT_CONTEXT *EventData = (EVENT_CONTEXT *) EventContext;
	uint32_t act_pfm_addr;

	struct pfr_manifest *pfr_manifest = get_pfr_manifest();

	pfr_manifest->state = FIRMWARE_RECOVERY;

	if (EventData->image == BMC_EVENT) {
		LOG_INF("Image Type: BMC");
		pfr_manifest->image_type = BMC_TYPE;
		if (get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)&act_pfm_addr,
				sizeof(act_pfm_addr))) {
			LOG_ERR("Failed to get PCH active PFM address");
			return Failure;
		}
		pfr_manifest->active_pfm_addr = act_pfm_addr;
	} else if (EventData->image == PCH_EVENT) {
		LOG_INF("Image Type: PCH");
		pfr_manifest->image_type = PCH_TYPE;
		if (get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)&act_pfm_addr,
				sizeof(act_pfm_addr))) {
			LOG_ERR("Failed to get PCH active PFM address");
			return Failure;
		}
		pfr_manifest->active_pfm_addr = act_pfm_addr;
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
#if (CONFIG_AFM_SPEC_VERSION == 4)
	else if (EventData->image == AFM_EVENT) {
		LOG_INF("Image Type: AFM");
		pfr_manifest->image_type = AFM_TYPE;
		pfr_manifest->address = CONFIG_BMC_AFM_STAGING_OFFSET;
		pfr_manifest->recovery_address = 0;
	}
#elif (CONFIG_AFM_SPEC_VERSION == 3)
	else if (EventData->image == AFM_EVENT) {
		LOG_INF("Image Type: AFM");
		pfr_manifest->image_type = AFM_TYPE;
		pfr_manifest->address = CONFIG_BMC_AFM_STAGING_OFFSET;
		pfr_manifest->recovery_address = CONFIG_BMC_AFM_RECOVERY_OFFSET;
	}
#endif
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	else if (EventData->image == CPLD_EVENT) {
		LOG_INF("Image Type: Intel CPLD");
		pfr_manifest->image_type = CPLD_TYPE;
		pfr_manifest->address = CONFIG_BMC_INTEL_CPLD_STAGING_OFFSET;
		pfr_manifest->recovery_address = 0;
	}
#endif
	else {
		LOG_ERR("Unsupported recovery event type %d", EventData->image);
		return Failure;
	}

	if (ActiveObjectData->RecoveryImageStatus != Success) {
		status = pfr_manifest->update_fw->base->verify((struct firmware_image *)pfr_manifest, NULL);
		if (status != Success) {
			LOG_ERR("PFR Staging Area Corrupted");
			if (ActiveObjectData->ActiveImageStatus != Success) {
				/* Scenarios
				 * Active | Recovery | Staging
				 * 0      | 0        | 0
				 */
				uint8_t minor_err = ACTIVE_RECOVERY_STAGING_AUTH_FAIL;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
				if (EventData->image == AFM_EVENT)
					minor_err = AFM_ACTIVE_RECOVERY_STAGING_AUTH_FAIL;
#endif
				LogErrorCodes((pfr_manifest->image_type == BMC_TYPE ?
							BMC_AUTH_FAIL : PCH_AUTH_FAIL), minor_err);
				if (pfr_manifest->image_type == PCH_TYPE) {
					status = pfr_staging_pch_staging(pfr_manifest);
					if (status != Success)
						return Failure;
				} else
					return Failure;
			} else {
				/* Scenarios
				 * Active | Recovery | Staging
				 * 1      | 0        | 0
				 */
				ActiveObjectData->RestrictActiveUpdate = 1;
				return VerifyActive;

			}
		}
		if (ActiveObjectData->ActiveImageStatus == Success) {
			/* Scenarios
			 * Active | Recovery | Staging
			 * 1      | 0        | 1
			 */
			status = does_staged_fw_image_match_active_fw_image(pfr_manifest);
			if (status != Success) {
				ActiveObjectData->RestrictActiveUpdate = 1;
				return VerifyActive;
			}
		}

		/* Scenarios
		 * Active | Recovery | Staging
		 * 1      | 0        | 1 (Firmware match)
		 * 0      | 0        | 1
		 */
		status = pfr_recover_recovery_region(
				pfr_manifest->image_type,
				pfr_manifest->address,
				pfr_manifest->recovery_address);
		if (status != Success)
			return Failure;

		ActiveObjectData->RecoveryImageStatus = Success;
		return VerifyRecovery;
	}

	if (ActiveObjectData->ActiveImageStatus != Success) {
		/* Scenarios
		 * Active | Recovery | Staging
		 * 0      | 1        | 0
		 * 0      | 1        | 1
		 */
		status = pfr_recover_active_region(pfr_manifest);
		if (status != Success)
			return Failure;

		ActiveObjectData->ActiveImageStatus = Success;
		return VerifyActive;
	}

	return Success;
}

void init_recovery_manifest(struct recovery_image *image)
{
	image->verify = recovery_verify;
}

int pfr_recover_recovery_region(int image_type, uint32_t source_address, uint32_t target_address)
{
	int sector_sz;
	bool support_block_erase;
	size_t area_size = 0;
	int src_type = image_type, dst_type = image_type;

	if (image_type == BMC_TYPE)
		area_size = CONFIG_BMC_STAGING_SIZE;
	else if (image_type == PCH_TYPE)
		area_size = CONFIG_PCH_STAGING_SIZE;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
#if (CONFIG_AFM_SPEC_VERSION == 4)
	else if (image_type == AFM_TYPE) {
		area_size = FIXED_PARTITION_SIZE(afm_rcv1_partition);
		src_type = BMC_SPI;
		dst_type = ROT_EXT_AFM_RC_1;
	}
#elif (CONFIG_AFM_SPEC_VERSION == 3)
	else if (image_type == AFM_TYPE) {
		area_size = FIXED_PARTITION_SIZE(afm_act_1_partition);
		image_type = BMC_TYPE;
		src_type = BMC_SPI;
		dst_type = BMC_SPI;
	}
#endif
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	else if (image_type == CPLD_TYPE) {
		uint32_t region_size;
		LOG_INF("Recovering...");
		region_size = pfr_spi_get_device_size(ROT_EXT_CPLD_RC);
		if (pfr_spi_erase_region(ROT_EXT_CPLD_RC, true, 0, region_size)) {
			LOG_ERR("Erase CPLD recovery region failed");
			return Failure;
		}

		LOG_INF("Copying BMC's CPLD staging region to ROT's recovery CPLD region");
		if (pfr_spi_region_read_write_between_spi(BMC_TYPE,
					CONFIG_BMC_INTEL_CPLD_STAGING_OFFSET,
					ROT_EXT_CPLD_RC, 0, region_size)) {
			LOG_ERR("Failed to write CPLD image to ROT's CPLD recovery region");
			return Failure;
		}
		LOG_INF("Recovery region update completed");
		return Success;
	}
#endif
	else {
		LOG_ERR("Unknown type (%d)", image_type);
		return Failure;
	}

	sector_sz = pfr_spi_get_block_size(dst_type);
	support_block_erase = (sector_sz == BLOCK_SIZE);
	LOG_INF("Recovering...");
	LOG_INF("image_type=%d, source_address=%x, target_address=%x, length=%x",
		dst_type, source_address, target_address, area_size);
	if (pfr_spi_erase_region(dst_type, support_block_erase, target_address, area_size)) {
		LOG_ERR("Recovery region erase failed");
		return Failure;
	}

	// use read_write_between spi for supporting dual flash
	if (pfr_spi_region_read_write_between_spi(src_type, source_address,
				dst_type, target_address, area_size)) {
		LOG_ERR("Recovery region update failed");
		return Failure;
	}

	LOG_INF("Recovery region update completed");

	return Success;
}

