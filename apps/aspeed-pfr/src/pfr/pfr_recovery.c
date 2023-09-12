/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <storage/flash_map.h>

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
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#include "cerberus_pfr/cerberus_pfr_recovery.h"
#include "cerberus_pfr/cerberus_pfr_svn.h"
#endif

#include "include/SmbusMailBoxCom.h"
#include "Smbus_mailbox/Smbus_mailbox.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int recover_image(void *AoData, void *EventContext)
{
	int status = 0;
	AO_DATA *ActiveObjectData = (AO_DATA *) AoData;
	EVENT_CONTEXT *EventData = (EVENT_CONTEXT *) EventContext;

	struct pfr_manifest *pfr_manifest = get_pfr_manifest();

	pfr_manifest->state = FIRMWARE_RECOVERY;

	if (EventData->image == BMC_EVENT) {
		LOG_INF("Image Type: BMC");
		pfr_manifest->image_type = BMC_TYPE;
	} else if (EventData->image == PCH_EVENT) {
		LOG_INF("Image Type: PCH");
		pfr_manifest->image_type = PCH_TYPE;
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (EventData->image == AFM_EVENT) {
		LOG_INF("Image Type: AFM");
		pfr_manifest->image_type = AFM_TYPE;
		pfr_manifest->address = CONFIG_BMC_AFM_STAGING_OFFSET;
		pfr_manifest->recovery_address = CONFIG_BMC_AFM_RECOVERY_OFFSET;
	}
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
		status = pfr_manifest->update_fw->base->verify((struct firmware_image *)pfr_manifest, NULL, NULL);
		if (status != Success) {
			LOG_INF("PFR Staging Area Corrupted");
			if (ActiveObjectData->ActiveImageStatus != Success) {
				/* Scenarios
				 * Active | Recovery | Staging
				 * 0      | 0        | 0
				 */
				LogErrorCodes((pfr_manifest->image_type == BMC_TYPE ?
							BMC_AUTH_FAIL : PCH_AUTH_FAIL),
						ACTIVE_RECOVERY_STAGING_AUTH_FAIL);
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

/**
 * Get the SHA-256 hash of the recovery image data, not including the signature.
 *
 * @param image The recovery image to query.
 * @param hash The hash engine to use for generating the hash.
 * @param hash_out Output buffer for the manifest hash.
 * @param hash_length Length of the hash output buffer.
 *
 * @return 0 if the hash was calculated successfully or an error code.
 */
int recovery_get_hash(struct recovery_image *image, struct hash_engine *hash, uint8_t *hash_out,
		      size_t hash_length)
{

	ARG_UNUSED(image);
	ARG_UNUSED(hash);
	ARG_UNUSED(hash_out);
	ARG_UNUSED(hash_length);

	return Success;
}

/**
 * Get the version of the recovery image.
 *
 * @param image The recovery image to query.
 * @param version The buffer to hold the version ID.
 * @param len The output buffer length.
 *
 * @return 0 if the ID was successfully retrieved or an error code.
 */
int recovery_get_version(struct recovery_image *image, char *version, size_t len)
{

	ARG_UNUSED(image);
	ARG_UNUSED(version);
	ARG_UNUSED(len);

	return Success;
}

void init_recovery_manifest(struct recovery_image *image)
{
	image->verify = recovery_verify;
	image->get_hash = recovery_get_hash;
	image->get_version = recovery_get_version;
	image->apply_to_flash = recovery_apply_to_flash;

}

int pfr_recover_recovery_region(int image_type, uint32_t source_address, uint32_t target_address)
{
	int sector_sz;
	bool support_block_erase;
	size_t area_size = 0;

	if (image_type == BMC_TYPE)
		area_size = CONFIG_BMC_STAGING_SIZE;
	else if (image_type == PCH_TYPE)
		area_size = CONFIG_PCH_STAGING_SIZE;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (image_type == AFM_TYPE) {
		area_size = FLASH_AREA_SIZE(afm_act_1);
		image_type = BMC_TYPE;
	}
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
	sector_sz = pfr_spi_get_block_size(image_type);
	support_block_erase = (sector_sz == BLOCK_SIZE);
	LOG_INF("Recovering...");
	LOG_INF("image_type=%d, source_address=%x, target_address=%x, length=%x",
		image_type, source_address, target_address, area_size);
	if (pfr_spi_erase_region(image_type, support_block_erase, target_address, area_size)) {
		LOG_ERR("Recovery region erase failed");
		return Failure;
	}

	// use read_write_between spi for supporting dual flash
	if (pfr_spi_region_read_write_between_spi(image_type, source_address,
				image_type, target_address, area_size)) {
		LOG_ERR("Recovery region update failed");
		return Failure;
	}

	LOG_INF("Recovery region update completed");

	return Success;
}

