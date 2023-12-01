/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <stdint.h>
#include "AspeedStateMachine/common_smc.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "pfr/pfr_ufm.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_key_manifest.h"
#include "include/SmbusMailBoxCom.h"
#include "flash/flash_aspeed.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int verify_cerberus_magic_number(uint32_t magic_number)
{
	int status = Success;

	if (magic_number != RECOVERY_HEADER_MAGIC)
		status = Failure;
	return status;
}

int verify_cerberus_provisioning_type(uint16_t image_type)
{
	int status = Success;

	if (image_type != PROVISIONING_IMAGE_TYPE)
		status = Failure;
	return status;
}

int cerberus_provisioning_root_key_action(struct pfr_manifest *manifest)
{
	struct PROVISIONING_IMAGE_HEADER provision_header;
	uint8_t rootkey_hash_buffer[SHA384_DIGEST_LENGTH];
	uint8_t keym_buffer[KEY_MANIFEST_SIZE];
	uint8_t pch_offsets_buffer[12];
	uint8_t bmc_offsets_buffer[12];
	CPLD_STATUS cpld_status;
	uint32_t region_size;
	int status = Success;

	LOG_INF("Provisioning, manifest->flash_id=%d address=%08x", manifest->flash_id, manifest->address);
	if (pfr_spi_read(manifest->flash_id, manifest->address, sizeof(provision_header), (uint8_t *)&provision_header)) {
		LOG_ERR("Provisioning: Failed to read image header.");
		return Failure;
	}

	LOG_HEXDUMP_INF(&provision_header, sizeof(provision_header), "Provision Header:");
	status = verify_cerberus_provisioning_type(provision_header.image_type);
	if (status != Success) {
		LOG_ERR("Provisioning: Type Error.");
		return Failure;
	}

	status = verify_cerberus_magic_number(provision_header.magic_num);
	if (status != Success) {
		LOG_ERR("Provisioning: Magic Number is not Matched.");
		return Failure;
	}

	if (provision_header.provisioning_flag[0] != PROVISION_OTP_KEY_FLAG &&
	    provision_header.provisioning_flag[0] != PROVISION_ROOT_KEY_FLAG) {
		LOG_ERR("Provisioning: Invalid flag(%d)", provision_header.provisioning_flag[0]);
		return Failure;
	}

	if (provision_header.provisioning_flag[0] == PROVISION_OTP_KEY_FLAG) {
		//Provision OTP Key Content
		LOG_ERR("Provisioning: Unsupport flag(%d)", provision_header.provisioning_flag[0]);
		return Failure;
	}

	if (provision_header.provisioning_flag[0] == PROVISION_ROOT_KEY_FLAG) {
		if (cerberus_pfr_get_public_key_hash(manifest, manifest->address + CERBERUS_ROOT_KEY,
						 PROVISIONING_ROOT_KEY_HASH_TYPE, rootkey_hash_buffer, sizeof(rootkey_hash_buffer)))
			return Failure;

		if (ProvisionRootKeyHash(rootkey_hash_buffer, PROVISIONING_ROOT_KEY_HASH_LENGTH) != Success)
			return Failure;

		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_BMC_ACTIVE_OFFSET, 4, bmc_offsets_buffer);
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_BMC_RECOVERY_OFFSET, 4, bmc_offsets_buffer + 4);
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_BMC_STAGE_OFFSET, 4, bmc_offsets_buffer + 8);
		if (ProvisionBmcOffsets(bmc_offsets_buffer, sizeof(bmc_offsets_buffer)) != Success)
			return Failure;

		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_PCH_ACTIVE_OFFSET, 4, pch_offsets_buffer);
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_PCH_RECOVERY_OFFSET, 4, pch_offsets_buffer + 4);
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_PCH_STAGE_OFFSET, 4, pch_offsets_buffer + 8);
		if (ProvisionPchOffsets(pch_offsets_buffer, sizeof(pch_offsets_buffer)) != Success)
			return Failure;

		// Provisioning key manifest 0
		if (pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_KEY_MANIFEST, KEY_MANIFEST_SIZE, keym_buffer)) {
			LOG_ERR("Provisioning: failed to read key manifest 0");
			return Failure;
		}

		region_size = pfr_spi_get_device_size(ROT_INTERNAL_KEY);
		if (pfr_spi_erase_region(ROT_INTERNAL_KEY, true, 0, region_size)) {
			LOG_ERR("Provisioning: erase the key manifest data failed");
			return Failure;
		}

		if (pfr_spi_write(ROT_INTERNAL_KEY, 0, KEY_MANIFEST_SIZE, keym_buffer)) {
			LOG_ERR("Provisioning: failed to save key manifest 0");
			return Failure;
		}

		ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_status, sizeof(CPLD_STATUS));
		if (cpld_status.DecommissionFlag) {
			cpld_status.DecommissionFlag = 0;
			ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_status, sizeof(CPLD_STATUS));
		}

		SetUfmStatusValue(UFM_PROVISIONED);
		LOG_INF("Provisioning: Done.");
	}

	return Success;
}

