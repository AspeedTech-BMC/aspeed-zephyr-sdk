/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <logging/log.h>
#include <storage/flash_map.h>
#include "common/common.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_ufm.h"
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "cerberus_pfr_recovery.h"
#include "manifest/pfm/pfm_manager.h"
#include "cerberus_pfr_authentication.h"
#include "cerberus_pfr_common.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_svn.h"
#include "flash/flash_util.h"
#include "flash/flash_aspeed.h"
#include "pfr/pfr_util.h"
#include "manifest/pfm/pfm.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int pfr_recover_active_region(struct pfr_manifest *manifest)
{
	struct recovery_header recovery_header;
	int status = Failure;
	uint32_t sig_address, recovery_offset, data_offset, start_address, erase_address;
	uint32_t section_length;
	struct pfm_fw_version_element_rw_region *rw_region = NULL;
	struct recovery_section recovery_section;
	uint32_t source_address;
	uint32_t src_pfm_addr, dest_pfm_addr;
	uint32_t manifest_addr = manifest->address;
	int sector_sz = pfr_spi_get_block_size(manifest->image_type);
	bool support_block_erase = (sector_sz == BLOCK_SIZE);

	if (manifest->image_type == BMC_TYPE) {
		get_provision_data_in_flash(BMC_RECOVERY_REGION_OFFSET,
				(uint8_t *)&source_address, sizeof(source_address));
	} else if (manifest->image_type == PCH_TYPE) {
		get_provision_data_in_flash(PCH_RECOVERY_REGION_OFFSET,
				(uint8_t *)&source_address, sizeof(source_address));
	} else {
		goto recovery_failed;
	}

	manifest->address = source_address;
	//read recovery header
	status = pfr_spi_read(manifest->image_type, source_address, sizeof(recovery_header),
			(uint8_t *)&recovery_header);

	// Get pfm address from recovery image
	if (cerberus_get_image_pfm_addr(manifest, &recovery_header, &src_pfm_addr, &dest_pfm_addr)) {
		LOG_ERR("PFM doesn't exist in recovery image");
		goto recovery_failed;
	}

	uint32_t rw_region_addr;
	struct pfm_firmware_version_element fw_ver_element;

	if (cerberus_get_rw_region_info(manifest->image_type, src_pfm_addr, &rw_region_addr,
				&fw_ver_element)) {
		LOG_ERR("Failed to get rw regions");
		goto recovery_failed;
	}

	uint32_t rw_region_size = fw_ver_element.rw_count *
		sizeof(struct pfm_fw_version_element_rw_region);
	rw_region = malloc(rw_region_size);

	if (rw_region == NULL) {
		LOG_ERR("Out of memory");
		goto recovery_failed;
	}

	if (pfr_spi_read(manifest->image_type, rw_region_addr, rw_region_size,
				(uint8_t *)rw_region)) {
		LOG_ERR("Failed to get read/write regions");
		goto recovery_failed;
	}

	uint32_t time_start, time_end;

	time_start = k_uptime_get_32();

	// Handle read/write region erasing
	for (int i = 0; i < fw_ver_element.rw_count; i++) {
		switch (rw_region[i].flags) {
		case PFM_RW_ERASE:
			LOG_INF("Eraseing RW region %x - %x", rw_region[i].region.start_addr,
					rw_region[i].region.end_addr);
			if (pfr_spi_erase_region(manifest->image_type, support_block_erase,
						rw_region[i].region.start_addr,
						(rw_region[i].region.end_addr -
						 rw_region[i].region.start_addr + 1)))
				goto recovery_failed;
			break;
		case PFM_RW_RESTORE:
			// It will be handled in the below recovery section update if the
			// restore region is defined in recovery sections
		case PFM_RW_DO_NOTHING:
		default:
			break;
		}
	}

	sig_address = source_address + recovery_header.image_length - recovery_header.sign_length;
	recovery_offset = source_address + recovery_header.header_length;

	bool is_rw_region_handled;

	// Handle recovery sections update
	while (recovery_offset < sig_address) {
		status = pfr_spi_read(manifest->image_type, recovery_offset,
				sizeof(recovery_section), (uint8_t *)&recovery_section);
		if (recovery_section.magic_number != RECOVERY_SECTION_MAGIC) {
			LOG_ERR("Recovery Section not matched..");
			break;
		}
		start_address = recovery_section.start_addr;
		section_length = recovery_section.section_length;
		erase_address = start_address;
		recovery_offset = recovery_offset + sizeof(recovery_section);
		data_offset = recovery_offset;
		recovery_offset += section_length;
		is_rw_region_handled = false;

		for (int i = 0; i < fw_ver_element.rw_count; i++) {
			// Update region is rw region
			if (start_address == rw_region[i].region.start_addr) {
				if ((rw_region[i].flags == PFM_RW_ERASE) ||
						(rw_region[i].flags == PFM_RW_DO_NOTHING))
					is_rw_region_handled = true;
				else if (rw_region[i].flags == PFM_RW_RESTORE)
					LOG_INF("Restoring RW region %x - %x",
							rw_region[i].region.start_addr,
							rw_region[i].region.end_addr);
				break;
			}
		}

		if (is_rw_region_handled)
			continue;

		if (pfr_spi_erase_region(manifest->image_type, support_block_erase, erase_address,
					section_length)) {
			goto recovery_failed;
		}

		if (pfr_spi_region_read_write_between_spi(manifest->image_type, data_offset,
					manifest->image_type, start_address, section_length)) {
			goto recovery_failed;
		}
	}

	time_end = k_uptime_get_32();
	LOG_INF("Firmware recovery completed, elapsed time = %u milliseconds",
			(time_end - time_start));
	LOG_INF("Active Updated!!");
	LOG_INF("Repair success");
	status = Success;

recovery_failed:
	// Restore manifest address
	manifest->address = manifest_addr;
	if (rw_region)
		free(rw_region);

	return status;
}

int active_region_pfm_update(struct pfr_manifest *manifest)
{
	return Success;
}

int pfr_staging_pch_staging(struct pfr_manifest *manifest)
{
	int status = Success;

	uint32_t source_address;
	uint32_t target_address;
	uint32_t image_type = manifest->image_type;
	uint32_t flash_id = manifest->flash_id;
	struct recovery_header image_header;
	uint32_t dest_pfm_addr;
	uint32_t src_pfm_addr;

	status = ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
			sizeof(source_address));
	if (status != Success)
		return Failure;

	status = ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&target_address,
			sizeof(target_address));
	if (status != Success)
		return Failure;

	manifest->image_type = BMC_TYPE;
	manifest->address = source_address;
	manifest->flash_id = BMC_FLASH_ID;
	manifest->pc_type = PFR_PCH_UPDATE_CAPSULE;

	LOG_INF("BMC's PCH Staging Area verification");
	LOG_INF("Verifying image, manifest->flash_id=%d address=%08x", manifest->flash_id, manifest->address);
	if (pfr_spi_read(manifest->flash_id, manifest->address, sizeof(image_header), (uint8_t *)&image_header)) {
		LOG_ERR("Unable to get image header.");
		return Failure;
	}

	if (image_header.format != UPDATE_FORMAT_TYPE_PCH) {
		LOG_HEXDUMP_ERR(&image_header, sizeof(image_header), "image_header:");
		LOG_ERR("Unsupported image format(%d)", image_header.format);
		return Failure;
	}

	status = cerberus_pfr_verify_image(manifest);
	if (status != Success) {
		LOG_ERR("BMC's PCH Stage Image Verify Failed");
		return Failure;
	}

	// Find PFM in BMC's PCH stage image
	if (cerberus_get_image_pfm_addr(manifest, &image_header, &src_pfm_addr, &dest_pfm_addr)) {
		LOG_ERR("PFM doesn't exist in BMC's PCH Stage Image");
		return Failure;
	}

	manifest->pc_type = PFR_PCH_PFM;

	// BMC's PCH Stage region PFM verification
	manifest->address = src_pfm_addr;
	LOG_INF("Verifying PFM address=0x%08x", manifest->address);
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash, manifest->verification->base,
			manifest->pfr_hash->hash_out, manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Verify PFM failed");
		return Failure;
	}

	status = cerberus_pfr_verify_pfm_csk_key(manifest);
	if (status != Success) {
		LOG_ERR("Verify PFM CSK key failed");
		return Failure;
	}

	LOG_INF("BMC's PCH Staging verification successful");
	manifest->address = target_address;
	manifest->image_type = image_type;
	manifest->flash_id = flash_id;

	int sector_sz = pfr_spi_get_block_size(manifest->image_type);
	bool support_block_erase = (sector_sz == BLOCK_SIZE);

	LOG_INF("Copying staging region from BMC addr: 0x%08x to PCH addr: 0x%08x, length: 0x%08x",
			source_address, target_address, CONFIG_PCH_STAGING_SIZE);

	if (pfr_spi_erase_region(manifest->image_type, support_block_erase, target_address,
				CONFIG_PCH_STAGING_SIZE))
		return Failure;

	if (pfr_spi_region_read_write_between_spi(BMC_TYPE, source_address, PCH_TYPE,
				target_address, CONFIG_PCH_STAGING_SIZE))
		return Failure;

	if (manifest->state == FIRMWARE_RECOVERY) {
		LOG_INF("PCH staging region verification");
		status = manifest->update_fw->base->verify((struct firmware_image *)manifest,
				NULL, NULL);
		if (status != Success)
			return Failure;
	}

	LOG_INF("PCH Staging region Update completed");

	return Success;
}

int pfr_recover_update_action(struct pfr_manifest *manifest)
{
	return Success;
}

/**
 * Verify if the recovery image is valid.
 *
 * @param image The recovery image to validate.
 * @param hash The hash engine to use for validation.
 * @param verification Verification instance to use to verify the recovery image signature.
 * @param hash_out Optional output buffer for the recovery image hash calculated during
 * verification.  Set to null to not return the hash.
 * @param hash_length Length of the hash output buffer.
 * @param pfm_manager The PFM manager to use for validation.
 *
 * @return 0 if the recovery image is valid or an error code.
 */
int recovery_verify(struct recovery_image *image, struct hash_engine *hash,
		    struct signature_verification *verification, uint8_t *hash_out,
		    size_t hash_length, struct pfm_manager *pfm)
{
	ARG_UNUSED(hash);
	ARG_UNUSED(verification);
	ARG_UNUSED(hash_out);
	ARG_UNUSED(hash_length);
	ARG_UNUSED(pfm);
	struct pfr_manifest *manifest = (struct pfr_manifest *)image;
	struct recovery_header image_header;
	uint32_t dest_pfm_addr;
	uint32_t src_pfm_addr;
	int status;

	LOG_INF("Verify recovery");

	if (manifest->image_type != BMC_TYPE &&
	    manifest->image_type != PCH_TYPE) {
		LOG_ERR("Unsupported image type %d", manifest->image_type);
		return Failure;
	}

	init_stage_and_recovery_offset(manifest);
	manifest->address = manifest->recovery_address;
	LOG_INF("Verifying image, manifest->flash_id=%d address=%08x", manifest->flash_id, manifest->address);
	if (pfr_spi_read(manifest->flash_id, manifest->address, sizeof(image_header), (uint8_t *)&image_header)) {
		LOG_ERR("Unable to get image header.");
		return Failure;
	}

	if (((manifest->image_type == BMC_TYPE) && (image_header.format != UPDATE_FORMAT_TYPE_BMC)) ||
	    ((manifest->image_type == PCH_TYPE) && (image_header.format != UPDATE_FORMAT_TYPE_PCH))) {
		LOG_HEXDUMP_ERR(&image_header, sizeof(image_header), "image_header:");
		LOG_ERR("Unsupported image format(%d) for manifest->image_type(%d)",
			image_header.format, manifest->image_type);
		return Failure;
	}

	if (cerberus_pfr_verify_image(manifest)) {
		LOG_ERR("Recovery Image Verify Failed");
		return Failure;
	}

	// Find PFM in recovery image
	if (cerberus_get_image_pfm_addr(manifest, &image_header, &src_pfm_addr, &dest_pfm_addr)) {
		LOG_ERR("PFM doesn't exist in recovery image");
		return Failure;
	}

	if (manifest->image_type == BMC_TYPE)
		manifest->pc_type = PFR_BMC_PFM;
	else if (manifest->image_type == PCH_TYPE)
		manifest->pc_type = PFR_PCH_PFM;
	else {
		LOG_ERR("Unsupported image type %d", manifest->image_type);
		return Failure;
	}

	// Recovery region PFM verification
	manifest->address = src_pfm_addr;
	LOG_INF("Verifying PFM address=0x%08x", manifest->address);
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash, manifest->verification->base,
			manifest->pfr_hash->hash_out, manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Verify PFM failed");
		return Failure;
	}

	status = cerberus_pfr_verify_pfm_csk_key(manifest);
	if (status != Success) {
		LOG_ERR("Verify PFM CSK key failed");
		return Failure;
	}

	status = get_recover_pfm_version_details(manifest);
	if (status != Success) {
		LOG_ERR("Get recovery pfm version failed");
		return Failure;
	}

	LOG_INF("Recovery area verification successful");

	return Success;
}

int recovery_apply_to_flash(struct recovery_image *image, struct spi_flash *flash)
{
	// TODO
	return Success;
}

