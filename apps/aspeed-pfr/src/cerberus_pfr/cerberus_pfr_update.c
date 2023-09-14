/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <logging/log.h>

#include "pfr/pfr_update.h"
#include "pfr/pfr_recovery.h"
#include "pfr/pfr_ufm.h"
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "include/SmbusMailBoxCom.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "cerberus_pfr_common.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_recovery.h"
#include "cerberus_pfr_key_cancellation.h"
#include "cerberus_pfr_key_manifest.h"
#include "cerberus_pfr_svn.h"
#include "flash/flash_aspeed.h"
#include "common/common.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

static uint8_t gKeymPageBuffer[PAGE_SIZE] __aligned(16);

int cerberus_pfr_decommission(struct pfr_manifest *manifest)
{
	CPLD_STATUS cpld_update_status;
	int status = 0;

	if (erase_provision_flash())
		return Failure;

	LOG_INF("Decommission Success");

	memset(&cpld_update_status, 0, sizeof(cpld_update_status));
	cpld_update_status.DecommissionFlag = 1;
	status = ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
	if (status != Success) {
		LOG_ERR("Update ROT status in UPDATE_STATUS_UFM failed");
		return Failure;
	}

	return Success;
}

int cerberus_append_key_manifest(struct pfr_manifest *manifest)
{
	struct recovery_section *image_section;
	struct PFR_KEY_MANIFEST *key_manifest;
	struct recovery_header *image_header;
	uint32_t target_page_align_address;
	uint32_t target_append_address;
	uint32_t last_keym_index;
	uint32_t source_address;
	uint32_t length;

	last_keym_index = KEY_MANIFEST_SIZE;
	source_address = manifest->address;
	if (pfr_spi_read(manifest->image_type, source_address, KEY_MANIFEST_SIZE, gKeymPageBuffer)) {
		LOG_ERR("Failed to read key manifest");
		return Failure;
	}

	image_header = (struct recovery_header *)gKeymPageBuffer;
	length = image_header->image_length + sizeof(struct rsa_public_key);
	if (length > KEY_MANIFEST_SIZE) {
		LOG_ERR("Key Manifest image length(%x) exceed the maximum size(%x)", length, KEY_MANIFEST_SIZE);
		return Failure;
	}

	image_section = (struct recovery_section *)&gKeymPageBuffer[image_header->header_length];
	if (image_section->magic_number != KEY_MANAGEMENT_SECTION_MAGIC ||
	    image_section->header_length != sizeof(struct recovery_section) ||
	    image_section->section_length != sizeof(struct PFR_KEY_MANIFEST)) {
		LOG_HEXDUMP_ERR((uint8_t *)image_section, sizeof(struct recovery_section), "section_header:");
		LOG_ERR("Failed to read image section.");
		return Failure;
	}

	key_manifest = (struct PFR_KEY_MANIFEST *)&gKeymPageBuffer[image_header->header_length + image_section->header_length];
	if (key_manifest->magic_number != KEY_MANIFEST_SECTION_MAGIC) {
		LOG_ERR("Key Manifest Magic Number is not Matched(%x).", key_manifest->magic_number);
		return Failure;
	}

	if (cerberus_pfr_get_key_manifest_append_addr(&target_append_address)) {
		LOG_ERR("Failed to get key manifest append address");
		return Failure;
	}

	target_page_align_address = target_append_address;
	if (target_append_address & (PAGE_SIZE - 1)) {
		target_page_align_address = target_append_address & ~(PAGE_SIZE - 1);
		LOG_INF("Read last key manifest, device_id=%d, address=%x, length=%x",
			ROT_INTERNAL_KEY, target_page_align_address, KEY_MANIFEST_SIZE);
		if (pfr_spi_read(ROT_INTERNAL_KEY, target_page_align_address, KEY_MANIFEST_SIZE, &gKeymPageBuffer[last_keym_index])) {
			LOG_ERR("Failed to read last key manifest");
			return Failure;
		}
	}

	if (pfr_spi_erase_4k(ROT_INTERNAL_KEY, target_page_align_address)) {
		LOG_ERR("Erase failed, device_id=%d, address=%x, length=%x",
			ROT_INTERNAL_KEY, target_page_align_address, PAGE_SIZE);
		return Failure;
	}

	if (target_page_align_address != target_append_address) {
		LOG_INF("Write last key manifest, device_id=%d, address=%x, length=%x",
			ROT_INTERNAL_KEY, target_page_align_address, KEY_MANIFEST_SIZE);
		if (pfr_spi_write(ROT_INTERNAL_KEY, target_page_align_address, KEY_MANIFEST_SIZE, &gKeymPageBuffer[last_keym_index])) {
			LOG_ERR("Failed to write last key manifest");
			return Failure;
		}
	}

	LOG_INF("Write key manifest, device_id=%d, address=%x, length=%x",
		ROT_INTERNAL_KEY, target_append_address, length);
	if (pfr_spi_write(ROT_INTERNAL_KEY, target_append_address, length, gKeymPageBuffer)) {
		LOG_ERR("Failed to write key manifest");
		return Failure;
	}

	LOG_INF("Key Manifest append done");

	return Success;
}

int cerberus_update_rot_fw(struct pfr_manifest *manifest, uint32_t flash_select)
{
	uint32_t region_size;
	uint32_t source_address = manifest->address;
	uint32_t length_page_align;
	uint8_t region_type;

	struct recovery_header image_header;
	struct recovery_section image_section;

	if (flash_select == PRIMARY_FLASH_REGION) {
		region_type = ROT_INTERNAL_ACTIVE;
	} else if (flash_select == SECONDARY_FLASH_REGION) {
		region_type = ROT_INTERNAL_RECOVERY;
	} else {
		return Failure;
	}

	pfr_spi_read(manifest->flash_id, source_address, sizeof(image_header),
			(uint8_t *)&image_header);
	source_address = source_address + image_header.header_length;
	pfr_spi_read(manifest->flash_id, source_address, sizeof(image_section),
			(uint8_t *)&image_section);
	source_address = source_address + image_section.header_length;

	region_size = pfr_spi_get_device_size(region_type);
	length_page_align =
		(image_section.section_length % PAGE_SIZE)
		? (image_section.section_length + (PAGE_SIZE - (image_section.section_length % PAGE_SIZE))) : image_section.section_length;

	if (length_page_align > region_size) {
		LOG_ERR("length(%x) exceed region size(%x)", length_page_align, region_size);
		return Failure;
	}

	if (pfr_spi_erase_region(region_type, true, 0, region_size)) {
		LOG_ERR("Erase PFR flash region failed, region id = %x, address = 0, length = %x",
				region_type, region_size);
		return Failure;
	}

	if (pfr_spi_region_read_write_between_spi(BMC_SPI, source_address,
				region_type, 0, length_page_align)) {
		LOG_ERR("read(BMC_SPI) address =%x, write(PFR_SPI) region id = %x, address = 0, length = %x",
				source_address, region_type, length_page_align);
		return Failure;
	}

	LOG_INF("ROT Firmware update done");

	return Success;
}

int cerberus_hrot_update(struct pfr_manifest *manifest, uint32_t flash_select)
{
	byte provision_state = GetUfmStatusValue();
	struct recovery_header image_header;
	struct PFR_VERSION *hrot_version;
	uint8_t hrot_svn = 0;

	if (provision_state & UFM_PROVISIONED) {
		LOG_INF("Verifying image, manifest->flash_id=%d address=%08x", manifest->flash_id, manifest->address);
		if (pfr_spi_read(manifest->flash_id, manifest->address, sizeof(image_header), (uint8_t *)&image_header)) {
			LOG_ERR("Unable to get image header.");
			return Failure;
		}

		if (image_header.format != UPDATE_FORMAT_TYPE_HROT &&
		    image_header.format != UPDATE_FORMAT_TYPE_KCC &&
		    image_header.format != UPDATE_FORMAT_TYPE_DCC &&
		    image_header.format != UPDATE_FORMAT_TYPE_KEYM) {
			LOG_ERR("Unsupported image format(%d)", image_header.format);
			return Failure;
		}

		manifest->pc_type = PFR_CPLD_UPDATE_CAPSULE;
		if (cerberus_pfr_verify_image(manifest)) {
			LOG_ERR("HRoT Image Verify Failed");
			return Failure;
		}

		if (image_header.format == UPDATE_FORMAT_TYPE_HROT) {
			LOG_INF("HRoT %s update start", (flash_select == PRIMARY_FLASH_REGION)? "Active" : "Recovery");
			hrot_version = (struct PFR_VERSION *)image_header.version_id;
			if (hrot_version->reserved1 != 0 ||
			    hrot_version->reserved2 != 0 ||
			    hrot_version->reserved3 != 0) {
				LOG_ERR("Invalid reserved data");
				return Failure;
			}

			hrot_svn = hrot_version->svn;
			if (svn_policy_verify(SVN_POLICY_FOR_CPLD_UPDATE, hrot_svn)) {
				LOG_ERR("HRoT verify svn failed");
				LogUpdateFailure(UPD_CAPSULE_INVALID_SVN, 1);
				return Failure;
			}

			if (cerberus_update_rot_fw(manifest, flash_select)) {
				LOG_ERR("HRoT update failed.");
				return Failure;
			}

			if (flash_select == SECONDARY_FLASH_REGION)
				set_ufm_svn(SVN_POLICY_FOR_CPLD_UPDATE, hrot_svn);
			SetCpldRotSvn(hrot_svn);
			LOG_INF("HRoT %s update end", (flash_select == PRIMARY_FLASH_REGION)? "Active" : "Recovery");
		} else if (image_header.format == UPDATE_FORMAT_TYPE_DCC) {
			if (cerberus_pfr_decommission(manifest)) {
				LOG_ERR("Decommission failed.");
				return Failure;
			}
		} else if (image_header.format == UPDATE_FORMAT_TYPE_KCC) {
			if (cerberus_pfr_cancel_csk_keys(manifest)) {
				LOG_ERR("Cancel CSK keys failed.");
				return Failure;
			}
		} else if (image_header.format == UPDATE_FORMAT_TYPE_KEYM) {
			if (cerberus_append_key_manifest(manifest)) {
				LOG_ERR("Key Manifest append failed");
				return Failure;
			}
		}
	} else {
		LOG_INF("Start HROT Provisioning %02x.", provision_state);
		return cerberus_provisioning_root_key_action(manifest);
	}

	return Success;
}

int cerberus_update_recovery_region(int image_type, uint32_t source_address, uint32_t target_address)
{
	return pfr_recover_recovery_region(image_type, source_address, target_address);
}

int cerberus_update_active_region(struct pfr_manifest *manifest, bool erase_rw_regions)
{
	int status = Success;

	struct recovery_header image_header;
	struct recovery_section image_section;

	uint32_t sig_address, recovery_offset, data_offset;
	uint32_t start_address, erase_address, section_length;
	uint32_t region_cnt;
	uint32_t *update_regions = NULL;
	int sector_sz = pfr_spi_get_block_size(manifest->image_type);
	bool support_block_erase = (sector_sz == BLOCK_SIZE);

	//read recovery header
	if (pfr_spi_read(manifest->image_type, manifest->address, sizeof(image_header),
			(uint8_t *)&image_header)) {
		LOG_ERR("Failed to read image header");
		return Failure;
	}

	if (!erase_rw_regions) {
		update_regions = cerberus_get_update_regions(manifest, &image_header, &region_cnt);
		if (!update_regions) {
			LOG_ERR("Failed to get update regions from PFM");
			return Failure;
		}
	}

	sig_address = manifest->address + image_header.image_length -
		image_header.sign_length;
	recovery_offset = manifest->address + image_header.header_length;
	bool should_update = false;

	while (recovery_offset < sig_address) {
		status = pfr_spi_read(manifest->image_type, recovery_offset,
				sizeof(image_section), (uint8_t *)&image_section);
		if (image_section.magic_number != RECOVERY_SECTION_MAGIC) {
			status = Failure;
			LOG_ERR("Recovery Section not matched.");
			break;
		}
		start_address = image_section.start_addr;
		section_length = image_section.section_length;
		erase_address = start_address;
		recovery_offset = recovery_offset + sizeof(image_section);
		data_offset = recovery_offset;
		should_update = false;
		recovery_offset = recovery_offset + image_section.section_length;

		if (!erase_rw_regions) {
			for (int i = 0; i < region_cnt; i++) {
				if (erase_address == update_regions[i]) {
					should_update = true;
					break;
				}
			}
		} else {
			should_update = true;
		}

		if (!should_update)
			continue;

		if (pfr_spi_erase_region(manifest->image_type, support_block_erase,
					erase_address, section_length)) {
			status = Failure;
			break;
		}
		if (pfr_spi_region_read_write_between_spi(manifest->image_type, data_offset,
					manifest->image_type, start_address,
					section_length)) {
			status = Failure;
			break;
		}
	}

	if (update_regions)
		free(update_regions);

	return status;
}

int update_firmware_image(uint32_t image_type, void *AoData, void *EventContext, CPLD_STATUS *cpld_update_status)
{
	EVENT_CONTEXT *EventData = (EVENT_CONTEXT *) EventContext;
	struct pfr_manifest *pfr_manifest = get_pfr_manifest();
	AO_DATA *ActiveObjectData = (AO_DATA *) AoData;
	uint8_t flash_select = EventData->flash;
	struct recovery_header image_header;
	bool erase_rw_regions = false;
	uint32_t source_address;
	uint32_t target_address;
	uint32_t act_pfm_offset;
	uint32_t flash_id;
	uint32_t pc_type;
	uint32_t address;
	uint8_t status = Success;
	uint8_t staging_svn = 0;

	if (((EVENT_CONTEXT *)EventContext)->flag & UPDATE_DYNAMIC)
		erase_rw_regions = true;

	pfr_manifest->state = FIRMWARE_UPDATE;
	pfr_manifest->image_type = image_type;

	LOG_INF("Firmware Update Start.");

	if (pfr_manifest->image_type != BMC_TYPE &&
	    pfr_manifest->image_type != PCH_TYPE &&
	    pfr_manifest->image_type != ROT_TYPE) {
		LOG_ERR("Unsupported image type %d", pfr_manifest->image_type);
		return Failure;
	}

	if (pfr_manifest->image_type == BMC_TYPE) {
		// BMC Update/Provisioning
		LOG_INF("BMC Update in Progress");
		if (ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
				sizeof(pfr_manifest->address)))
			return Failure;
		if (ufm_read(PROVISION_UFM, BMC_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
				sizeof(act_pfm_offset)))
			return Failure;
		flash_id = BMC_FLASH_ID;
		pfr_manifest->flash_id = flash_id;
		pc_type = PFR_BMC_UPDATE_CAPSULE;
		pfr_manifest->pc_type = pc_type;
	} else if (pfr_manifest->image_type == PCH_TYPE) {
		// PCH Update
		LOG_INF("PCH Update in Progress");
		if (ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
				sizeof(pfr_manifest->address)))
			return Failure;
		if (ufm_read(PROVISION_UFM, PCH_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
				sizeof(act_pfm_offset)))
			return Failure;
		flash_id = PCH_FLASH_ID;
		pfr_manifest->flash_id = flash_id;
		pc_type = PFR_PCH_UPDATE_CAPSULE;
		pfr_manifest->pc_type = pc_type;
	} else if (pfr_manifest->image_type == ROT_TYPE) {
		// HROT Update/Decommisioning
		LOG_INF("ROT Update in Progress");
		pfr_manifest->image_type = BMC_TYPE;
		pfr_manifest->address = BMC_CPLD_STAGING_ADDRESS;
		flash_id = BMC_FLASH_ID;
		pfr_manifest->flash_id = flash_id;
		pc_type = PFR_CPLD_UPDATE_CAPSULE;
		pfr_manifest->pc_type = pc_type;
		if (cpld_update_status->Region[ROT_REGION].Recoveryregion == RECOVERY_PENDING_REQUEST_HANDLED)
			cpld_update_status->Region[ROT_REGION].Recoveryregion = 0;
		return cerberus_hrot_update(pfr_manifest, flash_select);
	} else {
		LOG_ERR("Unknown image type : %x", pfr_manifest->image_type);
		return Failure;
	}

	pfr_manifest->staging_address = source_address;
	pfr_manifest->active_pfm_addr = act_pfm_offset;

	if (image_type == PCH_TYPE && cpld_update_status->BmcToPchStatus == 1) {
		cpld_update_status->BmcToPchStatus = 0;
		if (cpld_update_status->Region[PCH_REGION].Recoveryregion != RECOVERY_PENDING_REQUEST_HANDLED) {
			status = ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET,
					(uint8_t *)&address, sizeof(address));
			if (status != Success)
				return Failure;

			pfr_manifest->address = address;
			status = pfr_staging_pch_staging(pfr_manifest);
			if (status != Success)
				return Failure;
		}
	}

	pfr_manifest->image_type = image_type;
	pfr_manifest->address = source_address;
	pfr_manifest->flash_id = flash_id;
	pfr_manifest->pc_type = pc_type;

	// Checking for key cancellation
	if (pfr_spi_read(pfr_manifest->image_type, pfr_manifest->address, sizeof(image_header), (uint8_t *)&image_header)) {
		LOG_ERR("Unable to get image header.");
		return Failure;
	}

	if (image_header.format == UPDATE_FORMAT_TYPE_KCC) {
		if (cerberus_pfr_verify_image(pfr_manifest)) {
			LOG_ERR("Image Verify Failed");
			return Failure;
		}

		return cerberus_pfr_cancel_csk_keys(pfr_manifest);
	}

	// BMC/PCH Firmware Update for Active/Recovery Region
	status = pfr_manifest->update_fw->base->verify((struct firmware_image *)pfr_manifest,
			NULL, NULL);
	if (status != Success) {
		LOG_ERR("Staging Area verification failed.");
		if (flash_select == PRIMARY_FLASH_REGION)
			LogUpdateFailure(UPD_CAPSULE_AUTH_FAIL, 1);
		else
			LogUpdateFailure(UPD_CAPSULE_TO_RECOVERY_AUTH_FAIL, 1);

		return Failure;
	}

	// SVN number validation
	status = read_statging_area_pfm_svn(pfr_manifest, &image_header, &staging_svn);
	if (status != Success) {
		LogUpdateFailure(UPD_CAPSULE_INVALID_SVN, 1);
		LOG_ERR("Get staging svn failed");
		return Failure;
	}

	if (pfr_manifest->image_type == BMC_TYPE)
		status = svn_policy_verify(SVN_POLICY_FOR_BMC_FW_UPDATE, staging_svn);
	else
		status = svn_policy_verify(SVN_POLICY_FOR_PCH_FW_UPDATE, staging_svn);

	if (status != Success) {
		LogUpdateFailure(UPD_CAPSULE_INVALID_SVN, 1);
		LOG_ERR("Anti rollback");
		return Failure;
	}

	if (flash_select == PRIMARY_FLASH_REGION) {
		// Update Active
		LOG_INF("Update Type: Active Update.");

		if (ActiveObjectData->RestrictActiveUpdate == 1) {
			LOG_ERR("Restrict Active Update");
			LogUpdateFailure(UPD_NOT_ALLOWED, 0);
			return Failure;
		}

		uint32_t time_start, time_end;

		time_start = k_uptime_get_32();
		status = cerberus_update_active_region(pfr_manifest, erase_rw_regions);
		if (status != Success)
			return Failure;

		time_end = k_uptime_get_32();
		LOG_INF("Firmware update completed, elapsed time = %u milliseconds",
				(time_end - time_start));
	} else {
		// Update Recovery
		LOG_INF("Update Type: Recovery Update.");
		if (image_type == BMC_TYPE) {
			// BMC Update/Provisioning
			get_provision_data_in_flash(BMC_STAGING_REGION_OFFSET, (uint8_t *)&source_address, sizeof(source_address));
			get_provision_data_in_flash(BMC_RECOVERY_REGION_OFFSET, (uint8_t *)&target_address, sizeof(target_address));
			cpld_update_status->Region[BMC_REGION].Recoveryregion = 0;
		} else if (image_type == PCH_TYPE) {
			// PCH Update
			get_provision_data_in_flash(PCH_STAGING_REGION_OFFSET, (uint8_t *)&source_address, sizeof(source_address));
			get_provision_data_in_flash(PCH_RECOVERY_REGION_OFFSET, (uint8_t *)&target_address, sizeof(target_address));
			cpld_update_status->Region[PCH_REGION].Recoveryregion = 0;
		}

		if (ActiveObjectData->RestrictActiveUpdate == 1) {
			status = does_staged_fw_image_match_active_fw_image(pfr_manifest);
			if (status != Success) {
				LogUpdateFailure(UPD_NOT_ALLOWED, 0);
				return Failure;
			}
		}

		status = cerberus_update_recovery_region(image_type, source_address, target_address);
		if (status != Success) {
			LOG_ERR("Recovery region update failed");
			return Failure;
		}

		// update svn
		if (pfr_manifest->image_type == BMC_TYPE)
			status = set_ufm_svn(SVN_POLICY_FOR_BMC_FW_UPDATE, staging_svn);
		else
			status = set_ufm_svn(SVN_POLICY_FOR_PCH_FW_UPDATE, staging_svn);
	}

	return status;
}

/**
 * Verify the complete firmware image.  All components in the image will be fully validated.
 * This includes checking image signatures and key revocation.
 *
 * @param fw The firmware image to validate.
 * @param hash The hash engine to use for validation.
 * @param rsa The RSA engine to use for signature checking.
 *
 * @return 0 if the firmware image is valid or an error code.
 */
int firmware_image_verify(struct firmware_image *fw, struct hash_engine *hash, struct rsa_engine *rsa)
{
	ARG_UNUSED(hash);
	ARG_UNUSED(rsa);
	struct pfr_manifest *manifest = (struct pfr_manifest *) fw;
	struct recovery_header image_header;
	uint32_t dest_pfm_addr;
	uint32_t src_pfm_addr;
	int status;

	if (manifest->image_type != BMC_TYPE &&
	    manifest->image_type != PCH_TYPE) {
		LOG_ERR("Unsupported image type %d", manifest->image_type);
		return Failure;
	}

	LOG_INF("Staging Region Verification");

	init_stage_and_recovery_offset(manifest);
	manifest->address = manifest->staging_address;
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
		LOG_ERR("Stage Image Verify Failed");
		return Failure;
	}

	// Find PFM in stage image
	if (cerberus_get_image_pfm_addr(manifest, &image_header, &src_pfm_addr, &dest_pfm_addr)) {
		LOG_ERR("PFM doesn't exist in stage image");
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

	// Stage region PFM verification
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

	manifest->address = manifest->staging_address;
	LOG_INF("Staging area verification successful");

	return Success;
}

