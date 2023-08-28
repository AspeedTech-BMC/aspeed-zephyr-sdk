/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <storage/flash_map.h>
#include <drivers/flash.h>
#include "pfr/pfr_update.h"
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_util.h"
#include "pfr/pfr_recovery.h"
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "pfr/pfr_common.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "include/SmbusMailBoxCom.h"
#include "intel_pfr_verification.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_pbc.h"
#include "intel_pfr_recovery.h"
#include "intel_pfr_key_cancellation.h"
#include "intel_pfr_update.h"
#include "intel_pfr_svn.h"
#include "flash/flash_aspeed.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "gpio/gpio_aspeed.h"
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
#include "intel_pfr_cpld_utils.h"
#endif

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int pfr_staging_verify(struct pfr_manifest *manifest)
{
	int status = 0;
	uint32_t read_address = 0;
	uint32_t target_address = 0;
	bool afm_update = false;
	bool cpld_update = false;

	if (manifest->image_type == BMC_TYPE) {
		LOG_INF("BMC Staging Region Verification");
		status = ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET,
				(uint8_t *)&read_address, sizeof(read_address));
		if (status != Success)
			return status;

		status = ufm_read(PROVISION_UFM, BMC_RECOVERY_REGION_OFFSET,
				(uint8_t *)&target_address, sizeof(target_address));
		if (status != Success)
			return status;

		manifest->pc_type = PFR_BMC_UPDATE_CAPSULE;

	} else if (manifest->image_type == PCH_TYPE) {
		LOG_INF("PCH Staging Region Verification");
		status = ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET,
				(uint8_t *)&read_address, sizeof(read_address));
		if (status != Success)
			return Failure;

		status = ufm_read(PROVISION_UFM, PCH_RECOVERY_REGION_OFFSET,
				(uint8_t *)&target_address, sizeof(target_address));
		if (status != Success)
			return Failure;

#if defined(CONFIG_SEAMLESS_UPDATE)
		if (manifest->state == SEAMLESS_UPDATE) {
			manifest->pc_type = PFR_PCH_SEAMLESS_UPDATE_CAPSULE;
		} else
#endif
		{
			manifest->pc_type = PFR_PCH_UPDATE_CAPSULE;
		}
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (manifest->image_type == AFM_TYPE) {
		LOG_INF("AFM Staging Region Verification");
		manifest->image_type = BMC_TYPE;
		read_address = CONFIG_BMC_AFM_STAGING_OFFSET;
		target_address = CONFIG_BMC_AFM_RECOVERY_OFFSET;
		manifest->pc_type = PFR_AFM;
		afm_update = true;
	}
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	else if (manifest->image_type == CPLD_TYPE) {
		LOG_INF("Intel CPLD Staging Region Verification");
		manifest->image_type = BMC_TYPE;
		read_address = CONFIG_BMC_INTEL_CPLD_STAGING_OFFSET;
		manifest->pc_type = PFR_INTEL_CPLD_UPDATE_CAPSULE;
		cpld_update = true;
	}
#endif
	else {
		return Failure;
	}

	manifest->address = read_address;
	manifest->recovery_address = target_address;

	LOG_INF("Verifying capsule signature, address=0x%08x", manifest->address);
	// manifest verification
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Capsule signature verification failed");
		return Failure;
	}

	manifest->update_fw->pc_length = manifest->pc_length;

	if (afm_update == true)
		manifest->pc_type = PFR_AFM;
	else if (cpld_update == true)
		manifest->pc_type = PFR_INTEL_CPLD_UPDATE_CAPSULE;
	else if (manifest->image_type == BMC_TYPE)
		manifest->pc_type = PFR_BMC_PFM;
	else if (manifest->image_type == PCH_TYPE)
		manifest->pc_type = PFR_PCH_PFM;

	manifest->address += PFM_SIG_BLOCK_SIZE;

	LOG_INF("Verifying PFM signature, address=0x%08x", manifest->address);
	// manifest verification
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("PFM signature verification failed");
		return Failure;
	}

	manifest->update_fw->pfm_length = manifest->pc_length;
	manifest->address = read_address;
	manifest->staging_address = read_address;

#if defined(CONFIG_SEAMLESS_UPDATE)
	if (manifest->image_type == PCH_TYPE &&
			manifest->state == SEAMLESS_UPDATE) {
		status = manifest->pfr_authentication->fvm_verify(manifest);
	} else if (manifest->image_type == PCH_TYPE) {
		status = manifest->pfr_authentication->fvms_verify(manifest);
	}
#endif
	LOG_INF("Staging area verification successful");

	if (afm_update)
		manifest->image_type = AFM_TYPE;
	else if (cpld_update)
		manifest->image_type = CPLD_TYPE;

	return status;
}

int intel_pfr_update_verify(struct firmware_image *fw, struct hash_engine *hash, struct rsa_engine *rsa)
{

	ARG_UNUSED(hash);
	ARG_UNUSED(rsa);

	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) fw;

	return pfr_staging_verify(pfr_manifest);
}

int  check_rot_capsule_type(struct pfr_manifest *manifest)
{
	int status = 0;
	uint32_t pc_type;

	status = pfr_spi_read(manifest->image_type, manifest->address + (2 * sizeof(pc_type)),
			sizeof(pc_type), (uint8_t *)&pc_type);
	if (pc_type == PFR_CPLD_UPDATE_CAPSULE_DECOMMISSON) {
		LOG_INF("Decommission Certificate found");
		return PFR_CPLD_UPDATE_CAPSULE_DECOMMISSON;
	} else if ((pc_type == CPLD_CAPSULE_CANCELLATION) ||
			(pc_type == PCH_PFM_CANCELLATION) ||
			(pc_type == PCH_CAPSULE_CANCELLATION) ||
			(pc_type == BMC_PFM_CANCELLATION) ||
			(pc_type == BMC_CAPSULE_CANCELLATION)) {
		return KEY_CANCELLATION_CAPSULE;
	} else if (pc_type == PFR_CPLD_UPDATE_CAPSULE) {
		return PFR_CPLD_UPDATE_CAPSULE;
	} else if (pc_type == PFR_PCH_SEAMLESS_UPDATE_CAPSULE) {
		return PFR_PCH_SEAMLESS_UPDATE_CAPSULE;
	} else if (pc_type == PFR_AFM) {
		return PFR_AFM;
	} else {
		return 7;
	}
}

int pfr_decommission(struct pfr_manifest *manifest)
{
	uint8_t read_buffer[DECOMM_CAP_RESERVED_SIZE] = { 0 };
	CPLD_STATUS cpld_update_status;
	int status = 0;
	int i;

	status = pfr_spi_read(manifest->image_type, manifest->address, manifest->pc_length, read_buffer);
	if (status != Success) {
		LOG_ERR("Flash read decommission capsule data failed");
		return Failure;
	}

	for (i = 0; i < sizeof(read_buffer); i++) {
		if (read_buffer[i] != 0) {
			LOG_ERR("Invalid decommission capsule data");
			return Failure;
		}
	}

	if (erase_provision_flash())
		return Failure;

	LOG_INF("Decommission Success");

	memset(&cpld_update_status, 0, sizeof(cpld_update_status));
	cpld_update_status.DecommissionFlag = 1;
	status = ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status,
			sizeof(CPLD_STATUS));
	if (status != Success) {
		LOG_ERR("Update ROT status in UPDATE_STATUS_UFM failed");
		return Failure;
	}

	return Success;
}

int update_rot_fw(uint32_t address, uint32_t length, uint32_t flash_select)
{
	uint32_t region_size;
	uint32_t source_address = address;
	uint32_t length_page_align;
	uint8_t region_type;

	if (flash_select == PRIMARY_FLASH_REGION) {
		region_type = ROT_INTERNAL_ACTIVE;
	} else if (flash_select == SECONDARY_FLASH_REGION) {
		region_type = ROT_INTERNAL_RECOVERY;
	} else {
		LOG_ERR("Unknown flash region, Region = %x", flash_select);
		return Failure;
	}

	region_size = pfr_spi_get_device_size(region_type);
	length_page_align =
		(length % PAGE_SIZE) ? (length + (PAGE_SIZE - (length % PAGE_SIZE))) : length;

	if (length_page_align > region_size) {
		LOG_ERR("length(%x) exceed region size(%x)", length_page_align, region_size);
		return Failure;
	}

	if (pfr_spi_erase_region(region_type, true, 0, region_size)) {
		LOG_ERR("Erase PFR flash region failed, region id = %x, address = 0, length = %x",
				region_type, region_size);
		return Failure;
	}

	if (pfr_spi_region_read_write_between_spi(BMC_SPI, source_address, region_type, 0, length_page_align)) {
		LOG_ERR("read(BMC_SPI) address = %x, write(PFR_SPI) region id = %x, address = 0, length = %x",
			source_address, region_type, length_page_align);
		return Failure;
	}

	return Success;
}

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
int update_afm(enum AFM_PARTITION_TYPE part, uint32_t address, size_t length)
{
	uint32_t region_size = pfr_spi_get_device_size(ROT_INTERNAL_AFM);
	uint32_t source_address = address;
	uint32_t length_page_align;

	length_page_align =
		(length % PAGE_SIZE) ? (length + (PAGE_SIZE - (length % PAGE_SIZE))) : length;

	if (part == AFM_PART_ACT_1) {
		if (length_page_align > region_size) {
			LOG_ERR("length(%x) exceed region size(%x)", length_page_align, region_size);
			return Failure;
		}

		if (pfr_spi_erase_region(ROT_INTERNAL_AFM, true, 0, region_size)) {
			LOG_ERR("Failed to erase AFM Active Partition");
			return Failure;
		}

		if (pfr_spi_region_read_write_between_spi(BMC_SPI, source_address,
					ROT_INTERNAL_AFM, 0, length_page_align)) {
			LOG_ERR("Failed to write AFM Active Partition");
			return Failure;
		}
	} else if (part == AFM_PART_RCV_1) {
		if (pfr_spi_erase_region(BMC_SPI, true,
					CONFIG_BMC_AFM_RECOVERY_OFFSET,
					CONFIG_BMC_AFM_STAGING_RECOVERY_SIZE)) {
			LOG_ERR("Failed to erase AFM Recovery Partition");
			return Failure;
		}

		if (pfr_spi_region_read_write_between_spi(
					BMC_SPI, CONFIG_BMC_AFM_STAGING_OFFSET,
					BMC_SPI, CONFIG_BMC_AFM_RECOVERY_OFFSET,
					CONFIG_BMC_AFM_STAGING_RECOVERY_SIZE)) {
			LOG_ERR("Failed to write AFM Recovery Partition");
			return Failure;
		}

	} else {
		return Failure;
	}

	return Success;
}

int update_afm_image(struct pfr_manifest *manifest, uint32_t flash_select, void *AoData)
{
	AO_DATA *ActiveObjectData = (AO_DATA *) AoData;
	uint32_t payload_address;
	uint32_t pc_length = 0;
	uint32_t hrot_svn = 0;
	uint32_t pc_type;
	int status = 0;

	// Checking the PC type
	status = pfr_spi_read(manifest->image_type, manifest->address + (2 * sizeof(pc_type)),
			sizeof(pc_type), (uint8_t *)&pc_type);
	if (status != Success) {
		LOG_ERR("Flash read PC type failed");
		return Failure;
	}

	manifest->pc_type = pc_type;

	LOG_INF("manifest->address=%08x", manifest->address);
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("AFM update capsule verification failed");
		LogUpdateFailure(UPD_CAPSULE_AUTH_FAIL, 1);
		return Failure;
	}

	pc_length = manifest->pc_length;
	payload_address = manifest->address + PFM_SIG_BLOCK_SIZE;
	LOG_INF("AFM update start payload_address=%08x pc_length=%x", payload_address, pc_length);
	status = pfr_spi_read(manifest->image_type, payload_address + PFM_SIG_BLOCK_SIZE + 4,
				sizeof(uint8_t), (uint8_t *)&hrot_svn);
	if (status != Success) {
		LOG_ERR("Flash read AFM SVN failed");
		return Failure;
	}

	status = svn_policy_verify(SVN_POLICY_FOR_AFM, hrot_svn);
	if (status != Success) {
		LOG_ERR("Verify AFM SVN failed");
		LogUpdateFailure(UPD_CAPSULE_INVALID_SVN, 1);
		return Failure;
	}

	if (flash_select == PRIMARY_FLASH_REGION) {
		if (ActiveObjectData->RestrictActiveUpdate == 1) {
			LOG_ERR("Restrict Active Update");
			LogUpdateFailure(UPD_NOT_ALLOWED, 0);
			return Failure;
		}

		status = update_afm(AFM_PART_ACT_1, payload_address, pc_length);
		if (status != Success) {
			LOG_ERR("Update AFM Active failed");
			return Failure;
		}
	} else if (flash_select == SECONDARY_FLASH_REGION) {
		if (ActiveObjectData->RestrictActiveUpdate == 1) {
			manifest->image_type = AFM_TYPE;
			status = does_staged_fw_image_match_active_fw_image(manifest);
			if (status != Success) {
				LogUpdateFailure(UPD_NOT_ALLOWED, 0);
				return Failure;
			}
		}

		status = update_afm(AFM_PART_RCV_1, payload_address, pc_length);
		if (status != Success) {
			LOG_ERR("Update AFM Recovery failed");
			return Failure;
		}

		set_ufm_svn(SVN_POLICY_FOR_AFM, hrot_svn);
	}

	LOG_INF("AFM update end");

	return Success;
}

#endif

#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
int update_cpld_image(struct pfr_manifest *manifest)
{
	uint32_t dst_addr = 0;
	uint8_t rsu_type;
	uint8_t minor_error;
	uint8_t err_count = 0;

#if defined(CONFIG_INTEL_SCM_CPLD_UPDATE_ONLY)
	dst_addr = CONFIG_INTEL_SCM_RSU_FLASH_ADDR;
	minor_error = INTEL_CPLD_IMAGE_SCM_CPLD;
	rsu_type = SCM_CPLD;
	if (intel_rsu_perform_update(manifest, rsu_type, dst_addr)) {
		LOG_ERR("Failed to update CPLD firmware, rsu_type = %d", rsu_type);
		LogErrorCodes(INTEL_CPLD_UPDATE_FAIL, minor_error);
		err_count++;
	}
#else
	uint32_t fw_size = 0;
	uint8_t board_id = intel_rsu_get_scm_board_id();
	uint8_t rsu_count = (board_id == SCM_BOARD_ID_DEFAULT) ? MAX_RSU_TYPE : (MAX_RSU_TYPE - 1);
	for (rsu_type = 0; rsu_type < rsu_count; rsu_type++) {
		fw_size = manifest->intel_cpld_img_size[rsu_type];
		if (fw_size == 0)
			continue;

		switch (rsu_type) {
		case CPU_CPLD:
			dst_addr = CONFIG_INTEL_CPU_RSU_FLASH_ADDR;
			minor_error = INTEL_CPLD_IMAGE_CPU_CPLD;
			break;
		case SCM_CPLD:
			dst_addr = CONFIG_INTEL_SCM_RSU_FLASH_ADDR;
			minor_error = INTEL_CPLD_IMAGE_SCM_CPLD;
			break;
		case DEBUG_CPLD:
			dst_addr = CONFIG_INTEL_DEBUG_RSU_FLASH_ADDR;
			minor_error = INTEL_CPLD_IMAGE_DEBUG_CPLD;
			break;
		default:
			LOG_ERR("Invalid RSU type");
			return Failure;
		}

		if (intel_rsu_perform_update(manifest, rsu_type, dst_addr)) {
			LOG_ERR("Failed to update CPLD firmware, rsu_type = %d", rsu_type);
			LogErrorCodes(INTEL_CPLD_UPDATE_FAIL, minor_error);
			err_count++;
		}
	}
#endif

	if (err_count)
		return Failure;

	LOG_INF("Intel CPLD update succesful");
	return Success;
}

int verify_and_update_cpld_images(struct pfr_manifest *manifest, uint32_t flash_select,
		void *AoData)
{
	ARG_UNUSED(AoData);
	uint32_t read_addr = manifest->address;
	uint32_t region_size;

	manifest->pc_type = PFR_INTEL_CPLD_UPDATE_CAPSULE;

	if (manifest->pfr_authentication->online_update_cap_verify(manifest)) {
		LOG_ERR("Verify BMC's CPLD staging region failed");
		return Failure;
	}

	region_size = pfr_spi_get_device_size(ROT_EXT_CPLD_ACT);
	if (pfr_spi_erase_region(ROT_EXT_CPLD_ACT, true, 0, region_size)) {
		LOG_ERR("Erase CPLD active region failed");
		return Failure;
	}


	LOG_INF("Copying BMC's CPLD staging region to ROT's CPLD active region");
	if (pfr_spi_region_read_write_between_spi(BMC_SPI, read_addr,
				ROT_EXT_CPLD_ACT, 0, region_size)) {
		LOG_ERR("Failed to write CPLD image to ROT's CPLD active region");
		return Failure;
	}

	// Verify the copied capsule
	manifest->address = 0;
	manifest->image_type = ROT_EXT_CPLD_ACT;
	if (manifest->pfr_authentication->online_update_cap_verify(manifest)) {
		LOG_ERR("Verify ROT's CPLD active region failed");
		return Failure;
	}

	if (update_cpld_image(manifest))
		return Failure;

	region_size = pfr_spi_get_device_size(ROT_EXT_CPLD_RC);
	if (pfr_spi_erase_region(ROT_EXT_CPLD_RC, true, 0, region_size)) {
		LOG_ERR("Erase CPLD recovery region failed");
		return Failure;
	}

	LOG_INF("Copying ROT's active CPLD region to ROT's recovery CPLD region");
	if (pfr_spi_region_read_write_between_spi(ROT_EXT_CPLD_ACT, 0,
				ROT_EXT_CPLD_RC, 0, region_size)) {
		LOG_ERR("Failed to write CPLD image to ROT's CPLD recovery region");
		return Failure;
	}

	return Success;
}
#endif

int ast1060_update(struct pfr_manifest *manifest, uint32_t flash_select)
{
	uint32_t cancelled_id = 0;
	uint32_t payload_address;
	uint32_t pc_type_status;
	uint32_t pc_length = 0;
	uint32_t hrot_svn = 0;
	uint32_t pc_type;
	int status = 0;

	// Checking the PC type
	status = pfr_spi_read(manifest->image_type, manifest->address + (2 * sizeof(pc_type)),
			sizeof(pc_type), (uint8_t *)&pc_type);
	if (status != Success) {
		LOG_ERR("Flash read PC type failed");
		return Failure;
	}

	manifest->pc_type = pc_type;

	LOG_INF("manifest->address=%x", manifest->address);
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("ROT update capsule verification failed");
		LogUpdateFailure(UPD_CAPSULE_AUTH_FAIL, 1);
		return Failure;
	}

	LOG_INF("ROT update capsule verification success");
	pc_type_status = check_rot_capsule_type(manifest);
	payload_address = manifest->address + PFM_SIG_BLOCK_SIZE;
	if (pc_type_status == PFR_CPLD_UPDATE_CAPSULE_DECOMMISSON) {
		// Decommission validation
		manifest->address = payload_address;
		status = pfr_decommission(manifest);
		return status;
	} else if (pc_type_status == KEY_CANCELLATION_CAPSULE) {
		status = pfr_spi_read(manifest->image_type, payload_address, sizeof(uint32_t),
				(uint8_t *)&cancelled_id);
		if (status != Success) {
			LOG_ERR("Flash read key cancellation Id failed");
			return Failure;
		}

		status = manifest->keystore->kc_flag->cancel_kc_flag(manifest, cancelled_id);
		if (status == Success)
			LOG_INF("Key cancellation success. Key Id :%d was cancelled", cancelled_id);

		return status;
	} else if (pc_type_status == PFR_CPLD_UPDATE_CAPSULE) {
		LOG_INF("ROT %s update start", (flash_select == PRIMARY_FLASH_REGION)? "Active" : "Recovery");
		status = pfr_spi_read(manifest->image_type, payload_address, sizeof(uint32_t),
				(uint8_t *)&hrot_svn);
		if (status != Success) {
			LOG_ERR("ROT flash read svn failed");
			return Failure;
		}

		status = svn_policy_verify(SVN_POLICY_FOR_CPLD_UPDATE, hrot_svn);
		if (status != Success) {
			LOG_ERR("ROT verify svn failed");
			LogUpdateFailure(UPD_CAPSULE_INVALID_SVN, 1);
			return Failure;
		}
		pc_length = manifest->pc_length - sizeof(uint32_t);
		payload_address = payload_address + sizeof(uint32_t);

		status = update_rot_fw(payload_address, pc_length, flash_select);
		if (status != Success) {
			LOG_ERR("ROT %s update failed", (flash_select == PRIMARY_FLASH_REGION)? "Active" : "Recovery");
			return Failure;
		}

		if (flash_select == SECONDARY_FLASH_REGION)
			set_ufm_svn(SVN_POLICY_FOR_CPLD_UPDATE, hrot_svn);
		SetCpldRotSvn(hrot_svn);
		LOG_INF("ROT %s update end", (flash_select == PRIMARY_FLASH_REGION)? "Active" : "Recovery");
	}
	return Success;
}

int update_recovery_region(int image_type, uint32_t source_address, uint32_t target_address)
{
	return pfr_recover_recovery_region(image_type, source_address, target_address);
}

int update_firmware_image(uint32_t image_type, void *AoData, void *EventContext,
		CPLD_STATUS *cpld_update_status)
{
	int status = 0;
	uint32_t source_address, target_address, area_size;
	uint32_t act_pfm_offset;
	uint32_t address = 0;
	uint32_t pc_type_status = 0;
	uint8_t staging_svn = 0;
	AO_DATA *ActiveObjectData = (AO_DATA *) AoData;
	DECOMPRESSION_TYPE_MASK_ENUM decomp_event;
	uint32_t flash_select = ((EVENT_CONTEXT *)EventContext)->flash;
	struct pfr_manifest *pfr_manifest = get_pfr_manifest();

	if (((EVENT_CONTEXT *)EventContext)->flag & UPDATE_DYNAMIC) {
		decomp_event = DECOMPRESSION_STATIC_AND_DYNAMIC_REGIONS_MASK;
	} else {
		decomp_event = DECOMPRESSION_STATIC_REGIONS_MASK;
	}

	pfr_manifest->state = FIRMWARE_UPDATE;
	pfr_manifest->image_type = image_type;
	pfr_manifest->flash_id = flash_select;

	if (pfr_manifest->image_type == ROT_TYPE) {
		pfr_manifest->image_type = BMC_TYPE;
		pfr_manifest->address = CONFIG_BMC_PFR_STAGING_OFFSET;
		return ast1060_update(pfr_manifest, flash_select);
	}
	else if (pfr_manifest->image_type == BMC_TYPE) {
		LOG_INF("BMC Update in progress");
		if (ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
					sizeof(source_address)))
			return Failure;
		if (ufm_read(PROVISION_UFM, BMC_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	} else if (pfr_manifest->image_type == PCH_TYPE) {
		LOG_INF("PCH Update in progress");
		if (ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
					sizeof(source_address)))
			return Failure;
		if (ufm_read(PROVISION_UFM, PCH_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (pfr_manifest->image_type == AFM_TYPE) {
		LOG_INF("AFM Update in progress");
		pfr_manifest->image_type = BMC_TYPE;
		pfr_manifest->address = CONFIG_BMC_AFM_STAGING_OFFSET;
		return update_afm_image(pfr_manifest, flash_select, ActiveObjectData);
	}
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	else if (pfr_manifest->image_type == CPLD_TYPE) {
		LOG_INF("SCM/CPU/Debug CPLD Update in progress");
		pfr_manifest->image_type = BMC_TYPE;
		pfr_manifest->address = CONFIG_BMC_INTEL_CPLD_STAGING_OFFSET;
		return verify_and_update_cpld_images(pfr_manifest, flash_select, ActiveObjectData);
	}
#endif
	else {
		LOG_ERR("Unsupported image type %d", pfr_manifest->image_type);
		return Failure;
	}

	pfr_manifest->staging_address = source_address;
	pfr_manifest->active_pfm_addr = act_pfm_offset;

	if (image_type == PCH_TYPE && cpld_update_status->BmcToPchStatus == 1) {
		cpld_update_status->BmcToPchStatus = 0;
		// It is not necessary to copy image from bmc's staging to pch's staging again
		// for handling the pending recovery update.
		if (cpld_update_status->Region[PCH_REGION].Recoveryregion != RECOVERY_PENDING_REQUEST_HANDLED) {
			status = ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET,
					(uint8_t *)&address, sizeof(address));
			if (status != Success)
				return Failure;

			pfr_manifest->address = address;

			// Checking for key cancellation
			pfr_manifest->image_type = BMC_TYPE;
			pc_type_status = check_rot_capsule_type(pfr_manifest);
			pfr_manifest->image_type = image_type;

			status = pfr_staging_pch_staging(pfr_manifest);
			if (status != Success)
				return Failure;
		}
	}

	pfr_manifest->address = source_address;
	// Checking for key cancellation
	pc_type_status = check_rot_capsule_type(pfr_manifest);
	if (pc_type_status ==  KEY_CANCELLATION_CAPSULE)
		return ast1060_update(pfr_manifest, PRIMARY_FLASH_REGION);

	// Staging area verification
	LOG_INF("Staging Area verification");
	status = pfr_manifest->update_fw->base->verify((struct firmware_image *)pfr_manifest,
			NULL, NULL);
	if (status != Success) {
		LOG_ERR("Staging Area verification failed");
		if (flash_select == PRIMARY_FLASH_REGION) {
			// Log failure for the case of active region update.
			LogUpdateFailure(UPD_CAPSULE_AUTH_FAIL, 1);
		} else {
			// Log failure for the case of recovery region update.
			LogUpdateFailure(UPD_CAPSULE_TO_RECOVERY_AUTH_FAIL, 1);
		}

		return Failure;
	}

	// After staging manifest, Compression header will start
	area_size = pfr_manifest->update_fw->pc_length -
		(PFM_SIG_BLOCK_SIZE + pfr_manifest->update_fw->pfm_length);

	// SVN number validation
	status = read_statging_area_pfm_svn(pfr_manifest, &staging_svn);
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
		// Active Update
		LOG_INF("Active Region Update");

		if (ActiveObjectData->RestrictActiveUpdate == 1) {
			LOG_ERR("Restrict Active Update");
			LogUpdateFailure(UPD_NOT_ALLOWED, 0);
			return Failure;
		}

		uint32_t time_start, time_end;
		time_start = k_uptime_get_32();

		if (pfr_manifest->image_type == BMC_TYPE || pfr_manifest->image_type == PCH_TYPE) {
			if (decompress_capsule(pfr_manifest, decomp_event)) {
				LogUpdateFailure(UPD_CAPSULE_AUTH_FAIL, 1);
				return Failure;
			}
		}
		else {
			LOG_ERR("Unsupported image_type=%d", pfr_manifest->image_type);
			return Failure;
		}

		time_end = k_uptime_get_32();
		LOG_INF("Firmware update completed, elapsed time = %u milliseconds",
				(time_end - time_start));
	} else {
		if (pfr_manifest->image_type == BMC_TYPE) {
			LOG_INF("BMC Recovery Region Update");
			status = ufm_read(PROVISION_UFM, BMC_RECOVERY_REGION_OFFSET,
					(uint8_t *)&target_address, sizeof(target_address));
		}
		else if (pfr_manifest->image_type == PCH_TYPE) {
			LOG_INF("PCH Recovery Region Update");
			status = ufm_read(PROVISION_UFM, PCH_RECOVERY_REGION_OFFSET,
					(uint8_t *)&target_address, sizeof(target_address));
		}
		else {
			LOG_ERR("Unsupported image_type=%d", pfr_manifest->image_type);
			return Failure;
		}

		if (status != Success)
			return status;

		if (ActiveObjectData->RestrictActiveUpdate == 1) {
			status = does_staged_fw_image_match_active_fw_image(pfr_manifest);
			if (status != Success) {
				LogUpdateFailure(UPD_NOT_ALLOWED, 0);
				return Failure;
			}
		}

		status = update_recovery_region(pfr_manifest->image_type, source_address,
				target_address);
		if (status != Success) {
			LOG_ERR("Recovery capsule update failed");
			return Failure;
		}

		// update svn
		if (pfr_manifest->image_type == BMC_TYPE)
			status = set_ufm_svn(SVN_POLICY_FOR_BMC_FW_UPDATE, staging_svn);
		else
			status = set_ufm_svn(SVN_POLICY_FOR_PCH_FW_UPDATE, staging_svn);

		return status;
	}

	return Success;
}

#if defined(CONFIG_SEAMLESS_UPDATE)
int perform_seamless_update(uint32_t image_type, void *AoData, void *EventContext)
{
	int status = 0;
	uint32_t source_address;
	uint32_t act_pfm_offset;
	uint32_t address = 0;
	uint32_t pc_type_status = 0;
	CPLD_STATUS cpld_update_status;
	const struct device *dev_m = NULL;
#if defined(CONFIG_BMC_DUAL_FLASH)
	uint32_t flash_size = flash_get_flash_size("spi1_cs0");
	uint32_t staging_start_addr;
#endif

	uint32_t flash_select = ((EVENT_CONTEXT *)EventContext)->flash;

	struct pfr_manifest *pfr_manifest = get_pfr_manifest();

	// Currently, only support pch seamless update.
	if (image_type != PCH_TYPE) {
		return Failure;
	}

	LOG_INF("PCH Seamless Update in Progress");
	if (ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
				sizeof(source_address)))
		return Failure;
	if (ufm_read(PROVISION_UFM, PCH_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
				sizeof(act_pfm_offset)))
		return Failure;

	pfr_manifest->state = SEAMLESS_UPDATE;
	pfr_manifest->image_type = image_type;
	pfr_manifest->flash_id = flash_select;
	pfr_manifest->staging_address = source_address;
	pfr_manifest->active_pfm_addr = act_pfm_offset;

	status = ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status,
			sizeof(CPLD_STATUS));
	LOG_HEXDUMP_INF(&cpld_update_status, sizeof(cpld_update_status), "CPLD Status");
	if (status != Success)
		return Failure;

	LOG_INF("Switch PCH SPI MUX to ROT");
	dev_m = device_get_binding(PCH_SPI_MONITOR);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);
#if defined(CONFIG_CPU_DUAL_FLASH)
	dev_m = device_get_binding(PCH_SPI_MONITOR_2);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);
#endif

	if (cpld_update_status.BmcToPchStatus == 1) {

		cpld_update_status.BmcToPchStatus = 0;
		status = ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS,
				(uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
		if (status != Success)
			goto release_pch_mux;

		status = ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET,
				(uint8_t *)&address, sizeof(address));
		if (status != Success)
			goto release_pch_mux;

		LOG_INF("Switch BMC SPI MUX to ROT");
#if defined(CONFIG_BMC_DUAL_FLASH)
		staging_start_addr = address;
		if (staging_start_addr >= flash_size)
			dev_m = device_get_binding(BMC_SPI_MONITOR_2);
		else
			dev_m = device_get_binding(BMC_SPI_MONITOR);
#else
		dev_m = device_get_binding(BMC_SPI_MONITOR);
#endif
		spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);

		pfr_manifest->address = address;

		// Checking for key cancellation
		pfr_manifest->image_type = BMC_TYPE;
		pc_type_status = check_rot_capsule_type(pfr_manifest);
		pfr_manifest->image_type = image_type;

		status = pfr_staging_pch_staging(pfr_manifest);
		if (status != Success)
			goto release_both_muxes;

		// Release BMC SPI after copying capsule to PCH's flash.
		// PCH SPI will be release after firmware update completed.
		LOG_INF("Switch BMC SPI MUX to BMC");
		spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
	}


	pfr_manifest->address = source_address;
	// Staging area verification
	LOG_INF("Staging Area verification");
	status = pfr_manifest->update_fw->base->verify((struct firmware_image *)pfr_manifest,
			NULL, NULL);
	if (status != Success) {
		LOG_ERR("Staging Area verification failed");
		goto release_pch_mux;
	}

	status = decompress_fv_capsule(pfr_manifest);
	if (status != Success)
		LOG_ERR("Failed to decompress seamless capsule");

	goto release_pch_mux;

release_both_muxes:
	LOG_INF("Switch BMC SPI MUX to BMC");
#if defined(CONFIG_BMC_DUAL_FLASH)
	if (staging_start_addr >= flash_size)
		dev_m = device_get_binding(BMC_SPI_MONITOR_2);
	else
		dev_m = device_get_binding(BMC_SPI_MONITOR);
#else
	dev_m = device_get_binding(BMC_SPI_MONITOR);
#endif
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
release_pch_mux:
	LOG_INF("Switch PCH SPI MUX to PCH");
	dev_m = device_get_binding(PCH_SPI_MONITOR);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
#if defined(CONFIG_CPU_DUAL_FLASH)
	dev_m = device_get_binding(PCH_SPI_MONITOR_2);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
#endif

	return status;
}
#endif // CONFIG_SEAMLESS_UPDATE

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
	return intel_pfr_update_verify(fw, hash, rsa);
}

