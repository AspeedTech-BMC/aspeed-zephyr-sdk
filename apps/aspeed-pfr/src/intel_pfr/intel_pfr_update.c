/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_INTEL_PFR)
#include <logging/log.h>
#include <storage/flash_map.h>
#include <drivers/flash.h>
#include "pfr/pfr_update.h"
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_util.h"
#include "StateMachineAction/StateMachineActions.h"
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
#include "StateMachineAction/StateMachineActions.h"
#include "intel_pfr_pfm_manifest.h"
#include "flash/flash_aspeed.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "gpio/gpio_aspeed.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int pfr_staging_verify(struct pfr_manifest *manifest)
{

	int status = 0;
	uint32_t read_address = 0;
	uint32_t target_address = 0;

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
	} else  {
		return Failure;
	}

	manifest->address = read_address;
	manifest->recovery_address = target_address;

	LOG_INF("Veriifying capsule signature, address=0x%08x", manifest->address);
	// manifest verification
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Capsule signature verification failed");
		return Failure;
	}

	manifest->update_fw->pc_length = manifest->pc_length;

	if (manifest->image_type == BMC_TYPE)
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

	return status;
}

int intel_pfr_update_verify(struct firmware_image *fw, struct hash_engine *hash, struct rsa_engine *rsa)
{

	ARG_UNUSED(hash);
	ARG_UNUSED(rsa);

	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) fw;

	return pfr_staging_verify(pfr_manifest);
}

int set_ufm_svn(struct pfr_manifest *manifest, uint32_t offset, uint8_t svn_number)
{
	ARG_UNUSED(manifest);

	int status = 0;
	uint32_t svn_policy[2];
	uint32_t new_svn_policy;

	if (svn_number > SVN_MAX) {
		LOG_ERR("SVN number(%02x) exceed SVN max(%02x)", svn_number, SVN_MAX);
		return Failure;
	}

	memset(svn_policy, 0xff, sizeof(svn_policy));
	new_svn_policy = ~((1 << (svn_number % 32)) - 1);
	if (svn_number < 32)
		svn_policy[0] = new_svn_policy;
	else {
		svn_policy[0] = 0;
		if (svn_number < 64)
			svn_policy[1] = new_svn_policy;
		else if (svn_number == 64)
			svn_policy[1] = 0;
	}

	status = ufm_write(PROVISION_UFM, offset, (uint8_t *)svn_policy, sizeof(svn_policy));
	if (status != Success) {
		LOG_ERR("Set SVN number to UFM failed");
		return Failure;
	}

	return Success;
}

uint8_t get_ufm_svn(struct pfr_manifest *manifest, uint32_t offset)
{
	ARG_UNUSED(manifest);

	uint32_t svn_policy[2];
	uint8_t index;

	ufm_read(PROVISION_UFM, offset, (uint8_t *)svn_policy, sizeof(svn_policy));
	for (index = 0; index < 64; index++) {
		if ((svn_policy[(index / 32)] & (1 << (index % 32))) != 0)
			return index;
	}

	return 64;
}

int  check_rot_capsule_type(struct pfr_manifest *manifest)
{
	int status = 0;
	uint32_t pc_type;

	status = pfr_spi_read(manifest->image_type, manifest->address + (2 * sizeof(pc_type)),
			sizeof(pc_type), (uint8_t *)&pc_type);
	if (pc_type == DECOMMISSION_CAPSULE) {
		LOG_INF("Decommission Certificate found");
		return DECOMMISSION_CAPSULE;
	} else if ((pc_type == CPLD_CAPSULE_CANCELLATION) || (pc_type == PCH_PFM_CANCELLATION) ||
			(pc_type == PCH_CAPSULE_CANCELLATION)
		   || (pc_type == BMC_PFM_CANCELLATION) || (pc_type == BMC_CAPSULE_CANCELLATION)) {
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

	// Erasing provisioned data
	status = ufm_erase(PROVISION_UFM);
	if (status != Success) {
		LOG_ERR("Erase the provisioned UFM data failed");
		return Failure;
	}

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

int update_rot_fw(uint32_t address, uint32_t length)
{
	uint32_t region_size = pfr_spi_get_device_size(ROT_INTERNAL_ACTIVE);
	uint32_t source_address = address;
	uint32_t rot_recovery_address = 0;
	uint32_t rot_active_address = 0;
	uint32_t length_page_align;

	length_page_align =
		(length % PAGE_SIZE) ? (length + (PAGE_SIZE - (length % PAGE_SIZE))) : length;

	if (length_page_align > region_size) {
		LOG_ERR("length(%x) exceed region size(%x)", length_page_align, region_size);
		return Failure;
	}

	if (pfr_spi_erase_region(ROT_INTERNAL_RECOVERY, true, rot_recovery_address,
			region_size)) {
		LOG_ERR("Erase PFR Recovery region failed, address = %x, length = %x",
			rot_recovery_address, region_size);
		return Failure;
	}

	if (pfr_spi_region_read_write_between_spi(ROT_INTERNAL_ACTIVE, rot_active_address,
				ROT_INTERNAL_RECOVERY, rot_recovery_address, region_size)) {
		LOG_ERR("read(ROT_INTERNAL_ACTIVE) address =%x, write(ROT_INTERNAL_RECOVERY) address = %x, length = %x",
			rot_active_address, rot_recovery_address, region_size);
		return Failure;
	}

	if (pfr_spi_erase_region(ROT_INTERNAL_ACTIVE, true, rot_active_address,
				region_size)) {
		LOG_ERR("Erase PFR Active region failed, address = %x, length = %x",
			rot_active_address, region_size);
		return Failure;
	}

	if (pfr_spi_region_read_write_between_spi(BMC_SPI, source_address,
			ROT_INTERNAL_ACTIVE, rot_active_address, length_page_align)) {
		LOG_ERR("read(BMC_SPI) address =%x, write(ROT_INTERNAL_ACTIVE) address = %x, length = %x",
			source_address, rot_active_address, length_page_align);
		return Failure;
	}

	return Success;
}

int rot_svn_policy_verify(struct pfr_manifest *manifest, uint32_t hrot_svn)
{
	uint8_t current_svn;

	current_svn = get_ufm_svn(manifest, SVN_POLICY_FOR_CPLD_UPDATE);

	if (hrot_svn > SVN_MAX) {
		LOG_ERR("Invalid Staging area SVN Number, %02x", hrot_svn);
		return Failure;
	} else if (hrot_svn < current_svn) {
		LOG_ERR("Can't update with older version of SVN current=%02x staging=%02x",
				current_svn, hrot_svn);
		return Failure;
	}
	set_ufm_svn(manifest, SVN_POLICY_FOR_CPLD_UPDATE, hrot_svn);
	SetCpldRotSvn((uint8_t)hrot_svn);

	return Success;
}

int ast1060_update(struct pfr_manifest *manifest)
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

	if (pc_type_status == DECOMMISSION_CAPSULE) {
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
		LOG_INF("ROT update start");
		status = pfr_spi_read(manifest->image_type, payload_address, sizeof(uint32_t),
				(uint8_t *)&hrot_svn);
		if (status != Success) {
			LOG_ERR("ROT flash read svn failed");
			return Failure;
		}

		status = rot_svn_policy_verify(manifest, hrot_svn);
		if (status != Success) {
			LOG_ERR("ROT verify svn failed");
			LogUpdateFailure(UPD_CAPSULE_INVALID_SVN, 1);
			return Failure;
		}
		pc_length = manifest->pc_length - sizeof(uint32_t);
		payload_address = payload_address + sizeof(uint32_t);

		status = update_rot_fw(payload_address, pc_length);
		if (status != Success) {
			LOG_ERR("ROT update failed");
			return Failure;
		}
		LOG_INF("ROT update end");
	}

	return Success;
}

int check_svn_number(struct pfr_manifest *manifest, uint32_t read_address,
		uint8_t current_svn_number)
{
	int status = 0;
	uint32_t pfm_start_address = read_address + PFM_SIG_BLOCK_SIZE + PFM_SIG_BLOCK_SIZE;
	uint8_t buffer[sizeof(PFM_STRUCTURE)] = { 0 };
	uint8_t staging_svn_number = 0;

	status = pfr_spi_read(manifest->image_type, pfm_start_address, sizeof(PFM_STRUCTURE),
			(uint8_t *)buffer);
	if (status != Success)
		return Failure;

	staging_svn_number = ((PFM_STRUCTURE *)buffer)->SVN;

	if (staging_svn_number > SVN_MAX) {
		LOG_ERR("Invalid Staging area SVN Number");
		return Failure;
	} else if (staging_svn_number < current_svn_number) {
		LOG_ERR("Can't update with older version of SVN current=%02x staging=%02x",
				current_svn_number, staging_svn_number);
		return Failure;
	}

	if (manifest->image_type == PCH_TYPE)
		status = set_ufm_svn(manifest, SVN_POLICY_FOR_PCH_FW_UPDATE, staging_svn_number);
	else
		status = set_ufm_svn(manifest, SVN_POLICY_FOR_BMC_FW_UPDATE, staging_svn_number);

	return status;
}

int update_recovery_region(int image_type, uint32_t source_address, uint32_t target_address)
{
	return pfr_recover_recovery_region(image_type, source_address, target_address);
}

int update_firmware_image(uint32_t image_type, void *AoData, void *EventContext)
{
	int status = 0;
	uint32_t source_address, target_address, area_size;
	uint32_t act_pfm_offset;
	uint32_t address = 0;
	uint32_t pc_type_status = 0;
	uint8_t active_svn_number = 0;
	CPLD_STATUS cpld_update_status;
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
		if (ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
					sizeof(source_address))) {
			LOG_ERR("Read BMC staging region offset failed from UFM");
			return Failure;
		}

		source_address += CONFIG_BMC_STAGING_SIZE;
		source_address += CONFIG_BMC_PCH_STAGING_SIZE;
		pfr_manifest->address = source_address;
		return ast1060_update(pfr_manifest);
	}

	if (pfr_manifest->image_type == BMC_TYPE) {
		LOG_INF("BMC Update in Progress");
		if (ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
					sizeof(source_address)))
			return Failure;
		if (ufm_read(PROVISION_UFM, BMC_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	} else if (pfr_manifest->image_type == PCH_TYPE) {
		LOG_INF("PCH Update in Progress");
		if (ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
					sizeof(source_address)))
			return Failure;
		if (ufm_read(PROVISION_UFM, PCH_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	}

	pfr_manifest->staging_address = source_address;
	pfr_manifest->active_pfm_addr = act_pfm_offset;

	status = ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status,
			sizeof(CPLD_STATUS));
	LOG_HEXDUMP_INF(&cpld_update_status, sizeof(cpld_update_status), "CPLD Status");
	if (status != Success)
		return status;

	if (cpld_update_status.BmcToPchStatus == 1) {

		cpld_update_status.BmcToPchStatus = 0;
		status = ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS,
				(uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
		if (status != Success)
			return Failure;

		status = ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET,
				(uint8_t *)&address, sizeof(address));
		if (status != Success)
			return Failure;

		// PFR Staging - PCH Staging offset after BMC staging offset
		address += CONFIG_BMC_STAGING_SIZE;
		pfr_manifest->address = address;

		// Checking for key cancellation
		pfr_manifest->image_type = BMC_TYPE;
		pc_type_status = check_rot_capsule_type(pfr_manifest);
		pfr_manifest->image_type = image_type;

		status = pfr_staging_pch_staging(pfr_manifest);
		if (status != Success)
			return Failure;
	}

	pfr_manifest->address = source_address;
	// Checking for key cancellation
	pc_type_status = check_rot_capsule_type(pfr_manifest);
	if (pc_type_status ==  KEY_CANCELLATION_CAPSULE)
		return ast1060_update(pfr_manifest);

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
	if (pfr_manifest->image_type ==  BMC_TYPE)
		active_svn_number = get_ufm_svn(pfr_manifest, SVN_POLICY_FOR_BMC_FW_UPDATE);
	else
		active_svn_number = get_ufm_svn(pfr_manifest, SVN_POLICY_FOR_PCH_FW_UPDATE);

	status = check_svn_number(pfr_manifest, source_address, active_svn_number);
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

		if (decompress_capsule(pfr_manifest, decomp_event)) {
			LogUpdateFailure(UPD_CAPSULE_AUTH_FAIL, 1);
			return Failure;
		}

		time_end = k_uptime_get_32();
		LOG_INF("Firmware update completed, elapsed time = %u milliseconds",
				(time_end - time_start));
	} else   {
		if (pfr_manifest->image_type == BMC_TYPE) {
			LOG_INF("BMC Recovery Region Update");
			status = ufm_read(PROVISION_UFM, BMC_RECOVERY_REGION_OFFSET,
					(uint8_t *)&target_address, sizeof(target_address));
		} else if (pfr_manifest->image_type == PCH_TYPE) {
			LOG_INF("PCH Recovery Region Update");
			status = ufm_read(PROVISION_UFM, PCH_RECOVERY_REGION_OFFSET,
					(uint8_t *)&target_address, sizeof(target_address));
		}

		if (status != Success)
			return status;

		status = update_recovery_region(pfr_manifest->image_type, source_address,
				target_address);
		if (status != Success) {
			LOG_ERR("Recovery capsule update failed");
			return Failure;
		}
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

		// PFR Staging - PCH Staging offset after BMC staging offset
		address += CONFIG_BMC_STAGING_SIZE;
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
#endif // CONFIG_INTEL_PFR
