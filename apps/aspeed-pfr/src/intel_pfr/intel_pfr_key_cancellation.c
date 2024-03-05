/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>

#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "pfr/pfr_ufm.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_key_cancellation.h"
#include "AspeedStateMachine/common_smc.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int get_cancellation_policy_offset(uint32_t pc_type)
{
	if ((pc_type == CPLD_CAPSULE_CANCELLATION) || (pc_type == PFR_CPLD_UPDATE_CAPSULE) ||
			(pc_type == PFR_CPLD_UPDATE_CAPSULE_DECOMMISSON))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_CPLD_UPDATE_CAPSULE;
	else if ((pc_type == PCH_PFM_CANCELLATION) || (pc_type == PFR_PCH_PFM))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_PCH_PFM;
	else if ((pc_type == PCH_CAPSULE_CANCELLATION) || (pc_type == PFR_PCH_UPDATE_CAPSULE))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_PCH_UPDATE_CAPSULE;
	else if ((pc_type == BMC_PFM_CANCELLATION) || (pc_type == PFR_BMC_PFM))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_BMC_PFM;
	else if ((pc_type == BMC_CAPSULE_CANCELLATION) || (pc_type == PFR_BMC_UPDATE_CAPSULE))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_BMC_UPDATE_CAPSULE;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if ((pc_type == AFM_CANCELLATION) || (pc_type == PFR_AFM) || (pc_type == PFR_AFM_PER_DEV))
		return KEY_CANCELLATION_POLICY_FOR_AFM;
#endif

	return 0;
}

int validate_key_cancellation_flag(struct pfr_manifest *manifest)
{
	uint32_t block1_address = manifest->address + sizeof(PFR_AUTHENTICATION_BLOCK0);
	uint8_t read_buffer[KCH_CAN_CERT_RESERVED_SIZE] = { 0 };
	uint32_t reserved_address;
	uint32_t status = 0;
	uint32_t key_id = 0;
	int i;

	if ((manifest->pc_type == CPLD_CAPSULE_CANCELLATION) || (manifest->pc_type == PCH_PFM_CANCELLATION)
	    || (manifest->pc_type == PCH_CAPSULE_CANCELLATION) || (manifest->pc_type == BMC_PFM_CANCELLATION)
	    || (manifest->pc_type == BMC_CAPSULE_CANCELLATION)) {
		if (manifest->hash_curve == hash_sign_algo384 || manifest->hash_curve == hash_sign_algo256)
			reserved_address = manifest->address + LMS_PFM_SIG_BLOCK_SIZE + 4;
		else
			reserved_address = manifest->address + PFM_SIG_BLOCK_SIZE + 4;
		status = pfr_spi_read(manifest->image_type, reserved_address, sizeof(read_buffer), (uint8_t *)read_buffer);
		if (status != Success) {
			LOG_ERR("Flash read reserved data failed for key cancellation capsule");
			return Failure;
		}

		for (i = 0; i < sizeof(read_buffer); i++) {
			if (read_buffer[i] != 0) {
				LOG_ERR("Invalid reserved data for key cancellation capsule");
				return Failure;
			}
		}

		manifest->kc_flag = TRUE;
	} else   {
		// Read Csk key ID
		status = pfr_spi_read(manifest->image_type, block1_address + CSK_KEY_ID_ADDRESS, sizeof(key_id), (uint8_t *)&key_id);
		if (status != Success) {
			LOG_ERR("Flash read block1 CSK key Id failed");
			return Failure;
		}

		status = manifest->keystore->kc_flag->verify_kc_flag(manifest, key_id);
		if (status != Success)
			return Failure;

		manifest->kc_flag = FALSE;
	}

	LOG_INF("KeyCancellationFlag: %x", manifest->kc_flag);

	return Success;
}

int verify_csk_key_id(struct pfr_manifest *manifest, uint8_t key_id)
{
	uint32_t ufm_offset = get_cancellation_policy_offset(manifest->pc_type);
	uint32_t policy_data;
	uint32_t bit_offset;
	int status = 0;

#if defined(CONFIG_SEAMLESS_UPDATE)
	if (manifest->pc_type == PFR_PCH_SEAMLESS_UPDATE_CAPSULE)
		return Success;
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	// Remove the following code when Intel CPLD key cancellation policy is defined.
	if (manifest->pc_type == PFR_INTEL_CPLD_UPDATE_CAPSULE)
		return Success;
#endif

	if (!ufm_offset) {
		LOG_ERR("%s: Invalid provisioned UFM offset for key cancellation", __func__);
		return Failure;
	}

	// key id must be within 0-127
	if (key_id > KEY_CANCELLATION_MAX_KEY_ID) {
		LOG_ERR("%s: Invalid key Id: %d", __func__, key_id);
		return Failure;
	}

	ufm_offset += (key_id / 32) * 4;
	// bit little endian
	bit_offset = 31 - (key_id % 32);

	status = ufm_read(PROVISION_UFM, ufm_offset, (uint8_t *)&policy_data, sizeof(policy_data));
	if (status != Success) {
		LOG_ERR("%s: Read cancellation policy status from UFM failed", __func__);
		return Failure;
	}

	if (!(policy_data & (0x01 << bit_offset))) {
		LOG_ERR("This CSK key was cancelled..! Can't Proceed with verify with this key Id: %d", key_id);
		return Failure;
	}

	return Success;
}

int cancel_csk_key_id(struct pfr_manifest *manifest, uint8_t key_id)
{
	uint32_t ufm_offset = get_cancellation_policy_offset(manifest->pc_type);
	uint32_t policy_data;
	uint32_t bit_offset;
	int status = 0;

	if (!ufm_offset) {
		LOG_ERR("%s: Invalid provisioned UFM offset for key cancellation", __func__);
		return Failure;
	}

	// key id must be within 0-127
	if (key_id > KEY_CANCELLATION_MAX_KEY_ID) {
		LOG_ERR("%s: Invalid key Id: %d", __func__, key_id);
		return Failure;
	}

	ufm_offset += (key_id / 32) * 4;
	// bit little endian
	bit_offset = 31 - (key_id % 32);

	// store policy data from flash part
	status = ufm_read(PROVISION_UFM, ufm_offset, (uint8_t *)&policy_data, sizeof(policy_data));
	if (status != Success) {
		LOG_ERR("%s: Read cancellation policy status from UFM failed", __func__);
		return Failure;
	}

	policy_data &= ~(0x01 << bit_offset);

	status = ufm_write(PROVISION_UFM, ufm_offset, (uint8_t *)&policy_data, sizeof(policy_data));
	if (status != Success) {
		LOG_ERR("Write cancellation policy status to UFM failed, offset = %x, data = %x", ufm_offset, policy_data);
		return Failure;
	}

	return Success;
}

