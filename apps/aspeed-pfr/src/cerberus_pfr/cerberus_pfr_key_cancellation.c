/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>

#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "pfr/pfr_ufm.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_key_cancellation.h"
#include "cerberus_pfr_key_manifest.h"
#include "cerberus_pfr_recovery.h"
#include "AspeedStateMachine/common_smc.h"
#include "flash/flash_aspeed.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

/*
 * So far, the design of cerberus-pfr key cancellation only supports 3 pc types which are BMC, PCH and ROT.
 * Both pc type of update capsule and pfm use the same key cancellation policy.
 * ex: Both BMC_PFM and BMC_UPDATE_CAPSULE use KEY_CANCELLATION_POLICY_FOR_SIGNING_BMC_PFM cancellation policy.
 *
 */
int get_cancellation_policy_offset(uint32_t pc_type)
{
	if ((pc_type == CPLD_CAPSULE_CANCELLATION) ||
	    (pc_type == PFR_CPLD_UPDATE_CAPSULE))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_CPLD_UPDATE_CAPSULE;
	else if ((pc_type == PCH_PFM_CANCELLATION) ||
		 (pc_type == PFR_PCH_PFM) ||
		 (pc_type == PFR_PCH_UPDATE_CAPSULE))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_PCH_PFM;
	else if ((pc_type == BMC_PFM_CANCELLATION) ||
		 (pc_type == PFR_BMC_PFM) ||
		 (pc_type == PFR_BMC_UPDATE_CAPSULE))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_BMC_PFM;

	return 0;
}

int check_cancellation_pc_type(struct pfr_manifest *manifest, uint32_t kc_pc_type)
{
	if (!manifest)
		return Failure;

	uint32_t expected_pc_type;

	if (manifest->pc_type == PFR_CPLD_UPDATE_CAPSULE)
		expected_pc_type = CPLD_CAPSULE_CANCELLATION;
	else if (manifest->pc_type == PFR_BMC_PFM || manifest->pc_type == PFR_BMC_UPDATE_CAPSULE)
		expected_pc_type = BMC_PFM_CANCELLATION;
	else if (manifest->pc_type == PFR_PCH_PFM || manifest->pc_type == PFR_PCH_UPDATE_CAPSULE)
		expected_pc_type = PCH_PFM_CANCELLATION;
	else {
		LOG_ERR("Unsupport manifest->pc_type(%x)", manifest->pc_type);
		return Failure;
	}

	if (kc_pc_type != expected_pc_type) {
		LOG_ERR("manifest->pc_type(%x), expected_pc_type(%x) and kc_pc_type(%x) mismatch",
			manifest->pc_type, expected_pc_type, kc_pc_type);
		return Failure;
	}

	return Success;
}

int verify_csk_key_id(struct pfr_manifest *manifest, uint8_t key_manifest_id, uint8_t key_id)
{
	uint32_t ufm_offset = get_cancellation_policy_offset(manifest->pc_type);
	uint8_t policy_data;
	int status = 0;

	if (!manifest)
		return Failure;

	if (!ufm_offset) {
		LOG_ERR("Invalid provisioned UFM offset for key cancellation");
		return Failure;
	}

	if (key_manifest_id > MAX_KEY_MANIFEST_ID) {
		LOG_ERR("Invalid key manifest Id: %d", key_manifest_id);
		return Failure;
	}

	if (key_id > MAX_KEY_ID) {
		LOG_ERR("Invalid key Id: %d", key_id);
		return Failure;
	}

	ufm_offset += key_manifest_id;

	status = ufm_read(PROVISION_UFM, ufm_offset, &policy_data, sizeof(policy_data));
	if (status != Success) {
		LOG_ERR("Read cancellation policy status from UFM failed");
		return Failure;
	}

	if (!(policy_data & (0x01 << key_id))) {
		LOG_ERR("KEYM(%d): This CSK key was cancelled..! Can't Proceed with verify with this key Id: %d", key_manifest_id, key_id);
		return Failure;
	}

	return Success;
}

int cancel_csk_key_id(struct pfr_manifest *manifest, uint8_t key_manifest_id, uint8_t key_id)
{
	uint32_t ufm_offset = get_cancellation_policy_offset(manifest->pc_type);
	uint8_t policy_data;
	int status = 0;

	if (!manifest)
		return Failure;

	if (!ufm_offset) {
		LOG_ERR("Invalid provisioned UFM offset for key cancellation");
		return Failure;
	}

	if (key_manifest_id > MAX_KEY_MANIFEST_ID) {
		LOG_ERR("Invalid key manifest Id: %d", key_manifest_id);
		return Failure;
	}

	if (key_id > MAX_KEY_ID) {
		LOG_ERR("Invalid key Id: %d", key_id);
		return Failure;
	}

	ufm_offset += key_manifest_id;

	// store policy data from flash part
	status = ufm_read(PROVISION_UFM, ufm_offset, &policy_data, sizeof(policy_data));
	if (status != Success) {
		LOG_ERR("Read cancellation policy status from UFM failed");
		return Failure;
	}

	policy_data &= ~(0x01 << key_id);

	status = ufm_write(PROVISION_UFM, ufm_offset, &policy_data, sizeof(policy_data));
	if (status != Success) {
		LOG_ERR("Write cancellation policy status to UFM failed, offset = %x, data = %x", ufm_offset, policy_data);
		return Failure;
	}

	return Success;
}

int cerberus_pfr_get_key_cancellation_manifest(struct pfr_manifest *manifest,
	struct PFR_KEY_CANCELLATION_MANIFEST *pfr_kc_manifest, uint32_t *hash_length)
{
	struct recovery_section image_section;
	struct recovery_header image_header;
	uint32_t read_address;
	int status = Success;

	if (!manifest || !pfr_kc_manifest || !hash_length)
		return Failure;

	read_address = manifest->address;

	// read recovery header
	LOG_INF("manifest->flash_id=%d kc_header_address=%x", manifest->flash_id, read_address);
	if (pfr_spi_read(manifest->flash_id, read_address, sizeof(image_header),
			(uint8_t *)&image_header)) {
		LOG_ERR("Failed to read image header");
		return Failure;
	}

	status = verify_recovery_header_magic_number(image_header);
	if (status != Success) {
		LOG_HEXDUMP_ERR(&image_header, sizeof(image_header), "image_header:");
		LOG_ERR("Image Header Magic Number is not Matched.");
		return Failure;
	}

	read_address += image_header.header_length;

	// read section header
	if (pfr_spi_read(manifest->flash_id, read_address, sizeof(image_section),
			(uint8_t *)&image_section)) {
		LOG_ERR("Failed to read image section");
		return Failure;
	}

	if (image_section.magic_number != KEY_MANAGEMENT_SECTION_MAGIC ||
	    image_section.header_length != sizeof(struct recovery_section) ||
	    image_section.section_length != sizeof(struct PFR_KEY_CANCELLATION_MANIFEST)) {
		LOG_HEXDUMP_ERR(&image_header, sizeof(image_header), "section_header:");
		LOG_ERR("Unable to get image section.");
		return Failure;
	}

	read_address += image_section.header_length;

	LOG_INF("kc_manifest_address=%x", read_address);
	if (pfr_spi_read(manifest->flash_id, read_address, sizeof(struct PFR_KEY_CANCELLATION_MANIFEST),
			(uint8_t *)pfr_kc_manifest)) {
		LOG_ERR("Failed to read key cancellation manifest");
		return Failure;
	}

	if (pfr_kc_manifest->magic_number != KEY_CANCELLATION_SECTION_MAGIC) {
		LOG_ERR("Key Cancellation Manifest Magic Number(%x) is not Matched.", pfr_kc_manifest->magic_number);
		return Failure;
	}

	if (pfr_kc_manifest->key_count > MAX_CANCEL_KEY) {
		LOG_ERR("Cancel keys(%d) exceed max count(%d)", pfr_kc_manifest->key_count, MAX_CANCEL_KEY);
		return Failure;
	}

	if (pfr_kc_manifest->key_count < 1) {
		LOG_ERR("No cancel keys(%d)", pfr_kc_manifest->key_count);
		return Failure;
	}

	if (pfr_kc_manifest->hash_type == HASH_TYPE_SHA256) {
		*hash_length = SHA256_HASH_LENGTH;
	} else if (pfr_kc_manifest->hash_type == HASH_TYPE_SHA384) {
		*hash_length = SHA384_HASH_LENGTH;
	} else {
		LOG_ERR("Unsupported hash type(%d)", pfr_kc_manifest->hash_type);
		return Failure;
	}

	return Success;
}

int cerberus_pfr_cancel_csk_keys(struct pfr_manifest *manifest)
{
	struct PFR_KEY_CANCELLATION_MANIFEST kc_manifest;
	struct PFR_KEY_MANIFEST key_manifest;
	struct recovery_header image_header;
	uint32_t keym_address;
	uint32_t region_size;
	uint32_t hash_length;
	uint8_t key_manifest_id;
	uint8_t cancel_key_id;
	uint8_t cancel_key_list = 0;
	int status = Success;
	int i;

	if (!manifest)
		return Failure;

	if (cerberus_pfr_get_key_cancellation_manifest(manifest, &kc_manifest, &hash_length)) {
		LOG_ERR("Unable to get key cancellation manifest");
		return Failure;
	}

	if (check_cancellation_pc_type(manifest, kc_manifest.key_policy)) {
		LOG_ERR("Check cancellation pc type failed");
		return Failure;
	}

	region_size = pfr_spi_get_device_size(ROT_INTERNAL_KEY);
	manifest->pc_type = kc_manifest.key_policy;
	cancel_key_list = (0x01 << kc_manifest.key_count) - 1;

	// lookup all key manifests
	for (key_manifest_id = 0; key_manifest_id <= MAX_KEY_MANIFEST_ID; key_manifest_id++) {
		keym_address = key_manifest_id * KEY_MANIFEST_SIZE;
		if (keym_address >= region_size)
			break;

		if (!cancel_key_list)
			break;

		if (pfr_spi_read(ROT_INTERNAL_KEY, keym_address, sizeof(image_header), (uint8_t *)&image_header))
			continue;

		if (image_header.format != UPDATE_FORMAT_TYPE_KEYM && image_header.magic_number != KEY_MANAGEMENT_HEADER_MAGIC)
			continue;

		if (cerberus_pfr_get_key_manifest(manifest, key_manifest_id, &key_manifest)) {
			LOG_WRN("KEYM(%d): Unable to get key manifest", key_manifest_id);
			continue;
		}

		if (kc_manifest.hash_type != key_manifest.hash_type) {
			LOG_WRN("KEYM(%d): hash type not matched, hash_type=%d and key_cancellation_manifest_hash_type=%d",
				key_manifest_id, key_manifest.hash_type, kc_manifest.hash_type);
			continue;
		}

		// if csk key hash matched, cancel csk key
		for (i = 0; i < kc_manifest.key_count; i++) {
			if (cancel_key_list & (0x01 << i)) {
				cancel_key_id = kc_manifest.key_cancel_list[i].key_id;
				if (cancel_key_id > MAX_KEY_ID) {
					LOG_ERR("Invalid cancel key Id: %d", cancel_key_id);
					continue;
				}

				if (!memcmp(key_manifest.key_list[cancel_key_id].key_hash,
					    kc_manifest.key_cancel_list[i].key_hash,
					    hash_length)) {
					LOG_INF("KEYM(%d): This cancel Key Id(%d) was found.", key_manifest_id, cancel_key_id);
					status = manifest->keystore->kc_flag->cancel_kc_flag(manifest, key_manifest_id, cancel_key_id);
					if (status == Success) {
						LOG_INF("Key cancellation success. Policy=%x. KEYM(%d): Key Id(%d) was cancelled.",
							manifest->pc_type, key_manifest_id, cancel_key_id);
						cancel_key_list &= ~(0x01 << i);
					}
				}
			}
		}
	}

	if (cancel_key_list) {
		for (i = 0; i < kc_manifest.key_count; i++) {
			if (cancel_key_list & (0x01 << i)) {
				LOG_ERR("Cancel key Id(%d): cannot be cancelled.", kc_manifest.key_cancel_list[i].key_id);
				LOG_HEXDUMP_ERR(kc_manifest.key_cancel_list[i].key_hash, hash_length, "Cancel key hash:");
			}
		}
		return Failure;
	}

	return Success;
}

