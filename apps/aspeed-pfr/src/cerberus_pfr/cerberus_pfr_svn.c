/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include "pfr/pfr_common.h"
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_util.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "cerberus_pfr_common.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_svn.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_recovery.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int set_ufm_svn(uint32_t offset, uint8_t svn)
{
	uint32_t new_svn_policy;
	uint32_t svn_policy[2];
	uint8_t current_svn;
	int status = 0;

	if (svn > SVN_MAX) {
		LOG_ERR("SVN number(%d) exceed SVN max(%d)", svn, SVN_MAX);
		return Failure;
	}

	current_svn = get_ufm_svn(offset);

	if (current_svn == svn)
		return Success;

	memset(svn_policy, 0xff, sizeof(svn_policy));
	new_svn_policy = ~((1 << (svn % 32)) - 1);
	if (svn < 32)
		svn_policy[0] = new_svn_policy;
	else {
		svn_policy[0] = 0;
		if (svn < 64)
			svn_policy[1] = new_svn_policy;
		else if (svn == 64)
			svn_policy[1] = 0;
	}

	status = ufm_write(PROVISION_UFM, offset, (uint8_t *)svn_policy, sizeof(svn_policy));
	if (status != Success) {
		LOG_ERR("Set SVN number to UFM failed");
		return Failure;
	}

	return Success;
}

uint8_t get_ufm_svn(uint32_t offset)
{
	uint32_t svn_policy[2];
	uint8_t index;

	ufm_read(PROVISION_UFM, offset, (uint8_t *)svn_policy, sizeof(svn_policy));
	for (index = 0; index < 64; index++) {
		if ((svn_policy[(index / 32)] & (1 << (index % 32))) != 0)
			return index;
	}

	return 64;
}

int svn_policy_verify(uint32_t offset, uint32_t svn)
{
	uint8_t current_svn;

	current_svn = get_ufm_svn(offset);

	if (svn > SVN_MAX) {
		LOG_ERR("Invalid SVN Number(%d)", svn);
		return Failure;
	} else if (svn < current_svn) {
		LOG_ERR("Invalid SVN number, current=%d verify_svn=%d",
				current_svn, svn);
		return Failure;
	}

	return Success;
}

int does_staged_fw_image_match_active_fw_image(struct pfr_manifest *manifest)
{
	if (!manifest)
		return Failure;

	struct pfm_firmware_version_element staging_fw_ver_element;
	struct pfm_firmware_version_element act_fw_ver_element;
	struct PFR_VERSION *staging_pfm_version;
	struct PFR_VERSION *act_pfm_version;
	struct recovery_header image_header;
	uint32_t fw_ver_element_addr;
	uint32_t staging_address;
	uint32_t act_pfm_offset;
	uint32_t dest_pfm_addr;
	uint32_t src_pfm_addr;
	uint8_t ver_len;

	if (manifest->image_type != BMC_TYPE &&
	    manifest->image_type != PCH_TYPE) {
		LOG_ERR("Unsupported image type %d", manifest->image_type);
		return Failure;
	}

	if (manifest->image_type == BMC_TYPE) {
		if (ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET, (uint8_t *)&staging_address, sizeof(staging_address)))
			return Failure;

		if (ufm_read(PROVISION_UFM, BMC_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset, sizeof(act_pfm_offset)))
			return Failure;
	} else if (manifest->image_type == PCH_TYPE) {
		if (ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&staging_address, sizeof(staging_address)))
			return Failure;

		if (ufm_read(PROVISION_UFM, PCH_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset, sizeof(act_pfm_offset)))
			return Failure;
	}

	ver_len = sizeof(struct PFR_VERSION);

	// Staging
	LOG_INF("Staging image_type=%d address=%08x", manifest->image_type, staging_address);
	if (pfr_spi_read(manifest->image_type, staging_address, sizeof(image_header), (uint8_t *)&image_header)) {
		LOG_ERR("Unable to get image header.");
		return Failure;
	}

	// Find PFM in stage image
	if (cerberus_get_image_pfm_addr(manifest, &image_header, &src_pfm_addr, &dest_pfm_addr)) {
		LOG_ERR("PFM doesn't exist in stage image");
		return Failure;
	}

	if (dest_pfm_addr != act_pfm_offset) {
		LOG_ERR("Staged firmware dest pfm addr(%08x) does not match active firmware pfm addr(%08x)",
			dest_pfm_addr, act_pfm_offset);
		return Failure;
	}

	// Staging PFM start address
	LOG_INF("Get pfm version image_type=%d address=%08x", manifest->image_type, src_pfm_addr);
	if (cerberus_get_version_info(manifest->image_type, src_pfm_addr, &fw_ver_element_addr, &staging_fw_ver_element)) {
		LOG_ERR("Failed to get version info");
		return Failure;
	}

	if (staging_fw_ver_element.version_length != ver_len) {
		LOG_ERR("Invalid version length(%d)", staging_fw_ver_element.version_length);
		return Failure;
	}

	staging_pfm_version = (struct PFR_VERSION *)staging_fw_ver_element.version;

	if (staging_pfm_version->reserved1 != 0 ||
	    staging_pfm_version->reserved2 != 0 ||
	    staging_pfm_version->reserved3 != 0) {
		LOG_ERR("Invalid reserved data");
		return Failure;
	}

	// Active PFM start address
	LOG_INF("Active image_type=%d address=%08x", manifest->image_type, act_pfm_offset);
	if (cerberus_get_version_info(manifest->image_type, act_pfm_offset, &fw_ver_element_addr, &act_fw_ver_element)) {
		LOG_ERR("Failed to get version info");
		return Failure;
	}

	if (act_fw_ver_element.version_length != ver_len) {
		LOG_ERR("Invalid version length(%d)", act_fw_ver_element.version_length);
		return Failure;
	}

	act_pfm_version = (struct PFR_VERSION *)act_fw_ver_element.version;

	if (act_pfm_version->reserved1 != 0 ||
	    act_pfm_version->reserved2 != 0 ||
	    act_pfm_version->reserved3 != 0) {
		LOG_ERR("Invalid reserved data");
		return Failure;
	}

	if (memcmp(act_pfm_version, staging_pfm_version, ver_len)) {
		LOG_ERR("Staged firmware does not match active firmware");
		LOG_HEXDUMP_ERR(act_pfm_version, ver_len, "act_pfm_version:");
		LOG_HEXDUMP_ERR(staging_pfm_version, ver_len, "staging_pfm_version:");
		return Failure;
	}

	LOG_INF("Staged firmware and active firmware match");

	return Success;
}

int get_active_pfm_version_details(struct pfr_manifest *pfr_manifest)
{
	if (!pfr_manifest)
		return Failure;

	struct pfm_firmware_version_element fw_ver_element;
	struct PFR_VERSION *pfm_version;
	uint32_t fw_ver_element_addr;
	uint8_t active_major_version;
	uint8_t active_minor_version;
	uint32_t read_address;
	uint8_t active_svn;

	if (pfr_manifest->image_type != BMC_TYPE &&
	    pfr_manifest->image_type != PCH_TYPE) {
		LOG_ERR("Unsupported image type %d", pfr_manifest->image_type);
		return Failure;
	}

	read_address = pfr_manifest->address;
	LOG_INF("Get pfm version, manifest->image_type=%d address=%08x", pfr_manifest->image_type, pfr_manifest->address);
	if (cerberus_get_version_info(pfr_manifest->image_type, read_address, &fw_ver_element_addr, &fw_ver_element)) {
		LOG_ERR("Failed to get version info");
		return Failure;
	}

	if (fw_ver_element.version_length != sizeof(struct PFR_VERSION)) {
		LOG_ERR("Invalid version length(%d)", fw_ver_element.version_length);
		return Failure;
	}

	pfm_version = (struct PFR_VERSION *)fw_ver_element.version;

	if (pfm_version->reserved1 != 0 ||
	    pfm_version->reserved2 != 0 ||
	    pfm_version->reserved3 != 0) {
		LOG_ERR("Invalid reserved data");
		return Failure;
	}

	active_svn = pfm_version->svn;
	active_major_version = pfm_version->major;
	active_minor_version = pfm_version->minor;

	if (pfr_manifest->image_type == PCH_TYPE) {
		SetPchPfmActiveSvn(active_svn);
		SetPchPfmActiveMajorVersion(active_major_version);
		SetPchPfmActiveMinorVersion(active_minor_version);
	} else if (pfr_manifest->image_type == BMC_TYPE) {
		SetBmcPfmActiveSvn(active_svn);
		SetBmcPfmActiveMajorVersion(active_major_version);
		SetBmcPfmActiveMinorVersion(active_minor_version);
	}

	return Success;
}

int get_recover_pfm_version_details(struct pfr_manifest *pfr_manifest)
{
	if (!pfr_manifest)
		return Failure;

	struct pfm_firmware_version_element fw_ver_element;
	struct PFR_VERSION *pfm_version;
	uint8_t recovery_major_version;
	uint8_t recovery_minor_version;
	uint32_t fw_ver_element_addr;
	uint32_t read_address;
	uint8_t recovery_svn;
	uint8_t policy_svn;
	int status = Success;

	if (pfr_manifest->image_type != BMC_TYPE &&
	    pfr_manifest->image_type != PCH_TYPE) {
		LOG_ERR("Unsupported image type %d", pfr_manifest->image_type);
		return Failure;
	}

	read_address = pfr_manifest->address;
	LOG_INF("Get pfm version, manifest->image_type=%d address=%08x", pfr_manifest->image_type, pfr_manifest->address);
	if (cerberus_get_version_info(pfr_manifest->image_type, read_address, &fw_ver_element_addr, &fw_ver_element)) {
		LOG_ERR("Failed to get version info");
		return Failure;
	}

	if (fw_ver_element.version_length != sizeof(struct PFR_VERSION)) {
		LOG_ERR("Invalid version length(%d)", fw_ver_element.version_length);
		return Failure;
	}

	pfm_version = (struct PFR_VERSION *)fw_ver_element.version;

	if (pfm_version->reserved1 != 0 ||
	    pfm_version->reserved2 != 0 ||
	    pfm_version->reserved3 != 0) {
		LOG_ERR("Invalid reserved data");
		return Failure;
	}

	recovery_svn = pfm_version->svn;
	recovery_major_version = pfm_version->major;
	recovery_minor_version = pfm_version->minor;

	if (pfr_manifest->image_type == PCH_TYPE) {
		SetPchPfmRecoverSvn(recovery_svn);
		SetPchPfmRecoverMajorVersion(recovery_major_version);
		SetPchPfmRecoverMinorVersion(recovery_minor_version);
		policy_svn = get_ufm_svn(SVN_POLICY_FOR_PCH_FW_UPDATE);
		if (recovery_svn > policy_svn)
			status = set_ufm_svn(SVN_POLICY_FOR_PCH_FW_UPDATE, recovery_svn);
	} else if (pfr_manifest->image_type == BMC_TYPE) {
		SetBmcPfmRecoverSvn(recovery_svn);
		SetBmcPfmRecoverMajorVersion(recovery_major_version);
		SetBmcPfmRecoverMinorVersion(recovery_minor_version);
		policy_svn = get_ufm_svn(SVN_POLICY_FOR_BMC_FW_UPDATE);
		if (recovery_svn > policy_svn)
			status = set_ufm_svn(SVN_POLICY_FOR_BMC_FW_UPDATE, recovery_svn);
	}

	return status;
}

int read_statging_area_pfm_svn(struct pfr_manifest *pfr_manifest, struct recovery_header *image_header, uint8_t *svn_version)
{
	if (!pfr_manifest || !image_header || !svn_version)
		return Failure;

	struct pfm_firmware_version_element fw_ver_element;
	struct PFR_VERSION *pfm_version;
	uint32_t fw_ver_element_addr;
	uint32_t dest_pfm_addr;
	uint32_t src_pfm_addr;

	if (pfr_manifest->image_type != BMC_TYPE &&
	    pfr_manifest->image_type != PCH_TYPE) {
		LOG_ERR("Unsupported image type %d", pfr_manifest->image_type);
		return Failure;
	}

	// Find PFM in stage image
	LOG_INF("Find staging pfm, image_type=%d address=%08x", pfr_manifest->image_type, pfr_manifest->address);
	if (cerberus_get_image_pfm_addr(pfr_manifest, image_header, &src_pfm_addr, &dest_pfm_addr)) {
		LOG_ERR("PFM doesn't exist in stage image");
		return Failure;
	}

	LOG_INF("Get pfm version, manifest->image_type=%d address=%08x", pfr_manifest->image_type, src_pfm_addr);
	if (cerberus_get_version_info(pfr_manifest->image_type, src_pfm_addr, &fw_ver_element_addr, &fw_ver_element)) {
		LOG_ERR("Failed to get version info");
		return Failure;
	}

	if (fw_ver_element.version_length != sizeof(struct PFR_VERSION)) {
		LOG_ERR("Invalid version length(%d)", fw_ver_element.version_length);
		return Failure;
	}

	pfm_version = (struct PFR_VERSION *)fw_ver_element.version;

	if (pfm_version->reserved1 != 0 ||
	    pfm_version->reserved2 != 0 ||
	    pfm_version->reserved3 != 0) {
		LOG_ERR("Invalid reserved data");
		return Failure;
	}

	*svn_version = pfm_version->svn;
	LOG_HEXDUMP_DBG(fw_ver_element.version, fw_ver_element.version_length, "PFM:");

	return Success;
}

