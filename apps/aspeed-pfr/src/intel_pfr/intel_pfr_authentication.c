/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>
#include <flash/flash_aspeed.h>

#include "pfr/pfr_common.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_verification.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_pfm_manifest.h"
#include "pfr/pfr_ufm.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int pfr_recovery_verify(struct pfr_manifest *manifest)
{
	int status = 0;
	uint32_t read_address;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	bool verify_afm = false;
#endif

	LOG_INF("Verify recovery");

	// Recovery region verification
	if (manifest->image_type == BMC_TYPE) {
		ufm_read(PROVISION_UFM, BMC_RECOVERY_REGION_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
		manifest->pc_type = PFR_BMC_UPDATE_CAPSULE;
	} else if (manifest->image_type == PCH_TYPE) {
		ufm_read(PROVISION_UFM, PCH_RECOVERY_REGION_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
		manifest->pc_type = PFR_PCH_UPDATE_CAPSULE;
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (manifest->image_type == AFM_TYPE) {
		read_address = CONFIG_BMC_AFM_RECOVERY_OFFSET;
		manifest->pc_type = PFR_AFM;
		manifest->image_type = BMC_TYPE;
		verify_afm = true;
	}
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	else if (manifest->image_type == CPLD_TYPE) {
		manifest->image_type = ROT_EXT_CPLD_RC;
		read_address = 0;
		manifest->pc_type = PFR_INTEL_CPLD_UPDATE_CAPSULE;
	}
#endif
	else {
		LOG_ERR("Incorrect manifest image_type");
		return Failure;
	}

	manifest->address = read_address;

	LOG_INF("Verifying capsule signature, address=0x%08x", manifest->address);
	// Block0-Block1 verification
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Verify recovery capsule failed");
		return Failure;
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	if (verify_afm)
		manifest->pc_type = PFR_AFM;
	else if (manifest->image_type == BMC_TYPE)
		manifest->pc_type = PFR_BMC_PFM;
	else if (manifest->image_type == PCH_TYPE)
		manifest->pc_type = PFR_PCH_PFM;
#else
	if (manifest->image_type == BMC_TYPE)
		manifest->pc_type = PFR_BMC_PFM;
	else if (manifest->image_type == PCH_TYPE)
		manifest->pc_type = PFR_PCH_PFM;
#endif

	// Recovery region PFM verification
	if (manifest->hash_curve == hash_sign_algo384 || manifest->hash_curve == hash_sign_algo256)
		manifest->address += LMS_PFM_SIG_BLOCK_SIZE;
	else
		manifest->address += PFM_SIG_BLOCK_SIZE;
	LOG_INF("Hash curve = %d", manifest->hash_curve);
	LOG_INF("Verifying PFM signature, address=0x%08x", manifest->address);
	// manifest verification
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Verify recovery PFM failed");
		return Failure;
	}

	status = get_recover_pfm_version_details(manifest, read_address);
	if (status != Success)
		return Failure;

	LOG_INF("Recovery area verification successful");

	return Success;
}

int pfr_active_verify(struct pfr_manifest *manifest)
{
	int status = 0;
	uint32_t read_address;

	if (manifest->image_type == BMC_TYPE) {
		get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
		manifest->pc_type = PFR_BMC_PFM;
	} else if (manifest->image_type == PCH_TYPE) {
		get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
		manifest->pc_type = PFR_PCH_PFM;
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (manifest->image_type == ROT_INTERNAL_AFM) {
		/* Fixed partition so starts from zero */
		read_address = 0;
		manifest->pc_type = PFR_AFM;
	}
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	else if (manifest->image_type == CPLD_TYPE) {
		manifest->image_type = ROT_EXT_CPLD_ACT;
		read_address = 0;
		manifest->pc_type = PFR_INTEL_CPLD_UPDATE_CAPSULE;
		manifest->address = read_address;
		LOG_INF("Verifying capsule signature, address=0x%08x", manifest->address);
		if (manifest->pfr_authentication->online_update_cap_verify(manifest)) {
			LOG_ERR("Verify BMC's CPLD active region failed");
			return Failure;
		}
		LOG_INF("Verify CPLD active region success");
		return Success;
	}
#endif
	else {
		LOG_ERR("Unsupported image type %d", manifest->image_type);
		return Failure;
	}
	manifest->address = read_address;

	LOG_INF("Active Firmware Verification");
	LOG_INF("Verifying PFM signature, address=0x%08x", manifest->address);
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Verify active PFM failed");
		return Failure;
	}

	status = get_active_pfm_version_details(manifest, read_address);
	if (status != Success)
		return Failure;

	status = pfm_spi_region_verification(manifest);
	if (status != Success) {
		LOG_ERR("Verify active SPI region failed");
		return Failure;
	}

	LOG_INF("Verify active SPI region success");
	return Success;
}

