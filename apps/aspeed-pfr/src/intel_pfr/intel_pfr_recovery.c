/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <storage/flash_map.h>
#include "common/common.h"
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "manifest/pfm/pfm_manager.h"
#include "intel_pfr_recovery.h"
#include "intel_pfr_pbc.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_verification.h"
#include "intel_pfr_authentication.h"
#include "intel_pfr_cpld_utils.h"
#include "flash/flash_wrapper.h"
#include "flash/flash_util.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "intel_pfr_svn.h"
#include "intel_pfr_update.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int intel_pfr_recovery_verify(struct recovery_image *image, struct hash_engine *hash,
		struct signature_verification *verification, uint8_t *hash_out, size_t hash_length,
		struct pfm_manager *pfm)
{
	ARG_UNUSED(hash);
	ARG_UNUSED(verification);
	ARG_UNUSED(hash_out);
	ARG_UNUSED(hash_length);
	ARG_UNUSED(pfm);

	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) image;

	return pfr_recovery_verify(pfr_manifest);
}

/*
 * Compare staged firmware against active firmware.
 * RoT concludes that active firwmare and staged firmware are identical, if
 * the hashes of their PFM or AFM match exactly.
 *
 */
int does_staged_fw_image_match_active_fw_image(struct pfr_manifest *manifest)
{
	uint8_t act_pfm_sig_b0[sizeof(PFR_AUTHENTICATION_BLOCK0)] = { 0 };
	uint8_t staging_pfm_sig_b0[sizeof(PFR_AUTHENTICATION_BLOCK0)] = { 0 };
	uint8_t staging_pfm_sig_b1[256] = { 0 };
	PFR_AUTHENTICATION_BLOCK0 *act_block0_buffer;
	PFR_AUTHENTICATION_BLOCK0 *staging_block0_buffer;
	PFR_AUTHENTICATION_BLOCK1 *staging_block1_buffer;
	uint32_t act_pfm_image_type = 0;
	uint8_t digest_length = 0;
	uint32_t staging_address;
	uint32_t act_pfm_offset;
	uint8_t *staging_pfm_hash;
	uint8_t *act_pfm_hash;
	int status = 0;
	uint32_t backup_image_type = manifest->image_type;

	if (manifest->image_type == BMC_TYPE) {
		act_pfm_image_type = BMC_TYPE;
		if (ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET,
				(uint8_t *)&staging_address, sizeof(staging_address)))
			return Failure;

		if (ufm_read(PROVISION_UFM, BMC_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	} else if (manifest->image_type == PCH_TYPE) {
		act_pfm_image_type = PCH_TYPE;
		if (ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&staging_address,
					sizeof(staging_address)))
			return Failure;

		if (ufm_read(PROVISION_UFM, PCH_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (manifest->image_type == AFM_TYPE) {
		manifest->image_type = BMC_TYPE;
		staging_address = CONFIG_BMC_AFM_STAGING_OFFSET;
		/* Fixed partition so starts from zero */
		act_pfm_image_type = ROT_INTERNAL_AFM;
		act_pfm_offset = 0;
	}
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	else if (manifest->image_type == CPLD_TYPE) {
		manifest->image_type = BMC_TYPE;
		staging_address = CONFIG_BMC_INTEL_CPLD_STAGING_OFFSET;
		act_pfm_image_type = ROT_EXT_CPLD_ACT;
		act_pfm_offset = PFM_SIG_BLOCK_SIZE;
	}
#endif
	else {
		LOG_ERR("Unsupported image type %d", manifest->image_type);
		return Failure;
	}

	LOG_INF("Staging PFM signature, address=0x%08x, Active PFM signature, address=0x%08x", staging_address, act_pfm_offset);

	// Active PFM signature start address after Active
	status = pfr_spi_read(act_pfm_image_type, act_pfm_offset, sizeof(PFR_AUTHENTICATION_BLOCK0), act_pfm_sig_b0);
	if (status != Success) {
		LOG_ERR("Active pfm block0: Flash read data failed");
		return Failure;
	}

	act_block0_buffer = (PFR_AUTHENTICATION_BLOCK0 *)act_pfm_sig_b0;

	// Staging PFM signature start address after Staging block and capsule signature
	status = pfr_spi_read(manifest->image_type, staging_address + PFM_SIG_BLOCK_SIZE, sizeof(PFR_AUTHENTICATION_BLOCK0), staging_pfm_sig_b0);
	if (status != Success) {
		LOG_ERR("Staging pfm block0: Flash read data failed");
		return Failure;
	}

	staging_block0_buffer = (PFR_AUTHENTICATION_BLOCK0 *)staging_pfm_sig_b0;

	status = pfr_spi_read(manifest->image_type, staging_address + PFM_SIG_BLOCK_SIZE + sizeof(PFR_AUTHENTICATION_BLOCK0),
				sizeof(staging_block1_buffer->TagBlock1) + sizeof(staging_block1_buffer->ReservedBlock1) +
				sizeof(staging_block1_buffer->RootEntry), staging_pfm_sig_b1);
	if (status != Success) {
		LOG_ERR("Staging pfm block1: Flash read data failed");
		return Failure;
	}

	staging_block1_buffer = (PFR_AUTHENTICATION_BLOCK1 *)staging_pfm_sig_b1;

	if (staging_block1_buffer->RootEntry.PubCurveMagic == PUBLIC_SECP256_TAG) {
		act_pfm_hash = act_block0_buffer->Sha256Pc;
		staging_pfm_hash = staging_block0_buffer->Sha256Pc;
		digest_length = SHA256_DIGEST_LENGTH;
	} else if (staging_block1_buffer->RootEntry.PubCurveMagic == PUBLIC_SECP384_TAG) {
		act_pfm_hash = act_block0_buffer->Sha384Pc;
		staging_pfm_hash = staging_block0_buffer->Sha384Pc;
		digest_length = SHA384_DIGEST_LENGTH;
	} else {
		LOG_ERR("Staging block 1 root entry: Unsupported hash curve, %x", staging_block1_buffer->RootEntry.PubCurveMagic);
		return Failure;
	}

	// If the hashes of PFM or AFM match, the active image and staging image must be the same firmware.
	if (memcmp(act_pfm_hash, staging_pfm_hash, digest_length)) {
		LOG_ERR("Staged firmware does not match active firmware");
		LOG_HEXDUMP_ERR(act_pfm_hash, digest_length, "act_pfm_hash:");
		LOG_HEXDUMP_ERR(staging_pfm_hash, digest_length, "staging_pfm_hash:");
		return Failure;
	}

	manifest->image_type = backup_image_type;
	LOG_INF("Staged firmware and active firmware match");

	return Success;
}

int pfr_recover_active_region(struct pfr_manifest *manifest)
{
	uint32_t read_address;
	uint32_t staging_address;
	uint32_t act_pfm_offset;
	PFR_AUTHENTICATION_BLOCK0 *block0_buffer;
	uint8_t buffer[sizeof(PFR_AUTHENTICATION_BLOCK0)] = { 0 };

	LOG_INF("Active Data Corrupted");
	if (manifest->image_type == BMC_TYPE) {
		if (ufm_read(PROVISION_UFM, BMC_RECOVERY_REGION_OFFSET, (uint8_t *)&read_address,
					sizeof(read_address)))
			return Failure;

		if (ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET,
				(uint8_t *)&staging_address, sizeof(staging_address)))
			return Failure;

		if (ufm_read(PROVISION_UFM, BMC_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	} else if (manifest->image_type == PCH_TYPE) {
		if (ufm_read(PROVISION_UFM, PCH_RECOVERY_REGION_OFFSET, (uint8_t *)&read_address,
					sizeof(read_address)))
			return Failure;

		if (ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&staging_address,
					sizeof(staging_address)))
			return Failure;

		if (ufm_read(PROVISION_UFM, PCH_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (manifest->image_type == AFM_TYPE) {
		manifest->address = CONFIG_BMC_AFM_RECOVERY_OFFSET;
		manifest->image_type = BMC_TYPE;
		if (pfr_spi_read(manifest->image_type, manifest->address,
			sizeof(PFR_AUTHENTICATION_BLOCK0), buffer)) {
			LOG_ERR("Block0: Flash read data failed");
			return Failure;
		}

		block0_buffer = (PFR_AUTHENTICATION_BLOCK0 *)buffer;
		manifest->pc_length = block0_buffer->PcLength;
		manifest->address += PFM_SIG_BLOCK_SIZE;

		LOG_INF("AFM update start payload_address=%08x pc_length=%x", manifest->address, manifest->pc_length);
		if (update_afm(AFM_PART_ACT_1, manifest->address, manifest->pc_length))
			return Failure;

		LOG_INF("Repair success");
		return Success;
	}
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	else if(manifest->image_type == CPLD_TYPE) {
		uint32_t region_size;
		manifest->image_type = ROT_EXT_CPLD_RC;
		manifest->address = 0;

		if(manifest->pfr_authentication->cfms_verify(manifest)) {
			LOG_ERR("CFM signature verification failed");
			LogErrorCodes(INTEL_CPLD_UPDATE_FAIL, INTEL_CPLD_IMAGE_TOCTOU);
			return Failure;
		}

		region_size = pfr_spi_get_device_size(ROT_EXT_CPLD_ACT);
		if (pfr_spi_erase_region(ROT_EXT_CPLD_ACT, true, 0, region_size)) {
			LOG_ERR("Erase CPLD active region failed");
			return Failure;
		}

		LOG_INF("Copying ROT's recovery CPLD region to ROT's active CPLD region");
		if (pfr_spi_region_read_write_between_spi(ROT_EXT_CPLD_RC, 0,
					ROT_EXT_CPLD_ACT, 0, region_size)) {
			LOG_ERR("Failed to write CPLD image to ROT's CPLD active region");
			return Failure;
		}

		if (update_cpld_image(manifest)) {
#if defined(CONFIG_INTEL_SCM_CPLD_UPDATE_ONLY)
			if (intel_rsu_check_fw_loaded(SCM_CPLD, RSU_CFG_STS_CFM1_LOADED)) {
				intel_rsu_load_fw(SCM_CPLD, RSU_LOAD_CFM0);
				return Failure;
			}

#else
			for (uint8_t rsu_type = 0; rsu_type < MAX_RSU_TYPE; rsu_type++) {
				if (intel_rsu_check_fw_loaded(rsu_type, RSU_CFG_STS_CFM1_LOADED)) {
					intel_rsu_load_fw(rsu_type, RSU_LOAD_CFM0);
					return Failure;
				}

			}
#endif
			return Failure;
		}

		LOG_INF("Repair success");
		return Success;
	}
#endif
	else
		return Failure;

	manifest->recovery_address = read_address;
	manifest->staging_address = staging_address;
	manifest->active_pfm_addr = act_pfm_offset;
	manifest->address = read_address;
	manifest->address += PFM_SIG_BLOCK_SIZE;

	if (pfr_spi_read(manifest->image_type, manifest->address,
			sizeof(PFR_AUTHENTICATION_BLOCK0), buffer)) {
		LOG_ERR("Block0: Flash read data failed");
		return Failure;
	}

	block0_buffer = (PFR_AUTHENTICATION_BLOCK0 *)buffer;
	manifest->pc_length = block0_buffer->PcLength;

	uint32_t time_start, time_end;
	time_start = k_uptime_get_32();

	if (decompress_capsule(manifest, DECOMPRESSION_STATIC_AND_DYNAMIC_REGIONS_MASK)) {
		LOG_ERR("Repair Failed");
		return Failure;
	}

	time_end = k_uptime_get_32();
	LOG_INF("Firmware recovery completed, elapsed time = %u milliseconds",
			(time_end - time_start));

	LOG_INF("Repair success");

	return Success;
}

int pfr_staging_pch_staging(struct pfr_manifest *manifest)
{

	int status;

	uint32_t source_address;
	uint32_t target_address;
	uint32_t image_type = manifest->image_type;

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

#if defined(CONFIG_SEAMLESS_UPDATE)
	if (manifest->state == SEAMLESS_UPDATE) {
		manifest->pc_type = PFR_PCH_SEAMLESS_UPDATE_CAPSULE;
	} else
#endif
	{
		manifest->pc_type = PFR_PCH_UPDATE_CAPSULE;
	}

	LOG_INF("BMC's PCH Staging Area verification");
	LOG_INF("Veriifying capsule signature, address=0x%08x", manifest->address);
	// manifest verification
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("verify failed");
		return Failure;
	}

	// Recovery region PFM verification
	manifest->address += PFM_SIG_BLOCK_SIZE;
	manifest->pc_type = PFR_PCH_PFM;
	LOG_INF("Verifying PFM signature, address=0x%08x", manifest->address);
	// manifest verification
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success)
		return Failure;
	LOG_INF("BMC's PCH Staging verification successful");
	manifest->address = target_address;
	manifest->image_type = image_type;

	int sector_sz = pfr_spi_get_block_size(image_type);
	bool support_block_erase = (sector_sz == BLOCK_SIZE);

	LOG_INF("Copying staging region from BMC addr: 0x%08x to PCH addr: 0x%08x, length : 0x%08x",
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

int intel_pfr_recover_update_action(struct pfr_manifest *manifest)
{
	ARG_UNUSED(manifest);
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

	return intel_pfr_recovery_verify(image, hash, verification, hash_out, hash_length, pfm);
}

/**
 * Apply the recovery image to host flash.  It is assumed that the host flash region is already
 * blank.
 *
 * @param image The recovery image to query.
 * @param flash The flash device to write the recovery image to.
 *
 * @return 0 if applying the recovery image to host flash was successful or an error code.
 */
int recovery_apply_to_flash(struct recovery_image *image, struct spi_flash *flash)
{
	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) image;

	return intel_pfr_recover_update_action(pfr_manifest);
}

