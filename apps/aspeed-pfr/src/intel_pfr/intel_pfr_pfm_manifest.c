/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <flash/flash_aspeed.h>
#include <sys/types.h>
#include <zephyr/storage/flash_map.h>

#include "intel_pfr_pfm_manifest.h"
#include "intel_pfr_definitions.h"
#include "AspeedStateMachine/common_smc.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_update.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "intel_pfr_svn.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
#if (CONFIG_AFM_SPEC_VERSION == 4)
uint8_t afm_dev_idx = 0;
#include <aspeed_util.h>
extern off_t* spdm_get_afm_list();
int update_afm_body(uint32_t type, uint32_t address)
{
	uint8_t flash_type;
	uint32_t afm_body_offset;
	uint8_t sha_buffer[SHA384_DIGEST_LENGTH];
	uint8_t afm_body_sha[SHA384_DIGEST_LENGTH];
	int hash_length = SHA384_DIGEST_LENGTH;
	uint32_t org_type, afm_addr;
	off_t *afmlist = spdm_get_afm_list();
	PFR_AUTHENTICATION_BLOCK0 block0;

	struct pfr_manifest *pfr_manifest = get_pfr_manifest();
	org_type = pfr_manifest->image_type;
	if (type == BMC_TYPE) {
		flash_type = BMC_SPI;
		afm_body_offset = BMC_AFM_BODY_OFFSET;
	}
	else {
		flash_type = PCH_SPI;
		afm_body_offset = PCH1_AFM_BODY_OFFSET;
	}

	afm_addr = address;
	pfr_spi_read(flash_type, afm_addr, sizeof(PFR_AUTHENTICATION_BLOCK0), (uint8_t *)&block0);
	if (block0.PcType == PFR_AFM) {
		/* if AFM data is an address defintion data, to find AFM device data */
		pfr_spi_read(flash_type, afm_addr + AFM_BODY_SIZE, sizeof(PFR_AUTHENTICATION_BLOCK0), (uint8_t *)&block0);
		if (block0.Block0Tag == BLOCK0TAG)
			afm_addr += AFM_BODY_SIZE;
		else {
			LOG_WRN("there is no AFM device (%x, %x, %x)", block0.Block0Tag, block0.PcType, block0.PcLength);
			return Success;
		}
	} else if (block0.PcType != PFR_AFM_PER_DEV) {
		LOG_WRN("Invalid AFM type (%x, %x, %x)", block0.Block0Tag, block0.PcType, block0.PcLength);
		return Failure;
	}

	pfr_manifest->image_type = flash_type;
	pfr_manifest->pfr_hash->start_address = afm_addr;
	pfr_manifest->pfr_hash->type = HASH_TYPE_SHA384;
	pfr_manifest->flash->state->device_id[0] = flash_type;
	pfr_manifest->pfr_hash->length = AFM_BODY_SIZE;
	pfr_manifest->base->get_hash((struct manifest *)pfr_manifest, pfr_manifest->hash,
			sha_buffer, hash_length);

	pfr_manifest->image_type = ROT_INTERNAL_AFM;
	pfr_manifest->pfr_hash->start_address = afm_body_offset;
	pfr_manifest->flash->state->device_id[0] = ROT_INTERNAL_AFM;
	pfr_manifest->base->get_hash((struct manifest *)pfr_manifest, pfr_manifest->hash,
			afm_body_sha, hash_length);

	if (memcmp(sha_buffer, afm_body_sha, hash_length)) {
		LOG_INF("AFM (%d) body data is different than active image, to update AFM body", type);
		if (pfr_spi_erase_region(ROT_INTERNAL_AFM, true, afm_body_offset, AFM_BODY_SIZE)) {
			LOG_ERR("Failed to erase AFM body Partition (%x)", afm_body_offset);
			return Failure;
		}
		LOG_INF("From flash (%d:%x) to flash (%d:%x) with size %x", flash_type, afm_addr, ROT_INTERNAL_AFM, afm_body_offset, AFM_BODY_SIZE);
		if (pfr_spi_region_read_write_between_spi(flash_type, afm_addr,
					ROT_INTERNAL_AFM, afm_body_offset, AFM_BODY_SIZE)) {
			LOG_ERR("Failed to write AFM body Partition (%x)", afm_body_offset);
			return Failure;
		}
	}
	else
		LOG_INF("AFM (%d) body data are the same", type);

	if (type == BMC_TYPE) {
		afmlist[afm_dev_idx_bmc] = BMC_AFM_BODY_OFFSET;
	} else if (type == PCH_TYPE) {
		afmlist[afm_dev_idx_cpu0] = PCH1_AFM_BODY_OFFSET;
	}

	pfr_manifest->image_type = org_type;
	return 0;
}
#endif

void detect_PFM_format(uint32_t image_type, uint8_t *buf, int len, uint32_t hash_curve)
{
	uint32_t cap_pfm_body_offset = sizeof(PFM_STRUCTURE);
	uint32_t cap_pfm_body_end_addr = len;
	PFM_SPI_DEFINITION *spi_def;
	uint8_t new_format_found = 0;

	while (cap_pfm_body_offset < cap_pfm_body_end_addr) {
		spi_def = (PFM_SPI_DEFINITION *)(buf+cap_pfm_body_offset);
		if (spi_def->PFMDefinitionType == SMBUS_RULE) {
			cap_pfm_body_offset += sizeof(PFM_SMBUS_RULE);
		} else if (spi_def->PFMDefinitionType == SPI_REGION) {
			cap_pfm_body_offset += sizeof(PFM_SPI_DEFINITION);
			if (spi_def->HashAlgorithmInfo.SHA256HashPresent ||
			    spi_def->HashAlgorithmInfo.SHA384HashPresent) {
				cap_pfm_body_offset += sizeof(PFM_SPI_DEFINITION);
				cap_pfm_body_offset += (hash_curve == secp384r1) ?
					SHA384_SIZE : SHA256_SIZE;
			} else {
				cap_pfm_body_offset += SPI_REGION_DEF_MIN_SIZE;
			}
		} else if (spi_def->PFMDefinitionType == FVM_ADDR_DEF) {
			cap_pfm_body_offset += sizeof(PFM_FVM_ADDRESS_DEFINITION);
		} else if (spi_def->PFMDefinitionType == FVM_CAP) {
			cap_pfm_body_offset += sizeof(FVM_CAPABLITIES);
#if (CONFIG_AFM_SPEC_VERSION == 4)
		} else if (spi_def->PFMDefinitionType == AFM_ADDR_DEF) {
			AFM_ADDRESS_DEFINITION_v40 *afm_def = (AFM_ADDRESS_DEFINITION_v40 *)spi_def;
			LOG_INF("Get AFM addr info (%08x)", afm_def->AfmAddress);
			cap_pfm_body_offset += sizeof(AFM_ADDRESS_DEFINITION_v40);
			new_format_found = 1;
			update_afm_body(image_type, afm_def->AfmAddress);
#endif
		}
		else {
			break;
		}
	}

	LOG_INF("New PFM version is %s used", (new_format_found)?"":"not");

}
#endif

int get_active_pfm_version_details(struct pfr_manifest *manifest, uint32_t address)
{
	int status = 0;
	uint32_t pfm_data_address = 0;
	uint8_t active_svn;
	uint16_t active_major_version, active_minor_version;
	uint8_t buffer[sizeof(PFM_STRUCTURE)];

	// PFM data start address after signature
	if (manifest->hash_curve == hash_sign_algo384 || manifest->hash_curve == hash_sign_algo256)
		pfm_data_address = address + LMS_PFM_SIG_BLOCK_SIZE;
	else
		pfm_data_address = address + PFM_SIG_BLOCK_SIZE;

	status = pfr_spi_read(manifest->image_type, pfm_data_address, sizeof(PFM_STRUCTURE), buffer);
	if (status != Success) {
		LOG_ERR("Get Pfm Version Details failed");
		return Failure;
	}

	if (((PFM_STRUCTURE *)buffer)->PfmTag == PFMTAG) {
		active_svn = ((PFM_STRUCTURE *)buffer)->SVN;
		active_major_version = ((PFM_STRUCTURE *)buffer)->PfmRevision & 0xFF;
		active_minor_version = ((PFM_STRUCTURE *)buffer)->PfmRevision >> 8;

		if (manifest->image_type == PCH_TYPE) {
			SetPchPfmActiveSvn(active_svn);
			SetPchPfmActiveMajorVersion(active_major_version);
			SetPchPfmActiveMinorVersion(active_minor_version);
		} else if (manifest->image_type == BMC_TYPE) {
			SetBmcPfmActiveSvn(active_svn);
			SetBmcPfmActiveMajorVersion(active_major_version);
			SetBmcPfmActiveMinorVersion(active_minor_version);
		}
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
		else if (manifest->image_type == ROT_EXT_CPLD_ACT) {
			SetIntelCpldActiveSvn(active_svn);
			SetIntelCpldActiveMajorVersion(active_major_version);
			SetIntelCpldActiveMinorVersion(active_minor_version);
		}
#endif
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
		uint8_t tmpbuf[((PFM_STRUCTURE *)buffer)->Length];

		status = pfr_spi_read(manifest->image_type, pfm_data_address, ((PFM_STRUCTURE *)buffer)->Length, tmpbuf);
		if (status != Success) {
			LOG_ERR("Get Pfm Version Details failed");
			return Failure;
		}
		detect_PFM_format(manifest->image_type, tmpbuf, ((PFM_STRUCTURE *)buffer)->Length, manifest->hash_curve);
#endif
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (((PFM_STRUCTURE *)buffer)->PfmTag == AFM_TAG) {
		active_svn = ((PFM_STRUCTURE *)buffer)->SVN;
		active_major_version = ((PFM_STRUCTURE *)buffer)->PfmRevision & 0xFF;
		active_minor_version = ((PFM_STRUCTURE *)buffer)->PfmRevision >> 8;

		SetAfmActiveSvn(active_svn);
		SetAfmActiveMajorVersion(active_major_version);
		SetAfmActiveMinorVersion(active_minor_version);
	}
#endif
	else {
		LOG_ERR("PfmTag verification failed, expected: %x, actual: %x",
				PFMTAG, ((PFM_STRUCTURE *)buffer)->PfmTag);
		return Failure;
	}

	return Success;
}

int get_recover_pfm_version_details(struct pfr_manifest *manifest, uint32_t address)
{
	int status = 0;
	uint32_t pfm_data_address = 0;
	uint16_t recovery_major_version, recovery_minor_version;
	uint8_t recovery_svn;
	uint8_t policy_svn;
	PFM_STRUCTURE *pfm_data;
	uint8_t buffer[sizeof(PFM_STRUCTURE)];

	// PFM data start address after Recovery block and PFM block
	if (manifest->hash_curve == hash_sign_algo384 || manifest->hash_curve == hash_sign_algo256)
		pfm_data_address = address + LMS_PFM_SIG_BLOCK_SIZE + LMS_PFM_SIG_BLOCK_SIZE;
	else
		pfm_data_address = address + PFM_SIG_BLOCK_SIZE + PFM_SIG_BLOCK_SIZE;

	status = pfr_spi_read(manifest->image_type, pfm_data_address, sizeof(PFM_STRUCTURE),
			buffer);
	if (status != Success) {
		LOG_ERR("Get Recover Pfm Version Details failed");
		return Failure;
	}

	pfm_data = (PFM_STRUCTURE *)buffer;

	if (pfm_data->PfmTag == PFMTAG) {
		recovery_svn = pfm_data->SVN;
		recovery_major_version = pfm_data->PfmRevision & 0xFF;
		recovery_minor_version = pfm_data->PfmRevision >> 8;

		// MailBox Communication
		if (manifest->image_type == PCH_TYPE) {
			SetPchPfmRecoverSvn(recovery_svn);
			SetPchPfmRecoverMajorVersion(recovery_major_version);
			SetPchPfmRecoverMinorVersion(recovery_minor_version);
			policy_svn = get_ufm_svn(SVN_POLICY_FOR_PCH_FW_UPDATE);
			if (recovery_svn > policy_svn)
				status = set_ufm_svn(SVN_POLICY_FOR_PCH_FW_UPDATE, recovery_svn);
		} else if (manifest->image_type == BMC_TYPE) {
			SetBmcPfmRecoverSvn(recovery_svn);
			SetBmcPfmRecoverMajorVersion(recovery_major_version);
			SetBmcPfmRecoverMinorVersion(recovery_minor_version);
			policy_svn = get_ufm_svn(SVN_POLICY_FOR_BMC_FW_UPDATE);
			if (recovery_svn > policy_svn)
				status = set_ufm_svn(SVN_POLICY_FOR_BMC_FW_UPDATE, recovery_svn);
		}
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
		else if (manifest->image_type == ROT_EXT_CPLD_RC) {
			// TODO: Recovery CPLD SVN is not defined in the specification.
			return Success;
		}
#endif
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (pfm_data->PfmTag == AFM_TAG) {
		recovery_svn = pfm_data->SVN;
		recovery_major_version = pfm_data->PfmRevision & 0xFF;
		recovery_minor_version = pfm_data->PfmRevision >> 8;

		SetAfmRecoverSvn(recovery_svn);
		SetAfmRecoverMajorVersion(recovery_major_version);
		SetAfmRecoverMinorVersion(recovery_minor_version);
		policy_svn = get_ufm_svn(SVN_POLICY_FOR_AFM);
		if (recovery_svn > policy_svn)
			status = set_ufm_svn(SVN_POLICY_FOR_AFM, recovery_svn);
	}
#endif
	else {
		LOG_ERR("PfmTag verification failed, expected: %x, actual: %x",
			PFMTAG, ((PFM_STRUCTURE *)buffer)->PfmTag);
		return Failure;
	}

	return status;
}

int spi_region_hash_verification(struct pfr_manifest *pfr_manifest,
		PFM_SPI_DEFINITION *PfmSpiDefinition, uint8_t *pfm_spi_Hash)
{

	uint32_t region_length;

	LOG_INF("RegionStartAddress: %x, RegionEndAddress: %x",
		     PfmSpiDefinition->RegionStartAddress, PfmSpiDefinition->RegionEndAddress);
	region_length = (PfmSpiDefinition->RegionEndAddress) - (PfmSpiDefinition->RegionStartAddress);

	if ((PfmSpiDefinition->HashAlgorithmInfo.SHA256HashPresent == 1) ||
	    (PfmSpiDefinition->HashAlgorithmInfo.SHA384HashPresent == 1)) {
		LOG_INF("Digest verification start");

		uint8_t sha_buffer[SHA384_DIGEST_LENGTH] = { 0 };
		uint32_t hash_length = 0;

		pfr_manifest->pfr_hash->start_address = PfmSpiDefinition->RegionStartAddress;
		pfr_manifest->pfr_hash->length = region_length;

		if (PfmSpiDefinition->HashAlgorithmInfo.SHA256HashPresent == 1) {
			pfr_manifest->pfr_hash->type = HASH_TYPE_SHA256;
			hash_length = SHA256_DIGEST_LENGTH;
		} else if (PfmSpiDefinition->HashAlgorithmInfo.SHA384HashPresent == 1) {
			pfr_manifest->pfr_hash->type = HASH_TYPE_SHA384;
			hash_length = SHA384_DIGEST_LENGTH;
		} else  {
			return Failure;
		}

		pfr_manifest->flash->state->device_id[0] = pfr_manifest->image_type;
		pfr_manifest->base->get_hash((struct manifest *)pfr_manifest, pfr_manifest->hash,
				sha_buffer, hash_length);

		if (memcmp(pfm_spi_Hash, sha_buffer, hash_length)) {
			LOG_ERR("Digest verification failed");
			return Failure;
		}
		LOG_INF("Digest verification succeeded");
	}


	return Success;
}

int get_spi_region_hash(struct pfr_manifest *manifest, uint32_t address,
		PFM_SPI_DEFINITION *p_spi_definition, uint8_t *pfm_spi_hash)
{
	if (p_spi_definition->HashAlgorithmInfo.SHA256HashPresent == 1) {
		pfr_spi_read(manifest->image_type, address, SHA256_SIZE,
				pfm_spi_hash);

		return SHA256_SIZE;
	} else if (p_spi_definition->HashAlgorithmInfo.SHA384HashPresent == 1) {
		pfr_spi_read(manifest->image_type, address, SHA384_SIZE,
				pfm_spi_hash);

		return SHA384_SIZE;
	}

	return 0;
}

#if defined(CONFIG_SEAMLESS_UPDATE)
int fvm_spi_region_verification(struct pfr_manifest *manifest)
{
	uint32_t read_address = manifest->address;
	FVM_STRUCTURE fvm_data;
	bool done = false;
	uint32_t fvm_addr = read_address + PFM_SIG_BLOCK_SIZE;
	uint32_t fvm_end_addr;
	PFM_SPI_DEFINITION spi_definition = { 0 };
	uint8_t pfm_spi_hash[SHA384_SIZE] = { 0 };

	if (manifest->hash_curve == hash_sign_algo384 || manifest->hash_curve == hash_sign_algo256) {
		fvm_addr = read_address + LMS_PFM_SIG_BLOCK_SIZE;
	}

	LOG_INF("Verifying FVM...");
	if (manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length)) {
		LOG_ERR("Verify active FVM failed");
		return Failure;
	}

	if (pfr_spi_read(manifest->image_type, fvm_addr,
			sizeof(FVM_STRUCTURE), (uint8_t *)&fvm_data))
		return Failure;

	if (fvm_data.FvmTag != FVMTAG) {
		LOG_ERR("FVMTag verification failed...\n expected: %x\n actual: %x",
				FVMTAG, fvm_data.FvmTag);
		return Failure;
	}

	fvm_end_addr = fvm_addr + fvm_data.Length;
	fvm_addr += sizeof(FVM_STRUCTURE);

	while (!done) {
		if (pfr_spi_read(manifest->image_type, fvm_addr,
				sizeof(PFM_SPI_DEFINITION), (uint8_t *)&spi_definition))
			return Failure;

		switch (spi_definition.PFMDefinitionType) {
		case SPI_REGION:
			fvm_addr += sizeof(PFM_SPI_DEFINITION);
			fvm_addr += get_spi_region_hash(manifest, fvm_addr, &spi_definition,
					pfm_spi_hash);
			if (spi_region_hash_verification(manifest, &spi_definition,
							pfm_spi_hash))
				return Failure;

			memset(&spi_definition, 0, sizeof(PFM_SPI_DEFINITION));
			memset(pfm_spi_hash, 0, SHA384_SIZE);
			break;
		case PCH_FVM_CAP:
			fvm_addr += sizeof(FVM_CAPABLITIES);
			break;
		default:
			done = true;
			break;
		}

		if (fvm_addr >= fvm_end_addr)
			break;
	}

	return Success;
}
#endif

int pfm_spi_region_verification(struct pfr_manifest *manifest)
{
	uint32_t read_address = manifest->address;
	PFM_STRUCTURE pfm_data;
	bool done = false;
	uint32_t pfm_addr = read_address + PFM_SIG_BLOCK_SIZE;
	uint32_t pfm_end_addr;
#if defined(CONFIG_SEAMLESS_UPDATE)
	PFM_FVM_ADDRESS_DEFINITION *fvm_def;
#endif
	PFM_SPI_DEFINITION spi_definition = { 0 };
	uint8_t pfm_spi_hash[SHA384_SIZE] = { 0 };

	if (manifest->hash_curve == hash_sign_algo384 || manifest->hash_curve == hash_sign_algo256)
		pfm_addr = read_address + LMS_PFM_SIG_BLOCK_SIZE;

	if (pfr_spi_read(manifest->image_type, pfm_addr,
			sizeof(PFM_STRUCTURE), (uint8_t *)&pfm_data))
		return Failure;

	/* there is no SPI region definition in the AFM region, to ignore the SPI region verification */
	if (pfm_data.PfmTag == AFM_TAG)
		return Success;

	pfm_end_addr = pfm_addr + pfm_data.Length;
	pfm_addr += sizeof(PFM_STRUCTURE);

	while (!done) {
		if (pfr_spi_read(manifest->image_type, pfm_addr,
				sizeof(PFM_SPI_DEFINITION), (uint8_t *)&spi_definition))
			return Failure;

		switch (spi_definition.PFMDefinitionType) {
		case SPI_REGION:
			pfm_addr += sizeof(PFM_SPI_DEFINITION);
			pfm_addr += get_spi_region_hash(manifest, pfm_addr, &spi_definition,
					pfm_spi_hash);
			if (spi_region_hash_verification(manifest, &spi_definition,
					pfm_spi_hash))
				return Failure;

			memset(&spi_definition, 0, sizeof(PFM_SPI_DEFINITION));
			memset(pfm_spi_hash, 0, SHA384_SIZE);
			break;
		case SMBUS_RULE:
			pfm_addr += sizeof(PFM_SMBUS_RULE);
			break;
#if defined(CONFIG_SEAMLESS_UPDATE)
		case FVM_ADDR_DEF:
			fvm_def = (PFM_FVM_ADDRESS_DEFINITION *)&spi_definition;
			manifest->address = fvm_def->FVMAddress;
			if (fvm_spi_region_verification(manifest)) {
				manifest->address = read_address;
				LOG_ERR("FVM SPI region verification failed");
				return Failure;
			}
			pfm_addr += sizeof(PFM_FVM_ADDRESS_DEFINITION);
			break;
#endif
		default:
			done = true;
			break;
		}

		if (pfm_addr >= pfm_end_addr)
			break;
	}
	manifest->address = read_address;

	return Success;
}

