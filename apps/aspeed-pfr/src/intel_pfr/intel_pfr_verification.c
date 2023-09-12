/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <stdint.h>
#include <drivers/flash.h>
#include "common/common.h"
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "flash/flash_aspeed.h"
#include "pfr/pfr_common.h"
#include "intel_pfr_definitions.h"
#include "pfr/pfr_util.h"
#include "pfr/pfr_ufm.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_key_cancellation.h"
#include "intel_pfr_pfm_manifest.h"
#include "intel_pfr_verification.h"
#include "intel_pfr_cpld_utils.h"
#include "Smbus_mailbox/Smbus_mailbox.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#if defined(CONFIG_PIT_PROTECTION)
int intel_pfr_pit_level1_verify(void)
{
	// PIT level 1 verification should be customized.
	// This is the sample code that use ast1060 internal flash offset 0xdf000 - dffff to
	// simulate RF NVRAM.
#define RF_NVRAM_OFFSET 0xf000
	uint32_t ufm_status;
	uint8_t pit_password[8];
	uint8_t rf_pit_password[8];

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&ufm_status, sizeof(ufm_status));
	if (!CheckUfmStatus(ufm_status, UFM_STATUS_PIT_L1_ENABLE_BIT_MASK))
		return Success;

	ufm_read(PROVISION_UFM, PIT_PASSWORD,
			(uint8_t *)pit_password, sizeof(pit_password));
	pfr_spi_read(ROT_INTERNAL_INTEL_STATE, RF_NVRAM_OFFSET, sizeof(rf_pit_password),
			rf_pit_password);
	if (memcmp(pit_password, rf_pit_password, sizeof(pit_password))) {
		SetPlatformState(LOCKDOWN_DUE_TO_PIT_L1);
		LOG_ERR("PIT Level 1 verify failed, lockdown");
		return Lockdown;
	}

	LOG_INF("PIT L1 verify successful");
	return Success;
}

int intel_pfr_pit_level2_verify(void)
{
	struct pfr_manifest *pfr_manifest = get_pfr_manifest();
	const struct device *flash_dev;
	PFR_AUTHENTICATION_BLOCK1 block1;
	KEY_ENTRY *root_entry;
	uint32_t ufm_status;
	uint32_t act_pfm_offset;
	uint32_t flash_size;
	uint32_t hash_length;
	uint8_t sha_buffer[SHA384_DIGEST_LENGTH] = { 0 };
	uint8_t pit_hash_buffer[SHA384_DIGEST_LENGTH] = { 0 };
	static char *flash_devices[4] = {
		"spi1_cs0",
		"spi1_cs1",
		"spi2_cs0",
		"spi2_cs1",
	};

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&ufm_status, sizeof(ufm_status));
	if (CheckUfmStatus(ufm_status, UFM_STATUS_PIT_L2_PASSED_BIT_MASK) ||
			!CheckUfmStatus(ufm_status, UFM_STATUS_PIT_L2_ENABLE_BIT_MASK))
		return Success;

	if (ufm_read(PROVISION_UFM, BMC_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
				sizeof(act_pfm_offset))) {
		LOG_ERR("Failed to get active PFM address");
		return Failure;
	}

	if (pfr_spi_read(BMC_TYPE, act_pfm_offset + sizeof(PFR_AUTHENTICATION_BLOCK0),
				sizeof(PFR_AUTHENTICATION_BLOCK1), (uint8_t *)&block1)) {
		LOG_ERR("Failed to get block1");
		return Failure;
	}

	root_entry = &block1.RootEntry;
	if (root_entry->PubCurveMagic == PUBLIC_SECP384_TAG) {
		pfr_manifest->pfr_hash->type = HASH_TYPE_SHA384;
		hash_length = SHA384_DIGEST_LENGTH;
	} else {
		pfr_manifest->pfr_hash->type = HASH_TYPE_SHA256;
		hash_length = SHA256_DIGEST_LENGTH;
	}

	pfr_manifest->pfr_hash->start_address = 0;
	flash_dev = device_get_binding(flash_devices[BMC_TYPE]);
	flash_size = flash_get_flash_size(flash_dev);
#if defined(CONFIG_BMC_DUAL_FLASH)
	flash_dev = device_get_binding(flash_devices[BMC_TYPE + 1]);
	flash_size += flash_get_flash_size(flash_dev);
#endif
	pfr_manifest->image_type = BMC_TYPE;
	pfr_manifest->flash->state->device_id[0] = BMC_TYPE;
	pfr_manifest->pfr_hash->length = flash_size;
	pfr_manifest->base->get_hash((struct manifest *)pfr_manifest, pfr_manifest->hash,
			sha_buffer, hash_length);

	if (CheckUfmStatus(ufm_status, UFM_STATUS_PIT_HASH_STORED_BIT_MASK)) {
		ufm_read(PROVISION_UFM, PIT_BMC_FW_HASH,
				(uint8_t *)pit_hash_buffer, sizeof(pit_hash_buffer));
		if (memcmp(sha_buffer, pit_hash_buffer, sizeof(sha_buffer))) {
			LOG_ERR("PIT L2 BMC hash mismatch");
			LOG_HEXDUMP_ERR(sha_buffer, hash_length, "bmc pit hash :");
			LOG_HEXDUMP_ERR(pit_hash_buffer, hash_length, "ufm pit hash :");
			SetPlatformState(LOCKDOWN_ON_PIT_L2_BMC_HASH_MISMATCH);
			return Lockdown;
		}
		LOG_INF("PIT L2 BMC hash verify successful");
	} else {
		ufm_write(PROVISION_UFM, PIT_BMC_FW_HASH, sha_buffer, SHA384_DIGEST_LENGTH);
		LOG_INF("BMC firmware sealed");
	}


	flash_dev = device_get_binding(flash_devices[PCH_TYPE]);
	flash_size = flash_get_flash_size(flash_dev);
#if defined(CONFIG_CPU_DUAL_FLASH)
	flash_dev = device_get_binding(flash_devices[PCH_TYPE + 1]);
	flash_size += flash_get_flash_size(flash_dev);
#endif
	pfr_manifest->image_type = PCH_TYPE;
	pfr_manifest->flash->state->device_id[0] = PCH_TYPE;
	pfr_manifest->pfr_hash->length = flash_size;
	pfr_manifest->base->get_hash((struct manifest *)pfr_manifest, pfr_manifest->hash,
			sha_buffer, hash_length);

	if (CheckUfmStatus(ufm_status, UFM_STATUS_PIT_HASH_STORED_BIT_MASK)) {
		ufm_read(PROVISION_UFM, PIT_PCH_FW_HASH,
				(uint8_t *)pit_hash_buffer, sizeof(pit_hash_buffer));
		if (memcmp(sha_buffer, pit_hash_buffer, sizeof(sha_buffer))) {
			LOG_ERR("PIT L2 PCH hash mismatch");
			LOG_HEXDUMP_ERR(sha_buffer, hash_length, "pch pit hash :");
			LOG_HEXDUMP_ERR(pit_hash_buffer, hash_length, "ufm pit hash :");
			SetPlatformState(LOCKDOWN_ON_PIT_L2_PCH_HASH_MISMATCH);
			return Lockdown;
		}
		SetUfmFlashStatus(ufm_status, UFM_STATUS_PIT_L2_PASSED_BIT_MASK);
		LOG_INF("PIT L2 PCH hash verify successful");
	} else {
		ufm_write(PROVISION_UFM, PIT_PCH_FW_HASH, sha_buffer, SHA384_DIGEST_LENGTH);
		SetUfmFlashStatus(ufm_status, UFM_STATUS_PIT_HASH_STORED_BIT_MASK);
		SetPlatformState(PIT_L2_FW_SEALED);
		LOG_INF("PCH firmware sealed");
		// All firmware sealed, lockdown
		return Lockdown;
	}
	return Success;
}
#endif

int intel_pfr_manifest_verify(struct manifest *manifest, struct hash_engine *hash,
			      struct signature_verification *verification, uint8_t *hash_out, uint32_t hash_length)
{
	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) manifest;
	uint32_t pc_type = 0;
	int status = 0;

	ARG_UNUSED(hash);
	ARG_UNUSED(verification);
	ARG_UNUSED(hash_out);
	ARG_UNUSED(hash_length);

	init_pfr_authentication(pfr_manifest->pfr_authentication);

	status = pfr_spi_read(pfr_manifest->image_type, pfr_manifest->address + BLOCK0_PCTYPE_ADDRESS, sizeof(pc_type), (uint8_t *)&pc_type);
	if (status != Success) {
		LOG_INF("pfr_manifest->image_type=%d address=0x%08x", pfr_manifest->image_type, pfr_manifest->address + BLOCK0_PCTYPE_ADDRESS);
		LOG_ERR("Flash read PC type failed");
		return Failure;
	}

	LOG_INF("pfr_manifest->image_type=%d address=0x%08x pc_type=%x", pfr_manifest->image_type, pfr_manifest->address + BLOCK0_PCTYPE_ADDRESS, pc_type);

	// Validate PC type
	status = pfr_manifest->pfr_authentication->validate_pctye(pfr_manifest, pc_type);
	if (status != Success)
		return Failure;

	// Validate Key cancellation
	status = pfr_manifest->pfr_authentication->validate_kc(pfr_manifest);
	if (status != Success)
		return Failure;

	// Block1 Verification
	status = pfr_manifest->pfr_authentication->block1_verify(pfr_manifest);
	if (status != Success)
		return status;

	// Block0 Verification
	status = pfr_manifest->pfr_authentication->block0_verify(pfr_manifest);
	if (status != Success)
		return Failure;

	return status;
}

int validate_pc_type(struct pfr_manifest *manifest, uint32_t pc_type)
{
	if (pc_type != manifest->pc_type && manifest->pc_type != PFR_PCH_SEAMLESS_UPDATE_CAPSULE) {
		LOG_ERR("Validation PC Type failed, block0_read_pc_type = %x, manifest_pc_type = %x",
				pc_type, manifest->pc_type);
		return Failure;
	}

	return Success;
}

// Block 1 Block 0 Entry
int intel_block1_block0_entry_verify(struct pfr_manifest *manifest)
{
	uint8_t buffer[sizeof(BLOCK0ENTRY)] = { 0 };
	uint8_t block0_signature_curve_magic = 0;
	uint32_t block0_entry_address = 0;
	BLOCK0ENTRY *block1_buffer;
	uint32_t hash_length = 0;
	int status = 0;

	// Adjusting Block Address in case of KeyCancellation
	if (manifest->kc_flag == 0)
		block0_entry_address = manifest->address + sizeof(PFR_AUTHENTICATION_BLOCK0) + CSK_START_ADDRESS + sizeof(CSKENTRY);
	else
		block0_entry_address = manifest->address + sizeof(PFR_AUTHENTICATION_BLOCK0) + CSK_START_ADDRESS;

	status = pfr_spi_read(manifest->image_type, block0_entry_address, sizeof(BLOCK0ENTRY), buffer);
	if (status != Success) {
		LOG_ERR("Block1 Block0 Entry: Flash read data failed");
		return Failure;
	}

	block1_buffer = (BLOCK0ENTRY *)&buffer;

	if (block1_buffer->TagBlock0Entry != BLOCK1_BLOCK0ENTRYTAG) {
		LOG_ERR("Block1 Block0 Entry: Magic/Tag not matched, %x", block1_buffer->TagBlock0Entry);
		return Failure;
	}

	if (block1_buffer->Block0SignatureMagic == SIGNATURE_SECP256_TAG) {
		block0_signature_curve_magic = secp256r1;
		manifest->pfr_hash->type = HASH_TYPE_SHA256;
		hash_length = SHA256_HASH_LENGTH;
	} else if (block1_buffer->Block0SignatureMagic == SIGNATURE_SECP384_TAG) {
		block0_signature_curve_magic = secp384r1;
		manifest->pfr_hash->type = HASH_TYPE_SHA384;
		hash_length = SHA384_HASH_LENGTH;
	} else {
		LOG_ERR("Block1 Block0 Entry: Unsupported signature magic, %x", block1_buffer->Block0SignatureMagic);
		return Failure;
	}

	// Key curve and Block 0 signature curve type should match
	if (block0_signature_curve_magic != manifest->hash_curve) {
		LOG_ERR("Block1 Block0 Entry: key curve magic and Block0 signature curve magic not matched, key_curve = %x, sig_curve = %x",
			manifest->hash_curve, block0_signature_curve_magic);
		return Failure;
	}

	manifest->flash->state->device_id[0] = manifest->image_type;
	manifest->pfr_hash->start_address = manifest->address;
	manifest->pfr_hash->length = sizeof(PFR_AUTHENTICATION_BLOCK0);

	status = manifest->base->get_hash((struct manifest *)manifest, manifest->hash, manifest->pfr_hash->hash_out, hash_length);
	if (status != Success) {
		LOG_ERR("Block1 Block0 Entry: Get hash failed");
		return Failure;
	}

	memcpy(manifest->verification->pubkey->signature_r, block1_buffer->Block0SignatureR, hash_length);
	memcpy(manifest->verification->pubkey->signature_s, block1_buffer->Block0SignatureS, hash_length);

	status = manifest->verification->base->verify_signature((struct signature_verification *)manifest, manifest->pfr_hash->hash_out, hash_length, NULL, (2 * hash_length));
	if (status != Success) {
		LOG_ERR("Block1 Block0 Entry: Verify signature failed");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->x, hash_length, "ECDSA X:");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->y, hash_length, "ECDSA Y:");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->signature_r, hash_length, "ECDSA R:");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->signature_s, hash_length, "ECDSA S:");
		LOG_INF("Hash Info: address = %x, length = %x", manifest->pfr_hash->start_address, manifest->pfr_hash->length);
		LOG_HEXDUMP_INF(manifest->pfr_hash->hash_out, hash_length, "Calculated D:");
		return Failure;
	}

	return Success;
}

// Block 1 CSK Entry
int intel_block1_csk_block0_entry_verify(struct pfr_manifest *manifest)
{
	uint32_t block1_address = manifest->address + sizeof(PFR_AUTHENTICATION_BLOCK0);
	uint8_t buffer[sizeof(CSKENTRY)] = { 0 };
	uint8_t csk_sign_curve_magic = 0;
	uint8_t csk_key_curve_type = 0;
	uint32_t sign_bit_verify = 0;
	CSKENTRY *block1_buffer;
	uint32_t hash_length = 0;
	int status = 0;
	int i;

	status = pfr_spi_read(manifest->image_type, block1_address + CSK_START_ADDRESS, sizeof(CSKENTRY), buffer);
	if (status != Success) {
		LOG_ERR("Block1 CSK Entry: Flash read data failed");
		return Failure;
	}

	block1_buffer = (CSKENTRY *)&buffer;

	// validate CSK entry magic tag
	if (block1_buffer->CskEntryInitial.Tag != BLOCK1CSKTAG) {
		LOG_ERR("Block1 CSK Entry: Magic/Tag not matched, %x", block1_buffer->CskEntryInitial.Tag);
		return Failure;
	}

	if (block1_buffer->CskEntryInitial.PubCurveMagic == PUBLIC_SECP256_TAG) {
		csk_key_curve_type = secp256r1;
	} else if (block1_buffer->CskEntryInitial.PubCurveMagic == PUBLIC_SECP384_TAG) {
		csk_key_curve_type = secp384r1;
	} else {
		LOG_ERR("Block1 CSK Entry: Unsupported curve magic, %x", block1_buffer->CskEntryInitial.PubCurveMagic);
		return Failure;
	}

	// Root key curve and CSK curve should match
	if (csk_key_curve_type != manifest->hash_curve) {
		LOG_ERR("Block1 CSK Entry: Root key curve magic and CSK curve magic not matched, root_curve = %x, csk_curve = %x",
			manifest->hash_curve, csk_key_curve_type);
		return Failure;
	}

	if (block1_buffer->CskSignatureMagic == SIGNATURE_SECP256_TAG) {
		csk_sign_curve_magic = secp256r1;
		manifest->pfr_hash->type = HASH_TYPE_SHA256;
		hash_length = SHA256_DIGEST_LENGTH;
	} else if (block1_buffer->CskSignatureMagic == SIGNATURE_SECP384_TAG) {
		csk_sign_curve_magic = secp384r1;
		manifest->pfr_hash->type = HASH_TYPE_SHA384;
		hash_length = SHA384_DIGEST_LENGTH;
	} else {
		LOG_ERR("Block1 CSK Entry: Unsupported signature magic, %x", block1_buffer->CskSignatureMagic);
		return Failure;
	}

	if (csk_key_curve_type != csk_sign_curve_magic) {
		LOG_ERR("Block1 CSK Entry: curve magic type and signature magic type not matched, key_curve = %x, sig_curve = %x",
			csk_key_curve_type, csk_sign_curve_magic);
		return Failure;
	}

	// Key permission
	if (manifest->pc_type == PFR_BMC_UPDATE_CAPSULE) {// Bmc update
		sign_bit_verify = SIGN_BMC_UPDATE_BIT3;
	} else if (manifest->pc_type == PFR_PCH_UPDATE_CAPSULE) {       // PCH update
		sign_bit_verify = SIGN_PCH_UPDATE_BIT1;
	} else if (manifest->pc_type == PFR_BMC_PFM) {                  // BMC PFM
		sign_bit_verify = SIGN_BMC_PFM_BIT2;
	} else if (manifest->pc_type == PFR_PCH_PFM) {                  // PCH PFM
		sign_bit_verify = SIGN_PCH_PFM_BIT0;
	} else if (manifest->pc_type == PFR_CPLD_UPDATE_CAPSULE
		   || manifest->pc_type == PFR_CPLD_UPDATE_CAPSULE_DECOMMISSON) {
		// ROT update
		sign_bit_verify = SIGN_CPLD_UPDATE_BIT4;
	}
#if defined(CONFIG_SEAMLESS_UPDATE)
	else if (manifest->pc_type == PFR_PCH_SEAMLESS_UPDATE_CAPSULE) {
		sign_bit_verify = SIGN_PCH_UPDATE_BIT1;
	}
#endif
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (manifest->pc_type == PFR_AFM) {
		sign_bit_verify = SIGN_AFM_UPDATE_BIT5;
	}
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	else if (manifest->pc_type == PFR_INTEL_CPLD_UPDATE_CAPSULE) {
		sign_bit_verify = SIGN_INTEL_CPLD_UPDATE_BIT6;
	}
#endif

	if (!(block1_buffer->CskEntryInitial.KeyPermission & sign_bit_verify)) {
		LOG_ERR("Block1 CSK Entry: CSK key permission denied..., %x",
				block1_buffer->CskEntryInitial.KeyPermission);
		return Failure;
	}

	// Check for the 0s in the reserved field
	for (i = 0; i < BLOCK1_CSK_ENTRY_RESERVED_SIZE; i++) {
		if (block1_buffer->CskEntryInitial.Reserved[i] != 0) {
			LOG_ERR("Block1 CSK Entry: reserved data failed");
			return Failure;
		}
	}

	// Get hash
	if (csk_key_curve_type == secp256r1) {
		manifest->hash->start_sha256(manifest->hash);
		manifest->hash->calculate_sha256(manifest->hash, (uint8_t *)&block1_buffer->CskEntryInitial.PubCurveMagic,
						 CSK_ENTRY_PC_SIZE, manifest->pfr_hash->hash_out, SHA256_HASH_LENGTH);
	} else if (csk_key_curve_type == secp384r1) {
		manifest->hash->start_sha384(manifest->hash);
		manifest->hash->calculate_sha384(manifest->hash, (uint8_t *)&block1_buffer->CskEntryInitial.PubCurveMagic,
						 CSK_ENTRY_PC_SIZE, manifest->pfr_hash->hash_out, SHA384_HASH_LENGTH);
	} else	{
		LOG_ERR("Block1 CSK Entry: Get hash failed, Unsupported curve magic, %x", csk_key_curve_type);
		return Failure;
	}

	memcpy(manifest->verification->pubkey->signature_r, block1_buffer->CskSignatureR, hash_length);
	memcpy(manifest->verification->pubkey->signature_s, block1_buffer->CskSignatureS, hash_length);

	status = manifest->verification->base->verify_signature((struct signature_verification *)manifest, manifest->pfr_hash->hash_out, hash_length, NULL, (2 * hash_length));
	if (status != Success) {
		LOG_ERR("Block1 CSK Entry: Verify signature failed");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->x, hash_length, "ECDSA X:");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->y, hash_length, "ECDSA Y:");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->signature_r, hash_length, "ECDSA R:");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->signature_s, hash_length, "ECDSA S:");
		LOG_INF("Hash Info: address = %x, length = %x", manifest->pfr_hash->start_address, manifest->pfr_hash->length);
		LOG_HEXDUMP_INF(manifest->pfr_hash->hash_out, hash_length, "Calculated D:");
		return Failure;
	}

	// Update csk key to validate b0 entry
	memcpy(manifest->verification->pubkey->x, block1_buffer->CskEntryInitial.PubKeyX, hash_length);
	memcpy(manifest->verification->pubkey->y, block1_buffer->CskEntryInitial.PubKeyY, hash_length);

	status = manifest->pfr_authentication->block1_block0_entry_verify(manifest);
	if (status != Success)
		return Failure;

	return Success;
}

// Block 1
int intel_block1_verify(struct pfr_manifest *manifest)
{
	int status = 0;
	PFR_AUTHENTICATION_BLOCK1 *block1_buffer;
	uint8_t buffer[256] = { 0 };

	status = pfr_spi_read(manifest->image_type, manifest->address +
			sizeof(PFR_AUTHENTICATION_BLOCK0),
			sizeof(block1_buffer->TagBlock1) + sizeof(block1_buffer->ReservedBlock1) +
			sizeof(block1_buffer->RootEntry), buffer);

	if (status != Success) {
		LOG_ERR("Block1: Flash read data failed");
		return Failure;
	}

	block1_buffer = (PFR_AUTHENTICATION_BLOCK1 *)buffer;

	if (block1_buffer->TagBlock1 != BLOCK1TAG) {
		LOG_ERR("Block1: Tag Not Found, %x", block1_buffer->TagBlock1);
		return Failure;
	}

	status = verify_root_key_entry(manifest, block1_buffer);
	if (status != Success) {
		LOG_ERR("Block1 Root Entry: Validation failed");
		return Failure;
	}

	LOG_INF("Block1 Root Entry: Validation success");

	// Update root key to validate csk entry if csk entry exist or b0 entry if csk entry does not exist
	memcpy(manifest->verification->pubkey->x, block1_buffer->RootEntry.PubKeyX, sizeof(block1_buffer->RootEntry.PubKeyX));
	memcpy(manifest->verification->pubkey->y, block1_buffer->RootEntry.PubKeyY, sizeof(block1_buffer->RootEntry.PubKeyY));

	if (manifest->kc_flag == 0) {
		// CSK and Block 0 entry verification
		status = manifest->pfr_authentication->block1_csk_block0_entry_verify(manifest);
		if (status != Success) {
			LOG_ERR("Block1 CSK and Block0 Entry: Validation failed");
			return Failure;
		}
		LOG_INF("Block1 CSK and Block0 Entry: Validation success");
	} else  {
		status = manifest->pfr_authentication->block1_block0_entry_verify(manifest);
		if (status != Success) {
			LOG_ERR("Block1 Block0 Entry: Validation failed");
			return Failure;
		}
		LOG_INF("Block1 Block0 Entry: Validation success");
	}

	return Success;
}

// BLOCK 0
int intel_block0_verify(struct pfr_manifest *manifest)
{
	uint8_t buffer[sizeof(PFR_AUTHENTICATION_BLOCK0)] = { 0 };
	uint8_t sha_buffer[SHA384_DIGEST_LENGTH] = { 0 };
	PFR_AUTHENTICATION_BLOCK0 *block0_buffer;
	uint32_t hash_length = 0;
	uint8_t *ptr_sha;
	int status = 0;
	int i;

	status = pfr_spi_read(manifest->image_type, manifest->address, sizeof(PFR_AUTHENTICATION_BLOCK0), buffer);
	if (status != Success) {
		LOG_ERR("Block0: Flash read data failed");
		return Failure;
	}

	block0_buffer = (PFR_AUTHENTICATION_BLOCK0 *)buffer;

	if (block0_buffer->Block0Tag != BLOCK0TAG) {
		LOG_ERR("Block0: Tag Not Found, %x", block0_buffer->Block0Tag);
		return Failure;
	}

	if ((block0_buffer->PcLength < 128) || (block0_buffer->PcLength % 128 != 0)) {
		LOG_ERR("Block0: PC length failed, %x", block0_buffer->PcLength);
		return Failure;
	}

	// Both key cancellation certificate and decommission capsule have the same fixed size of 128 bytes.
	if (block0_buffer->PcType & PFR_CPLD_UPDATE_CAPSULE_DECOMMISSON) {
		if (block0_buffer->PcLength != KCH_CAN_CERT_OR_DECOMM_CAP_PC_SIZE) {
			LOG_ERR("Block0: Invalid decommission capsule PC length, %x", block0_buffer->PcLength);
			return Failure;
		}
	}

	if (block0_buffer->PcType & KEY_CANCELLATION_CAPSULE) {
		if (block0_buffer->PcLength != KCH_CAN_CERT_OR_DECOMM_CAP_PC_SIZE) {
			LOG_ERR("Block0: Invalid key cancellation capsule PC length, %x", block0_buffer->PcLength);
			return Failure;
		}
	}

	// Check for the 0s in the reserved field
	for (i = 0; i < BLOCK0_SECOND_RESERVED_SIZE; i++) {
		if (block0_buffer->Reserved2[i] != 0) {
			LOG_ERR("Block0: Invalid reserved2 data");
			return Failure;
		}
	}

	// Protected content length
	manifest->flash->state->device_id[0] = manifest->image_type;
	manifest->pc_length = block0_buffer->PcLength;
	manifest->pfr_hash->start_address = manifest->address + PFM_SIG_BLOCK_SIZE;
	manifest->pfr_hash->length = block0_buffer->PcLength;

	if (manifest->hash_curve == secp256r1) {
		manifest->pfr_hash->type = HASH_TYPE_SHA256;
		hash_length = SHA256_DIGEST_LENGTH;
		ptr_sha = block0_buffer->Sha256Pc;
	} else if (manifest->hash_curve == secp384r1) {
		manifest->pfr_hash->type = HASH_TYPE_SHA384;
		hash_length = SHA384_DIGEST_LENGTH;
		ptr_sha = block0_buffer->Sha384Pc;
	} else  {
		LOG_ERR("Block0: Unsupported hash curve, %x", manifest->hash_curve);
		return Failure;
	}

	status = manifest->base->get_hash((struct manifest *)manifest, manifest->hash, sha_buffer, hash_length);
	if (status != Success) {
		LOG_ERR("Block0: Get hash failed");
		return Failure;
	}

	LOG_INF("Block0: Verification PC, address = %x, length = %x", manifest->pfr_hash->start_address, manifest->pfr_hash->length);
	if (memcmp(ptr_sha, sha_buffer, hash_length)) {
		LOG_ERR("Block0: Verification PC failed");
		LOG_HEXDUMP_INF(sha_buffer, hash_length, "Calculated hash:");
		LOG_HEXDUMP_INF(ptr_sha, hash_length, "Expected hash:");
		return Failure;
	}

	LOG_INF("Block0: Hash Matched");
	return Success;
}

#if defined(CONFIG_SEAMLESS_UPDATE)
uint32_t find_fvm_addr(struct pfr_manifest *manifest, uint16_t fv_type)
{
	uint32_t image_type = manifest->image_type;
	uint32_t act_pfm_offset = manifest->active_pfm_addr + PFM_SIG_BLOCK_SIZE;
	uint32_t act_pfm_body_offset = act_pfm_offset + sizeof(PFM_STRUCTURE);
	PFM_STRUCTURE act_pfm_header;
	uint32_t act_pfm_end_addr;

	PFM_SPI_DEFINITION spi_def;
	PFM_FVM_ADDRESS_DEFINITION *fvm_def;


	if (pfr_spi_read(image_type, act_pfm_offset, sizeof(PFM_STRUCTURE),
				(uint8_t *)&act_pfm_header)) {
		LOG_ERR("Failed to read active PFM");
		return Failure;
	}

	act_pfm_end_addr = act_pfm_body_offset + act_pfm_header.Length - sizeof(PFM_STRUCTURE);

	while (act_pfm_body_offset < act_pfm_end_addr) {
		pfr_spi_read(image_type, act_pfm_body_offset, sizeof(PFM_SPI_DEFINITION),
				(uint8_t *)&spi_def);
		if (spi_def.PFMDefinitionType == SMBUS_RULE) {
			act_pfm_body_offset += sizeof(PFM_SMBUS_RULE);
		} else if (spi_def.PFMDefinitionType == SPI_REGION) {
			if (spi_def.HashAlgorithmInfo.SHA256HashPresent ||
			    spi_def.HashAlgorithmInfo.SHA384HashPresent) {
				act_pfm_body_offset += sizeof(PFM_SPI_DEFINITION);
				act_pfm_body_offset += (manifest->hash_curve == secp384r1) ?
					SHA384_SIZE : SHA256_SIZE;
			} else {
				act_pfm_body_offset += SPI_REGION_DEF_MIN_SIZE;
			}
		} else if (spi_def.PFMDefinitionType == FVM_ADDR_DEF) {
			fvm_def = (PFM_FVM_ADDRESS_DEFINITION *)&spi_def;
			if (fvm_def->FVType == fv_type) {
				manifest->target_fvm_addr = fvm_def->FVMAddress;
				return fvm_def->FVMAddress;
			}
			act_pfm_body_offset += sizeof(PFM_FVM_ADDRESS_DEFINITION);
		} else if (spi_def.PFMDefinitionType == FVM_CAP) {
			act_pfm_body_offset += sizeof(FVM_CAPABLITIES);
		} else {
			break;
		}
	}

	return 0;
}

int intel_fvm_verify(struct pfr_manifest *manifest)
{
	uint32_t image_type = manifest->image_type;
	uint32_t read_address = manifest->address;
	uint32_t signed_fvm_offset = read_address + PFM_SIG_BLOCK_SIZE;
	uint32_t cap_fvm_offset = signed_fvm_offset + PFM_SIG_BLOCK_SIZE;
	uint32_t act_fvm_offset;
	uint32_t target_fvm_addr;

	FVM_STRUCTURE cap_fvm_header;
	FVM_STRUCTURE act_fvm_header;

	if (pfr_spi_read(image_type, cap_fvm_offset, sizeof(FVM_STRUCTURE),
				(uint8_t *)&cap_fvm_header)) {
		LOG_ERR("Failed to read capsule FVM");
		return Failure;
	}


	target_fvm_addr = find_fvm_addr(manifest, cap_fvm_header.FvType);

	if (target_fvm_addr == 0) {
		LogUpdateFailure(SEAMLESS_UNKNOWN_FV_TYPE, 1);
		LOG_ERR("Failed to find FVM address in active PFM");
		return Failure;
	}

	act_fvm_offset = target_fvm_addr + PFM_SIG_BLOCK_SIZE;


	if (pfr_spi_read(image_type, act_fvm_offset, sizeof(FVM_STRUCTURE),
				(uint8_t *)&act_fvm_header)) {
		LOG_ERR("Failed to read active FVM");
		return Failure;
	}

	if (act_fvm_header.SVN != cap_fvm_header.SVN) {
		LOG_ERR("Capsule FVM SVN doesn't match the active FVM SVN");
		return Failure;
	} else if (act_fvm_header.Length != cap_fvm_header.Length) {
		LOG_ERR("Capsule FVM length doesn't match the active FVM length");
		return Failure;
	}

	return Success;
}

int intel_fvms_verify(struct pfr_manifest *manifest)
{
	uint32_t image_type = manifest->image_type;
	uint32_t read_address = manifest->address;
	uint32_t state = manifest->state;
	uint32_t signed_pfm_offset = read_address + PFM_SIG_BLOCK_SIZE;
	uint32_t cap_pfm_offset = signed_pfm_offset + PFM_SIG_BLOCK_SIZE;
	uint32_t cap_pfm_body_offset = cap_pfm_offset + sizeof(PFM_STRUCTURE);
	uint32_t cap_pfm_body_end_addr;
	uint32_t fvm_addr;
	PFM_STRUCTURE pfm_header;
	PFM_SPI_DEFINITION spi_def;
	PFM_FVM_ADDRESS_DEFINITION *fvm_def;

	if (pfr_spi_read(image_type, cap_pfm_offset, sizeof(PFM_STRUCTURE), (uint8_t *)&pfm_header))
		return Failure;

	if (pfm_header.PfmTag != PFMTAG) {
		LOG_ERR("FVM verification failed");
		LOG_HEXDUMP_INF(&pfm_header, sizeof(PFM_STRUCTURE), "PFM Header:");
		return Failure;
	}

	cap_pfm_body_end_addr = cap_pfm_body_offset + pfm_header.Length - sizeof(PFM_STRUCTURE);

	while (cap_pfm_body_offset < cap_pfm_body_end_addr) {
		pfr_spi_read(image_type, cap_pfm_body_offset, sizeof(PFM_SPI_DEFINITION),
				(uint8_t *)&spi_def);
		if (spi_def.PFMDefinitionType == SMBUS_RULE) {
			cap_pfm_body_offset += sizeof(PFM_SMBUS_RULE);
		} else if (spi_def.PFMDefinitionType == SPI_REGION) {
			if (spi_def.HashAlgorithmInfo.SHA256HashPresent ||
			    spi_def.HashAlgorithmInfo.SHA384HashPresent) {
				cap_pfm_body_offset += sizeof(PFM_SPI_DEFINITION);
				cap_pfm_body_offset += (manifest->hash_curve == secp384r1) ?
					SHA384_SIZE : SHA256_SIZE;
			} else {
				cap_pfm_body_offset += SPI_REGION_DEF_MIN_SIZE;
			}
		} else if (spi_def.PFMDefinitionType == FVM_ADDR_DEF) {
			// Verify FVMs signature.
			LOG_INF("Verifying Capsule FVMs... ");
			manifest->state = FIRMWARE_UPDATE;
			fvm_def = (PFM_FVM_ADDRESS_DEFINITION *)&spi_def;
			fvm_addr = fvm_def->FVMAddress - manifest->active_pfm_addr +
				+ read_address + PFM_SIG_BLOCK_SIZE;

			manifest->address = fvm_addr;
			if (manifest->base->verify((struct manifest *)manifest,
						NULL, NULL, NULL, 0)) {
				LOG_ERR("Verify FVM failed");
				return Failure;
			}
			LOG_INF("FVM region verify successful");
			cap_pfm_body_offset += sizeof(PFM_FVM_ADDRESS_DEFINITION);
		} else if (spi_def.PFMDefinitionType == FVM_CAP) {
			cap_pfm_body_offset += sizeof(FVM_CAPABLITIES);
		} else {
			break;
		}
	}

	// Restore manifest settings.
	manifest->state = state;
	manifest->address = read_address;

	return Success;
}
#endif

#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
int intel_cfms_verify(struct pfr_manifest *manifest)
{
	uint32_t image_type = manifest->image_type;
	uint32_t cap_base_address = manifest->address;
	uint32_t pfm_sig_offset = cap_base_address + PFM_SIG_BLOCK_SIZE;
	uint32_t pfm_offset = pfm_sig_offset + PFM_SIG_BLOCK_SIZE;
	uint32_t pfm_body_offset = pfm_offset + sizeof(CPLD_PFM_STRUCTURE);
	uint32_t pfm_body_end_addr;
	uint32_t cfm_offset;
	uint8_t major_ver, minor_ver;
	CPLD_PFM_STRUCTURE pfm_header;
	CPLD_ADDR_DEF_STRUCTURE cpld_addr_def;
	CFM_STRUCTURE cfm_header;

	if (pfr_spi_read(image_type, pfm_offset, sizeof(CPLD_PFM_STRUCTURE),
				(uint8_t *)&pfm_header)) {
		return Failure;
	}

	if (pfm_header.PfmTag != PFMTAG) {
		LOG_ERR("CPLD PFM verification failed");
		LOG_HEXDUMP_INF(&pfm_header, sizeof(PFM_STRUCTURE), "CPLD PFM Header:");
		return Failure;
	}

#if 0
	// TODO: define the online cpld update svn policy.
	status = svn_policy_verify(SVN_POLICY_FOR_ONLINE_CPLD_FW_UPDATE, pfm_header.SVN);
	if (status != Success) {
		LogUpdateFailure(UPD_CAPSULE_INVALID_SVN, 1);
		LOG_ERR("Anti rollback");
		return Failure;
	}
#endif
	major_ver = (uint8_t)(pfm_header.PfmRevision & 0xFF);
	minor_ver = (uint8_t)(pfm_header.PfmRevision >> 8);
	SetIntelCpldActiveMajorVersion(major_ver);
	SetIntelCpldActiveMinorVersion(minor_ver);

	pfm_body_end_addr = pfm_body_offset + pfm_header.Length - sizeof(CPLD_PFM_STRUCTURE);
	while(pfm_body_offset < pfm_body_end_addr) {
		pfr_spi_read(image_type, pfm_body_offset, sizeof(CPLD_ADDR_DEF_STRUCTURE),
				(uint8_t *)&cpld_addr_def);
		if (cpld_addr_def.FmDef == CFM_SPI_REGION) {
			if (cpld_addr_def.FwType == CPU_CPLD)
				LOG_INF("Verifying CPU CPLD Capsule");
			else if (cpld_addr_def.FwType == SCM_CPLD)
				LOG_INF("Verifying SCM CPLD Capsule");
			else if (cpld_addr_def.FwType == DEBUG_CPLD)
				LOG_INF("Verifying Debug CPLD Capsule");
			else {
				LOG_ERR("Unknown CPLD firmware type");
				return Failure;
			}
			// Verify signature of indiviual cpld firmware image.
			cfm_offset = cap_base_address + cpld_addr_def.ImageStartAddr;
			manifest->address = cfm_offset;
			manifest->pc_type = PFR_INTEL_CPLD_UPDATE_CAPSULE;
			if (manifest->base->verify((struct manifest *)manifest,
						NULL, NULL, NULL, 0)){
				LOG_ERR("Verify CPLD firmware signature failed");
				return Failure;
			}
			cfm_offset += PFM_SIG_BLOCK_SIZE;
			pfr_spi_read(image_type, cfm_offset, sizeof(CFM_STRUCTURE),
					(uint8_t *)&cfm_header);
			if (cpld_addr_def.FwType != cfm_header.FwType) {
				LOG_ERR("Incorrect capsule format");
				return Failure;
			}
			cfm_offset += sizeof(CFM_STRUCTURE);
			manifest->intel_cpld_addr[cpld_addr_def.FwType] = cfm_offset;
			manifest->intel_cpld_img_size[cpld_addr_def.FwType] = cfm_header.Length;
		} else {
			break;
		}
		pfm_body_offset += sizeof(CPLD_ADDR_DEF_STRUCTURE);
	}

	manifest->address = cap_base_address;

	return Success;
}

int intel_online_update_capsule_verify(struct pfr_manifest *manifest)
{
	int status = 0;
	uint32_t cap_addr = manifest->address;

	LOG_INF("Verifying Intel CPLD capsule");

	manifest->pc_type = PFR_INTEL_CPLD_UPDATE_CAPSULE;
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Capsule signature verification failed");
		LogErrorCodes(INTEL_CPLD_UPDATE_FAIL, INTEL_CPLD_IMAGE_AUTH_FAIL);
		return Failure;
	}

	manifest->address += PFM_SIG_BLOCK_SIZE;
	LOG_INF("Verifying Intel CPLD PFM, address=%08x", manifest->address);
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("PFM signature verification failed");
		LogErrorCodes(INTEL_CPLD_UPDATE_FAIL, INTEL_CPLD_IMAGE_AUTH_FAIL);
		return Failure;
	}

	manifest->address = cap_addr;
	status = manifest->pfr_authentication->cfms_verify(manifest);
	if (status != Success) {
		LOG_ERR("CFM signature verification failed");
		LogErrorCodes(INTEL_CPLD_UPDATE_FAIL, INTEL_CPLD_IMAGE_TOCTOU);
		return Failure;
	}

	return Success;
}

#endif

void init_pfr_authentication(struct pfr_authentication *pfr_authentication)
{
	pfr_authentication->validate_pctye = validate_pc_type;
	pfr_authentication->validate_kc = validate_key_cancellation_flag;
	pfr_authentication->block1_verify = intel_block1_verify;
	pfr_authentication->block1_csk_block0_entry_verify = intel_block1_csk_block0_entry_verify;
	pfr_authentication->block1_block0_entry_verify = intel_block1_block0_entry_verify;
	pfr_authentication->block0_verify = intel_block0_verify;
#if defined(CONFIG_SEAMLESS_UPDATE)
	pfr_authentication->fvms_verify = intel_fvms_verify;
	pfr_authentication->fvm_verify = intel_fvm_verify;
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	pfr_authentication->cfms_verify = intel_cfms_verify;
	pfr_authentication->online_update_cap_verify = intel_online_update_capsule_verify;
#endif
}

/**
 * Verify if the manifest is valid.
 *
 * @param manifest The manifest to validate.
 * @param hash The hash engine to use for validation.
 * @param verification Verification instance to use to verify the manifest signature.
 * @param hash_out Optional output buffer for manifest hash calculated during verification.  A
 * validation error does not necessarily mean the hash output is not valid.  If the manifest
 * hash was not calculated, this buffer will be cleared.  Set this to null to not return the
 * manifest hash.
 * @param hash_length Length of the hash output buffer.
 *
 * @return 0 if the manifest is valid or an error code.
 */
int manifest_verify(struct manifest *manifest, struct hash_engine *hash,
		    struct signature_verification *verification, uint8_t *hash_out,
		    size_t hash_length)
{
	return intel_pfr_manifest_verify(manifest, hash, verification, hash_out, hash_length);
}

