/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <stdint.h>
#include "AspeedStateMachine/common_smc.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_ufm.h"
#include "intel_pfr_definitions.h"
#include "pfr/pfr_util.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_verification.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int verify_root_key_hash(struct pfr_manifest *manifest, uint8_t *pubkey_x, uint8_t *pubkey_y)
{
	uint8_t root_public_key[SHA384_DIGEST_LENGTH * 2] = { 0 };
	uint8_t ufm_sha_data[SHA384_DIGEST_LENGTH] = { 0 };
	uint8_t sha_buffer[SHA384_DIGEST_LENGTH] = { 0 };
	uint8_t digest_length = 0;
	uint8_t i = 0;
	int status;

	if (manifest->hash_curve == secp256r1)
		digest_length = SHA256_DIGEST_LENGTH;
	else if (manifest->hash_curve == secp384r1)
		digest_length = SHA384_DIGEST_LENGTH;
	else {
		LOG_ERR("Block1 Root Entry: Unsupported hash curve, %x", manifest->hash_curve);
		return Failure;
	}

	// Changing little endianess
	for (i = 0; i < digest_length; i++) {
		root_public_key[i] = pubkey_x[digest_length - 1 - i];
		root_public_key[i + digest_length] = pubkey_y[digest_length - 1 - i];
	}

	if (manifest->hash_curve == secp256r1) {
		manifest->hash->start_sha256(manifest->hash);
		manifest->hash->calculate_sha256(manifest->hash, root_public_key, digest_length * 2, sha_buffer, digest_length);
	} else if (manifest->hash_curve == secp384r1) {
		manifest->hash->start_sha384(manifest->hash);
		manifest->hash->calculate_sha384(manifest->hash, root_public_key, digest_length * 2, sha_buffer, digest_length);
	} else {
		LOG_ERR("Block1 Root Entry: Get hash failed, Unsupported hash curve, %x", manifest->hash_curve);
		return Failure;
	}

	// Read hash from provisoned UFM 0
	status = ufm_read(PROVISION_UFM, ROOT_KEY_HASH, ufm_sha_data, digest_length);
	if (status != Success) {
		LOG_ERR("Block1 Root Entry: Read hash from UFM failed");
		return status;
	}

	if (memcmp(sha_buffer, ufm_sha_data, digest_length)) {
		LOG_ERR("Block1 Root Entry: hash not matched");
		LOG_HEXDUMP_INF(root_public_key, digest_length * 2, "Public key:");
		LOG_HEXDUMP_INF(sha_buffer, digest_length, "Calculated hash:");
		LOG_HEXDUMP_INF(ufm_sha_data, digest_length, "Expected hash:");
		return Failure;
	}

	return Success;
}

int verify_root_key_hash_lms(struct pfr_manifest *manifest, uint8_t *lms_verify_pubkey, int lms_verify_pubkey_len)
{
	uint8_t digest_length = 0;
	uint8_t sha_buffer[SHA384_DIGEST_LENGTH] = { 0 };
	uint8_t ufm_sha_data[SHA384_DIGEST_LENGTH] = { 0 };
	int status;

	if (manifest->hash_curve == hash_sign_algo384)
		digest_length = SHA384_DIGEST_LENGTH;
	else if (manifest->hash_curve == hash_sign_algo256)
		digest_length = SHA256_DIGEST_LENGTH;
	else {
		LOG_ERR("Block1 Root Entry: Unsupported hash curve, %x", manifest->hash_curve);
		return Failure;
	}

	if (manifest->hash_curve == hash_sign_algo384) {
		manifest->hash->start_sha384(manifest->hash);
		manifest->hash->calculate_sha384(manifest->hash, lms_verify_pubkey, lms_verify_pubkey_len, sha_buffer, digest_length);
	} else if (manifest->hash_curve == hash_sign_algo256) {
		manifest->hash->start_sha256(manifest->hash);
		manifest->hash->calculate_sha256(manifest->hash, lms_verify_pubkey, lms_verify_pubkey_len, sha_buffer, digest_length);
	} else {
		LOG_ERR("Block1 Root Entry: Get hash failed, Unsupported hash curve, %x", manifest->hash_curve);
		return Failure;
	}

	// Read hash from provisoned UFM 0
	status = ufm_read(PROVISION_UFM, ROOT_KEY_HASH, ufm_sha_data, digest_length);
	if (status != Success) {
		LOG_ERR("Block1 Root Entry: Read hash from UFM failed");
		return status;
	}

	if (memcmp(sha_buffer, ufm_sha_data, digest_length)) {
		LOG_ERR("Block1 Root Entry: hash not matched");
		LOG_HEXDUMP_INF(lms_verify_pubkey, lms_verify_pubkey_len, "Public key:");
		LOG_HEXDUMP_INF(sha_buffer, digest_length, "Calculated hash:");
		LOG_HEXDUMP_INF(ufm_sha_data, digest_length, "Expected hash:");
		return Failure;
	}

	return Success;
}

// Block1 Root Entry
int verify_root_key_entry(struct pfr_manifest *manifest, PFR_AUTHENTICATION_BLOCK1 *block1_buffer)
{
	uint32_t root_key_permission = 0xFFFFFFFF; // -1;
	int status;

	if (block1_buffer->RootEntry.Tag != BLOCK1_ROOTENTRY_TAG) {
		LOG_ERR("Block1 Root Entry: Magic/Tag not matched, %x", block1_buffer->RootEntry.Tag);
		return Failure;
	}

	// Update root key entry curve type to validate csk/b0 entry
	if (block1_buffer->RootEntry.PubCurveMagic == PUBLIC_SECP256_TAG)
		manifest->hash_curve = secp256r1;
	else if (block1_buffer->RootEntry.PubCurveMagic == PUBLIC_SECP384_TAG)
		manifest->hash_curve = secp384r1;
	else if (block1_buffer->RootEntry.PubCurveMagic == PUBLIC_LMS384_TAG)
		manifest->hash_curve = hash_sign_algo384;
	else if (block1_buffer->RootEntry.PubCurveMagic == PUBLIC_LMS256_TAG)
		manifest->hash_curve = hash_sign_algo256;
	else {
		LOG_ERR("Block1 Root Entry: curve magic not support, %x", block1_buffer->RootEntry.PubCurveMagic);
		return Failure;
	}

	// Key permission
	if (block1_buffer->RootEntry.KeyPermission != root_key_permission) {
		LOG_ERR("Block1 Root Entry: key permission not matched, %x", block1_buffer->RootEntry.KeyPermission);
		return Failure;
	}

	// Key Cancellation
	if (block1_buffer->RootEntry.KeyId != root_key_permission) {
		LOG_ERR("Block1 Root Entry: key id not matched, %x", block1_buffer->RootEntry.KeyId);
		return Failure;
	}

	if (manifest->hash_curve == hash_sign_algo384 || manifest->hash_curve == hash_sign_algo256) {
		PFR_AUTHENTICATION_BLOCK1_lms *block1_lms = (PFR_AUTHENTICATION_BLOCK1_lms *)block1_buffer;

		status = verify_root_key_hash_lms(manifest, block1_lms->RootEntry.pubkey, block1_lms->RootEntry.keylen);
		if (status != Success)
			return Failure;
		else
			return Success;
	}

	status = verify_root_key_hash(manifest, block1_buffer->RootEntry.PubKeyX, block1_buffer->RootEntry.PubKeyY);
	if (status != Success)
		return Failure;

	return Success;
}

