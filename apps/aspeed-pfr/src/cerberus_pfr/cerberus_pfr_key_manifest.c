/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>
#include <logging/log.h>
#include <stdint.h>
#include "common/common.h"
#include "flash/flash_aspeed.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "AspeedStateMachine/common_smc.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "pfr/pfr_ufm.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_key_manifest.h"
#include "cerberus_pfr_recovery.h"
#include "cerberus_pfr_verification.h"
#include "crypto/rsa.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

/*
 * The root public key is placed in each key manifest.
 * The contentes of root public key from all key manifests should be identical,
 * because it has only one root public key.
 */
int key_manifest_get_root_key(struct rsa_public_key *public_key, uint32_t keym_address)
{
	struct recovery_header image_header;
	uint32_t root_key_address = 0;
	int status = Success;

	if (!public_key)
		return Failure;

	status = pfr_spi_read(ROT_INTERNAL_KEY, keym_address, sizeof(image_header), (uint8_t *)&image_header);
	if (status != Success) {
		LOG_ERR("Unable to get image header.");
		return Failure;
	}

	status = verify_recovery_header_magic_number(image_header);
	if (status != Success) {
		LOG_HEXDUMP_ERR(&image_header, sizeof(image_header), "image_header:");
		LOG_ERR("Image Header Magic Number is not Matched.");
		return Failure;
	}

	root_key_address = keym_address + image_header.image_length;
	LOG_INF("flash_device_id=%d root_key_address=%08x", ROT_INTERNAL_KEY, root_key_address);
	status = pfr_spi_read(ROT_INTERNAL_KEY, root_key_address, sizeof(struct rsa_public_key), (uint8_t *)public_key);
	if (status != Success) {
		LOG_ERR("Unable to get root key.");
		return Failure;
	}

	if (public_key->mod_length != image_header.sign_length) {
		LOG_ERR("root key length(%d) and signature length (%d) mismatch", public_key->mod_length, image_header.sign_length);
		return Failure;
	}

	return Success;
}

int cerberus_pfr_get_public_key_hash(struct pfr_manifest *manifest, uint32_t address, uint32_t hash_type, uint8_t *hash_buf, uint32_t buf_length)
{
	uint32_t digest_length;
	int status;

	if (!manifest || !hash_buf)
		return Failure;

	if (hash_type == HASH_TYPE_SHA256)
		digest_length = SHA256_DIGEST_LENGTH;
	else if (hash_type == HASH_TYPE_SHA384)
		digest_length = SHA384_DIGEST_LENGTH;
	else {
		LOG_ERR("Root Key: Unsupported hash type(%d)", hash_type);
		return Failure;
	}

	if (digest_length > buf_length) {
		LOG_ERR("Root Key: hash length(%d) exceed buffer length (%d)", digest_length, buf_length);
		return Failure;
	}

	manifest->flash->state->device_id[0] = manifest->image_type;
	manifest->pfr_hash->start_address = address;
	manifest->pfr_hash->length = sizeof(struct rsa_public_key);
	manifest->pfr_hash->type = hash_type;
	status = manifest->base->get_hash((struct manifest *)manifest, manifest->hash, hash_buf, digest_length);
	if (status != Success) {
		LOG_ERR("Get hash failed");
		return Failure;
	}

	return Success;
}

int cerberus_pfr_verify_root_key(struct pfr_manifest *manifest, struct rsa_public_key *public_key)
{
	uint8_t ufm_sha_data[PROVISIONING_ROOT_KEY_HASH_LENGTH];
	uint8_t hash_buffer[PROVISIONING_ROOT_KEY_HASH_LENGTH];
	uint32_t hash_length = PROVISIONING_ROOT_KEY_HASH_LENGTH;
	int status = 0;

	if (!manifest || !public_key)
		return Failure;

	if (PROVISIONING_ROOT_KEY_HASH_TYPE == HASH_TYPE_SHA256) {
		manifest->hash->start_sha256(manifest->hash);
		manifest->hash->calculate_sha256(manifest->hash, (uint8_t *)public_key, sizeof(struct rsa_public_key), hash_buffer, SHA256_HASH_LENGTH);
	} else if (PROVISIONING_ROOT_KEY_HASH_TYPE == HASH_TYPE_SHA384) {
		manifest->hash->start_sha384(manifest->hash);
		manifest->hash->calculate_sha384(manifest->hash, (uint8_t *)public_key, sizeof(struct rsa_public_key), hash_buffer, SHA384_HASH_LENGTH);
	} else {
		LOG_ERR("Unsupported hash type(%d)", PROVISIONING_ROOT_KEY_HASH_TYPE);
		return Failure;
	}

	// Read hash from provisoned UFM 0
	status = ufm_read(PROVISION_UFM, ROOT_KEY_HASH, ufm_sha_data, hash_length);
	if (status != Success) {
		LOG_ERR("Failed to read root key hash from UFM.");
		return status;
	}

	if (memcmp(hash_buffer, ufm_sha_data, hash_length)) {
		LOG_ERR("Verify root key failed.");
		LOG_HEXDUMP_ERR(hash_buffer, hash_length, "Calculated hash:");
		LOG_HEXDUMP_ERR(ufm_sha_data, hash_length, "Expected hash:");
		return Failure;
	}

	return Success;
}

int cerberus_pfr_verify_key_manifest(struct pfr_manifest *manifest, uint8_t keym_id)
{
	uint32_t keym_address;
	uint32_t region_size;

	if (!manifest)
		return Failure;

	if (keym_id > MAX_KEY_MANIFEST_ID) {
		LOG_ERR("Invalid key manifest Id: %d", keym_id);
		return Failure;
	}

	region_size = pfr_spi_get_device_size(ROT_INTERNAL_KEY);
	keym_address = keym_id * KEY_MANIFEST_SIZE;
	if (keym_address >= region_size) {
		LOG_ERR("Key partition size is too small");
		return Failure;
	}

	manifest->address = keym_address;
	manifest->flash_id = ROT_INTERNAL_KEY;
	LOG_INF("Verifying image, manifest->flash_id=%d address=%08x", manifest->flash_id, manifest->address);

	if (cerberus_pfr_verify_image(manifest)) {
		LOG_ERR("KEYM(%d) Image Verify Fail", keym_id);
		return Failure;
	}

	LOG_INF("KEYM(%d) Image Verify Success", keym_id);

	return Success;
}

int cerberus_pfr_verify_all_key_manifests(struct pfr_manifest *manifest)
{
	struct recovery_header image_header;
	uint32_t keym_address;
	uint32_t region_size;
	uint8_t keym_count = 0;
	uint8_t keym_id;

	if (!manifest)
		return Failure;

	region_size = pfr_spi_get_device_size(ROT_INTERNAL_KEY);
	manifest->state = FIRMWARE_VERIFY;
	LOG_INF("Image Type: KEYM");
	LOG_INF("Key Manifest Verification");

	// lookup all key manifests
	for (keym_id = 0; keym_id <= MAX_KEY_MANIFEST_ID; keym_id++) {
		keym_address = keym_id * KEY_MANIFEST_SIZE;
		if (keym_address >= region_size)
			break;

		if (pfr_spi_read(ROT_INTERNAL_KEY, keym_address, sizeof(image_header), (uint8_t *)&image_header))
			continue;

		if (image_header.format != UPDATE_FORMAT_TYPE_KEYM && image_header.magic_number != KEY_MANAGEMENT_HEADER_MAGIC)
			continue;

		if (cerberus_pfr_verify_key_manifest(manifest, keym_id))
			return Failure;

		keym_count++;
	}

	if (keym_count < 1) {
		LOG_ERR("Key Manifest is empty");
		return Failure;
	}

	return Success;
}

int cerberus_pfr_get_key_manifest(struct pfr_manifest *manifest, uint8_t keym_id, struct PFR_KEY_MANIFEST *pfr_key_manifest)
{
	struct recovery_section image_section;
	struct recovery_header image_header;
	uint32_t region_size;
	uint32_t keym_address;
	uint32_t read_address;
	int status = Success;

	if (!manifest || !pfr_key_manifest)
		return Failure;

	if (keym_id > MAX_KEY_MANIFEST_ID) {
		LOG_ERR("Invalid key manifest Id: %d", keym_id);
		return Failure;
	}

	region_size = pfr_spi_get_device_size(ROT_INTERNAL_KEY);
	keym_address = keym_id * KEY_MANIFEST_SIZE;
	read_address = keym_address;
	if (keym_address >= region_size) {
		LOG_ERR("Key partition size is too small");
		return Failure;
	}

	// read recovery header
	if (pfr_spi_read(ROT_INTERNAL_KEY, read_address, sizeof(image_header),
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
	if (pfr_spi_read(ROT_INTERNAL_KEY, read_address, sizeof(image_section),
			(uint8_t *)&image_section)) {
		LOG_ERR("Failed to read imag section");
		return Failure;
	}

	if (image_section.magic_number != KEY_MANAGEMENT_SECTION_MAGIC ||
	    image_section.header_length != sizeof(struct recovery_section) ||
	    image_section.section_length != sizeof(struct PFR_KEY_MANIFEST)) {
		LOG_HEXDUMP_ERR(&image_header, sizeof(image_header), "section_header:");
		LOG_ERR("Unable to get image section.");
		return Failure;
	}

	read_address += image_section.header_length;

	LOG_INF("flash_device_id=%d, read_keym_address=%x", ROT_INTERNAL_KEY, read_address);
	if (pfr_spi_read(ROT_INTERNAL_KEY, read_address, sizeof(struct PFR_KEY_MANIFEST),
			(uint8_t *)pfr_key_manifest)) {
		LOG_ERR("Failed to read key manifest");
		return Failure;
	}

	if (pfr_key_manifest->magic_number != KEY_MANIFEST_SECTION_MAGIC) {
		LOG_ERR("Key Manifest Magic Number is not Matched(%x).", pfr_key_manifest->magic_number);
		return Failure;
	}

	return Success;
}

int cerberus_pfr_verify_csk_key(struct pfr_manifest *manifest, struct rsa_public_key *public_key, uint8_t key_manifest_id, uint8_t key_id)
{
	uint8_t hash_buffer[SHA512_DIGEST_LENGTH];
	struct PFR_KEY_MANIFEST pfr_key_manifest;
	uint32_t hash_length;

	if (!manifest || !public_key)
		return Failure;

	if (key_id > MAX_KEY_ID) {
		LOG_ERR("Invalid key Id: %d", key_id);
		return Failure;
	}

	if (cerberus_pfr_get_key_manifest(manifest, key_manifest_id, &pfr_key_manifest)) {
		LOG_ERR("KEYM(%d): Unable to get key manifest", key_manifest_id);
		return Failure;
	}

	if (pfr_key_manifest.hash_type == HASH_TYPE_SHA256) {
		manifest->hash->start_sha256(manifest->hash);
		manifest->hash->calculate_sha256(manifest->hash, (uint8_t *)public_key, sizeof(struct rsa_public_key), hash_buffer, SHA256_HASH_LENGTH);
		hash_length = SHA256_HASH_LENGTH;
	} else if (pfr_key_manifest.hash_type == HASH_TYPE_SHA384) {
		manifest->hash->start_sha384(manifest->hash);
		manifest->hash->calculate_sha384(manifest->hash, (uint8_t *)public_key, sizeof(struct rsa_public_key), hash_buffer, SHA384_HASH_LENGTH);
		hash_length = SHA384_HASH_LENGTH;
	} else {
		LOG_ERR("KEYM(%d): Unsupported hash type(%d)", key_manifest_id, pfr_key_manifest.hash_type);
		return Failure;
	}

	if (memcmp(hash_buffer, pfr_key_manifest.key_list[key_id].key_hash, hash_length)) {
		LOG_DBG("KEYM(%d): This CSK(%d) was not found.", key_manifest_id, key_id);
		LOG_HEXDUMP_DBG(hash_buffer, hash_length, "Calculated hash:");
		LOG_HEXDUMP_DBG(pfr_key_manifest.key_list[key_id].key_hash, hash_length, "Expected hash:");
		return Failure;
	}

	return Success;
}

int cerberus_pfr_find_key_manifest_id(struct pfr_manifest *manifest, struct rsa_public_key *public_key, uint8_t key_id, uint8_t *get_keym_id)
{
	struct recovery_header image_header;
	uint32_t keym_address;
	uint32_t region_size;
	uint8_t key_manifest_id;
	int status = Success;

	if (!manifest || !public_key || !get_keym_id)
		return Failure;

	if (key_id > MAX_KEY_ID) {
		LOG_ERR("Invalid key Id: %d", key_id);
		return Failure;
	}

	region_size = pfr_spi_get_device_size(ROT_INTERNAL_KEY);

	// lookup all key manifests
	for (key_manifest_id = 0; key_manifest_id <= MAX_KEY_MANIFEST_ID; key_manifest_id++) {
		keym_address = key_manifest_id * KEY_MANIFEST_SIZE;
		if (keym_address >= region_size)
			break;

		if (pfr_spi_read(ROT_INTERNAL_KEY, keym_address, sizeof(image_header), (uint8_t *)&image_header))
			continue;

		if (image_header.format != UPDATE_FORMAT_TYPE_KEYM && image_header.magic_number != KEY_MANAGEMENT_HEADER_MAGIC)
			continue;

		status = cerberus_pfr_verify_csk_key(manifest, public_key, key_manifest_id, key_id);
		if (status == Success) {
			LOG_INF("This CSK(%d) was found in KEYM(%d).", key_id, key_manifest_id);
			*get_keym_id = key_manifest_id;
			return Success;
		}
	}

	LOG_ERR("This CSK(%d) was not found in all key manifests", key_id);
	LOG_DBG("CSK Key Exponent=%08x", public_key->exponent);
	LOG_HEXDUMP_DBG(public_key->modulus, public_key->mod_length, "CSK Key Modulus:");

	return Failure;
}

int cerberus_pfr_find_key_manifest_id_and_key_id(struct pfr_manifest *manifest, struct rsa_public_key *public_key,
	uint8_t *get_key_manifest_id, uint8_t *get_key_id)
{
	uint8_t hash_buffer[SHA512_DIGEST_LENGTH];
	struct PFR_KEY_MANIFEST pfr_key_manifest;
	struct recovery_header image_header;
	uint8_t key_manifest_id;
	uint32_t keym_address;
	uint32_t region_size;
	uint32_t hash_length;
	uint8_t key_id;

	if (!manifest || !public_key || !get_key_manifest_id || !get_key_id)
		return Failure;

	region_size = pfr_spi_get_device_size(ROT_INTERNAL_KEY);

	// lookup all key manifests
	for (key_manifest_id = 0; key_manifest_id <= MAX_KEY_MANIFEST_ID; key_manifest_id++) {
		keym_address = key_manifest_id * KEY_MANIFEST_SIZE;
		if (keym_address >= region_size)
			break;

		if (pfr_spi_read(ROT_INTERNAL_KEY, keym_address, sizeof(image_header), (uint8_t *)&image_header))
			continue;

		if (image_header.format != UPDATE_FORMAT_TYPE_KEYM && image_header.magic_number != KEY_MANAGEMENT_HEADER_MAGIC)
			continue;

		if (cerberus_pfr_get_key_manifest(manifest, key_manifest_id, &pfr_key_manifest)) {
			LOG_WRN("KEYM(%d): Unable to get key manifest", key_manifest_id);
			continue;
		}

		if (pfr_key_manifest.hash_type == HASH_TYPE_SHA256) {
			manifest->hash->start_sha256(manifest->hash);
			manifest->hash->calculate_sha256(manifest->hash, (uint8_t *)public_key, sizeof(struct rsa_public_key), hash_buffer, SHA256_HASH_LENGTH);
			hash_length = SHA256_HASH_LENGTH;
		} else if (pfr_key_manifest.hash_type == HASH_TYPE_SHA384) {
			manifest->hash->start_sha384(manifest->hash);
			manifest->hash->calculate_sha384(manifest->hash, (uint8_t *)public_key, sizeof(struct rsa_public_key), hash_buffer, SHA384_HASH_LENGTH);
			hash_length = SHA384_HASH_LENGTH;
		} else {
			LOG_WRN("KEYM(%d): Unsupported hash type(%d)", key_manifest_id, pfr_key_manifest.hash_type);
			continue;
		}

		for (key_id = 0; key_id < pfr_key_manifest.key_count; key_id++) {
			if (!memcmp(hash_buffer, pfr_key_manifest.key_list[key_id].key_hash, hash_length)) {
				LOG_INF("This CSK was found in KEYM(%d) and KEYID(%d).", key_manifest_id, key_id);
				*get_key_manifest_id = key_manifest_id;
				*get_key_id = key_id;
				return Success;
			}
		}
	}

	LOG_ERR("This CSK was not found in all key manifests");
	LOG_DBG("CSK Key Exponent=%08x", public_key->exponent);
	LOG_HEXDUMP_DBG(public_key->modulus, public_key->mod_length, "CSK Key Modulus:");

	return Failure;
}

int cerberus_pfr_get_key_manifest_append_addr(uint32_t *append_addr)
{
	struct recovery_header image_header;
	uint8_t key_manifest_id;
	uint32_t keym_address;
	uint32_t region_size;

	if (!append_addr)
		return Failure;

	region_size = pfr_spi_get_device_size(ROT_INTERNAL_KEY);

	// lookup all key manifests
	for (key_manifest_id = 0; key_manifest_id <= MAX_KEY_MANIFEST_ID; key_manifest_id++) {
		keym_address = key_manifest_id * KEY_MANIFEST_SIZE;
		if (keym_address >= region_size)
			break;

		if (pfr_spi_read(ROT_INTERNAL_KEY, keym_address, sizeof(image_header), (uint8_t *)&image_header))
			continue;

		if (image_header.format == UPDATE_FORMAT_TYPE_KEYM && image_header.magic_number == KEY_MANAGEMENT_HEADER_MAGIC)
			continue;

		*append_addr = keym_address;
		return Success;
	}

	if (keym_address >= region_size)
		LOG_ERR("Key Manifest is full");

	if (key_manifest_id > MAX_KEY_MANIFEST_ID)
		LOG_ERR("Key Manifest exceed the maximum count(%d)", CONFIG_KEY_MANIFEST_MAX_COUNT);

	return Failure;
}

