/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>

#include "common/common.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "AspeedStateMachine/common_smc.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "cerberus_pfr_common.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_recovery.h"
#include "cerberus_pfr_key_manifest.h"
#include "manifest/manifest_format.h"
#include "manifest/pfm/pfm_format.h"
#include "crypto/rsa.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int verify_recovery_header_magic_number(struct recovery_header rec_head)
{
	int status = Success;

	if (rec_head.format == UPDATE_FORMAT_TYPE_BMC ||
	    rec_head.format == UPDATE_FORMAT_TYPE_PCH ||
	    rec_head.format == UPDATE_FORMAT_TYPE_HROT) {
		if (rec_head.magic_number != RECOVERY_HEADER_MAGIC)
			status = Failure;
	} else if (rec_head.format == UPDATE_FORMAT_TYPE_KCC ||
		   rec_head.format == UPDATE_FORMAT_TYPE_DCC ||
		   rec_head.format == UPDATE_FORMAT_TYPE_KEYM) {
		if (rec_head.magic_number != KEY_MANAGEMENT_HEADER_MAGIC)
			status = Failure;
	} else
		status = Failure;

	return status;
}

void init_stage_and_recovery_offset(struct pfr_manifest *pfr_manifest)
{
	if (!pfr_manifest)
		return;

	if (pfr_manifest->image_type == BMC_TYPE) {
		get_provision_data_in_flash(BMC_STAGING_REGION_OFFSET,
				(uint8_t *)&pfr_manifest->staging_address, sizeof(pfr_manifest->address));
		get_provision_data_in_flash(BMC_RECOVERY_REGION_OFFSET,
				(uint8_t *)&pfr_manifest->recovery_address,
				sizeof(pfr_manifest->recovery_address));
		pfr_manifest->flash_id = BMC_FLASH_ID;
		pfr_manifest->pc_type = PFR_BMC_UPDATE_CAPSULE;
	} else if (pfr_manifest->image_type == PCH_TYPE) {
		get_provision_data_in_flash(PCH_STAGING_REGION_OFFSET,
				(uint8_t *)&pfr_manifest->staging_address, sizeof(pfr_manifest->address));
		get_provision_data_in_flash(PCH_RECOVERY_REGION_OFFSET,
				(uint8_t *)&pfr_manifest->recovery_address,
				sizeof(pfr_manifest->recovery_address));
		pfr_manifest->flash_id = PCH_FLASH_ID;
		pfr_manifest->pc_type = PFR_PCH_UPDATE_CAPSULE;
	}
}

/*
 * Key Management images which are key cancellation image,
 * key manifest image and decommission image are signed by root key.
 * It should verify root public key and image signature.
 * The root public key hash is provisioned in UFM and it cannot be cancelled.
 *
 * Aspeed Cerberus key management image format:
 *
 * struct key_management_image {
 *     struct recovery_header
 *     struct recovery_section
 *     u8 imagedata[image_length]
 *     u8 signature[sign_length]
 *     struct rsa_public_key // (root key)
 * }
 *
 */
int cerberus_pfr_verify_key_management_image(struct pfr_manifest *manifest, struct recovery_header *image_header)
{
	if (!manifest || !image_header)
		return Failure;

	uint8_t sig_data[SHA256_SIGNATURE_LENGTH];
	struct rsa_public_key public_key;
	uint8_t *hashStorage = NULL;
	uint32_t signature_address;
	uint32_t rootkey_address;
	uint32_t verify_address;
	int status = Success;

	verify_address = manifest->address;
	rootkey_address = verify_address + image_header->image_length;
	LOG_INF("rootkey_address=%08x", rootkey_address);
	if (pfr_spi_read(manifest->flash_id, rootkey_address, sizeof(public_key), (uint8_t *)&public_key)) {
		LOG_ERR("Unable to get root key");
		return Failure;
	}

	if (public_key.mod_length != image_header->sign_length) {
		LOG_ERR("root key length(%d) and signature length (%d) mismatch", public_key.mod_length, image_header->sign_length);
		return Failure;
	}

	// verify root key hash
	if (cerberus_pfr_verify_root_key(manifest, &public_key))
		return Failure;

	// get signature
	signature_address = verify_address + image_header->image_length - image_header->sign_length;
	LOG_INF("signature_address=%08x", signature_address);
	if (pfr_spi_read(manifest->flash_id, signature_address, image_header->sign_length, (uint8_t *)sig_data)) {
		LOG_ERR("Unable to get the Signature.");
		return Failure;
	}

	// verify
	manifest->flash->state->device_id[0] = manifest->flash_id;
	status = flash_verify_contents((struct flash *)manifest->flash,
			verify_address,
			(image_header->image_length - image_header->sign_length),
			get_hash_engine_instance(),
			HASH_TYPE_SHA256,
			&getRsaEngineInstance()->base,
			sig_data,
			image_header->sign_length,
			&public_key,
			hashStorage,
			image_header->sign_length
			);
	if (status != Success) {
		LOG_ERR("Key Management Image Verify Fail manifest->flash_id=%d address=%08x", manifest->flash_id,
				verify_address);
		LOG_ERR("Public Key Exponent=%08x", public_key.exponent);
		LOG_HEXDUMP_ERR(public_key.modulus, public_key.mod_length, "Public Key Modulus:");
		LOG_ERR("image_header->image_length=%x", image_header->image_length);
		LOG_ERR("image_header->sign_length=%x", image_header->sign_length);
		LOG_HEXDUMP_ERR(sig_data, image_header->sign_length, "Image Signature:");
		return Failure;
	}

	LOG_INF("Key Management Image Verify Success.");

	return Success;
}

/*
 * Both recovery and update images are signed by CSK keys.
 * It should verify CSK public key, CSK key cancellation and image signature.
 * The CSK public key hash is provisioned in key manifests.
 *
 * Aspeed Cerberus recovery and update image format:
 *
 * struct recovery_image {
 *     struct recovery_header
 *     struct recovery_image_section_lists {
 *         struct recovery_section
 *         u8 imagedata[image_length]
 *     }
 *     u8 signature[sign_length]
 *     struct rsa_public_key // (CSK key)
 * }
 *
 */
int cerberus_pfr_verify_image(struct pfr_manifest *manifest)
{
	if (!manifest)
		return Failure;

	struct recovery_header image_header;
	struct rsa_public_key public_key;
	uint32_t signature_address;
	uint32_t cskkey_address;
	uint32_t verify_address;
	uint8_t sig_data[SHA256_SIGNATURE_LENGTH];
	uint8_t *hashStorage = NULL;
	uint8_t key_manifest_id;
	uint8_t key_id;
	int status = Success;

	verify_address = manifest->address;
	if (pfr_spi_read(manifest->flash_id, verify_address, sizeof(image_header), (uint8_t *)&image_header)) {
		LOG_ERR("Unable to get image header.");
		return Failure;
	}

	if (verify_recovery_header_magic_number(image_header)) {
		LOG_HEXDUMP_ERR(&image_header, sizeof(image_header), "image_header:");
		LOG_ERR("Image Header Magic Number is not Matched.");
		return Failure;
	}

	if (image_header.format == UPDATE_FORMAT_TYPE_KCC ||
	    image_header.format == UPDATE_FORMAT_TYPE_DCC ||
	    image_header.format == UPDATE_FORMAT_TYPE_KEYM)
		return cerberus_pfr_verify_key_management_image(manifest, &image_header);

	// get csk key
	cskkey_address = verify_address + image_header.image_length;
	LOG_INF("cskkey_address=%08x", cskkey_address);
	if (pfr_spi_read(manifest->flash_id, cskkey_address, sizeof(public_key), (uint8_t *)&public_key)) {
		LOG_ERR("Unable to get CSK key");
		return Failure;
	}

	if (public_key.mod_length != image_header.sign_length) {
		LOG_ERR("CSK key length(%d) and signature length (%d) mismatch", public_key.mod_length, image_header.sign_length);
		return Failure;
	}

	// Validate CSK and find its key manifest id and key id
	if (cerberus_pfr_find_key_manifest_id_and_key_id(manifest, &public_key, &key_manifest_id, &key_id)) {
		LOG_ERR("Verify CSK key failed");
		return Failure;
	}

	// Validate Key cancellation
	if (manifest->keystore->kc_flag->verify_kc_flag(manifest, key_manifest_id, key_id)) {
		LOG_ERR("Verify CSK key cancellation failed");
		return Failure;
	}

	// get signature
	signature_address = verify_address + image_header.image_length - image_header.sign_length;
	LOG_INF("signature_address=%08x", signature_address);
	if (pfr_spi_read(manifest->flash_id, signature_address, image_header.sign_length, (uint8_t *)sig_data)) {
		LOG_ERR("Unable to get the Signature.");
		return Failure;
	}

	// verify
	manifest->flash->state->device_id[0] = manifest->flash_id;
	status = flash_verify_contents((struct flash *)manifest->flash,
			verify_address,
			(image_header.image_length - image_header.sign_length),
			get_hash_engine_instance(),
			HASH_TYPE_SHA256,
			&getRsaEngineInstance()->base,
			sig_data,
			image_header.sign_length,
			&public_key,
			hashStorage,
			image_header.sign_length
			);
	if (status != Success) {
		LOG_ERR("Image Verify Fail manifest->flash_id=%d address=%08x", manifest->flash_id,
				verify_address);
		LOG_ERR("Public Key Exponent=%08x", public_key.exponent);
		LOG_HEXDUMP_ERR(public_key.modulus, public_key.mod_length, "Public Key Modulus:");
		LOG_ERR("image_header.image_length=%x", image_header.image_length);
		LOG_ERR("image_header.sign_length=%x", image_header.sign_length);
		LOG_HEXDUMP_ERR(sig_data, image_header.sign_length, "Image Signature:");
		return Failure;
	}

	LOG_INF("%s Image Verify Success.",
			(manifest->state == FIRMWARE_UPDATE) ? "Stage" : "Recovery");

	return Success;
}

int rsa_verify_signature(struct signature_verification *verification,
		const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	if (!verification || !digest || !signature)
		return Failure;

	struct rsa_engine_wrapper *rsa = getRsaEngineInstance();
	struct pfr_manifest *pfr_manifest = get_pfr_manifest();
	struct rsa_public_key rsa_public;
	int status = Success;

	status = key_manifest_get_root_key(&rsa_public, KEY_MANIFEST_0_ADDRESS);
	if (status != Success) {
		LOG_ERR("Unable to get root public Key.");
		return Failure;
	}

	if (rsa_public.mod_length != sig_length) {
		LOG_ERR("root key length(%d) and signature length (%d) mismatch", rsa_public.mod_length, sig_length);
		return Failure;
	}

	// verify root key hash
	if (cerberus_pfr_verify_root_key(pfr_manifest, &rsa_public))
		return Failure;

	status = rsa->base.sig_verify(&rsa->base, &rsa_public, signature, sig_length, digest, length);
	if (status != Success) {
		LOG_ERR("public key mod length = 0x%x", rsa_public.mod_length);
		LOG_ERR("public key exponent = 0x%x", rsa_public.exponent);
		LOG_HEXDUMP_ERR(rsa_public.modulus, rsa_public.mod_length, "public key modulus:");
		LOG_HEXDUMP_ERR(signature, sig_length, "signature:");
		LOG_HEXDUMP_ERR(digest, length, "expected hash:");
	}

	return status;
}

int signature_verification_init(struct signature_verification *verification)
{
	if (!verification)
		return Failure;

	memset(verification, 0, sizeof(struct signature_verification));
	verification->verify_signature = rsa_verify_signature;

	return Success;
}

int cerberus_pfr_manifest_verify(struct manifest *manifest, struct hash_engine *hash,
		struct signature_verification *verification, uint8_t *hash_out, uint32_t hash_length)
{
	if (!manifest || !hash || !verification || !hash_out)
		return Failure;

	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) manifest;
	struct manifest_flash *manifest_flash = getManifestFlashInstance();
	struct manifest_toc_header *toc_header = &manifest_flash->toc_header;
	uint32_t read_address;
	int status = 0;

	status = signature_verification_init(getSignatureVerificationInstance());
	if (status)
		return Failure;

	read_address = pfr_manifest->address;
	pfr_manifest->flash->state->device_id[0] = pfr_manifest->image_type;
	status = manifest_flash_init(manifest_flash, getFlashDeviceInstance(), read_address,
			PFM_V2_MAGIC_NUM);
	if (status) {
		LOG_ERR("manifest flash init failed");
		goto free_manifest;
	}

	// TOC header Offset
	read_address = pfr_manifest->address + sizeof(struct manifest_header);
	if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(struct manifest_toc_header),
			(uint8_t *)toc_header)) {
		LOG_ERR("Failed to read TOC header");
		status = Failure;
		goto free_manifest;
	}

	switch (manifest_flash->toc_header.hash_type) {
	case MANIFEST_HASH_SHA256:
		manifest_flash->toc_hash_type = HASH_TYPE_SHA256;
		manifest_flash->toc_hash_length = SHA256_HASH_LENGTH;
		break;
	// Cerberus manifest v1 only support SHA256
	case MANIFEST_HASH_SHA384:
	case MANIFEST_HASH_SHA512:
	default:
		LOG_ERR("Invalid or unsupported hash type");
		status = Failure;
		goto free_manifest;
	}

	uint8_t *hashStorage = getNewHashStorage();
	status = manifest_flash_verify(manifest_flash, get_hash_engine_instance(),
			getSignatureVerificationInstance(), hashStorage,
			manifest_flash->max_signature);

	if (true == manifest_flash->manifest_valid) {
		LOG_INF("Manifest Verification Successful");
		status = Success;
	} else {
		LOG_ERR("Manifest Verification Failure");
		status = Failure;
	}

free_manifest:
	manifest_flash_release(manifest_flash);

	return status;
}

/*
 * Aspeed Cerberus PFM format:
 *
 * struct {
 *     struct manifest_header
 *     struct manifest_toc_header
 *     struct manifest_toc_entry[toc_entry_count]
 *     u8 toc_entry_hash[toc_entry_count][HASH_LEN]
 *     u8 toc_hash[HASH_LEN]
 *     struct manifest_platform_id
 *     struct pfm_flash_device_element
 *     struct pfm_firmware_element
 *     struct pfm_firmware_version_element
 *     struct pfm_fw_version_element_rw_region[rw_count]
 *     struct signed_region_def {
 *         struct pfm_fw_version_element_image {
 *             u8 hash_type;       // The hashing algorithm.
 *             u8 region_count;    // The number of flash regions.
 *             u8 flags;           // ValidateOnBoot.
 *             u8 reserved;        // key_id (0-based) 0~7
 *         };
 *         u8 signature[256]
 *         struct rsa_public_key // CSK key
 *         struct pfm_flash_region {
 *             u32 region_start_addr
 *             u32 region_end_addr
 *         } regions[pfm_fw_version_element_image.region_count]
 *     } signed_region[pfm_firmware_version_element.img_count]
 * }
 *
 */
int cerberus_pfr_verify_pfm_csk_key(struct pfr_manifest *pfr_manifest)
{
	if (!pfr_manifest)
		return Failure;

	struct manifest_flash *manifest_flash = getManifestFlashInstance();
	struct pfm_fw_version_element_image fw_ver_element_img;
	struct pfm_firmware_version_element fw_ver_element;
	struct rsa_public_key pub_key;
	uint32_t signed_region_addr;
	uint8_t key_manifest_id;
	uint32_t read_address;
	uint8_t key_id;

	read_address = pfr_manifest->address;
	if (cerberus_get_signed_region_info(pfr_manifest->image_type, read_address,
		&signed_region_addr, &fw_ver_element)) {
		LOG_ERR("Failed to get signed regions");
		return Failure;
	}

	read_address = signed_region_addr;
	LOG_INF("signed_region_address=0x%08x", read_address);

	// PFM Firmware Version Element Image Offset
	for (int signed_region_id = 0; signed_region_id < fw_ver_element.img_count; signed_region_id++) {
		if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(fw_ver_element_img),
					(uint8_t *)&fw_ver_element_img)) {
			LOG_ERR("Signed Region(%d): Failed to get PFM firmware version element image header", signed_region_id);
			return Failure;
		}

		key_id = fw_ver_element_img.reserved;
		LOG_INF("Signed Region(%d): CSK KeyId=%d", signed_region_id, key_id);
		read_address += sizeof(fw_ver_element_img);

		// signature length
		read_address += manifest_flash->header.sig_length;

		if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(pub_key), (uint8_t *)&pub_key)) {
			LOG_ERR("Signed Region(%d): Failed to get CSK key", signed_region_id);
			return Failure;
		}

		if (pub_key.mod_length != manifest_flash->header.sig_length) {
			LOG_ERR("Signed Region(%d): CSK key length(%d) and signature length (%d) mismatch",
				signed_region_id, pub_key.mod_length, manifest_flash->header.sig_length);
			return Failure;
		}

		read_address += sizeof(pub_key);

		// Validate CSK and find its key manifest id
		if (cerberus_pfr_find_key_manifest_id(pfr_manifest, &pub_key, key_id, &key_manifest_id)) {
			LOG_ERR("Signed Region(%d): Verify CSK key failed", signed_region_id);
			return Failure;
		}

		// Validate Key cancellation
		if (pfr_manifest->keystore->kc_flag->verify_kc_flag(pfr_manifest, key_manifest_id, key_id)) {
			LOG_ERR("Signed Region(%d): Verify CSK key cancellation failed", signed_region_id);
			return Failure;
		}

		// Region Address
		read_address += sizeof(struct pfm_flash_region) * fw_ver_element_img.region_count;
	}

	return Success;
}

int cerberus_verify_regions(struct pfr_manifest *pfr_manifest)
{
	if (!pfr_manifest)
		return Failure;

	struct manifest_flash *manifest_flash = getManifestFlashInstance();
	struct pfm_firmware_version_element fw_ver_element;
	uint8_t signature[RSA_MAX_KEY_LENGTH];
	uint32_t signed_region_addr;
	uint32_t read_address;

	read_address = pfr_manifest->address;
	if (cerberus_get_signed_region_info(pfr_manifest->image_type, read_address,
		&signed_region_addr, &fw_ver_element)) {
		LOG_ERR("Failed to get signed regions");
		return Failure;
	}

	read_address = signed_region_addr;
	LOG_INF("signed_region_address=0x%08x", read_address);

	// PFM Firmware Version Element Image Offset
	struct pfm_fw_version_element_image fw_ver_element_img;
	uint8_t *hashStorage = getNewHashStorage();
	struct rsa_public_key pub_key;
	uint8_t key_manifest_id;
	uint8_t key_id;

	for (int signed_region_id = 0; signed_region_id < fw_ver_element.img_count;
			signed_region_id++) {
		if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(fw_ver_element_img),
					(uint8_t *)&fw_ver_element_img)) {
			LOG_ERR("Signed Region(%d): Failed to get PFM firmware version element image header", signed_region_id);
			return Failure;
		}

		key_id = fw_ver_element_img.reserved;
		LOG_INF("Signed Region(%d): CSK KeyId=%d", signed_region_id, key_id);

		struct flash_region region_list[fw_ver_element_img.region_count];
		struct pfm_flash_region region;

		read_address += sizeof(fw_ver_element_img);

		// Image Signature
		if (pfr_spi_read(pfr_manifest->image_type, read_address, manifest_flash->header.sig_length,
					(uint8_t *)signature)) {
			LOG_ERR("Signed Region(%d): Failed to get region signature", signed_region_id);
			return Failure;
		}

		read_address += manifest_flash->header.sig_length;

		if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(pub_key), (uint8_t *)&pub_key)) {
			LOG_ERR("Signed Region(%d): Failed to get CSK key", signed_region_id);
			return Failure;
		}

		if (pub_key.mod_length != manifest_flash->header.sig_length) {
			LOG_ERR("Signed Region(%d): CSK key length(%d) and signature length (%d) mismatch",
				signed_region_id, pub_key.mod_length, manifest_flash->header.sig_length);
			return Failure;
		}

		read_address += sizeof(pub_key);
		// Validate CSK and find its key manifest id
		if (cerberus_pfr_find_key_manifest_id(pfr_manifest, &pub_key, key_id, &key_manifest_id)) {
			LOG_ERR("Signed Region(%d): Verify CSK key failed", signed_region_id);
			return Failure;
		}

		// Validate Key cancellation
		if (pfr_manifest->keystore->kc_flag->verify_kc_flag(pfr_manifest, key_manifest_id, key_id)) {
			LOG_ERR("Signed Region(%d): Verify CSK key cancellation failed", signed_region_id);
			return Failure;
		}

		// Region Address
		for (int count = 0; count < fw_ver_element_img.region_count; count++) {
			if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(struct pfm_flash_region),
					(uint8_t *)&region)) {
				LOG_ERR("Signed Region(%d), Failed to get region (%d)", signed_region_id, count);
				return Failure;
			}

			read_address += sizeof(struct pfm_flash_region);

			if (region.end_addr <= region.start_addr) {
				LOG_ERR("Signed Region(%d): Failed to get region address(%d), RegionStartAddress: %x, RegionEndAddress: %x",
					signed_region_id, count, region.start_addr, region.end_addr);
				return Failure;
			}

			region_list[count].start_addr = region.start_addr;
			region_list[count].length = (region.end_addr - region.start_addr) + 1;
			LOG_INF("Signed Region(%d): RegionStartAddress: %08x, RegionEndAddress: %08x",
				signed_region_id, region.start_addr, region.end_addr);
		}

		// Bypass verification if validation flag of the region is not set.
		if (!(fw_ver_element_img.flags & PFM_IMAGE_MUST_VALIDATE)) {
			LOG_INF("Signed Region(%d): Digest verification bypassed", signed_region_id);
			continue;
		}

		if (flash_verify_noncontiguous_contents((struct flash *)pfr_manifest->flash,
				region_list,
				fw_ver_element_img.region_count,
				get_hash_engine_instance(),
				manifest_flash->toc_hash_type,
				&getRsaEngineInstance()->base,
				signature,
				manifest_flash->header.sig_length,
				&pub_key,
				hashStorage,
				manifest_flash->header.sig_length
				)) {
			LOG_ERR("Signed Region(%d): Digest verification failed", signed_region_id);
			return Failure;
		}

		LOG_INF("Signed Region(%d): Digest verification succeeded", signed_region_id);
	}

	// Record the i2c filtering rule address in manifest
	// i2c filtering rule will be applied after verification.
	uint32_t i2c_magic;
	pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(i2c_magic),
			(uint8_t *)&i2c_magic);
	if (i2c_magic == I2C_FILTER_SECTION_MAGIC) {
		uint8_t id = (pfr_manifest->image_type == BMC_TYPE) ? 0 : 1;
		pfr_manifest->i2c_filter_addr[id] = read_address;
	}

	return Success;
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
	if (!manifest || !hash || !verification || !hash_out)
		return Failure;

	return cerberus_pfr_manifest_verify(manifest, hash, verification, hash_out, hash_length);
}

