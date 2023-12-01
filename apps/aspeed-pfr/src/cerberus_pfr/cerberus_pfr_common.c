/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdlib.h>
#include <zephyr/logging/log.h>
#include "AspeedStateMachine/common_smc.h"
#include "cerberus_pfr_common.h"
#include "cerberus_pfr_definitions.h"
#include "manifest/pfm/pfm_format.h"
#include "manifest/manifest_format.h"
#include "pfr/pfr_util.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

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
int cerberus_get_version_info(int spi_dev, uint32_t pfm_addr, uint32_t *fw_ver_element_addr,
	struct pfm_firmware_version_element *fw_ver_element)
{
	if (!fw_ver_element_addr || !fw_ver_element)
		return Failure;

	struct manifest_platform_id plat_id_header;
	struct pfm_flash_device_element flash_dev;
	struct pfm_firmware_element fw_element;
	struct manifest_toc_header toc_header;
	uint32_t read_address;
	uint32_t hash_length;
	uint16_t id_length;
	uint8_t alignment;

	read_address = pfm_addr + sizeof(struct manifest_header);

	// TOC header Offset
	if (pfr_spi_read(spi_dev, read_address, sizeof(toc_header),
				(uint8_t *)&toc_header)) {
		LOG_ERR("Failed to read toc header");
		return Failure;
	}

	if (toc_header.hash_type == MANIFEST_HASH_SHA256)
		hash_length = SHA256_HASH_LENGTH;
	else {
		// Cerberus manifest v1 only support SHA256
		LOG_ERR("Invalid or unsupported hash type");
		return Failure;
	}

	// Manifest Header + TOC Header + TOC Entries + TOC Entries Hash + TOC Hash
	read_address += sizeof(struct manifest_toc_header) +
		(toc_header.entry_count * sizeof(struct manifest_toc_entry)) +
		(toc_header.entry_count * hash_length) +
		hash_length;

	// Platform Header Offset
	if (pfr_spi_read(spi_dev, read_address, sizeof(plat_id_header),
				(uint8_t *)&plat_id_header)) {
		LOG_ERR("Failed to read TOC header");
		return Failure;
	}

	// id length should be 4 byte aligned
	alignment = (plat_id_header.id_length % 4) ?
		(4 - (plat_id_header.id_length % 4)) : 0;
	id_length = plat_id_header.id_length + alignment;
	read_address += sizeof(plat_id_header) + id_length;

	// Flash Device Element Offset
	if (pfr_spi_read(spi_dev, read_address, sizeof(flash_dev),
				(uint8_t *)&flash_dev)) {
		LOG_ERR("Failed to get flash device element");
		return Failure;
	}

	if (flash_dev.fw_count == 0) {
		LOG_ERR("Unknow firmware");
		return Failure;
	}

	read_address += sizeof(flash_dev);

	// PFM Firmware Element Offset
	if (pfr_spi_read(spi_dev, read_address, sizeof(fw_element),
				(uint8_t *)&fw_element)) {
		LOG_ERR("Failed to get PFM firmware element");
		return Failure;
	}

	// id length should be 4 byte aligned
	alignment = (fw_element.id_length % 4) ? (4 - (fw_element.id_length % 4)) : 0;
	id_length = fw_element.id_length + alignment;
	read_address += sizeof(fw_element) - sizeof(fw_element.id) + id_length;

	// PFM Firmware Version Element Offset
	if (pfr_spi_read(spi_dev, read_address, sizeof(struct pfm_firmware_version_element),
				(uint8_t *)fw_ver_element)) {
		LOG_ERR("Failed to get PFM firmware version element");
		return Failure;
	}

	*fw_ver_element_addr = read_address;

	return Success;
}

int cerberus_get_rw_region_info(int spi_dev, uint32_t pfm_addr, uint32_t *rw_region_addr,
		struct pfm_firmware_version_element *fw_ver_element)
{
	if (!rw_region_addr || !fw_ver_element)
		return Failure;

	uint32_t fw_ver_element_addr;
	uint8_t ver_length;
	uint8_t alignment;

	if (cerberus_get_version_info(spi_dev, pfm_addr, &fw_ver_element_addr, fw_ver_element)) {
		LOG_ERR("Failed to get version info");
		return Failure;
	}

	// version length should be 4 byte aligned
	alignment = (fw_ver_element->version_length % 4) ?
		(4 - (fw_ver_element->version_length % 4)) : 0;
	ver_length = fw_ver_element->version_length + alignment;

	// PFM Firmware Version Element RW Region Offset
	*rw_region_addr = fw_ver_element_addr + sizeof(struct pfm_firmware_version_element)
		- sizeof(fw_ver_element->version) + ver_length;

	return Success;
}

int cerberus_get_signed_region_info(int spi_dev, uint32_t pfm_addr, uint32_t *signed_region_addr,
		struct pfm_firmware_version_element *fw_ver_element)
{
	if (!signed_region_addr || !fw_ver_element)
		return Failure;

	uint32_t rw_region_addr;

	if (cerberus_get_rw_region_info(spi_dev, pfm_addr, &rw_region_addr, fw_ver_element)) {
		LOG_ERR("Failed to get rw regions");
		return Failure;
	}

	// PFM Firmware Version Element Image Offset
	*signed_region_addr = rw_region_addr + fw_ver_element->rw_count *
		sizeof(struct pfm_fw_version_element_rw_region);

	return Success;
}

int cerberus_get_image_pfm_addr(struct pfr_manifest *manifest,
		struct recovery_header *image_header, uint32_t *src_pfm_addr,
		uint32_t *dest_pfm_addr)
{
	if (!manifest || !image_header || !src_pfm_addr || !dest_pfm_addr)
		return Failure;

	struct manifest_header manifest_header;
	struct recovery_section image_section;
	bool found_pfm = false;
	uint32_t sig_address = manifest->address + image_header->image_length -
			image_header->sign_length;
	uint32_t read_address = manifest->address + image_header->header_length;

	// Find PFM in update image
	while (read_address < sig_address) {
		if (pfr_spi_read(manifest->image_type, read_address, sizeof(image_section),
					(uint8_t *)&image_section)) {
			LOG_ERR("Failed to read image section info in Flash : %d , Offset : %x",
					manifest->image_type, read_address);
			return Failure;
		}

		if (image_section.magic_number != RECOVERY_SECTION_MAGIC) {
			LOG_ERR("Recovery Section magic number not matched");
			return Failure;
		}

		read_address = read_address + sizeof(image_section);
		if (pfr_spi_read(manifest->image_type, read_address,
					sizeof(struct manifest_header),
					(uint8_t *)&manifest_header)) {
			LOG_ERR("Failed to read PFM from update image");
			return Failure;
		}

		if ((manifest_header.magic == PFM_V2_MAGIC_NUM) &&
				(manifest_header.sig_length <
				(manifest_header.length - sizeof(manifest_header))) &&
				(manifest_header.sig_length <= RSA_KEY_LENGTH_2K)) {
			found_pfm = true;
			break;
		}

		read_address += image_section.section_length;
	}

	if (!found_pfm) {
		LOG_ERR("Failed to get PFM from update image");
		return Failure;
	}

	*src_pfm_addr = read_address;
	*dest_pfm_addr = image_section.start_addr;

	return Success;
}

uint32_t *cerberus_get_update_regions(struct pfr_manifest *manifest,
		struct recovery_header *image_header, uint32_t *region_cnt)
{
	if (!manifest || !image_header || !region_cnt)
		return NULL;

	uint32_t read_address, src_pfm_addr, dest_pfm_addr;
	uint32_t *update_regions = NULL;

	// Find PFM in update image
	if (cerberus_get_image_pfm_addr(manifest, image_header, &src_pfm_addr, &dest_pfm_addr)) {
		LOG_ERR("PFM doesn't exist in update image");
		goto error;
	}

	struct pfm_firmware_version_element fw_ver_element;
	uint32_t signed_region_addr;

	if (cerberus_get_signed_region_info(manifest->image_type, src_pfm_addr, &signed_region_addr,
				&fw_ver_element)) {
		LOG_ERR("Failed to get signed regions");
		goto error;
	}

	read_address = signed_region_addr;

	// PFM Firmware Version Element Image Offset
	struct pfm_fw_version_element_image fw_ver_element_img;
	struct pfm_flash_region region;

	update_regions = malloc(sizeof(uint32_t) * ((fw_ver_element.img_count * 5) + 1));

	if (!update_regions) {
		LOG_ERR("Failed to malloc update_regions");
		goto error;
	}

	*region_cnt = 0;
	update_regions[*region_cnt] = dest_pfm_addr;
	++*region_cnt;

	for (int signed_region_id = 0; signed_region_id < fw_ver_element.img_count;
			signed_region_id++) {
		if (pfr_spi_read(manifest->image_type, read_address, sizeof(fw_ver_element_img),
					(uint8_t *)&fw_ver_element_img)) {
			LOG_ERR("Signed Region(%d): Failed to get PFM firmware version element image header", signed_region_id);
			goto error;
		}

		if (fw_ver_element_img.region_count > 5) {
			LOG_ERR("Signed Region(%d): PFM firmware version element image regions(%d) exceeds 5",
				signed_region_id, fw_ver_element_img.region_count);
			goto error;
		}

		read_address += sizeof(fw_ver_element_img);

		// signature length
		read_address += RSA_KEY_LENGTH_2K;

		// public key lenght
		read_address += sizeof(struct rsa_public_key);

		// Region Address
		for (int count = 0; count < fw_ver_element_img.region_count; count++) {
			if (pfr_spi_read(manifest->image_type, read_address, sizeof(struct pfm_flash_region),
					(uint8_t *)&region)) {
				LOG_ERR("Signed Region(%d): failed to get region (%d)", signed_region_id, count);
				goto error;
			}

			read_address += sizeof(region);
			update_regions[*region_cnt] = region.start_addr;
			++*region_cnt;
		}
	}

	return update_regions;

error:
	if (update_regions)
		free(update_regions);

	return NULL;
}

