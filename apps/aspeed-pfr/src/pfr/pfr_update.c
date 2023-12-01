/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <stdint.h>
#include <zephyr/drivers/misc/aspeed/pfr_aspeed.h>
#include <flash/flash_wrapper.h>

#include "pfr_ufm.h"
#include "AspeedStateMachine/common_smc.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_verification.h"
#include "intel_pfr/intel_pfr_update.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#include "cerberus_pfr/cerberus_pfr_provision.h"
#include "cerberus_pfr/cerberus_pfr_verification.h"
#include "cerberus_pfr/cerberus_pfr_update.h"
#endif
#include "gpio/gpio_aspeed.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "include/SmbusMailBoxCom.h"
#include "pfr_common.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

/**
 * Update the image referenced by an instance.
 *
 * @param fw The firmware image instance to update.
 * @param flash The flash device that contains the firmware image.
 * @param base_addr The starting address of the new firmware image.
 *
 * @return 0 if the image reference was updated successfully or an error code.  Load-time
 * validation errors will generate one of the following errors:
 *              - FIRMWARE_IMAGE_INVALID_FORMAT
 *              - FIRMWARE_IMAGE_BAD_CHECKSUM
 *              - KEY_MANIFEST_INVALID_FORMAT
 *              - FIRMWARE_HEADER validation errors
 */
int firmware_image_load(struct firmware_image *fw, struct flash *flash, uint32_t base_addr)
{
	return Success;
}

/**
 * Get the total size of the firmware image.
 *
 * @param fw The firmware image to query.
 *
 * @return The size of the firmware image or an error code.  Use ROT_IS_ERROR to check the
 * return value.
 */
int firmware_image_get_image_size(struct firmware_image *fw)
{
	ARG_UNUSED(fw);
	return Success;
}

/**
 * Get the key manifest for the current firmware image.
 *
 * @param fw The firmware image to query.
 *
 * @return The image key manifest or null if there is an error.  The memory for the key
 * manifest is managed by the firmware image instance and is only guaranteed to be valid until
 * the next call to 'load'.
 */
struct key_manifest *firmware_imag_eget_key_manifest(struct firmware_image *fw)
{
	ARG_UNUSED(fw);
	return NULL;
}

/**
 * Get the main image header for the current firmware image.
 *
 * @param fw The firmware image to query.
 *
 * @return The image firmware header or null if there is an error.  The memory for the header
 * is managed by the firmware image instance and is only guaranteed to be valid until the next
 * call to 'load'.
 */
struct firmware_header *firmware_image_get_firmware_header(struct firmware_image *fw)
{
	ARG_UNUSED(fw);
	return NULL;
}

void init_update_fw_manifest(struct firmware_image *fw)
{
	// fw->load = firmware_image_load;
	fw->verify = firmware_image_verify;
	// fw->get_image_size = firmware_image_get_image_size;
}
