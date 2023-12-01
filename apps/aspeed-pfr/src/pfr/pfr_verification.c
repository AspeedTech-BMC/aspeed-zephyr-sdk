/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_authentication.h"
#include "intel_pfr/intel_pfr_verification.h"
#include "intel_pfr/intel_pfr_definitions.h"
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
#include "intel_pfr/intel_pfr_cpld_utils.h"
#endif
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_authentication.h"
#include "cerberus_pfr/cerberus_pfr_verification.h"
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#endif
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "flash/flash_aspeed.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "pfr/pfr_common.h"
#include "pfr_util.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int authentication_image(void *AoData, void *EventContext)
{
	int status = 0;
	EVENT_CONTEXT *EventData = (EVENT_CONTEXT *) EventContext;

	struct pfr_manifest *pfr_manifest = get_pfr_manifest();

	pfr_manifest->state = FIRMWARE_VERIFY;

	if (EventData->image == BMC_EVENT) {
		// BMC SPI
		LOG_INF("Image Type: BMC");
		pfr_manifest->image_type = BMC_TYPE;

	} else if (EventData->image == PCH_EVENT) {
		// PCH SPI
		LOG_INF("Image Type: PCH");
		pfr_manifest->image_type = PCH_TYPE;
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (EventData->image == AFM_EVENT) {
		// AFM Image
		LOG_INF("Image Type: AFM");
		if (EventData->operation == VERIFY_BACKUP)
			pfr_manifest->image_type = AFM_TYPE;
		else
			pfr_manifest->image_type = ROT_INTERNAL_AFM;
	}
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	else if (EventData->image == CPLD_EVENT) {
		// Intel CPLD Image
		LOG_INF("Image Type: Intel CPLD");
		pfr_manifest->image_type = CPLD_TYPE;
		if (EventData->operation == VERIFY_ACTIVE) {
#if defined(CONFIG_INTEL_SCM_CPLD_UPDATE_ONLY)
			if (intel_rsu_handshake(SCM_CPLD))
				return Failure;
			if (intel_rsu_check_fw_loaded(SCM_CPLD, RSU_CFG_STS_CFM1_LOADED))
				return Failure;
#else
			uint8_t board_id = intel_rsu_get_scm_board_id();
			uint8_t rsu_count = (board_id == SCM_BOARD_ID_DEFAULT) ?
				MAX_RSU_TYPE : (MAX_RSU_TYPE - 1);
			for (uint8_t rsu_type = 0; rsu_type < rsu_count; rsu_type++) {
				if (intel_rsu_handshake(rsu_type))
					return Failure;
				if (intel_rsu_check_fw_loaded(rsu_type, RSU_CFG_STS_CFM1_LOADED))
					return Failure;
			}
#endif
		}
	}
#endif

	if (EventData->operation == VERIFY_BACKUP) {
		status = pfr_manifest->recovery_base->verify((struct recovery_image *)pfr_manifest,
				pfr_manifest->hash, pfr_manifest->verification->base,
				pfr_manifest->pfr_hash->hash_out, pfr_manifest->pfr_hash->length,
				pfr_manifest->recovery_pfm);
	} else if (EventData->operation == VERIFY_ACTIVE) {
		status = pfr_manifest->active_image_base->verify(pfr_manifest);
	}

	return status;
}

/**
 * Get the ID of the manifest.
 *
 * @param manifest The manifest to query.
 * @param id The buffer to hold the manifest ID.
 *
 * @return 0 if the ID was successfully retrieved or an error code.
 */
int manifest_get_id(struct manifest *manifest, uint32_t *id)
{
	ARG_UNUSED(manifest);
	ARG_UNUSED(id);

	return Success;
}

/**
 * Get the string identifier of the platform for the manifest.
 *
 * @param manifest The manifest to query.
 * @param id Pointer to the output buffer for the platform identifier.  The buffer pointer
 * cannot be null, but if the buffer itself is null, the manifest instance will allocate an
 * output buffer for the platform identifier.  When using a manifest-allocated buffer, the
 * output must be treated as const (i.e. do not modify the contents) and must be freed by
 * calling free_platform_id on the same instance that allocated it.
 * @param length Length of the output buffer if the buffer is static (i.e. not null).  This
 * argument is ignored when using manifest allocation.
 *
 * @return 0 if the platform ID was retrieved successfully or an error code.
 */
int manifest_get_platform_id(struct manifest *manifest, char **id, size_t length)
{
	ARG_UNUSED(manifest);
	ARG_UNUSED(id);
	ARG_UNUSED(length);

	return Success;
}

/**
 * Free a platform identifier allocated by a manifest instance.  Do not call this function for
 * static buffers owned by the caller.
 *
 * @param manifest The manifest that allocated the platform identifier.
 * @param id The platform identifier to free.
 */
void manifest_free_platform_id(struct manifest *manifest, char *id)
{
	ARG_UNUSED(manifest);
	ARG_UNUSED(id);
}

/**
 * Get the hash of the manifest data, not including the signature.  The hash returned will be
 * calculated using the same algorithm as was used to generate the manifest signature.
 *
 * @param manifest The manifest to query.
 * @param hash The hash engine to use for generating the hash.
 * @param hash_out Output buffer for the manifest hash.
 * @param hash_length Length of the hash output buffer.
 *
 * @return Length of the hash if it was calculated successfully or an error code.  Use
 * ROT_IS_ERROR to check the return value.
 */
int manifest_get_hash(struct manifest *manifest, struct hash_engine *hash, uint8_t *hash_out,
		      size_t hash_length)
{
	return get_hash(manifest, hash, hash_out, hash_length);
}

/**
 * Get the signature of the manifest.
 *
 * @param manifest The manifest to query.
 * @param signature Output buffer for the manifest signature.
 * @param length Length of the signature buffer.
 *
 * @return The length of the signature or an error code.  Use ROT_IS_ERROR to check the return
 * value.
 */
int manifest_get_signature(struct manifest *manifest, uint8_t *signature, size_t length)
{
	ARG_UNUSED(manifest);
	ARG_UNUSED(signature);
	ARG_UNUSED(length);

	return Success;
}

/**
 * Determine if the manifest is considered to be empty.  What indicates an empty manifest will
 * depend on the specific implementation, and it doesn't necessarily mean there is no data in
 * the manifest.
 *
 * @param manifest The manifest to query.
 *
 * @return 1 if the manifest is empty, 0 if it is not, or an error code.
 */
int is_manifest_empty(struct manifest *manifest)
{
	ARG_UNUSED(manifest);
	return Success;
}

void init_manifest(struct manifest *manifest)
{
	manifest->verify = manifest_verify;
	manifest->get_id = manifest_get_id;
	manifest->get_platform_id = manifest_get_platform_id;
	manifest->free_platform_id = manifest_free_platform_id;
	manifest->get_hash = manifest_get_hash;
	manifest->get_signature = manifest_get_signature;
	manifest->is_empty = is_manifest_empty;
}


void init_signature_verification(struct signature_verification *signature_verification)
{
	signature_verification->verify_signature = verify_signature;
}
