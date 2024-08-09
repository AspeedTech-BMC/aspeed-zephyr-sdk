/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <zephyr/kernel.h>
#include "intel_pfr_definitions.h"

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
enum AFM_PARTITION_TYPE {
	AFM_PART_ACT_1,
	AFM_PART_RCV_1,
	// Reserved for Intel PFR 4.0
	AFM_PART_ACT_2,
	AFM_PART_RCV_2,
};

int update_afm(enum AFM_PARTITION_TYPE part, uint32_t address, size_t length);
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
int update_cpld_image(struct pfr_manifest *manifest);
#endif

int intel_pfr_update_verify(const struct firmware_image *fw, struct hash_engine *hash);
int update_firmware_image(uint32_t image_type, void *AoData, void *EventContext, CPLD_STATUS *cpld_update_status, struct event_context *evt_ctx);

#if defined(CONFIG_SEAMLESS_UPDATE)
int perform_seamless_update(uint32_t image_type, void *AoData, void *EventContext);
#endif

int firmware_image_verify(const struct firmware_image *fw, struct hash_engine *hash);

