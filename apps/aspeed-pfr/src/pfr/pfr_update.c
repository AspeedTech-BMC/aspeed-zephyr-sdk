/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <zephyr/drivers/misc/aspeed/pfr_aspeed.h>
#include <flash/flash_wrapper.h>
#include "pfr_common.h"

#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_update.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_update.h"
#endif

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

void init_update_fw_manifest(struct firmware_image *fw)
{
	fw->verify = firmware_image_verify;
}
