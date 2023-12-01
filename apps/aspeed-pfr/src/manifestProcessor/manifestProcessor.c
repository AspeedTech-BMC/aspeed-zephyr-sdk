/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <assert.h>

#include "manifestProcessor.h"
#include "pfr/pfr_common.h"
#include "common/common.h"
#include "firmware/app_image.h"

LOG_MODULE_REGISTER(manifest, CONFIG_LOG_DEFAULT_LEVEL);

int initializeManifestProcessor(void)
{
	int status = 0;

	init_pfr_bases();

	return status;
}

