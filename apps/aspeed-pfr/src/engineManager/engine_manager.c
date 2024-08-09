/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/i2c/pfr/i2c_filter.h>

#include "Smbus_mailbox/Smbus_mailbox.h"
#include "crypto/hash_wrapper.h"
#include "engine_manager.h"
#include "common/common.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_verification.h"
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_definitions.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_verification.h"
#include "cerberus_pfr/cerberus_pfr_provision.h"
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#endif
#include "manifestProcessor/manifestProcessor.h"
#include "flash/flash_wrapper.h"
#include "gpio/gpio_aspeed.h"
#include "pfr/pfr_util.h"

LOG_MODULE_REGISTER(engine, CONFIG_LOG_DEFAULT_LEVEL);

static int initialize_crypto(/*struct engine_instances *engineInstances*/)
{
	int status = 0;

	status = hash_wrapper_init(get_hash_engine_instance());
	if (status)
		return status;
#if defined(CONFIG_CERBERUS_PFR)
	status = rsa_wrapper_init(getRsaEngineInstance());
#endif

	return status;
}

static int initialize_flash(void)
{
	int status = flash_master_wrapper_init(getFlashEngineWrapper());
	if (status)
		return status;

	status = flash_wrapper_init(getSpiEngineWrapper(), getFlashEngineWrapper(), getSpiEngineStateWrapper());

	return status;
}

int initializeEngines(void)
{
	int status = 0;

	status = initialize_flash();
	assert(status == 0);
	status = initialize_crypto();
	assert(status == 0);

	return status;
}

