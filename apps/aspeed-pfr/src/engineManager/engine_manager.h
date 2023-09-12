/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <zephyr.h>
#include "flash/flash_wrapper.h"


struct engine_instances {
	struct aes_engine *aesEngine;
	struct base64_engine *base64Engine;
	struct ecc_engine *eccEngine;
	struct flash *flashDevice;
	struct flash_master *flashMaster;                               /**< Flash master for the PFM flash. */
	struct flash_engine_wrapper *flashEngineWrapper;
	struct hash_engine *hashEngine;
	struct keystore *keyStore;
	struct manifest *manifestHandler;
	struct pfm_flash *pfmFlash;
	struct rng_engine *rngEngine;
	struct rsa_engine *rsaEngine;
	struct signature_verification *verification;    /**< PFM signature verification. */
	struct spi_flash *spiFlash;                     /**< Flash where the PFM is stored. */
	struct spi_flash_wrapper *spiEngineWrapper;
	struct x509_engine *x509Engine;
};

int initializeEngines(void);
void apply_fvm_spi_protection(uint32_t fvm_addr);
