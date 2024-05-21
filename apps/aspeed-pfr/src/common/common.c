/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>
#include "common.h"

struct hash_engine hashEngine;				/**< Hashing engine for validation. */
struct manifest_flash manifestFlash;
struct signature_verification signatureVerification;	/**< PFM signature verification. */
struct rsa_engine_wrapper rsaEngineWrapper;

// Zephyr Ported structures
struct spi_engine_wrapper spiEngineWrapper;
struct spi_engine_state_wrapper spiEngineStateWrapper;
struct flash_master_wrapper flashEngineWrapper;

static uint8_t hashStorage[RSA_MAX_KEY_LENGTH] __aligned(16);

struct flash *getFlashDeviceInstance(void)
{
	return &spiEngineWrapper.spi.base;
}

struct hash_engine *get_hash_engine_instance(void)
{
	return &hashEngine;
}

struct manifest_flash *getManifestFlashInstance(void)
{
        return &manifestFlash;
}

struct signature_verification *getSignatureVerificationInstance(void)
{
	return &signatureVerification;
}

struct rsa_engine_wrapper *getRsaEngineInstance(void)
{
	return &rsaEngineWrapper;
}

struct spi_engine_wrapper *getSpiEngineWrapper(void)
{
	return &spiEngineWrapper;
}

struct spi_engine_state_wrapper *getSpiEngineStateWrapper(void)
{
	return &spiEngineStateWrapper;
}

struct flash_master_wrapper *getFlashEngineWrapper(void)
{
	return &flashEngineWrapper;
}

uint8_t *getNewHashStorage(void)
{
	memset(hashStorage, 0, RSA_MAX_KEY_LENGTH);

	return hashStorage;
}

