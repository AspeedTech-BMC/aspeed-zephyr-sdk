/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <zephyr/crypto/hash.h>

#define ZEPHYR_HASH_API_MIDLEYER_TEST_SUPPORT 1    // non-zero for support hash functions testing

#ifdef CONFIG_CRYPTO_ASPEED
#ifndef HASH_DRV_NAME
#define HASH_DRV_NAME CONFIG_CRYPTO_ASPEED_HASH_DRV_NAME    // define hash driver for Aspeed
#endif
#endif

/**
 * Structure internal hash parameters.
 *
 * Refer to comments for individual fields to know the contract in terms
 */
typedef struct hash_params {
	/**
	 * Structure encoding session parameters.
	 *
	 * Refer to comments for individual fields to know the contract
	 * in terms of who fills what and when w.r.t begin_session() call.
	 */
	struct hash_ctx ctx;
	/**
	 * Structure encoding IO parameters of one cryptographic
	 * operation like encrypt/decrypt.
	 *
	 * The fields which has not been explicitly called out has to
	 * be filled up by the app before making the cipher_xxx_op()
	 * call.
	 */
	struct hash_pkt pkt;
	/**
	 * non-zero value for this parameter is present hash session is ready
	 */
	uint8_t sessionReady;
} hash_params;

#if ZEPHYR_HASH_API_MIDLEYER_TEST_SUPPORT
void hash_engine_function_test(void);     // hash functions testing
#endif

int hash_engine_sha_calculate(enum hash_algo algo, const uint8_t *data, size_t length, uint8_t *hash, size_t hash_length);
int hash_engine_start(enum hash_algo algo);
int hash_engine_update(const uint8_t *data, size_t length);
int hash_engine_finish(uint8_t *hash, size_t hash_length);
void hash_engine_cancel(void);

