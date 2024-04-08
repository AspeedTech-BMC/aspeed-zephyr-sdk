/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <crypto/hash.h>
#include "hash_wrapper.h"
#include <crypto/hash_aspeed.h>
static int hash_wrapper_calculate_sha256(struct hash_engine *engine, const uint8_t *data,
					 size_t length, uint8_t *hash, size_t hash_length)
{
	enum hash_algo shaAlgo = CRYPTO_HASH_ALGO_SHA256;

	return hash_engine_sha_calculate(shaAlgo, data, length, hash, hash_length);
}

static int hash_wrapper_start_sha256(struct hash_engine *engine)
{
	enum hash_algo shaAlgo = CRYPTO_HASH_ALGO_SHA256;

	return hash_engine_start(shaAlgo);
}

static int hash_wrapper_calculate_sha384(struct hash_engine *engine, const uint8_t *data,
					 size_t length, uint8_t *hash, size_t hash_length)
{
	enum hash_algo shaAlgo = CRYPTO_HASH_ALGO_SHA384;

	return hash_engine_sha_calculate(shaAlgo, data, length, hash, hash_length);
}

static int hash_wrapper_start_sha384(struct hash_engine *engine)
{
	enum hash_algo shaAlgo = CRYPTO_HASH_ALGO_SHA384;

	return hash_engine_start(shaAlgo);
}

static int hash_wrapper_update(struct hash_engine *engine, const uint8_t *data, size_t length)
{
	return hash_engine_update(data, length);
}

static int hash_wrapper_finish(struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	return hash_engine_finish(hash, hash_length);
}

static void hash_wrapper_cancel(struct hash_engine *engine)
{
	hash_engine_cancel();
}
/**
 * Initialize an mbed TLS hash engine.
 *
 * @param engine The hash engine to initialize.
 *
 * @return 0 if the hash engine was successfully initialized or an error code.
 */
int hash_wrapper_init(struct hash_engine *engine)
{
	if (engine == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	memset(engine, 0, sizeof(struct hash_engine));

	engine->calculate_sha256 = hash_wrapper_calculate_sha256;
	engine->start_sha256 = hash_wrapper_start_sha256;
	engine->calculate_sha384 = hash_wrapper_calculate_sha384;
	engine->start_sha384 = hash_wrapper_start_sha384;
	engine->update = hash_wrapper_update;
	engine->finish = hash_wrapper_finish;
	engine->cancel = hash_wrapper_cancel;

	return 0;
}
