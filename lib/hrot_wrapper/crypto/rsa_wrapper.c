/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <zephyr/crypto/rsa_structs.h>
#include <zephyr/crypto/rsa.h>
#include <crypto/rsa_aspeed.h>
#include "rsa_wrapper.h"

int rsa_wrapper_generate_key(struct rsa_engine *engine, struct rsa_private_key *key, int bits)
{
	return 0;
}

int rsa_wrapper_init_private_key(struct rsa_engine *engine, struct rsa_private_key *key,
				 const uint8_t *der, size_t length)
{
	return 0;
}

int rsa_wrapper_init_public_key(struct rsa_engine *engine, struct rsa_public_key *key,
				const uint8_t *der, size_t length)
{
	return 0;
}

void rsa_wrapper_release_key(struct rsa_engine *engine, struct rsa_private_key *key)
{

}

int rsa_wrapper_get_private_key_der(struct rsa_engine *engine, const struct rsa_private_key *key,
				    uint8_t **der, size_t *length)
{
	return 0;
}

int rsa_wrapper_get_public_key_der(struct rsa_engine *engine, const struct rsa_private_key *key,
				   uint8_t **der, size_t *length)
{
	return 0;
}

int rsa_wrapper_decrypt(struct rsa_engine *engine, const struct rsa_private_key *key,
			const uint8_t *encrypted, size_t in_length, const uint8_t *label, size_t label_length,
			enum hash_type pad_hash, uint8_t *decrypted, size_t out_length)
{
	return decrypt_aspeed((struct rsa_key *)key, encrypted, in_length, decrypted, out_length);
}

int rsa_wrapper_sig_verify(struct rsa_engine *engine, const struct rsa_public_key *key,
			   const uint8_t *signature, size_t sig_length, enum hash_type sig_hash, const uint8_t *match, size_t match_length)
{
	struct rsa_key driver_key;

	driver_key.m = (char *)key->modulus;
	driver_key.m_bits = (uint32_t)(key->mod_length * 8);
	driver_key.e = (char *)&key->exponent;
	driver_key.e_bits = 24;
	driver_key.d = NULL;
	driver_key.d_bits =  0;

	return sig_verify_aspeed(&driver_key, signature, sig_length, match, match_length);
}

/**
 * Initialize an aspeed RSA engine.
 *
 * @param engine The RSA engine to initialize.
 *
 * @return 0 if the RSA engine was successfully initialize or an error code.
 */
int rsa_wrapper_init(struct rsa_engine_wrapper *engine)
{
	if (engine == NULL)
		return RSA_ENGINE_INVALID_ARGUMENT;

	memset(engine, 0, sizeof(struct rsa_engine_wrapper));

	engine->base.generate_key = rsa_wrapper_generate_key;
	engine->base.init_private_key = rsa_wrapper_init_private_key;
	engine->base.init_public_key = rsa_wrapper_init_public_key;
	engine->base.release_key = rsa_wrapper_release_key;
	engine->base.get_private_key_der = rsa_wrapper_get_private_key_der;
	engine->base.get_public_key_der = rsa_wrapper_get_public_key_der;
	engine->base.decrypt = rsa_wrapper_decrypt;
	engine->base.sig_verify = rsa_wrapper_sig_verify;

	return 0;
}
