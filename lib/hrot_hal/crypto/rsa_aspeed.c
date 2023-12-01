/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/crypto/rsa_structs.h>
#include <zephyr/crypto/rsa.h>
#include <zephyr/logging/log.h>
#include "rsa_aspeed.h"

LOG_MODULE_REGISTER(rsa_middle_aspeed, CONFIG_LOG_DEFAULT_LEVEL);

#ifdef CONFIG_RSA_ASPEED
#define RSA_DRV_NAME DEVICE_DT_NAME(DT_INST(0, aspeed_rsa))
#endif

int decrypt_aspeed(const struct rsa_key *key, const uint8_t *encrypted, size_t in_length, uint8_t *decrypted, size_t out_length)
{
	const struct device *dev = device_get_binding(RSA_DRV_NAME);
	struct rsa_ctx ini;
	struct rsa_pkt pkt;
	int status = 1;

	if (dev == NULL) {
		LOG_ERR("device not found");
		return status;
	}

	pkt.in_buf = (uint8_t *)encrypted;
	pkt.in_len = in_length;
	pkt.out_buf = decrypted;
	pkt.out_buf_max = out_length;
	status = rsa_begin_session(dev, &ini, (struct rsa_key *)key);
	if (status)
		LOG_ERR("rsa_begin_session fail: %d", status);

	rsa_decrypt(&ini, &pkt);
	rsa_free_session(dev, &ini);

	return status;
}

/**
 * Verify that a signature matches the expected SHA-256 hash.  The signature is expected to be
 * in PKCS v1.5 format.
 *
 * @param key The public key to decrypt the signature.
 * @param signature The signature to validate.
 * @param sig_length The length of the signature.
 * @param match The value that should match the decrypted signature.
 * @param match_length The length of the match value.
 *
 * @return 0 if the signature matches the digest or an error code.
 */
int sig_verify_aspeed(const struct rsa_key *key, const uint8_t *signature, int sig_length, const uint8_t *match, size_t match_length)
{
	const struct device *dev = device_get_binding(RSA_DRV_NAME);
	char plain_text[sig_length];
	struct rsa_ctx ini;
	struct rsa_pkt pkt;
	int status = 1;

	if (dev == NULL) {
		LOG_ERR("device not found");
		return status;
	}

	pkt.in_buf = (uint8_t *)signature;
	pkt.in_len = sig_length;
	pkt.out_buf = plain_text;
	pkt.out_buf_max = sig_length;
	memset(plain_text, 0, sig_length);
	status = rsa_begin_session(dev, &ini, (struct rsa_key *)key);
	if (status)
		LOG_ERR("begin session fail: %d", status);

	rsa_verify(&ini, &pkt);
	rsa_free_session(dev, &ini);
	/* ignore pkcs1.5 padding, only compare the digest */
	status = memcmp(plain_text + pkt.out_len - match_length, match, match_length);

	if (status != 0)
		LOG_HEXDUMP_ERR(plain_text, sig_length, "result text:");
	else
		LOG_DBG("hardware verification successful");

	return status;
}

