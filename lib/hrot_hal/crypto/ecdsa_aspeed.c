/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/crypto/ecdsa_structs.h>
#include <zephyr/crypto/ecdsa.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ecdsa_middle_aspeed, CONFIG_LOG_DEFAULT_LEVEL);

#ifdef CONFIG_ECDSA_ASPEED
#define ECDSA_DRV_NAME DEVICE_DT_NAME(DT_INST(0, aspeed_ecdsa))
#endif

/**
 * This function verifies the expected SHA384 hash and EC signature (for secp384) for a given data.
 *
 * The function calculate_sha is called initially to obtain the hash output of the data
 * and this hash data will be transfered to the ecdsa block to be used for signature
 * verification.
 *
 * @param public_key_x : Q(x) public key
 * @param public_key_y : Q(y) public key
 * @param digest : hash data
 * @param length : digest length
 * @param signature_r : signature r
 * @param signature_s : signature s
 *
 * @return 0 if the digest matches the signature or an error code.
 *
 */
int aspeed_ecdsa_verify_middlelayer(uint8_t *public_key_x, uint8_t *public_key_y,
	const uint8_t *digest, size_t length, uint8_t *signature_r, uint8_t *signature_s)
{
	const struct device *dev = device_get_binding(ECDSA_DRV_NAME);
	struct ecdsa_ctx ini;
	struct ecdsa_pkt pkt;
	struct ecdsa_key ek;
	int status = 1;

	if (dev == NULL) {
		LOG_ERR("device not found");
		return status;
	}

	if (length != 48) {
		LOG_ERR("digest length not support, %d", length);
		return status;
	}

	ek.curve_id = ECC_CURVE_NIST_P384;
	ek.qx = public_key_x;
	ek.qy = public_key_y;
	pkt.m = (uint8_t *) digest;
	pkt.r = signature_r;
	pkt.s = signature_s;
	pkt.m_len = length;
	pkt.r_len = length;
	pkt.s_len = length;

	status = ecdsa_begin_session(dev, &ini, &ek);
	if (status) {
		LOG_ERR("begin session failed: %d", status);
		return status;
	}

	status = ecdsa_verify(&ini, &pkt);
	ecdsa_free_session(dev, &ini);
	return status;
}

