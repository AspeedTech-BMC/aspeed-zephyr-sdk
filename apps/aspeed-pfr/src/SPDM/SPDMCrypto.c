/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>

#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMContext.h"

LOG_MODULE_REGISTER(spdm_crytpo, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_crypto_sign(void *ctx, uint8_t *input, size_t input_size, uint8_t *sig, size_t *sig_size,
		bool sig_context_hash, uint8_t *sig_context, size_t sig_context_len)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	int ret = -1;
	uint8_t *message_hash = NULL;
	if (sig_context_hash) {
		/* DSP0274 v1.2.1: 15 Signature generation */
		uint8_t *M = malloc(100 + input_size);
		if (M == NULL) {
			LOG_ERR("Failed to allocate M size=%d", 100 + input_size);
			ret = -1;
			goto cleanup;
		}
		memset(M, 0, 100 + input_size);
		/* PREFIX = VERSION STRING(16) * 4 + Zero Padding + SPDM Context String = 100 bytes */
		memcpy(M, SPDM_PREFIX_VERSION_12, 64);
		memcpy(M + (100 - sig_context_len), sig_context, sig_context_len);

		/* Concat the PREFIX and data_to_be_signed */
		memcpy(M + 100, input, input_size);
		LOG_HEXDUMP_DBG(M, 100 + input_size, "M:");

		/* Final message hash */
		message_hash = malloc(input_size);
		if (message_hash == NULL) {
			LOG_ERR("Failed to allocate message_hash size=%d", input_size);
			free(M);
			goto cleanup;
		}
		mbedtls_sha512(M, 100 + input_size, message_hash, true);
		free(M);
		M = NULL;
	} else {
		message_hash = input;
	}



	switch(context->remote.algorithms.base_asym_sel) {
	case SPDM_ALGORITHMS_BASE_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
	{
		mbedtls_mpi r, s;
		mbedtls_mpi_init(&r);
		mbedtls_mpi_init(&s);

		LOG_HEXDUMP_INF(message_hash, input_size, "Message Hash");
		ret = mbedtls_ecdsa_sign(&context->key_pair.MBEDTLS_PRIVATE(grp),
				&r, &s, &context->key_pair.MBEDTLS_PRIVATE(d),
				message_hash, input_size, context->random_callback, context);

		if (ret != 0) {
			LOG_HEXDUMP_ERR(input, input_size, "Hash:");
			LOG_ERR("mbedtls_ecdsa_sign ret=%x", -ret);
		}
		mbedtls_mpi_write_binary(&r, sig, 48);
		mbedtls_mpi_write_binary(&s, sig + 48, 48);
		*sig_size = 96;
		mbedtls_mpi_free(&s);
		mbedtls_mpi_free(&r);
		ret = 0;
		break;
	}
	default:
		LOG_ERR("Unsupported BaseAsymSel algorithm %08x", context->remote.algorithms.base_asym_sel);
		ret = -1;
		break;
	}

cleanup:
	if (sig_context_hash && message_hash) {
		free(message_hash);
		message_hash = NULL;
	}

	return ret;
}

int spdm_crypto_verify(void *ctx, uint8_t slot_id, uint8_t *input, size_t input_size,
		uint8_t *sig, size_t sig_size,
		bool sig_context_hash, uint8_t *sig_context, size_t sig_context_len)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	int ret = -1;

	/* Get Public Key for verification */
	mbedtls_x509_crt *cur = &context->remote.certificate.certs[slot_id].chain;
	size_t cert_index = 0;
	while (cur) {
		++cert_index;
		if (cur->next != NULL)
			cur = cur->next;
		else {
			break;
		}
	}

	if (cur == NULL) {
		ret = -1;
		goto cleanup;
	}

	uint8_t *message_hash = NULL;
	if (sig_context_hash) {
		/* DSP0274 v1.2.1: 15 Signature generation */
		uint8_t *M = malloc(100 + input_size);
		if (M == NULL) {
			LOG_ERR("Failed to allocate M size=%d", 100 + input_size);
			ret = -1;
			goto cleanup;
		}
		memset(M, 0, 100 + input_size);
		/* PREFIX = VERSION STRING(16) * 4 + Zero Padding + SPDM Context String = 100 bytes */
		memcpy(M, SPDM_PREFIX_VERSION_12, 64);
		memcpy(M + (100 - sig_context_len), sig_context, sig_context_len);

		/* Concat the PREFIX and data_to_be_signed */
		memcpy(M + 100, input, input_size);

		/* Final message hash */
		message_hash = malloc(input_size);
		if (message_hash == NULL) {
			LOG_ERR("Failed to allocate message_hash size=%d", input_size);
			free(M);
			goto cleanup;
		}
		mbedtls_sha512(M, 100 + input_size, message_hash, true);
		LOG_HEXDUMP_DBG(input, input_size, "M1/M2 L1L2:");
		LOG_HEXDUMP_DBG(M, 100+input_size, "M");
		LOG_HEXDUMP_DBG(message_hash, input_size, "message_hash");
		free(M);
		M = NULL;
	} else {
		message_hash = input;
	}

	/* TODO: EC vs RSA */
	switch(mbedtls_pk_ec(cur->pk)->MBEDTLS_PRIVATE(grp).id) {
	case MBEDTLS_ECP_DP_SECP384R1:
	{
		mbedtls_mpi r, s;
		mbedtls_mpi_init(&r);
		mbedtls_mpi_init(&s);

		mbedtls_mpi_read_binary(&r, (uint8_t *)sig, 48);
		mbedtls_mpi_read_binary(&s, (uint8_t *)sig + 48, 48);

		ret = mbedtls_ecdsa_verify(
				&mbedtls_pk_ec(cur->pk)->MBEDTLS_PRIVATE(grp),
				message_hash, input_size,
				&mbedtls_pk_ec(cur->pk)->MBEDTLS_PRIVATE(Q),
				&r, &s);
		if (ret != 0) {
			LOG_HEXDUMP_ERR(input, input_size, "Hash:");
			LOG_ERR("mbedtls_ecdsa_verify ret=%x", -ret);
		}
		mbedtls_mpi_free(&s);
		mbedtls_mpi_free(&r);
		break;
	}
	default:
		ret = -1;
		break;
	}

	if (sig_context_hash) {
		free(message_hash);
		message_hash = NULL;
	}
cleanup:
	return ret;
}
