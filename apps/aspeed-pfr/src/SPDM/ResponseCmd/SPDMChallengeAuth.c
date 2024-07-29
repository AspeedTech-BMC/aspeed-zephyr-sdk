/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr/random/rand32.h>
#include <mbedtls/sha512.h>

#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_handle_challenge(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	int ret;
	/* Deserialize */

	// TODO: Check if slot exists
	uint8_t slot_id = req_msg->header.param1;
	uint8_t measurmenent_summary_hash = req_msg->header.param2;

	if ((req_msg->header.spdm_version != SPDM_VERSION_10) &&
			(req_msg->header.spdm_version != SPDM_VERSION_11) &&
			(req_msg->header.spdm_version != SPDM_VERSION_12)) {
		LOG_ERR("Unsupported header SPDM_VERSION %x", req_msg->header.spdm_version);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_MAJOR_VERSION_MISMATCH;
		ret = -1;
		goto cleanup;
	} else if (slot_id > 7 || !(context->local.certificate.slot_mask & (1<<slot_id))) {
		LOG_ERR("CHALLENGE Slot[%d] not exist. Slot_mask=%02x",
				slot_id, context->local.certificate.slot_mask);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
		ret = -1;
		goto cleanup;
	} else if (req_msg->buffer.write_ptr != 32) {
		LOG_ERR("CHALLENGE message length incorrect %d",
				req_msg->buffer.write_ptr + 4);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
		ret = -1;
		goto cleanup;
	}

	/* Serialize the result */
	// H + 32 + H + 2 + OpaqueLen + S
	// H:  Cert Chain Has
	// 32: Random Selected Nonce
	// H:  MeasurementSummaryHash
	// 2:   Opaque Length
	// OPL: Opaque Data
	// S:  Signature Length
	size_t hash_length = spdm_context_base_hash_size(context);
	uint32_t opaque_length = 0;
	uint32_t signature_length = MBEDTLS_ECDSA_MAX_LEN;
	spdm_buffer_init(&rsp_msg->buffer, hash_length + 32 + hash_length + 2 + opaque_length + signature_length);

	rsp_msg->header.spdm_version = req_msg->header.spdm_version;
	rsp_msg->header.request_response_code = SPDM_RSP_CHALLENGE_AUTH;
	rsp_msg->header.param1 = slot_id; // SlotID for request
	rsp_msg->header.param2 = context->local.certificate.slot_mask; // SlotMask

	// Calculate Certificate Chain hash
	uint8_t hash[MBEDTLS_MD_MAX_SIZE];
	mbedtls_sha512(context->local.certificate.certs[slot_id].data,
			context->local.certificate.certs[slot_id].size,
			hash, 1);
	spdm_buffer_append_array(&rsp_msg->buffer, hash, hash_length);

	// Nonce
	spdm_buffer_append_nonce(&rsp_msg->buffer);

	// TODO: Measurement Summary Hash
	if (measurmenent_summary_hash == 0x01) {
		mbedtls_sha512(req_msg->buffer.data, 32, hash, /* is384 */ 1);
		spdm_buffer_append_array(&rsp_msg->buffer, hash, hash_length);
	} else if (measurmenent_summary_hash == 0xFF) {
		mbedtls_sha512(req_msg->buffer.data, 32, hash, /* is384 */ 1);
		spdm_buffer_append_array(&rsp_msg->buffer, hash, hash_length);
	}

	// OpaqueLength
	spdm_buffer_append_u16(&rsp_msg->buffer, opaque_length);

	// Opaque Data: Reserved for now.
	// Signature by selected ALGORITHMS by alias id private key
	// Alias ID Key is in context->key_pair
	// Signature = Sign(SK, Hash(M1))
	// - Sign(): Algorithm selected in ALGORITHMS (SECP384R1)
	// - SK: private key associated with the leaf ceritficate of
	//       the responder in slot=Param1 of the CHALLENGE request message
	// - Hash(): Algorithm selected in ALGORITHMS (SHA384)
	// - M1: Concatenate(A, B, C) from responder
	// - A: Concatenate(GET_VERSION, VERSION, GET_CAPABILITEIS,
	//                  CAPABILITIES, NEGOTIATE_ALGORITHMS, ALGORITHMS)
	// - B: Concatenate(GET_DIGEST, DIGEST, GET_CERTIFICATE, CERTIFICATE)
	// - C: Concatenate(CHALLENGE, CHALLENGE_AUTH\Signature)
	uint8_t sig[MBEDTLS_ECDSA_MAX_LEN];
	size_t sig_len;

	// Calculate HASH(M1)
	spdm_context_update_m1m2_hash(context, req_msg, rsp_msg);
	mbedtls_sha512_finish(&context->m1m2_context, hash);
	spdm_context_reset_m1m2_hash(context);

	ret = spdm_crypto_sign(context, hash, hash_length, sig, &sig_len,
			req_msg->header.spdm_version == SPDM_VERSION_12,
			SPDM_SIGN_CONTEXT_M1M2_RSP, strlen(SPDM_SIGN_CONTEXT_M1M2_RSP));
	if (ret == 0) {
		LOG_HEXDUMP_INF(sig, sig_len, "Signature:");
		spdm_buffer_append_array(&rsp_msg->buffer, sig, sig_len);
	} else {
		LOG_ERR("CHALLENGE Failed to sign message");
		rsp_msg->header.request_response_code = SPDM_RSP_ERROR;
		rsp_msg->header.param1 = SPDM_ERROR_CODE_UNSPECIFIED;
		rsp_msg->header.param2 = 0;
		spdm_buffer_release(&rsp_msg->buffer);
		ret = -1;
	}

cleanup:
	return ret;
}
