/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr/random/rand32.h>
#include <stdlib.h>

#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_challenge(void *ctx, uint8_t slot_id, uint8_t measurements)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;
	int ret;

	req_msg.header.spdm_version = context->local.version.version_number_selected;
	req_msg.header.request_response_code = SPDM_REQ_CHALLENGE;
	req_msg.header.param1 = slot_id; // SlotID or 0xFF
	req_msg.header.param2 = measurements; // No measuments, TCB measurement, All measurement

	spdm_buffer_init(&req_msg.buffer, 32);
	spdm_buffer_init(&rsp_msg.buffer, 0);
	spdm_buffer_append_nonce(&req_msg.buffer);

	ret = spdm_send_request(context, &req_msg, &rsp_msg);
	if (ret != 0) {
		LOG_ERR("CHALLENGE failed %x", ret);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.spdm_version != req_msg.header.spdm_version) {
		LOG_ERR("Unsupported header SPDM_VERSION Req %x Rsp %x",
				req_msg.header.spdm_version, rsp_msg.header.spdm_version);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.request_response_code != SPDM_RSP_CHALLENGE_AUTH) {
		LOG_ERR("Expecting CHALLENGE_AUTH message but got %02x Param[%02x,%02x]",
				rsp_msg.header.request_response_code,
				rsp_msg.header.param1,
				rsp_msg.header.param2);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.buffer.write_ptr < 48 + 32 + (measurements?48:0) + 2 + 96) {
		// Exact length require to read OpaqueLength
		LOG_ERR("CHALLENGE_AUTH message length incorrect len=%d", rsp_msg.buffer.write_ptr);
		ret = -1;
		goto cleanup;
	}

	/* Verify the CHALLENGE_AUTH result 
	 * Off         Len    Name
	 *    0,         H    CertChainHash
	 *    H,        32    Nonce
	 * 32+H,         H    MeasuremenHash
	 * 32+2H,        2    OpaqueDataLength (O)
	 * 34+2H,        O    OpaqueDataData
	 * 34+2H+O, SigLen    Signature
	 */
	LOG_HEXDUMP_INF(&rsp_msg.header, 4, "CHALLENGE_AUTH HEADER:");
	LOG_HEXDUMP_DBG(rsp_msg.buffer.data, rsp_msg.buffer.write_ptr, "CHALLENGE_AUTH:");

	/* Verify the CHALLENGE_AUTH signature */
	uint8_t hash[48];

	/* Signature is excluded from M1/M2 hash */
	rsp_msg.buffer.write_ptr -= 96;
	spdm_context_update_m1m2_hash(context, &req_msg, &rsp_msg);
	rsp_msg.buffer.write_ptr += 96;
	mbedtls_sha512_finish(&context->m1m2_context, hash);
	spdm_context_reset_m1m2_hash(context);

	ret = spdm_crypto_verify(context, slot_id,
			hash, 48,
			(uint8_t *)rsp_msg.buffer.data + rsp_msg.buffer.write_ptr - 96, 96,
			req_msg.header.spdm_version == SPDM_VERSION_12,
			SPDM_SIGN_CONTEXT_M1M2_RSP, strlen(SPDM_SIGN_CONTEXT_M1M2_RSP));
	LOG_INF("CHALLENG_AUTH SIGNATURE VERIFY ret=%x", -ret);
	if (ret < 0) {
		LOG_HEXDUMP_ERR(hash, 48, "Requester M2 hash:");
		ret = -1;
	}

cleanup:
	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return ret;
}
