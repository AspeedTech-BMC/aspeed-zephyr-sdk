/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr/random/rand32.h>

#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_get_measurements(void *ctx,
		uint8_t request_attribute, uint8_t measurement_operation,
		uint8_t *number_of_blocks,
		void *possible_measure)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;
	int ret = 0;

	AFM_DEVICE_MEASUREMENT_VALUE *possible_measurement = possible_measure;

	req_msg.header.spdm_version = context->local.version.version_number_selected;
	req_msg.header.request_response_code = SPDM_REQ_GET_MEASUREMENTS;
	req_msg.header.param1 = request_attribute; // GET_MEASUREMENTS request attributes : NL
	req_msg.header.param2 = measurement_operation;

	spdm_buffer_init(&req_msg.buffer, 33 /* NONCE + SPDM 1.2: + 1*/);
	spdm_buffer_init(&rsp_msg.buffer, 0);

	if (req_msg.header.param1) {
		// nonce(32)
		spdm_buffer_append_nonce(&req_msg.buffer);

		// SPDM 1.2 Requested Slot ID
		if (req_msg.header.spdm_version == SPDM_VERSION_12) {
			spdm_buffer_append_u8(&req_msg.buffer, 0x01);
		}
	}


	ret = spdm_send_request(context, &req_msg, &rsp_msg);

	if (ret != 0) {
		LOG_ERR("GET_MEASUREMENTS failed %x", ret);
		ret = -3;
		goto cleanup;
	} else if (rsp_msg.header.spdm_version != req_msg.header.spdm_version) {
		LOG_ERR("Unsupported header SPDM_VERSION Req %x Rsp %x",
				req_msg.header.spdm_version, rsp_msg.header.spdm_version);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.request_response_code != SPDM_RSP_MEASUREMENTS) {
		LOG_DBG("GET MEASUREMENTS FAILED Error Code %02x %02x",
				rsp_msg.header.param1, rsp_msg.header.param2);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.buffer.write_ptr < 4) {
		LOG_ERR("MEASUREMENTS message length incorrect %d", rsp_msg.buffer.write_ptr);
		ret = -1;
		goto cleanup;
	}

	if (measurement_operation == SPDM_MEASUREMENT_OPERATION_TOTAL_NUMBER) {
		*number_of_blocks = rsp_msg.header.param1;
	} else if (measurement_operation == SPDM_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
		*number_of_blocks = rsp_msg.header.param1;
	}

	LOG_HEXDUMP_DBG(&rsp_msg.header, 4, "MEASUREMENTS Header:");
	LOG_HEXDUMP_DBG(rsp_msg.buffer.data, rsp_msg.buffer.size, "MEASUREMENTS:");

	/* Process L1L2 hash */
	if (request_attribute == 0x00) {
		spdm_context_update_l1l2_hash(context, &req_msg, &rsp_msg);
	} else if (request_attribute == 0x01) {
		if (rsp_msg.buffer.write_ptr < 96) {
			LOG_ERR("MEASUREMENTS message length incorrect %d", rsp_msg.buffer.write_ptr);
			ret = -1;
			goto cleanup;
		}

		/* Signature is excluded from L1/L2 Hash */
		rsp_msg.buffer.write_ptr -= 96;
		spdm_context_update_l1l2_hash(context, &req_msg, &rsp_msg);
		rsp_msg.buffer.write_ptr += 96;

		/* Verify signature */
		uint8_t hash[48];

		mbedtls_sha512_finish(&context->l1l2_context, hash);
		spdm_context_reset_l1l2_hash(context);
		if (req_msg.header.spdm_version == SPDM_VERSION_12) {
			/* Append VCA to L1L2 for SPDM 1.2 */
			spdm_context_update_l1l2_hash_buffer(context, &context->message_a);
		}

		/* DSP0274_1.0.1: 
		 * 310: Public key associated with the slot 0 certificate of the Responder.
		 */
		ret = spdm_crypto_verify(context, 0, hash, 48,
				(uint8_t *)rsp_msg.buffer.data + rsp_msg.buffer.write_ptr - 96, 96,
				req_msg.header.spdm_version == SPDM_VERSION_12,
				SPDM_SIGN_CONTEXT_L1L2_RSP, strlen(SPDM_SIGN_CONTEXT_L1L2_RSP));
		LOG_INF("GET_MEASUREMENT SIGNATURE VERIFY ret=%x", -ret);
		if (ret < 0) {
			LOG_HEXDUMP_ERR(hash, 48, "Requester L2 hash:");
			ret = -2;
			goto cleanup;
		}

		uint8_t number_of_blocks = 0;
		uint32_t meas_record_len = 0;
		uint8_t device_meas_index = 0;
		uint8_t device_meas_spec = 0;
		uint16_t device_meas_size = 0;
		uint8_t device_meas_value_type = 0;
		uint16_t device_meas_value_size = 0;
		uint8_t *device_meas = NULL;


		spdm_buffer_get_u8(&rsp_msg.buffer, &number_of_blocks);
		if (number_of_blocks != 1) {
			LOG_ERR("number_of_blocks %d", number_of_blocks);
			ret = -1;
			goto cleanup;
		}

		spdm_buffer_get_u24(&rsp_msg.buffer, &meas_record_len);
		// TODO: Check total length
		
		spdm_buffer_get_u8(&rsp_msg.buffer, &device_meas_index);
		spdm_buffer_get_u8(&rsp_msg.buffer, &device_meas_spec);
		spdm_buffer_get_u16(&rsp_msg.buffer, &device_meas_size);
		spdm_buffer_get_u8(&rsp_msg.buffer, &device_meas_value_type);
		spdm_buffer_get_u16(&rsp_msg.buffer, &device_meas_value_size);

		device_meas = (uint8_t *)rsp_msg.buffer.data + rsp_msg.buffer.read_ptr;

		if (possible_measurement != NULL) {
			/* Verify measurements */
			if (device_meas_value_size != possible_measurement->ValueSize) {
				LOG_ERR("Measurement size mismatch expect %d but got %d",
						possible_measurement->ValueSize, device_meas_size);
				ret = -1;
				goto cleanup;
			}
			uint8_t *meas_value = possible_measurement->Values;

			for (uint8_t i = 0; i<possible_measurement->PossibleMeasurements; ++i) {
				if (memcmp(device_meas, meas_value, possible_measurement->ValueSize) == 0) {
					ret = 0;
					goto cleanup;
				} else {
					meas_value += possible_measurement->ValueSize;
				}
			}

			// Not matching any measurement.
			LOG_ERR("Not matching any measurement");
			ret = -1;
		}
	}

cleanup:
	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return ret;
}

