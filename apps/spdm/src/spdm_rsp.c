/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <assert.h>
#include <kernel.h>

#include <spdm_rsp.h>
#include <spdm_fifo.h>

#include <logging/log.h>

LOG_MODULE_REGISTER(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

#include <industry_standard/spdm.h>
#include <library/spdm_common_lib.h>
#include <library/spdm_responder_lib.h>
#include <library/spdm_transport_mctp_lib.h>
#include <hal/library/memlib.h>

#include <cert.h>

#define NDEBUG
#define LIBSPDM_MAX_SPDM_MSG_SIZE 2048
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE (1024 - 0x100)
#define LIBSPDM_SENDER_BUFFER_SIZE LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE
#define LIBSPDM_RECEIVER_BUFFER_SIZE LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE
#define LIBSPDM_ASSERT(x) assert(x)

static bool m_send_receive_buffer_acquired = false;
static uint8_t m_send_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
static libspdm_return_t spdm_device_acquire_sender_buffer (
	void *context, void **msg_buf_ptr)
{
	LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
	*msg_buf_ptr = m_send_receive_buffer;
	libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
	m_send_receive_buffer_acquired = true;
	return LIBSPDM_STATUS_SUCCESS;
}

static void spdm_device_release_sender_buffer (
	void *context, const void *msg_buf_ptr)
{
	LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
	LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
	m_send_receive_buffer_acquired = false;
	return;
}

static libspdm_return_t spdm_device_acquire_receiver_buffer (
	void *context, void **msg_buf_ptr)
{
	LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
	*msg_buf_ptr = m_send_receive_buffer;
	libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
	m_send_receive_buffer_acquired = true;
	return LIBSPDM_STATUS_SUCCESS;
}

static void spdm_device_release_receiver_buffer (
	void *context, const void *msg_buf_ptr)
{
	LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
	LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
	m_send_receive_buffer_acquired = false;
	return;
}

static libspdm_return_t spdm_device_send_message(void *spdm_context,
					  size_t message_size,
					  const void *message,
					  uint64_t timeout)
{
//	LOG_INF("spdm_device_send_message ctx=%p buffer=%p", spdm_context, message);
//	LOG_HEXDUMP_DBG(message, message_size, "spdm_device_send_message");
	struct spdm_fifo_item_t *item = (struct spdm_fifo_item_t *)malloc(sizeof(struct spdm_fifo_item_t));
	item->fifo_reserved = NULL;
	item->message = (uint8_t *)malloc(message_size);
	memcpy(item->message, message, message_size);
	item->message_size = message_size;

	k_fifo_put(&RSP_TO_REQ, item);

	return 0;
}

static libspdm_return_t spdm_device_receive_message(void *spdm_context, size_t *message_size, void **message, uint64_t timeout)
{
	struct spdm_fifo_item_t *item = k_fifo_get(&REQ_TO_RSP, K_FOREVER);
	//LOG_INF("spdm_device_receive_message ctx=%p message=%p size=%d", spdm_context, item->message, item->message_size);

	if (item != NULL && item->message != NULL)
	{
		uint8_t *buffer = *message;
		*message_size = item->message_size;
		memcpy(buffer, item->message, item->message_size);
		//LOG_HEXDUMP_DBG(buffer, item->message_size, "Incoming message");
		free(item->message);
		free(item);
	}

	return 0;
}

void spdm_server_connection_state_callback(
    void *spdm_context, libspdm_connection_state_t connection_state)
{
	bool res;
	void *data;
	void *data1;
	size_t data_size;
	size_t data1_size;
	libspdm_data_parameter_t parameter;
	uint8_t data8;
	uint16_t data16;
	uint32_t data32;
	libspdm_return_t status;
	void *hash;
	size_t hash_size;
	const uint8_t *root_cert;
	size_t root_cert_size;
	uint8_t index;
	spdm_version_number_t spdm_version;


	uint32_t m_use_measurement_hash_algo, m_use_asym_algo, m_use_hash_algo, m_use_req_asym_algo;
	uint8_t m_use_version = SPDM_MESSAGE_VERSION_10, m_use_slot_count = 1;

	switch (connection_state) {
		case LIBSPDM_CONNECTION_STATE_NOT_STARTED:
			/* clear perserved state*/
			//spdm_clear_negotiated_state(spdm_context);
			break;

		case LIBSPDM_CONNECTION_STATE_AFTER_VERSION:
#if 0
			if ((m_exe_connection & EXE_CONNECTION_VERSION_ONLY) != 0) {
				/* GET_VERSION is done, handle special PSK use case*/
				status = spdm_provision_psk_version_only (spdm_context, false);
				if (LIBSPDM_STATUS_IS_ERROR(status)) {
					LIBSPDM_ASSERT (false);
					return;
				}
				/* pass through to NEGOTIATED */
			} else {
				/* normal action - do nothing */
				break;
			}
#else
			break;
#endif
		case LIBSPDM_CONNECTION_STATE_NEGOTIATED:

			if (m_use_version == 0) {
				libspdm_zero_mem(&parameter, sizeof(parameter));
				parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
				data_size = sizeof(spdm_version);
				libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter, &spdm_version, &data_size);
				m_use_version = spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT;
			}

			/* Provision new content*/

			libspdm_zero_mem(&parameter, sizeof(parameter));
			parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

			data_size = sizeof(data32);
			libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &data32, &data_size);
			m_use_measurement_hash_algo = data32;
			data_size = sizeof(data32);
			libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &data32, &data_size);
			m_use_asym_algo = data32;
			data_size = sizeof(data32);
			libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &data32, &data_size);
			m_use_hash_algo = data32;
			data_size = sizeof(data16);
			libspdm_get_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &data16, &data_size);
			m_use_req_asym_algo = data16;

			res = libspdm_read_responder_public_certificate_chain(m_use_hash_algo,
							 m_use_asym_algo,
							 &data, &data_size,
							 NULL, NULL);
			if (res) {
				libspdm_zero_mem(&parameter, sizeof(parameter));
				parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
				// parameter.additional_data[0] = index;
				parameter.additional_data[0] = 0;
				libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, data, data_size);

			}
#if 0
			if (m_use_req_asym_algo != 0) {
				if ((m_use_responder_capability_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP) != 0) {
					m_use_slot_id = 0xFF;
				}
				if (m_use_slot_id == 0xFF) {
					res = libspdm_read_responder_public_key(m_use_asym_algo, &data, &data_size);
					if (res) {
						libspdm_zero_mem(&parameter, sizeof(parameter));
						parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
						libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_KEY, &parameter, data, data_size);
						/* Do not free it.*/
					}
					res = libspdm_read_requester_public_key(m_use_req_asym_algo, &data, &data_size);
					if (res) {
						libspdm_zero_mem(&parameter, sizeof(parameter));
						parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
						libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_PUBLIC_KEY, &parameter, data, data_size);
						/* Do not free it.*/
					}
				} else {
					res = libspdm_read_requester_root_public_certificate(
						m_use_hash_algo, m_use_req_asym_algo, &data,
						&data_size, &hash, &hash_size);
					libspdm_x509_get_cert_from_cert_chain(
						(uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
					if (res) {
						libspdm_zero_mem(&parameter, sizeof(parameter));
						parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
						libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, (void *)root_cert, root_cert_size);
						/* Do not free it.*/
					}
				}

				if (res) {
					if (m_use_slot_id == 0xFF) {
						/* 0xFF slot is only allowed in */
						m_use_mut_auth = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
					}
					data8 = m_use_mut_auth;
					parameter.additional_data[0] = m_use_slot_id; /* req_slot_id;*/
					libspdm_set_data(spdm_context, LIBSPDM_DATA_MUT_AUTH_REQUESTED, &parameter, &data8, sizeof(data8));

					data8 = m_use_basic_mut_auth;
					parameter.additional_data[0] = m_use_slot_id; /* req_slot_id;*/
					libspdm_set_data(spdm_context, LIBSPDM_DATA_BASIC_MUT_AUTH_REQUESTED, &parameter, &data8, sizeof(data8));
				}
			}
#endif
			break;

		default:
			break;
	}

	return;
}

void spdm_server_session_state_callback(void *spdm_context,
                                        uint32_t session_id,
                                        libspdm_session_state_t session_state)
{
}

static void *spdm_server_init()
{
	void *spdm_ctx = (void *)malloc(libspdm_get_context_size());
	bool ret = false;
	
	LOG_INF("SPDM context size=%d ptr=%p", libspdm_get_context_size(), spdm_ctx);
	assert(spdm_ctx != NULL);

	libspdm_init_context(spdm_ctx);
	

	libspdm_register_device_io_func (
		spdm_ctx,
		spdm_device_send_message,
		spdm_device_receive_message);

	libspdm_register_device_buffer_func (
		spdm_ctx,
		LIBSPDM_SENDER_BUFFER_SIZE, // defined by the Integrator
		LIBSPDM_RECEIVER_BUFFER_SIZE, // defined by the Integrator
		spdm_device_acquire_sender_buffer,
		spdm_device_release_sender_buffer,
		spdm_device_acquire_receiver_buffer,
		spdm_device_release_receiver_buffer);

	libspdm_register_transport_layer_func (
		spdm_ctx,
		LIBSPDM_MAX_SPDM_MSG_SIZE, // defined by the Integrator
		LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
		LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
		libspdm_transport_mctp_encode_message,
		libspdm_transport_mctp_decode_message);

	LOG_INF("m_send_receive_buffer=%p", m_send_receive_buffer);

	size_t scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(spdm_ctx);
	void *scratch_buffer = (void *)malloc(scratch_buffer_size);

	LOG_INF("SPDM scratch_buffer size=%d ptr=%p", scratch_buffer_size, scratch_buffer);
	assert(scratch_buffer != NULL);

	libspdm_set_scratch_buffer(spdm_ctx, scratch_buffer, scratch_buffer_size);
	libspdm_data_parameter_t parameter;
	spdm_version_number_t spdm_version[3];
	uint64_t data64;
	uint32_t data32;
	uint16_t data16;
	uint8_t data8;

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	spdm_version[0] = SPDM_MESSAGE_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
	spdm_version[1] = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
	spdm_version[2] = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_SPDM_VERSION, &parameter, &spdm_version, sizeof(spdm_version));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data8 = 0;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter, &data8, sizeof(data8));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data32 = 0 |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP |
		0;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &data32, sizeof(data32));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data64 = 0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_CAPABILITY_RTT_US, &parameter, &data64, sizeof(data64));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data8 = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter, &data8, sizeof(data8));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data32 = 0 |
		SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256 |
		SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &data32, sizeof(data32));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data32 = 0 | \
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &data32, sizeof(data32));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data32 = 0 | \
		SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
		SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &data32, sizeof(data32));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 |
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
		0;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
		  &data16, sizeof(data16));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 |
		SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
		SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter, &data16, sizeof(data16));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 | \
		SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter, &data16, sizeof(data16));

	/*
	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 | \
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &data16, sizeof(data16));
	*/
	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 | \
		SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16, sizeof(data16));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
		  &data8, sizeof(data8));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data8 = 0xF0;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_HEARTBEAT_PERIOD, &parameter,
		  &data8, sizeof(data8));

	#if 0
	libspdm_register_get_response_func(
		spdm_ctx, spdm_get_response_vendor_defined_request);
	#endif

	libspdm_register_session_state_callback_func(
		spdm_ctx, spdm_server_session_state_callback);
	libspdm_register_connection_state_callback_func(
		spdm_ctx, spdm_server_connection_state_callback);

#if LIBSPDM_CHECK_SPDM_CONTEXT
	ret = libspdm_check_context(spdm_ctx);
	if (!ret) {
		LOG_ERR("SPDM Context check invalid");
		goto cleanup;
	}
#endif

	return spdm_ctx;
cleanup:
	libspdm_deinit_context(spdm_ctx);
	free(spdm_ctx);
	return NULL;
}

void spdm_responder_main(void *a, void *b, void *c)
{
	void *spdm_context = NULL;
	spdm_context = spdm_server_init();
	if (spdm_context != NULL) {
		// spdm_device_evidence_collection(spdm_context);
		while (1) {
			libspdm_return_t ret = libspdm_responder_dispatch_message(spdm_context);
			if (LIBSPDM_STATUS_IS_ERROR(ret)) {
				LOG_ERR("libspdm_responder_dispatch_message ret=%08x", ret);
				continue;
			}
#if 0
			else if (LIBSPDM_STATUS_IS_SUCCESS(ret)) {
				LOG_INF("Success");

			}
#endif
		}
		libspdm_deinit_context(spdm_context);
		free(spdm_context);
	}

}
