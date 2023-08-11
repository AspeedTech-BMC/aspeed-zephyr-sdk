/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include "kernel.h"
#include "library/cryptlib/cryptlib_cert.h"
#include "library/spdm_return_status.h"
#include <stdlib.h>
#include <assert.h>

#include <zephyr.h>
#include <logging/log.h>

#include <spdm_fifo.h>

LOG_MODULE_REGISTER(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

#include <industry_standard/spdm.h>
#include <library/spdm_common_lib.h>
#include <library/spdm_requester_lib.h>
#include <library/spdm_transport_mctp_lib.h>
#include <hal/library/memlib.h>
#include <hal/library/cryptlib/cryptlib_cert.h>
#include <spdm_device_secret_lib_internal.h>
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
	//LOG_INF("spdm_device_send_message ctx=%p buffer=%p", spdm_context, message);
	LOG_HEXDUMP_INF(message, message_size, "spdm_device_send_message");
	
	struct spdm_fifo_item_t *item = (struct spdm_fifo_item_t *)malloc(sizeof(struct spdm_fifo_item_t));
	item->fifo_reserved = NULL;
	item->message = (uint8_t *)malloc(message_size);
	memcpy(item->message, message, message_size);
	item->message_size = message_size;

	k_fifo_put(&REQ_TO_RSP, item);
	//k_msleep(2);
	return 0;
}


static libspdm_return_t spdm_device_receive_message(void *spdm_context, size_t *message_size, void **message, uint64_t timeout)
{
	struct spdm_fifo_item_t *item = k_fifo_get(&RSP_TO_REQ, K_FOREVER);
	//k_msleep(2);
	//LOG_INF("spdm_device_receive_message ctx=%p message=%p size=%d", spdm_context, item->message, item->message_size);

	if (item != NULL && item->message != NULL)
	{
		uint8_t *buffer = *message;
		*message_size = item->message_size;
		memcpy(buffer, item->message, item->message_size);
		LOG_HEXDUMP_INF(buffer, item->message_size, "Incoming message");
		free(item->message);
		free(item);
	}

	return 0;
}

static void *spdm_client_init()
{
	void *spdm_ctx = (void *)malloc(libspdm_get_context_size());
	libspdm_return_t ret;
	bool res;
	
	LOG_INF("SPDM context size=%d ptr=%p", libspdm_get_context_size(), spdm_ctx);
	assert(spdm_ctx != NULL);

	libspdm_init_context(spdm_ctx);
	

	libspdm_register_device_io_func (
		spdm_ctx,
		spdm_device_send_message,
		spdm_device_receive_message);

	libspdm_register_transport_layer_func (
		spdm_ctx,
		LIBSPDM_MAX_SPDM_MSG_SIZE, // defined by the Integrator
		LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
		LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
		libspdm_transport_mctp_encode_message,
		libspdm_transport_mctp_decode_message);

	libspdm_register_device_buffer_func (
		spdm_ctx,
		LIBSPDM_SENDER_BUFFER_SIZE, // defined by the Integrator
		LIBSPDM_RECEIVER_BUFFER_SIZE, // defined by the Integrator
		spdm_device_acquire_sender_buffer,
		spdm_device_release_sender_buffer,
		spdm_device_acquire_receiver_buffer,
		spdm_device_release_receiver_buffer);


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
	data32 = 0 | \
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
		/* SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP | */
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
		/* SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER | */
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP |
		/* SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
	  * SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP |*/
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
	data32 = 0 | \
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 | \
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 | \
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &data32, sizeof(data32));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data32 = 0 | \
		SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 | \
		SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 | \
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &data32, sizeof(data32));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 | \
		SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 | \
		SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 | \
		0;
	ret = libspdm_set_data (spdm_ctx, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter, &data16, sizeof(data16));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 | \
		SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM | \
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter, &data16, sizeof(data16));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 | \
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 | \
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 | \
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &data16, sizeof(data16));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 | \
		SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH | \
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16, sizeof(data16));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
		  &data8, sizeof(data8));

#if LIBSPDM_CHECK_SPDM_CONTEXT
	res = libspdm_check_context(spdm_ctx);
	if (!res) {
		LOG_ERR("SPDM Context check invalid");
		goto cleanup;
	}
#endif

	ret = libspdm_init_connection(spdm_ctx, 0);
	if (ret != LIBSPDM_STATUS_SUCCESS) {
		LOG_ERR("libspdm_init_connetion ret=%08x", ret);
		goto cleanup;
	}

	uint32_t use_asym_algo, use_hash_algo;
	void *data = NULL, *hash = NULL;
	const uint8_t *root_cert = NULL;
	size_t data_size, hash_size, root_cert_size;
	
	parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
	data_size = sizeof(data32);
	libspdm_get_data(spdm_ctx, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &data32, &data_size);
	use_asym_algo = data32;

	parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
	data_size = sizeof(data32);
	libspdm_get_data(spdm_ctx, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &data32, &data_size);
	use_hash_algo = data32;

	res = libspdm_read_responder_root_public_certificate(use_hash_algo, use_asym_algo, &data, &data_size, &hash, &hash_size);
	if (res) {
		libspdm_x509_get_cert_from_cert_chain(
			(uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size, 
			data_size - sizeof(spdm_cert_chain_t) - hash_size,
			0, &root_cert, &root_cert_size);

		libspdm_zero_mem(&parameter, sizeof(parameter));
		parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
		libspdm_set_data(spdm_ctx, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, (void *)root_cert, root_cert_size);
	}

	return spdm_ctx;

cleanup:
	LOG_INF("Clean up");
	libspdm_deinit_context(spdm_ctx);
	free(scratch_buffer);
	free(spdm_ctx);
	return NULL;
}

libspdm_return_t
spdm_authentication(void *context, uint8_t *slot_mask,
		    void *total_digest_buffer, uint8_t slot_id,
		    size_t *cert_chain_size, void *cert_chain,
		    uint8_t measurement_hash_type, void *measurement_hash)
{
	libspdm_return_t status;
	size_t cert_chain_buffer_size;
	uint8_t index;
	uint8_t m_other_slot_id = 0;	

	status = libspdm_get_digest(context, NULL, slot_mask,
	total_digest_buffer);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		return status;
	}
	for (index = 1; index < SPDM_MAX_SLOT_COUNT; index++) {
		if ((*slot_mask & (1 << index)) != 0) {
			m_other_slot_id = index;
		}
	}

	cert_chain_buffer_size = *cert_chain_size;

	if (slot_id != 0xFF) {
		if (slot_id == 0) {
			status = libspdm_get_certificate(
				context, NULL, 0, cert_chain_size, cert_chain);
			if (LIBSPDM_STATUS_IS_ERROR(status)) {
				LOG_ERR("libspdm_get_certificate 0 status=%08x", status);
				return status;
			}
			if (m_other_slot_id != 0) {
				*cert_chain_size = cert_chain_buffer_size;
				libspdm_zero_mem(cert_chain, cert_chain_buffer_size);
				status = libspdm_get_certificate(
					context, NULL, m_other_slot_id, cert_chain_size, cert_chain);
			if (LIBSPDM_STATUS_IS_ERROR(status)) {
				LOG_ERR("libspdm_get_certificate 1 status=%08x", status);
					return status;
				}
			}
			} else {
			status = libspdm_get_certificate(
				context, NULL, slot_id, cert_chain_size, cert_chain);
			if (LIBSPDM_STATUS_IS_ERROR(status)) {
				LOG_ERR("libspdm_get_certificate 2 status=%08x", status);
				return status;
			}
		}
	}

	status = libspdm_challenge(context, NULL, slot_id, measurement_hash_type,
			    measurement_hash, NULL);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
				LOG_ERR("libspdm_challenge 3 status=%08x", status);
		return status;
	}

	status = libspdm_get_digest(context, NULL, slot_mask,
	total_digest_buffer);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
				LOG_ERR("libspdm_get_digest 3 status=%08x", status);
		return status;
	}

	if (slot_id != 0xFF) {
		*cert_chain_size = cert_chain_buffer_size;
		status = libspdm_get_certificate(
			context, NULL, slot_id, cert_chain_size, cert_chain);
		if (LIBSPDM_STATUS_IS_ERROR(status)) {
				LOG_ERR("libspdm_get_certificate 3 status=%08x", status);
			return status;
		}
	}

	status = libspdm_get_digest(context, NULL, slot_mask,
	total_digest_buffer);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
				LOG_ERR("libspdm_get_digest 3 status=%08x", status);
		return status;
	}

	return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t do_authentication_via_spdm(void *spdm_context)
{
	libspdm_return_t status;
	uint8_t slot_mask;
	uint8_t total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
	uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
	size_t cert_chain_size;
	uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

	libspdm_zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	cert_chain_size = sizeof(cert_chain);
	libspdm_zero_mem(cert_chain, sizeof(cert_chain));
	libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_authentication(spdm_context, &slot_mask,
			      &total_digest_buffer, 0,
			      &cert_chain_size, cert_chain,
			      SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH,
			      measurement_hash);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		return status;
	}
	return LIBSPDM_STATUS_SUCCESS;
}

/**
 * This function executes SPDM measurement and extend to TPM.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t spdm_send_receive_get_measurement(void *spdm_context,
						   const uint32_t *session_id,
						   uint32_t use_measurement_operation,
						   uint8_t use_slot_id,
						   uint8_t use_measurement_attribute)
{
	libspdm_return_t status;
	uint8_t number_of_blocks;
	uint8_t number_of_block;
	uint8_t received_number_of_block;
	uint32_t measurement_record_length;
	uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
	uint8_t index;
	uint8_t request_attribute;

	if (use_measurement_operation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {

		/* request all at one time.*/

		request_attribute =
			SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
		measurement_record_length = sizeof(measurement_record);
		status = libspdm_get_measurement(
			spdm_context, session_id, request_attribute,
			SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
			use_slot_id & 0xF, NULL, &number_of_block,
			&measurement_record_length, measurement_record);
		if (LIBSPDM_STATUS_IS_ERROR(status)) {
			return status;
		}
	} else {
		request_attribute = use_measurement_attribute;

		/* 1. query the total number of measurements available.*/

		status = libspdm_get_measurement(
			spdm_context, session_id, request_attribute,
			SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
			use_slot_id & 0xF, NULL, &number_of_blocks, NULL, NULL);
		if (LIBSPDM_STATUS_IS_ERROR(status)) {
			return status;
		}
		LOG_INF("Number of blocks = %d", number_of_blocks);
		received_number_of_block = 0;
		for (index = 1; index <= 0xFE; index++) {
			if (received_number_of_block == number_of_blocks) {
				break;
			}
			LOG_INF("Index %d", index);

			/* 2. query measurement one by one
			 * get signature in last message only.*/

			if (received_number_of_block == number_of_blocks - 1) {
				request_attribute = use_measurement_attribute |
					SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
			}
			measurement_record_length = sizeof(measurement_record);
			status = libspdm_get_measurement(
				spdm_context, session_id, request_attribute,
				index, use_slot_id & 0xF, NULL, &number_of_block,
				&measurement_record_length, measurement_record);
			if (LIBSPDM_STATUS_IS_ERROR(status)) {
				continue;
			}
			received_number_of_block += 1;
		}
		if (received_number_of_block != number_of_blocks) {
			return LIBSPDM_STATUS_INVALID_STATE_PEER;
		}
	}
	return LIBSPDM_STATUS_SUCCESS;
}

/**
 * This function executes SPDM measurement and extend to TPM.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t do_measurement_via_spdm(void *spdm_context, const uint32_t *session_id)
{
	libspdm_return_t status;

	status = spdm_send_receive_get_measurement(spdm_context, session_id, SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS, 0, SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		return status;
	}
	return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t do_session_via_spdm(void *spdm_context, bool use_psk, uint32_t *session_id)
{
	libspdm_return_t status;
	uint8_t heartbeat_period;
	uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
	size_t response_size;
	bool result;
	uint32_t response;


	heartbeat_period = 0;
	libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
	status = libspdm_start_session(spdm_context, use_psk,
				LIBSPDM_TEST_PSK_HINT_STRING,
				sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
				SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
				0, 0, session_id,
				&heartbeat_period, measurement_hash);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		printf("libspdm_start_session - %x\n", (uint32_t)status);
		return status;
	}

	status = libspdm_heartbeat(spdm_context, *session_id);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		printf("libspdm_heartbeat - %x\n", (uint32_t)status);
	}

	return status;
}


void spdm_requester_main(void *a, void *b, void *c)
{
	void *spdm_context = NULL;
	libspdm_return_t status;

	spdm_context = spdm_client_init();
	if (spdm_context != NULL) {
		status = do_authentication_via_spdm(spdm_context);
		if (LIBSPDM_STATUS_IS_ERROR(status)) {
			LOG_ERR("do_authentication_via_spdm ret=%08x", status);
			goto cleanup;
		}

		LOG_INF("SPDM Authentication Success");

		uint32_t count = 0;
		do {
			status = do_measurement_via_spdm(spdm_context, NULL);
			if (LIBSPDM_STATUS_IS_ERROR(status)) {
				LOG_ERR("do_measurement_via_spdm - %x\n", (uint32_t)status);
				goto cleanup;
			}

			LOG_INF("SPDM Measuremnt Succesas count=%d", ++count);
			k_msleep(1);
		} while (0);

		uint32_t session_id = 0x0123;
		status = do_session_via_spdm(spdm_context, false, &session_id);
		if (LIBSPDM_STATUS_IS_ERROR(status)) {
			LOG_ERR("do_session_via_spdm - %x", status);
			goto cleanup;
		}
		LOG_INF("Session initiated");

		do {
			status = libspdm_heartbeat(spdm_context, session_id);
			if (LIBSPDM_STATUS_IS_ERROR(status)) {
				LOG_ERR("libspdm_heartbeat - %x", status);
				goto cleanup;
			}

			status = do_measurement_via_spdm(spdm_context, &session_id);
			if (LIBSPDM_STATUS_IS_ERROR(status)) {
				LOG_ERR("do_measurement_via_spdm - %x\n", (uint32_t)status);
				goto cleanup;
			}

			LOG_INF("SPDM Measuremnt Succesas count=%d", ++count);
			k_msleep(1000);
		} while (1);
cleanup:
		libspdm_deinit_context(spdm_context);
		free(spdm_context);
	}

	while (1) {
		k_msleep(1000);
	}
}


