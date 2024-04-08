/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/random/rand32.h>
#include <stdlib.h>
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm, CONFIG_LOG_DEFAULT_LEVEL);

static mbedtls_x509_crt system_root_ca;

int random_callback(void *context, unsigned char *output, size_t output_len)
{
	sys_rand_get(output, output_len);
	return 0;
}

void *spdm_context_create()
{
	struct spdm_context *context = (struct spdm_context *)malloc(sizeof(struct spdm_context));

	context->release_connection_data = NULL;
	context->connection_state = SPDM_STATE_NOT_READY;

	context->local.version.version_number_entry_count = 3;
	context->local.version.version_number_selected = SPDM_VERSION_10;
	context->local.version.version_number_entry[0] = SPDM_VERSION_12 << SPDM_VERSION_NUMBER_ENTRY_SHIFT_BIT;
	context->local.version.version_number_entry[1] = SPDM_VERSION_11 << SPDM_VERSION_NUMBER_ENTRY_SHIFT_BIT;
	context->local.version.version_number_entry[2] = SPDM_VERSION_10 << SPDM_VERSION_NUMBER_ENTRY_SHIFT_BIT;

	context->remote.version.version_number_entry_count = 0;
	context->remote.version.version_number_selected = SPDM_VERSION_10;
	context->remote.version.version_number_entry[0] = 0;
	context->remote.version.version_number_entry[1] = 0;
	context->remote.version.version_number_entry[2] = 0;

	/* Set CT to 32768us due to mbedtls ecdsa */
	context->local.capabilities.ct_exponent = 15;
	context->local.capabilities.flags = SPDM_CHAL_CAP | SPDM_CERT_CAP | SPDM_MEAS_CAP_SIG;
	context->local.capabilities.data_transfer_size = 256;
	context->local.capabilities.max_spdm_msg_size = 256;

	context->local.algorithms.length = 0;
	context->local.algorithms.measurement_spec_sel = SPDM_MEASUREMENT_BLOCK_DMTF_SPEC;
	context->local.algorithms.other_param_sel = 0;
	context->local.algorithms.measurement_hash_algo = SPDM_ALGORITHMS_MEAS_HASH_TPM_ALG_SHA_384;
	context->local.algorithms.base_asym_sel =SPDM_ALGORITHMS_BASE_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
	context->local.algorithms.base_hash_sel = SPDM_ALGORITHMS_BASE_HASH_TPM_ALG_SHA_384;
#if 1
	context->local.algorithms.ext_asym_sel_count = 0;
	context->local.algorithms.ext_hash_sel_count = 0;
	context->local.algorithms.ext_asym_sel[0] = 0;
	context->local.algorithms.ext_hash_sel[0] = 0;
#endif

	context->local.certificate.slot_mask = 0;
	context->remote.certificate.slot_mask = 0;
	for (size_t i = 0; i < 8; ++i) {
		context->local.certificate.certs[i].size = 0;
		context->local.certificate.certs[i].data = NULL;
		mbedtls_x509_crt_init(&context->local.certificate.certs[i].chain);

		context->remote.certificate.certs[i].size = 0;
		context->remote.certificate.certs[i].data = NULL;
		mbedtls_x509_crt_init(&context->remote.certificate.certs[i].chain);
	}

	context->get_measurement = NULL;

	spdm_buffer_init(&context->message_a, 0);
#if defined(SPDM_TRANSCRIPT)
	spdm_buffer_init(&context->message_b, 0);
	spdm_buffer_init(&context->message_c, 0);
#else
	spdm_context_reset_m1m2_hash(context);
#endif

	mbedtls_sha512_init(&context->l1l2_context);
	mbedtls_sha512_starts(&context->l1l2_context, /* is384 */ 1);

	mbedtls_ecp_keypair_init(&context->key_pair);

	context->random_callback = random_callback;

	return (void *)context;
}

void spdm_context_release(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;

	for (size_t slot_id=0; slot_id<8; ++slot_id) {
		if (context->local.certificate.certs[slot_id].data) {
			free(context->local.certificate.certs[slot_id].data);
			context->local.certificate.certs[slot_id].data = NULL;
			context->local.certificate.certs[slot_id].size = 0;
		}
		if (context->remote.certificate.certs[slot_id].data) {
			free(context->remote.certificate.certs[slot_id].data);
			context->remote.certificate.certs[slot_id].data = NULL;
			context->remote.certificate.certs[slot_id].size = 0;
		}
		mbedtls_x509_crt_free(&context->local.certificate.certs[slot_id].chain);
		mbedtls_x509_crt_free(&context->remote.certificate.certs[slot_id].chain);
	}

	mbedtls_ecp_keypair_free(&context->key_pair);
	spdm_buffer_release(&context->message_a);
#if defined(SPDM_TRANSCRIPT)
	spdm_buffer_release(&context->message_b);
	spdm_buffer_release(&context->message_c);
#else
	/* TODO: Assuming the hash algorithm is SHA384 */
	mbedtls_sha512_free(&context->m1m2_context);
#endif
	/* TODO: Assuming the hash algorithm is SHA384 */
	mbedtls_sha512_free(&context->l1l2_context);
	if (context->release_connection_data)
		context->release_connection_data(context);
	free(context);
}

int spdm_load_certificate(void *ctx, bool remote, uint8_t slot_id, void *cert_data, uint16_t cert_len)
{
	struct spdm_context *context = (struct spdm_context*)ctx;
	struct spdm_certificate_info *cert_info = &context->local.certificate;

	if (remote) {
		cert_info = &context->remote.certificate;
	}

	if (slot_id > 7) {
		LOG_ERR("Invalid slot_id[%d]", slot_id);
		return -1;
	}

	if (cert_info->slot_mask & (1<<slot_id)) {
		LOG_ERR("Slot_id[%d] already occupided, slot_mask[%x]", slot_id, cert_info->slot_mask);
		return -1;
	}

	/* TODO: Copy certificate or just assign the pointer? */
	cert_info->slot_mask |= 1 << slot_id;

	cert_info->certs[slot_id].data = malloc(cert_len + 4 + 48);
	memcpy(cert_info->certs[slot_id].data + 4 + 48, cert_data, cert_len);
	cert_info->certs[slot_id].size = cert_len + 4 + 48;
	cert_info->certs[slot_id].data[0] = (cert_len + 4 + 48) & 0xff;
	cert_info->certs[slot_id].data[1] = ((cert_len + 4 + 48) >> 8) & 0xff;

	/* Hash the  Root Cert */
	// TODO: Find the root cert length
	mbedtls_sha512(cert_data, 468, cert_info->certs[slot_id].data + 4, 1);

	return 0;
}

int spdm_load_root_certificate(void *cert_data, uint16_t cert_len)
{
	/* Root Certificate */
	return mbedtls_x509_crt_parse_der_nocopy(&system_root_ca, cert_data, cert_len);
}

mbedtls_x509_crt* spdm_get_root_certificate()
{
	return &system_root_ca;
}

size_t spdm_context_base_hash_size(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	size_t ret = -1;

	switch(context->remote.algorithms.base_hash_sel) {
	case SPDM_ALGORITHMS_BASE_HASH_TPM_ALG_SHA_384:
		ret = 48;
		break;
	default:
		LOG_ERR("Unsupported base_hash_sel = %x", context->remote.algorithms.base_hash_sel);
		break;
	}

	return ret;
}

size_t spdm_context_base_algo_size(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	size_t ret = -1;

	switch(context->remote.algorithms.base_asym_sel) {
	case SPDM_ALGORITHMS_BASE_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
		ret = 48 * 2;
		break;
	default:
		LOG_ERR("Unsupported base_asym_sel = %x", context->remote.algorithms.base_asym_sel);
		break;
	}

	return ret;

}

size_t spdm_context_measurement_hash_size(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	size_t ret = -1;

	switch(context->remote.algorithms.base_hash_sel) {
	case SPDM_ALGORITHMS_MEAS_HASH_TPM_ALG_SHA_384:
		ret = 48;
		break;
	default:
		LOG_ERR("Unsupported measurement_hash_sel = %x", context->remote.algorithms.base_hash_sel);
		break;
	}

	return ret;
}

void spdm_context_reset_m1m2_hash(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;

	mbedtls_sha512_free(&context->m1m2_context);
	mbedtls_sha512_init(&context->m1m2_context);
	mbedtls_sha512_starts(&context->m1m2_context, /* is384 */ 1);
}

void spdm_context_update_m1m2_hash(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;

	LOG_HEXDUMP_DBG((const unsigned char *)&req_msg->header, sizeof(req_msg->header), "M1M2 Append REQ Header");
	LOG_HEXDUMP_DBG((const unsigned char *)req_msg->buffer.data, req_msg->buffer.write_ptr, "M1M2 Append REQ Payload");
	LOG_HEXDUMP_DBG((const unsigned char *)&rsp_msg->header, sizeof(rsp_msg->header), "M1M2 Append RSP Header");
	LOG_HEXDUMP_DBG((const unsigned char *)rsp_msg->buffer.data, rsp_msg->buffer.write_ptr, "M1M2 Append RSP Payload");
	mbedtls_sha512_update(&context->m1m2_context,
			(const unsigned char *)&req_msg->header,
			sizeof(req_msg->header));
	mbedtls_sha512_update(&context->m1m2_context,
			(const unsigned char *)req_msg->buffer.data,
			req_msg->buffer.write_ptr);
	mbedtls_sha512_update(&context->m1m2_context,
			(const unsigned char *)&rsp_msg->header,
			sizeof(rsp_msg->header));
	mbedtls_sha512_update(&context->m1m2_context,
			(const unsigned char *)rsp_msg->buffer.data,
			rsp_msg->buffer.write_ptr);
}

void spdm_context_reset_l1l2_hash(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;

	mbedtls_sha512_free(&context->l1l2_context);
	mbedtls_sha512_init(&context->l1l2_context);
	mbedtls_sha512_starts(&context->l1l2_context, /* is384 */ 1);

	LOG_DBG("RESET L1L2 BUFFER");
}

void spdm_context_update_l1l2_hash_buffer(void *ctx, void *buf)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_buffer *buffer = (struct spdm_buffer *)buf;
	LOG_HEXDUMP_DBG(buffer->data, buffer->write_ptr, "UPDATE L1L2 BUFFER VCA");

	mbedtls_sha512_update(&context->l1l2_context, buffer->data, buffer->write_ptr);
}

void spdm_context_update_l1l2_hash(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;

	LOG_HEXDUMP_DBG(&req_msg->header, sizeof(req_msg->header),
			"UPDATE L1L2 req_msg->header");
	LOG_HEXDUMP_DBG((const unsigned char *)req_msg->buffer.data, req_msg->buffer.write_ptr,
			"UPDATE L1L2 req_msg->buffer");
	LOG_HEXDUMP_DBG(&rsp_msg->header, sizeof(rsp_msg->header),
			"UPDATE L1L2 rsp_msg->header");
	LOG_HEXDUMP_DBG((const unsigned char *)rsp_msg->buffer.data, rsp_msg->buffer.write_ptr,
			"UPDATE L1L2 rsp_msg->buffer");
	mbedtls_sha512_update(&context->l1l2_context,
			(const unsigned char *)&req_msg->header,
			sizeof(req_msg->header));
	mbedtls_sha512_update(&context->l1l2_context,
			(const unsigned char *)req_msg->buffer.data,
			req_msg->buffer.write_ptr);
	mbedtls_sha512_update(&context->l1l2_context,
			(const unsigned char *)&rsp_msg->header,
			sizeof(rsp_msg->header));
	mbedtls_sha512_update(&context->l1l2_context,
			(const unsigned char *)rsp_msg->buffer.data,
			rsp_msg->buffer.write_ptr);
}


