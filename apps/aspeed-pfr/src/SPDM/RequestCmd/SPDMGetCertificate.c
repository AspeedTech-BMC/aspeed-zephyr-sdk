/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>

#include "SPDM/SPDMCommon.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_crl.h"
#include "intel_pfr/intel_pfr_pfm_manifest.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_get_certificate(void *ctx, uint8_t slot_id)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	uint16_t offset = 0;
	uint16_t block_size = 0xF0;
	bool first_request = true;
	int ret;

	do {
		struct spdm_message req_msg, rsp_msg;

		req_msg.header.spdm_version = context->local.version.version_number_selected;
		req_msg.header.request_response_code = SPDM_REQ_GET_CERTIFICATE;
		req_msg.header.param1 = slot_id & 0x0F;
		req_msg.header.param2 = 0;

		spdm_buffer_init(&req_msg.buffer, 4);
		spdm_buffer_init(&rsp_msg.buffer, 0);
		spdm_buffer_append_u16(&req_msg.buffer, offset);
		spdm_buffer_append_u16(&req_msg.buffer, block_size);

		ret = spdm_send_request(context, &req_msg, &rsp_msg);
		if (ret != 0) {
			ret = -1;
			goto cleanup;
		} else if (rsp_msg.header.spdm_version != req_msg.header.spdm_version) {
			LOG_ERR("Unsupported header SPDM_VERSION Req %02x Rsp %02x",
					req_msg.header.spdm_version, rsp_msg.header.spdm_version);
			ret = -1;
			goto cleanup;
		} else if (rsp_msg.header.request_response_code != SPDM_RSP_CERTIFICATE) {
			LOG_ERR("Expecting CERTIFICATE message but got %02x Param[%02x,%02x]",
					rsp_msg.header.request_response_code,
					rsp_msg.header.param1,
					rsp_msg.header.param2);
			ret = -1;
			goto cleanup;
		} else if (rsp_msg.buffer.write_ptr < 4) {
			LOG_ERR("CERTIFICATE message length incorrect");
			ret = -1;
			goto cleanup;
		}

		uint16_t portion_length, remainder_length;
		spdm_buffer_get_u16(&rsp_msg.buffer, &portion_length);
		spdm_buffer_get_u16(&rsp_msg.buffer, &remainder_length);

		/* Check the message length again */
		if (rsp_msg.buffer.write_ptr != portion_length + 4) {
			LOG_ERR("CERTIFICATE portion length incorrect");
			ret = -1;
			goto cleanup;
		}

		if (first_request) {
			if (context->remote.certificate.certs[slot_id].data) {
				free(context->remote.certificate.certs[slot_id].data);
				context->remote.certificate.certs[slot_id].data = NULL;
			}
			// Allocate the certificate memory
			context->remote.certificate.certs[slot_id].size =
				portion_length + remainder_length;
			context->remote.certificate.certs[slot_id].data =
				(uint8_t *)malloc(portion_length + remainder_length);
			if (context->remote.certificate.certs[slot_id].data == NULL) {
				LOG_ERR("Failed to alloc memory size=%d", portion_length + remainder_length);
				return -1;
			}
			first_request = false;
		}
		spdm_buffer_get_array(&rsp_msg.buffer,
				context->remote.certificate.certs[slot_id].data + offset,
				portion_length);
		offset += portion_length;

#if defined(SPDM_TRANSCRIPT)
		/* Construct transcript for challenge */
		spdm_buffer_resize(&context->message_b,
				context->message_b.size +
				req_msg.buffer.size + sizeof(req_msg.header) +
				rsp_msg.buffer.size + sizeof(rsp_msg.header));
		spdm_buffer_append_array(&context->message_b, &req_msg.header, sizeof(req_msg.header));
		spdm_buffer_append_array(&context->message_b, req_msg.buffer.data, req_msg.buffer.size);
		spdm_buffer_append_array(&context->message_b, &rsp_msg.header, sizeof(rsp_msg.header));
		spdm_buffer_append_array(&context->message_b, rsp_msg.buffer.data, rsp_msg.buffer.size);
#else
		spdm_context_update_m1m2_hash(context, &req_msg, &rsp_msg);
#endif

cleanup:
		spdm_buffer_release(&req_msg.buffer);
		spdm_buffer_release(&rsp_msg.buffer);

		if (ret == 0 && remainder_length == 0) {
			/* Check DIGEST first */
			uint8_t hash[48];
			mbedtls_sha512(context->remote.certificate.certs[slot_id].data,
					context->remote.certificate.certs[slot_id].size,
					hash, 1);
			if (memcmp(hash, context->remote.certificate.certs[slot_id].digest, 48) != 0) {
				LOG_ERR("Certificate[%d] doesn't match with DIGEST", slot_id);
				LOG_HEXDUMP_ERR(hash, 48, "HASH:");
				LOG_HEXDUMP_ERR(context->remote.certificate.certs[slot_id].digest, 48, "DIGESTS:");
				ret = -1;
				goto cleanup;
			}
			break;
		}
	} while (ret == 0);


	if (ret == 0) {
		/* Load Root Certificate */
		mbedtls_x509_crt *ca_cert = spdm_get_root_certificate();
		uint32_t flags;
		mbedtls_x509_crt local_ca;
		AFM_DEVICE_STRUCTURE_v40_p2 *pPubkey;

		if (context->private_data) {
			mbedtls_x509_crt_init(&local_ca);
			pPubkey = (AFM_DEVICE_STRUCTURE_v40_p2 *)context->private_data;
			if (pPubkey->CertificateSize) {
				mbedtls_x509_crt_parse_der_nocopy(&local_ca, pPubkey->Certificate, pPubkey->CertificateSize);
				ca_cert = &local_ca;
			}
		}

		/* Verify the certificate */
		mbedtls_x509_crt *remote_cert = &context->remote.certificate.certs[slot_id].chain;
		mbedtls_x509_crt_free( remote_cert );
		mbedtls_x509_crt_init( remote_cert );

		size_t asn1_len, current_cert_len = 0;
		size_t cert_chain_len = context->remote.certificate.certs[slot_id].size - 4 - 48;
		uint8_t *cert_chain = context->remote.certificate.certs[slot_id].data + 4 + 48;
		uint8_t *tmp_ptr, *current_cert = cert_chain;
		int32_t current_index = -1;

		while (true) {
			tmp_ptr = current_cert;
			ret = mbedtls_asn1_get_tag(
					&tmp_ptr, cert_chain + cert_chain_len, &asn1_len,
					MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
			if (ret != 0) {
				break;
			}

			current_cert_len = asn1_len + (tmp_ptr - current_cert);
			current_index++;

			ret = mbedtls_x509_crt_parse_der_nocopy(
					remote_cert, current_cert, current_cert_len);
			if (ret < 0) {
				break;
			}

			current_cert = current_cert + current_cert_len;
		}

		ret = mbedtls_x509_crt_verify(remote_cert, ca_cert, NULL, NULL, &flags, NULL, NULL);
		if (context->private_data && pPubkey->CertificateSize) {
			mbedtls_x509_crt_free(ca_cert);
		}
		if (ret < 0 || flags != 0) {
			LOG_ERR("Failed to verify Certificate[%d], reject this cert ret=%x flags=%x", slot_id, -ret, flags);
			/* Drop the certificate */
			free(context->remote.certificate.certs[slot_id].data);
			context->remote.certificate.certs[slot_id].data = NULL;
			context->remote.certificate.certs[slot_id].size = 0;
			context->remote.certificate.slot_mask &= ~(1 << slot_id);
			mbedtls_x509_crt_free(remote_cert);
			ret = -1;
		} else {
			LOG_INF("Certificate[%d] verified", slot_id);
			ret = 0;
		}
	}

	return ret;
}
