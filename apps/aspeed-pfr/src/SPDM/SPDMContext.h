/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <mbedtls/x509_crt.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha512.h>

#include "SPDM/SPDMBuffer.h"
#include "SPDM/SPDMDefinitions.h"

enum SPDM_CONNECTION_STATE {
	SPDM_STATE_NOT_READY,
	SPDM_STATE_GOT_VERSION,
	SPDM_STATE_GOT_CAPABILITIES,
	SPDM_STATE_NEGOTIATED_ALGORITHMS,
	SPDM_STATE_GOT_DIGESTS,
	SPDM_STATE_GOT_CERTIFICATE,
	SPDM_STATE_CHANLLENGED,
	SPDM_STATE_SESSION_ESTABLISHED,
};

struct spdm_version_info {
	uint8_t version_number_entry_count;
	uint8_t version_number_selected;
	uint16_t version_number_entry[SPDM_MAX_VERSION]; // Placeholder for SPDM 1.0 1.1 1.2
};

struct spdm_capabilities_info {
	uint8_t ct_exponent;
	uint32_t flags;
	uint32_t data_transfer_size;
	uint32_t max_spdm_msg_size;
};

struct spdm_algorithms_info {
	uint16_t length;
	uint8_t measurement_spec_sel;
	uint8_t other_param_sel;
	uint32_t measurement_hash_algo;
	uint32_t base_asym_sel;
	uint32_t base_hash_sel;
#if 1
	uint8_t ext_asym_sel_count; // A'
	uint8_t ext_hash_sel_count; // E'
	uint32_t ext_asym_sel[SPDM_EXT_ASYM_SEL_COUNT];
	uint32_t ext_hash_sel[SPDM_EXT_HASH_SEL_COUNT];
#endif
};

struct spdm_certificate_info {
	uint8_t slot_mask;
	struct {
		uint16_t size;
		uint8_t *data;
		mbedtls_x509_crt chain;
		uint8_t digest[48];
	} certs[8]; // Slot ID 0~7 and root
};

struct spdm_context_info {
	struct spdm_version_info version;
	struct spdm_capabilities_info capabilities;
	struct spdm_algorithms_info algorithms;
	struct spdm_certificate_info certificate;
};

/* Connection context information */
struct spdm_context {
	/* low-level communication handler */
	int (*send)(void *context, void *buffer, size_t buffer_size);
	int (*recv)(void *context, void *buffer, size_t *buffer_size);
	int (*send_recv)(void *context, void *request_buffer, void *response_buffer);
	void (*release_connection_data)(void *context);
	void *connection_data;

	/* request responsed callback */
	int (*callback)(void *context, void *message);

	/* Connection State */
	enum SPDM_CONNECTION_STATE connection_state;

	/* Handshaking Information */
	struct spdm_context_info local;
	struct spdm_context_info remote;

	/* Measurement Callback */
	int (*get_measurement)(void *context, uint8_t measurement_index, uint8_t* measurement_count, uint8_t* measurement, size_t* measurement_size);

	/* VCA transcript */
	struct spdm_buffer message_a;
#if defined(SPDM_TRANSCRIPT)
	/* Message Transcript */
	struct spdm_buffer message_b;
	struct spdm_buffer message_c;
#endif
	/* M1/M2 Hash Context */
	struct mbedtls_sha512_context m1m2_context;

	/* Measurement L1/L2 Hash Context */
	struct mbedtls_sha512_context l1l2_context;

	/* Private Key for Signing */
	mbedtls_ecp_keypair key_pair;

	/* Random number wrapper */
	int (*random_callback)(void *context, unsigned char *output, size_t output_len);

	/* private data */
	void *private_data;
};

struct spdm_req_fifo_data {
	void *fifo_reserved;
	void *spdm_ctx;
	enum {
		RESERVED_0,
		SPDM_REQ_ADD,
		RESERVED_1,
		SPDM_REQ_REMOVE,
	} command;
};

void *spdm_context_create();
void spdm_context_release(void *ctx);
int spdm_load_certificate(void *ctx, bool remote, uint8_t slot_id, void *cert_data, uint16_t cert_len);
int spdm_load_root_certificate(void *cert_data, uint16_t cert_len);
mbedtls_x509_crt* spdm_get_root_certificate();
size_t spdm_context_base_hash_size(void *context);
size_t spdm_context_base_algo_size(void *context);
size_t spdm_context_measurement_hash_size(void *context);
void spdm_context_reset_m1m2_hash(void *ctx);
void spdm_context_update_m1m2_hash(void *ctx, void *req, void *rsp);
void spdm_context_reset_l1l2_hash(void *ctx);
void spdm_context_update_l1l2_hash_buffer(void *ctx, void *buf);
void spdm_context_update_l1l2_hash(void *ctx, void *req, void *rsp);
