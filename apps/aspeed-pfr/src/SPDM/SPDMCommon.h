/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "SPDM/SPDMContext.h"
#include "SPDM/SPDMCrypto.h"
#include "SPDM/SPDMBuffer.h"
#include "SPDM/SPDMDefinitions.h"
#include "SPDM/SPDMRequester.h"
#include "crypto/hash.h"

#pragma pack(1)

#define SPDM_MAJOR_VERSION 1
#define SPDM_MINOR_VERSION_0 0
#define SPDM_MINOR_VERSION_1 1
#define SPDM_MINOR_VERSION_2 2
#define SPDM_VERSION_10 ((SPDM_MAJOR_VERSION << 4) | SPDM_MINOR_VERSION_0)
#define SPDM_VERSION_11 ((SPDM_MAJOR_VERSION << 4) | SPDM_MINOR_VERSION_1)
#define SPDM_VERSION_12 ((SPDM_MAJOR_VERSION << 4) | SPDM_MINOR_VERSION_2)
#define SPDM_VERSION SPDM_VERSION_12

typedef enum {
	/* SPDM 1.0 */
	SPDM_REQ_GET_DIGESTS = 0x81,
	SPDM_REQ_GET_CERTIFICATE = 0x82,
	SPDM_REQ_CHALLENGE = 0x83,
	SPDM_REQ_GET_VERSION = 0x84,
	SPDM_REQ_GET_MEASUREMENTS = 0xE0,
	SPDM_REQ_GET_CAPABILITIES = 0xE1,
	SPDM_REQ_NEGOTIATE_ALGORITHMS = 0xE3,
	SPDM_REQ_VENDOR_DEFINED_REQUEST = 0xFE,
	SPDM_REQ_RESPOND_IF_READY = 0xFF,
} SPDM_REQUEST_CODE;

typedef enum {
	/* SPDM 1.0 */
	SPDM_RSP_DIGESTS = 0x01,
	SPDM_RSP_CERTIFICATE = 0x02,
	SPDM_RSP_CHALLENGE_AUTH = 0x03,
	SPDM_RSP_VERSION = 0x04,
	SPDM_RSP_MEASUREMENTS = 0x60,
	SPDM_RSP_CAPABILITIES = 0x61,
	SPDM_RSP_ALGORITHMS = 0x63,
	SPDM_RSP_VENDOR_DEFINED_RESPONSE = 0x7E,
	SPDM_RSP_ERROR = 0x7F,
} SPDM_RESPONSE_CODE;

struct spdm_message_header {
	uint8_t spdm_version;
	uint8_t request_response_code;
	uint8_t param1;
	uint8_t param2;
};

typedef enum SPDM_MEDIUM {
	SPDM_MEDIUM_SMBUS = 0x01,
	SPDM_MEDIUM_I3C = 0x06,
} SPDM_MEDIUM;
#pragma pack()

struct spdm_message {
	struct spdm_message_header header;
	struct spdm_buffer buffer;
};

/* Request Event to Requester Thread */
typedef struct {
	void *fifo_reserved;
	struct spdm_context *context;
	struct spdm_message *message;
} spdm_request_data;

void init_spdm();
bool init_requester_context(struct spdm_context *context, SPDM_MEDIUM medium, uint8_t bus, uint8_t dst_sa, uint8_t dst_eid);
