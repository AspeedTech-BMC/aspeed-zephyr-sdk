/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <zephyr/kernel.h>

#define CERT_INFO_MAGIC_NUM               0x43455254    // hex of 'CERT'
#define ECDSA384_PUBLIC_KEY_SIZE          SHA384_HASH_LENGTH * 2 + 1
#define CERT_CHAIN_SIZE                   0x1000

#define SHA256_HASH_LENGTH		  32
#define SHA384_HASH_LENGTH		  48

#define IS_CSR(info) (info.cert_type == CERT_REQ_TYPE)

enum cert_type {
	CERT_TYPE = 0,
	PUBLICKEY_TYPE,
	ECC_PRIVATEKEY_TYPE,
	CERT_REQ_TYPE,
	LAST_CERT_TYPE
};

typedef struct {
	uint32_t magic;
	uint32_t length;
	uint8_t data[CERT_CHAIN_SIZE];
	uint8_t hash[SHA256_HASH_LENGTH];
} PFR_CERT_INFO;

typedef struct {
	PFR_CERT_INFO cert;
	uint8_t pubkey[ECDSA384_PUBLIC_KEY_SIZE];
	uint8_t cert_type;
} PFR_DEVID_CERT_INFO;

int get_certificate_info(PFR_DEVID_CERT_INFO *devid_cert_info, uint32_t cert_size);
uint8_t get_certificate_chain(uint8_t *cert_chain, uint32_t *cert_chain_len);
int verify_certificate(uint8_t *cert_chain, uint32_t cert_chain_len);
int write_cert_chain(uint8_t *cert_chain, uint32_t cert_chain_len);
void cleanup_cert_info(void);
