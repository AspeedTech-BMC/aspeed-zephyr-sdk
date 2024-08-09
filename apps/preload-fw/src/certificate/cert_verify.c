/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <soc.h>
#include <zephyr/kernel.h>
#include <zephyr/storage/flash_map.h>
#include <mbedtls/sha256.h>
#include <zephyr/drivers/flash.h>
#include "cert_verify.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

LOG_MODULE_REGISTER(cert, CONFIG_LOG_DEFAULT_LEVEL);

#define DEVID_CERT_AREA_OFFSET        0
#define ALIAS_CERT_AREA_OFFSET        0x2000
#define CERT_AREA_SIZE                0x2000

static uint8_t devid_pub_key[ECDSA384_PUBLIC_KEY_SIZE] = {0};
mbedtls_x509_crt leaf_cert;
mbedtls_x509_crt root_cert;

int get_certificate_info(PFR_DEVID_CERT_INFO *devid_cert_info, uint32_t cert_size)
{
	const struct flash_area *fa = NULL;
	PFR_CERT_INFO *cert_info;
	uint8_t cert_hash[SHA256_HASH_LENGTH];

	if (flash_area_open(FIXED_PARTITION_ID(certificate_partition), &fa)) {
		LOG_ERR("Failed to open certificate region");
		return -1;
	}

	if (flash_area_read(fa, DEVID_CERT_AREA_OFFSET, devid_cert_info, cert_size)) {
		LOG_ERR("Failed to read certificate(s) from flash");
		goto error;
	}

	cert_info = &devid_cert_info->cert;

	if (cert_info->magic != CERT_INFO_MAGIC_NUM) {
		LOG_ERR("Invalid magic number");
		goto error;
	}

	mbedtls_sha256(cert_info->data, cert_info->length, cert_hash, 0);

	if (memcmp(cert_hash, cert_info->hash, SHA256_HASH_LENGTH)) {
		LOG_ERR("Device ID certificate hash mismatch");
		LOG_HEXDUMP_ERR(cert_info->hash, sizeof(cert_hash), "Expected :");
		LOG_HEXDUMP_ERR(cert_hash, sizeof(cert_hash), "Actual :");
		goto error;
	}

	memcpy(devid_pub_key, devid_cert_info->pubkey, ECDSA384_PUBLIC_KEY_SIZE);

	return 0;
error:
	flash_area_close(fa);
	return -1;
}

