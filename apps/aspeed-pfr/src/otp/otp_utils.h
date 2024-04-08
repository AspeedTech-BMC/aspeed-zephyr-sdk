/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <zephyr/kernel.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/drivers/misc/aspeed/otp_aspeed.h>

#define DWORD                           4
// OTP Header definition
#define OTP_HEADER_START_ADDR           0x0
// 16 DW(64 bytes)
#define OTP_HEADER_LENGTH               16

enum {
	OTP_EMPTY_HEADER,
	OTP_AES256_SECRET_KEY,
	OTP_AES256_OEM_KEY,
	OTP_ECDSA384_PARAM          = 5,
	OTP_ECDSA384_PUBKEY         = 7,
	OTP_RSA_OEM_LE_PUBKEY,
	OTP_RSA_OEM_BE_PUBKEY,
	OTP_RSA_SOC_LE_PUBKEY,
	OTP_RSA_SOC_BE_PUBKEY,
	OTP_RSA_SOC_LE_PRIVKEY,
	OTP_RSA_SOC_BE_PRIVKEY,
};

enum {
	OTP_KPARAM_ECDSA384,
	OTP_KPARAM_RSA2048,
	OTP_KPARAM_RSA3072,
	OTP_KPARAM_RSA4096,
};

typedef struct otp_key_header {
	uint32_t key_id : 3;
	uint32_t key_offset : 10;
	uint32_t last : 1;
	uint32_t key_type : 4;
	uint32_t key_param : 2;
	uint32_t key_exp_len : 12;
} OTP_KEY_HEADER;

int otpu_retire_key(uint32_t retire_id);
int otpu_write_key(uint8_t header_slot, uint8_t key_param, uint8_t key_type, uint32_t key_offset,
		uint8_t key_id, uint16_t key_exp_len, uint32_t key_len, const uint8_t *key);
