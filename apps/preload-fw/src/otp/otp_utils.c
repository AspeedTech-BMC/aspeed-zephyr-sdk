/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/entropy.h>
#include "otp_utils.h"
#include "gpio/gpio_ctrl.h"
#if defined(CONFIG_OTP_SIM)
#include "otp_sim.h"
#else
#include <soc.h>
#endif

LOG_MODULE_REGISTER(otp, CONFIG_LOG_DEFAULT_LEVEL);

#define DWORD                           4
#define AES_VAULT_KEY_DW_OFFSET         0x10
#define AES_VAULT_KEY_OFFSET            (AES_VAULT_KEY_DW_OFFSET * DWORD)
// 16 DW for aes256 vault key1 and vault key2
#define AES_VAULT_KEY_DW_LENGTH         16

// OTP Header definition
#define OTP_HEADER_START_ADDR           0x0
// 16 DW(64 bytes)
#define OTP_HEADER_LENGTH               16

// OTP Strap definition
#define OTP_STRAP_SECURE_BOOT_EN        0
#define OTP_STRAP_SECURE_BOOT_EN_BIT    BIT(0)

// OTP Config definition
#define OTP_CONF0                       0
#define     OTP_CONF0_SECURE_BOOT_EN    BIT(1)

#define OTP_CONF3                       3
#define     OTP_CONF3_CDI_EN            BIT(31)

// SEC register
#define SEC_BASE                        0x7e6f2000
#define SEC_STATUS                      (SEC_BASE + 0x14)
#define SEC_STATUS_SECURE_BOOT_EN       BIT(6)

static uint32_t vault_key_buf[AES_VAULT_KEY_DW_LENGTH];
static uint32_t otp_header_buf[OTP_HEADER_LENGTH];
// OTP strap total 64 bits(8 bytes)

bool is_otp_secureboot_en(enum otp_status *otp_rc)
{
#if defined(CONFIG_OTP_SIM)
	bool is_secureboot_en = false;
	uint32_t otp_conf_val;

	*otp_rc = aspeed_otp_read_conf(OTP_CONF0, &otp_conf_val, 1);
	if (*otp_rc) {
		LOG_ERR("Failed to get secure boot status");
		return is_secureboot_en;
	}

	return (otp_conf_val & OTP_CONF0_SECURE_BOOT_EN) ? true :  false;
#else
	uint32_t val;

	val = sys_read32(SEC_STATUS);
	*otp_rc = 0;

	return (val & SEC_STATUS_SECURE_BOOT_EN) ? true : false;
#endif
}

int otp_append_vault_key(uint32_t *vault_key)
{
	enum otp_status otp_rc = OTP_SUCCESS;
	uint32_t header = 0;
	uint32_t *data;
	bool found_empty = false;
	int i;

	// OTP Header
	// [17:14] key type
	//     0001 : AES-256 as secret vault key
	//
	// [12:03] key offset (8-byte aligned)
	header |= BIT(14);
	header |= AES_VAULT_KEY_OFFSET;
	otp_rc = aspeed_otp_read_data(OTP_HEADER_START_ADDR, otp_header_buf, OTP_HEADER_LENGTH);
	if (otp_rc)
		return otp_rc;

	data = otp_header_buf;

	// Find an empty slot from OTP header region
	for (i = OTP_HEADER_START_ADDR; i < OTP_HEADER_LENGTH; i++) {
		if (data[i] == header) {
			LOG_ERR("Failed to write the vault key due to vault key exists");
			return OTP_PROG_FAILED;
		}
		if (i % 2) {
			if (data[i] == 0xffffffff) {
				// Found empty slot
				found_empty = true;
				break;
			}
		} else {
			if (data[i] == 0) {
				// Found empty slot
				found_empty = true;
				break;
			}
		}
	}

	if (!found_empty) {
		LOG_ERR("Insufficient space to store vault key");
		return OTP_PROG_FAILED;
	}

	// Write key header, length is 1 DW
	otp_header_buf[i] = header;
	otp_rc = aspeed_otp_prog_data(OTP_HEADER_START_ADDR, otp_header_buf, OTP_HEADER_LENGTH);

	if (otp_rc)
		return otp_rc;

	// Write vault key
	otp_rc = aspeed_otp_prog_data(AES_VAULT_KEY_DW_OFFSET, vault_key, AES_VAULT_KEY_DW_LENGTH);

	return otp_rc;
}

int otp_gen_vault_key(uint32_t *buf, uint32_t buf_len)
{
	const struct device *dev_entropy;

	LOG_INF("Generating vault key...");
	dev_entropy = device_get_binding(DEVICE_DT_NAME(DT_NODELABEL(rng)));
	if (!dev_entropy) {
		LOG_ERR("Hardware random number generator not found");
		return -1;
	}

	entropy_get_entropy(dev_entropy, (uint8_t *)buf, buf_len);
	//LOG_HEXDUMP_INF(buf, buf_len, "vault key:");
	return 0;
}

int otp_prog(uint32_t addr)
{
	enum otp_status otp_rc = OTP_SUCCESS;
	const struct flash_area *fa;
	uint32_t otp_conf_val = 0;

	// Write OTP image from internal flash to OTP memory
	otp_rc = aspeed_otp_prog_image(addr);

	if (otp_rc)
		goto out;
	// Generate AES256 vault key
	otp_rc = otp_gen_vault_key(vault_key_buf, sizeof(vault_key_buf));
	if (otp_rc)
		goto out;

	// Write vault key to OTP data region
	otp_rc = otp_append_vault_key(vault_key_buf);
	if (otp_rc)
		goto out;

	otp_rc = aspeed_otp_read_conf(OTP_CONF0, &otp_conf_val, 1);
	if (otp_rc)
		goto out;

	// Enable secure boot
	otp_conf_val |= OTP_CONF0_SECURE_BOOT_EN;
	otp_rc = aspeed_otp_prog_conf(OTP_CONF0, &otp_conf_val, 1);
	if (otp_rc)
		goto out;

	//otp_rc = aspeed_otp_prog_strap_bit(OTP_STRAP_SECURE_BOOT_EN, 1);
	//if (otp_rc)
	//	goto out;

	// Enable CDI
	otp_rc = aspeed_otp_read_conf(OTP_CONF3, &otp_conf_val, 1);
	if (otp_rc)
		goto out;

	if (otp_conf_val & OTP_CONF3_CDI_EN) {
		LOG_ERR("CDI was enabled");
		otp_rc = OTP_PROG_FAILED;
		goto out;
	}

	otp_conf_val |= OTP_CONF3_CDI_EN;
	otp_rc = aspeed_otp_prog_conf(OTP_CONF3, &otp_conf_val, 1);

out:
	memset(vault_key_buf, 0, sizeof(vault_key_buf));
	if (otp_rc)
		set_mp_status(0, 1);

	switch (otp_rc) {
	case OTP_INVALID_HEADER:
		LOG_ERR("Invalid OTP image header");
		break;
	case OTP_INVALID_SOC:
		LOG_ERR("Invalid OTP soc version");
		break;
	case OTP_INVALID_CHECKSUM:
		LOG_ERR("Invalid OTP image checksum");
		break;
	case OTP_PROTECTED:
		LOG_ERR("OTP memory is protected");
		break;
	case OTP_USAGE:
		LOG_ERR("Illegal access");
		break;
	case OTP_FAILURE:
	case OTP_PROG_FAILED:
	case OTP_INVALID_PARAM:
		LOG_ERR("Failed to program OTP memory");
		break;
	case OTP_SUCCESS:
		// OTP image update successfully, erase OTP image in AST1060 internal flash
		if (flash_area_open(FIXED_PARTITION_ID(otp_img_partition), &fa)) {
			LOG_ERR("OTP partition not found");
			set_mp_status(1, 0);
			return -1;
		}
		if (flash_area_erase(fa, 0, fa->fa_size)) {
			LOG_ERR("Failed to erase OTP image");
			set_mp_status(1, 0);
			return -1;
		}
		LOG_INF("Secureboot is enabled successfully");
		LOG_INF("CDI is enabled successfully");
		LOG_INF("OTP image is erased");
		break;
	}

	return otp_rc;
}


