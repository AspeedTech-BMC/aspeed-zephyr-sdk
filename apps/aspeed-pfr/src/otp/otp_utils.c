/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <aspeed_util.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/drivers/flash.h>
#include "otp_utils.h"
#if defined(CONFIG_OTP_SIM)
#include "otp/otp_sim.h"
#else
#include <zephyr/drivers/misc/aspeed/otp_aspeed.h>
#include <zephyr/drivers/misc/aspeed/otp.h>
#endif

LOG_MODULE_REGISTER(otp, CONFIG_LOG_DEFAULT_LEVEL);

#if defined(CONFIG_OTP_ASPEED)
#define OTP_DRV_NAME		CONFIG_OTP_ASPEED_DRV_NAME
#endif

#if defined (CONFIG_OTP_SIM) || defined(CONFIG_OTP_ASPEED)
struct otp_info_cb info_cb;
int otpu_retire_key(uint32_t retire_id)
{
	const struct device *dev = NULL;
	uint32_t otpcfg4;
	uint32_t krb;
	uint32_t krb_b;
	uint32_t krb_or;
	uint32_t current_id;
	uint32_t retire_id_bit;
	uint32_t retire_id_backup;
	int ret;

#if defined(CONFIG_OTP_SIM)
	aspeed_otp_flash_init();
#else
	dev = device_get_binding(OTP_DRV_NAME);
	otp_begin_session(dev, &info_cb);
	otp_free_session(dev);
#endif
	// retire key
	aspeed_otp_read_conf(4, (uint32_t *)&otpcfg4, 1);
	ret = otp_get_key_num(dev, &current_id);

	current_id &= 7;
	retire_id_bit = 1 << retire_id;
	krb = otpcfg4 & 0xff;
	krb_b = (otpcfg4 >> 16) & 0xff;
	krb_or = krb | krb_b;

	if (info_cb.pro_sts.pro_key_ret) {
		LOG_ERR("OTPCFG4 is protected");
		return OTP_FAILURE;
	}

	if (retire_id >= current_id) {
		LOG_ERR("Retire key id is equal or bigger than current boot key");
		return OTP_FAILURE;
	}

	if (krb_or & (1 << retire_id)) {
		LOG_ERR("Key 0x%X already retired", retire_id);
		return OTP_SUCCESS;
	}

	otpcfg4 |= retire_id_bit;
	if (aspeed_otp_prog_conf(4, &otpcfg4, 1)) {
		LOG_ERR("Key retirement bit programming failed, try to program backup region");
		retire_id_backup = retire_id_bit << 16;
		otpcfg4 |=retire_id_bit;
		if (aspeed_otp_prog_conf(4, &otpcfg4, 1)) {
			LOG_ERR("Key retirement bit programming failed");
			return OTP_FAILURE;
		}
	}

	aspeed_otp_read_conf(4, (uint32_t *)&otpcfg4, 1);
	krb = otpcfg4 & 0xff;
	krb_b = (otpcfg4 >> 16) & 0xff;
	krb_or = krb | krb_b;
	if (krb_or & (1 << retire_id)) {
		LOG_WRN("key id %d is retired", retire_id);
		return OTP_SUCCESS;
	}

	return OTP_FAILURE;
}

static const uint32_t key_len_info[] = {
	0x60,    // ECDSA384
	0x100,   // RSA2048
	0x180,   // RSA3072
	0x200    // RSA4096
};

int otpu_write_key(uint8_t header_slot, uint8_t key_param, uint8_t key_type, uint32_t key_offset,
		uint8_t key_id, uint16_t key_exp_len, uint32_t key_len, const uint8_t *key)
{
	uint32_t otp_header[OTP_HEADER_LENGTH];
	uint32_t secure_area_sz = 0;
	uint32_t otpcfg0;
	uint32_t *data;
	enum otp_status ret = OTP_SUCCESS;
	OTP_KEY_HEADER *key_header;
	bool is_header_empty = false;

	if (key_len != key_len_info[key_param]) {
		LOG_ERR("Key is invalid, key_type : %x, key_param: %x, key_len: %x",
				key_type, key_param, key_len);
		return OTP_FAILURE;
	}


	ret = aspeed_otp_read_data(OTP_HEADER_START_ADDR, otp_header, OTP_HEADER_LENGTH);
	if (ret)
		return ret;

	data = otp_header;
	// new key should be added in empty slot
	if (header_slot % 2) {
		if (data[header_slot] == 0xffffffff)
			is_header_empty = true;


	} else {
		if (data[header_slot] == 0)
			is_header_empty = true;

	}

	if (!is_header_empty) {
		LOG_ERR("otp header [%d] is not empty", header_slot);
		return OTP_FAILURE;
	}

	data[header_slot] = 0;
	key_header = (OTP_KEY_HEADER *)&data[header_slot];

	key_header->key_exp_len = key_exp_len;
	key_header->key_param = key_param;
	key_header->key_type = key_type;
	key_header->key_offset = key_offset >> 3;
	key_header->key_id = key_id;

	aspeed_otp_read_conf(0, (uint32_t *)&otpcfg0, 1);
	secure_area_sz = (otpcfg0 >> 16) & 0x3f;
	secure_area_sz = secure_area_sz * 32 * DWORD;

	if (secure_area_sz) {
		if (key_offset >= secure_area_sz)
			LOG_WRN("Key is writing to non-secure area");

		if ((key_offset <= secure_area_sz) &&
				(key_offset + key_len > secure_area_sz)) {
			LOG_ERR("key crosses the boundary of secure area");
			return OTP_FAILURE;
		}
	}

	ret = aspeed_otp_prog_data(OTP_HEADER_START_ADDR, otp_header, OTP_HEADER_LENGTH);
	if (ret) {
		LOG_ERR("Failed to update otp key header");
		return OTP_FAILURE;
	}

	ret = aspeed_otp_prog_data( key_offset / DWORD, (uint32_t *)key, key_len / DWORD);
	if (ret) {
		LOG_ERR("Failed to add key to OTP region");
		return OTP_FAILURE;
	}

	LOG_WRN("New key is added in otp successfully");

	return OTP_SUCCESS;
}
#endif
