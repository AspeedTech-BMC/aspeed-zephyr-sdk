/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_OTP_SIM)
#include <zephyr/kernel.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/sys_io.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <aspeed_util.h>

#include "otp_sim.h"

#define OTPTOOL_VERSION_MAJOR(x) (((x) >> 24) & 0xff)

#define ASPEED_REVISION_ID0             0x7e6e2004
#define ASPEED_REVISION_ID1             0x7e6e2014

static struct otp_info_cb info_cb;
struct otpstrap_status strap_status[64];

static uint32_t otp_data_buf[OTP_DATA_DW_SIZE] NON_CACHED_BSS_ALIGN16;
static uint32_t otp_conf_buf[OTP_CONF_DW_SIZE] NON_CACHED_BSS_ALIGN16;
const struct device *otp_sim_dev;
const struct flash_area *otp_sim_fa;

static uint32_t chip_version(void)
{
	uint32_t revid0, revid1;

	revid0 = sys_read32(ASPEED_REVISION_ID0);
	revid1 = sys_read32(ASPEED_REVISION_ID1);

	if (revid0 == ID0_AST1030A0 && revid1 == ID1_AST1030A0) {
		/* AST1030-A0 */
		return OTP_AST1030A0;
	} else if (revid0 == ID0_AST1030A1 && revid1 == ID1_AST1030A1) {
		/* AST1030-A1 */
		return OTP_AST1030A1;
	} else if (revid0 == ID0_AST1060A1 && revid1 == ID1_AST1060A1) {
		/* AST1060-A1 */
		return OTP_AST1060A1;
	} else if ((revid0 == ID0_AST1060A2 && revid1 == ID1_AST1060A2) ||
			(revid0 == ID0_AST1060A2_ENG && revid1 == ID1_AST1060A2_ENG)) {
		/* AST1060-A1 */
		return OTP_AST1060A2;
	}
	return OTP_FAILURE;
}

void init_otp_sim_region(void)
{
	otp_sim_dev = device_get_binding(OTP_FLASH_DEV);
	if (!otp_sim_dev) {
		printk("Flash driver was not found!\n");
	}
}

int aspeed_otp_read_data(uint32_t offset, uint32_t *buf, uint32_t len)
{
	uint32_t flash_offset = offset * DWORD;
	int i;

	if (offset + len > 2048)
		return OTP_USAGE;

	init_otp_sim_region();
	flash_read(otp_sim_dev, OTP_SIM_BASE_ADDR + flash_offset, otp_data_buf, (len * DWORD));
	for (i = 0; i < len; i++) {
		if (otp_data_buf[i] == 0xffffffff) {
			if (offset % 2) {
				if (i % 2)
					otp_data_buf[i] = 0;
			} else {
				if (!(i % 2))
					otp_data_buf[i] = 0;
			}
		}
	}
	memcpy(buf, otp_data_buf, (len * DWORD));

	return OTP_SUCCESS;
}

int aspeed_otp_read_conf(uint32_t offset, uint32_t *buf, uint32_t len)
{
	int i;
	int config_offset = 0;
	int buf_idx = 0;

	init_otp_sim_region();

	if (offset + len > 32)
		return OTP_USAGE;

	flash_read(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR), otp_conf_buf,
			sizeof(otp_conf_buf));

	for (i = offset; i < offset + len; i++) {
		/*       OTPCFG                 ADDR (DW unit)
		 *  ------------------------------------------
		 *  OTPCFG0  - OTPCFG7           0x800 - 0x80E
		 *  OTPCFG8  - OTPCFG15          0xA00 - 0xA0E
		 *  OTPCFG16 - OTPCFG23          0xC00 - 0xC0E
		 *  OTPCFG24 - OTPCFG31          0xE00 - 0xE0E
		 */
		config_offset = (i / 8) * 0x200;
		config_offset |= (i % 8) * 0x2;
		otp_conf_buf[config_offset] = ~otp_conf_buf[config_offset];
		memcpy(&buf[buf_idx], &otp_conf_buf[config_offset], DWORD);
		buf_idx++;
	}

	return OTP_SUCCESS;
}

static int _aspeed_otp_prog_strap(struct otp_image_layout *image_layout,
			  struct otpstrap_status *os)
{
	uint32_t *strap;
	uint32_t *strap_ignore;
	uint32_t *strap_pro;
	uint32_t prog_address;
	int bit, pbit, ibit, offset;
	int prog_flag = 0;
	int fail = 0;
	int i;

	strap = (uint32_t *)image_layout->strap;
	strap_pro = (uint32_t *)image_layout->strap_pro;
	strap_ignore = (uint32_t *)image_layout->strap_ignore;
	flash_read(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR),
			otp_conf_buf, sizeof(otp_conf_buf));

	for (i = 0; i < 64; i++) {
		prog_address = 0;
		if (i < 32) {
			offset = i;
			bit = (strap[0] >> offset) & 0x1;
			ibit = (strap_ignore[0] >> offset) & 0x1;
			pbit = (strap_pro[0] >> offset) & 0x1;
			prog_address |= ((os[i].writeable_option * 2 + 16) / 8) * 0x200;
			prog_address |= ((os[i].writeable_option * 2 + 16) % 8) * 0x2;

		} else {
			offset = (i - 32);
			bit = (strap[1] >> offset) & 0x1;
			ibit = (strap_ignore[1] >> offset) & 0x1;
			pbit = (strap_pro[1] >> offset) & 0x1;
			prog_address |= ((os[i].writeable_option * 2 + 17) / 8) * 0x200;
			prog_address |= ((os[i].writeable_option * 2 + 17) % 8) * 0x2;
		}

		if (ibit == 1)
			continue;
		if (bit == os[i].value)
			prog_flag = 0;
		else
			prog_flag = 1;

		if (os[i].protected == 1 && prog_flag) {
			fail = 1;
			continue;
		}
		if (os[i].remain_times == 0 && prog_flag) {
			fail = 1;
			continue;
		}

		if (prog_flag) {
			otp_conf_buf[prog_address] &= (~BIT(offset));
		}

		if (pbit != 0) {
			prog_address = 0;
			if (i < 32)
				prog_address |= 0x60c;
			else
				prog_address |= 0x60e;

			otp_conf_buf[prog_address] &= (~BIT(offset));
		}
	}

	if (fail == 1)
		return OTP_FAILURE;

	flash_erase(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR), OTP_CONF_SIZE);
	flash_write(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR), otp_conf_buf,
			sizeof(otp_conf_buf));

	return OTP_SUCCESS;
}

static int _aspeed_otp_prog_scu_protect(struct otp_image_layout *image_layout,
				uint32_t *scu_pro)
{
	uint32_t *OTPSCU_IGNORE = (uint32_t *)image_layout->scu_pro_ignore;
	uint32_t *OTPSCU = (uint32_t *)image_layout->scu_pro;
	uint32_t prog_address;
	uint32_t data_masked;
	uint32_t buf_masked;
	int i;

	flash_read(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR),
			otp_conf_buf, sizeof(otp_conf_buf));

	for (i = 0; i < 2; i++) {
		data_masked = scu_pro[i]  & ~OTPSCU_IGNORE[i];
		buf_masked  = OTPSCU[i] & ~OTPSCU_IGNORE[i];
		prog_address = 0x608 + i * 2;
		if (data_masked == buf_masked)
			continue;

		otp_conf_buf[prog_address] = ~OTPSCU[i];
	}

	flash_erase(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR), OTP_CONF_SIZE);
	flash_write(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR), otp_conf_buf,
			sizeof(otp_conf_buf));

	return OTP_SUCCESS;
}

static int _aspeed_otp_prog_data(struct otp_image_layout *image_layout)
{
	uint32_t *buf_ignore;
	uint32_t *buf;
	int i;

	buf = (uint32_t *)image_layout->data;
	buf_ignore = (uint32_t *)image_layout->data_ignore;

	init_otp_sim_region();
	flash_read(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_DATA_BASE_ADDR), otp_data_buf,
			sizeof(otp_data_buf));

	for (i = OTP_DATA_BASE_ADDR; i < OTP_DATA_DW_SIZE; i++) {
		if (buf[i] & ~buf_ignore[i]) {
			otp_data_buf[i] = buf[i];
		}
	}

	flash_erase(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_DATA_BASE_ADDR), OTP_DATA_SIZE);
	flash_write(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_DATA_BASE_ADDR), otp_data_buf,
			sizeof(otp_data_buf));

	return OTP_SUCCESS;
}

int aspeed_otp_prog_data(uint32_t offset, uint32_t *buf, uint32_t len)
{
	if (offset + len > OTP_DATA_DW_SIZE)
		return OTP_USAGE;

	init_otp_sim_region();
	flash_read(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_DATA_BASE_ADDR), otp_data_buf,
			sizeof(otp_data_buf));
	memcpy(&otp_data_buf[offset], buf, (len * DWORD));

	flash_erase(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_DATA_BASE_ADDR), OTP_DATA_SIZE);
	flash_write(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_DATA_BASE_ADDR), otp_data_buf,
			sizeof(otp_data_buf));
	return OTP_SUCCESS;
}

static int _aspeed_otp_prog_conf(struct otp_image_layout *image_layout,
			 uint32_t *otp_conf)
{
	uint32_t *conf_ignore = (uint32_t *)image_layout->conf_ignore;
	uint32_t *conf = (uint32_t *)image_layout->conf;
	uint32_t prog_address;
	uint32_t data_masked;
	uint32_t buf_masked;
	int i;

	flash_read(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR), otp_conf_buf,
			sizeof(otp_conf_buf));

	for (i = 0; i < 16; i++) {
		data_masked = otp_conf[i]  & ~conf_ignore[i];
		buf_masked  = conf[i] & ~conf_ignore[i];
		prog_address = (i / 8) * 0x200;
		prog_address |= (i % 8) * 0x2;
		if (data_masked == buf_masked)
			continue;

		otp_conf_buf[prog_address] = ~conf[i];
	}

	flash_erase(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR), OTP_CONF_SIZE);
	flash_write(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR), otp_conf_buf,
			sizeof(otp_conf_buf));

	return OTP_SUCCESS;
}

int aspeed_otp_prog_conf(uint32_t offset, uint32_t *buf, uint32_t len)
{
	int i;
	int config_offset = 0;

	if (offset + len > 32)
		return OTP_USAGE;

	init_otp_sim_region();

	flash_read(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR),
			otp_conf_buf, sizeof(otp_conf_buf));

	for (i = 0; i < len; i++) {
		/*      OTPCFG                 ADDR (DW unit)
		 * ------------------------------------------
		 * OTPCFG0  - OTPCFG7           0x800 - 0x80E
		 * OTPCFG8  - OTPCFG15          0xA00 - 0xA0E
		 * OTPCFG16 - OTPCFG23          0xC00 - 0xC0E
		 * OTPCFG24 - OTPCFG31          0xE00 - 0xE0E
		 */
		config_offset = ((offset + i) / 8) * 0x200;
		config_offset |= ((offset + i) % 8) * 0x2;
		buf[i] = ~buf[i];
		memcpy(&otp_conf_buf[config_offset], &buf[i], DWORD);
	}

	flash_erase(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR), OTP_CONF_SIZE);
	flash_write(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR), otp_conf_buf,
			sizeof(otp_conf_buf));

	return OTP_SUCCESS;
}

void aspeed_otp_flash_init(void)
{
	struct otp_pro_sts *pro_sts;
	uint32_t otp_conf0;
	uint32_t chip_ver = chip_version();

	switch(chip_ver) {
	case OTP_AST1060A1:
		info_cb.version = OTP_AST1060A1;
		sprintf(info_cb.ver_name, "AST1060A1");
		break;
	case OTP_AST1060A2:
		info_cb.version = OTP_AST1060A2;
		sprintf(info_cb.ver_name, "AST1060A2");
		break;
	}

	info_cb.conf_info = ast1030a1_conf_info;
	info_cb.conf_info_len = ARRAY_SIZE(ast1030a1_conf_info);
	info_cb.strap_info = ast1030a0_strap_info;
	info_cb.strap_info_len = ARRAY_SIZE(ast1030a0_strap_info);
	info_cb.scu_info = ast1030a0_scu_info;
	info_cb.scu_info_len = ARRAY_SIZE(ast1030a0_scu_info);
	info_cb.key_info = ast10xxa1_key_type;
	info_cb.key_info_len = ARRAY_SIZE(ast10xxa1_key_type);

	init_otp_sim_region();
	aspeed_otp_read_conf(0, &otp_conf0, 1);

	pro_sts = &info_cb.pro_sts;
	pro_sts->mem_lock = (otp_conf0 >> 31) & 0x1;
	pro_sts->pro_key_ret = (otp_conf0 >> 29) & 0x1;
	pro_sts->pro_strap = (otp_conf0 >> 25) & 0x1;
	pro_sts->pro_conf = (otp_conf0 >> 24) & 0x1;
	pro_sts->pro_data = (otp_conf0 >> 23) & 0x1;
	pro_sts->pro_sec = (otp_conf0 >> 22) & 0x1;
	pro_sts->sec_size = ((otp_conf0 >> 16) & 0x3f) << 5;
}

static void otp_flash_strap_status(struct otpstrap_status *os)
{
	uint32_t OTPSTRAP_RAW[2];
	uint32_t otp_conf_0_31[32];
	int strap_end;
	int i, j;

	for (j = 0; j < 64; j++) {
		os[j].value = 0;
		os[j].remain_times = 6;
		os[j].writeable_option = -1;
		os[j].protected = 0;
	}
	strap_end = 28;

	aspeed_otp_read_conf(0, otp_conf_0_31, 32);
	for (i = 16; i < strap_end; i += 2) {
		int option = (i - 16) / 2;

		OTPSTRAP_RAW[0] = otp_conf_0_31[i];
		OTPSTRAP_RAW[1] = otp_conf_0_31[i + 1];

		for (j = 0; j < 32; j++) {
			char bit_value = ((OTPSTRAP_RAW[0] >> j) & 0x1);

			if (bit_value == 0 && os[j].writeable_option == -1)
				os[j].writeable_option = option;
			if (bit_value == 1)
				os[j].remain_times--;
			os[j].value ^= bit_value;
			os[j].option_array[option] = bit_value;
		}
		for (j = 32; j < 64; j++) {
			char bit_value = ((OTPSTRAP_RAW[1] >> (j - 32)) & 0x1);

			if (bit_value == 0 && os[j].writeable_option == -1)
				os[j].writeable_option = option;
			if (bit_value == 1)
				os[j].remain_times--;
			os[j].value ^= bit_value;
			os[j].option_array[option] = bit_value;
		}
	}

	OTPSTRAP_RAW[0] = otp_conf_0_31[30];
	OTPSTRAP_RAW[1] = otp_conf_0_31[31];

	for (j = 0; j < 32; j++) {
		if (((OTPSTRAP_RAW[0] >> j) & 0x1) == 1)
			os[j].protected = 1;
	}
	for (j = 32; j < 64; j++) {
		if (((OTPSTRAP_RAW[1] >> (j - 32)) & 0x1) == 1)
			os[j].protected = 1;
	}
}

int aspeed_otp_read_strap(uint32_t *buf)
{
	if (!buf)
		return -EINVAL;

	aspeed_otp_flash_init();
	otp_flash_strap_status(strap_status);
	for (int i = 0; i < 2; i++) {
		for (int j = 0; j < 32; j++)
			buf[i] |= strap_status[i * 32 + j].value << j;
	}

	return OTP_SUCCESS;
}

int aspeed_otp_prog_strap_bit(uint32_t bit_offset, int value)
{
	int ret = 0;
	uint32_t prog_address = 0;
	uint32_t offset;

	if (bit_offset >= 64 || (value != 0 && value != 1))
		return -EINVAL;

	aspeed_otp_flash_init();

	if (info_cb.pro_sts.pro_strap)
		return -EINVAL;

	otp_flash_strap_status(strap_status);

	if (bit_offset < 32) {
		offset = bit_offset;
		prog_address |= ((strap_status[bit_offset].writeable_option * 2 + 16) / 8) * 0x200;
		prog_address |= ((strap_status[bit_offset].writeable_option * 2 + 16) % 8) * 0x2;

	} else {
		offset = (bit_offset - 32);
		prog_address |= ((strap_status[bit_offset].writeable_option * 2 + 17) / 8) * 0x200;
		prog_address |= ((strap_status[bit_offset].writeable_option * 2 + 17) % 8) * 0x2;
	}

	flash_read(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR),
			otp_conf_buf, sizeof(otp_conf_buf));
	otp_conf_buf[prog_address] &= (~BIT(offset));
	flash_erase(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR), OTP_CONF_SIZE);
	flash_write(otp_sim_dev, (OTP_SIM_BASE_ADDR + OTP_CONF_BASE_ADDR), otp_conf_buf,
			sizeof(otp_conf_buf));

	return ret;
}

static int otp_verify_image(uint8_t *src_buf, uint32_t length,
			    uint8_t *digest_buf, int version)
{
	uint8_t digest_ret[48];
	int digest_len;

	switch (version) {
	case 1:
		mbedtls_sha256(src_buf, length, digest_ret, 0);
		digest_len = 32;
		break;
	case 2:
		mbedtls_sha512(src_buf, length, digest_ret, 1);
		digest_len = 48;
		break;
	default:
		return OTP_FAILURE;
	}

	if (!memcmp(digest_buf, digest_ret, digest_len))
		return OTP_SUCCESS;
	return OTP_FAILURE;
}

int aspeed_otp_prog_image(uint32_t addr)
{
	struct otp_image_layout image_layout;
	struct otp_header *otp_header;
	uint32_t data[2048];
	uint32_t scu_pro[2];
	uint32_t conf[16];
	uint8_t *checksum;
	uint8_t *buf;
	int image_soc_ver = 0;
	int image_size;
	int ret;

	aspeed_otp_flash_init();

	otp_header = (struct otp_header *)addr;
	image_size = OTP_IMAGE_SIZE(otp_header->image_info);
	buf = (uint8_t *)addr;

	if (!buf) {
		return OTP_FAILURE;
	}
	otp_header = (struct otp_header *)buf;
	checksum = buf + otp_header->checksum_offset;

	if (strcmp(OTP_MAGIC, (char *)otp_header->otp_magic) != 0) {
		return OTP_INVALID_HEADER;
	}

	image_layout.data_length = (int)(OTP_REGION_SIZE(otp_header->data_info) / 2);
	image_layout.data = buf + OTP_REGION_OFFSET(otp_header->data_info);
	image_layout.data_ignore = image_layout.data + image_layout.data_length;

	image_layout.conf_length = (int)(OTP_REGION_SIZE(otp_header->config_info) / 2);
	image_layout.conf = buf + OTP_REGION_OFFSET(otp_header->config_info);
	image_layout.conf_ignore = image_layout.conf + image_layout.conf_length;

	image_layout.strap = buf + OTP_REGION_OFFSET(otp_header->strap_info);
	image_layout.strap_length = (int)(OTP_REGION_SIZE(otp_header->strap_info) / 3);
	image_layout.strap_pro = image_layout.strap + image_layout.strap_length;
	image_layout.strap_ignore = image_layout.strap + 2 * image_layout.strap_length;

	image_layout.scu_pro = buf + OTP_REGION_OFFSET(otp_header->scu_protect_info);
	image_layout.scu_pro_length = (int)(OTP_REGION_SIZE(otp_header->scu_protect_info) / 2);
	image_layout.scu_pro_ignore = image_layout.scu_pro + image_layout.scu_pro_length;

	if (otp_header->soc_ver == SOC_AST1060A1)
		image_soc_ver = OTP_AST1060A1;
	else if (otp_header->soc_ver == SOC_AST1060A2)
		image_soc_ver = OTP_AST1060A2;
	else
		return OTP_INVALID_SOC;

	if (image_soc_ver != info_cb.version)
		return OTP_INVALID_SOC;

	switch (OTPTOOL_VERSION_MAJOR(otp_header->otptool_ver)) {
	case 1:
		/* WARNING: OTP image is not generated by otptool v2.x.x */
		/* Please use the latest version of otptool to generate OTP image */
		ret = otp_verify_image(buf, image_size, checksum, 1);
		break;
	case 2:
		ret = otp_verify_image(buf, image_size, checksum, 2);
		break;
	default:
		return OTP_FAILURE;
	}

	if (ret) {
		return OTP_INVALID_CHECKSUM;
	}

	if (info_cb.pro_sts.mem_lock) {
		return OTP_PROTECTED;
	}
	ret = 0;
	if (otp_header->image_info & OTP_INC_DATA) {
		if (info_cb.pro_sts.pro_data) {
			ret = OTP_PROTECTED;
		}
		if (info_cb.pro_sts.pro_sec) {
			ret = OTP_PROTECTED;
		}
		aspeed_otp_read_data(0, data, OTP_DATA_DW_SIZE);
	}
	if (otp_header->image_info & OTP_INC_CONFIG) {
		if (info_cb.pro_sts.pro_conf) {
			ret = OTP_PROTECTED;
		}
		aspeed_otp_read_conf(0, conf, 16);
	}
	if (otp_header->image_info & OTP_INC_STRAP) {
		if (info_cb.pro_sts.pro_strap) {
			ret = OTP_PROTECTED;
		}
		otp_flash_strap_status(strap_status);
	}

	if (otp_header->image_info & OTP_INC_SCU_PRO) {
		if (info_cb.pro_sts.pro_strap) {
			ret = OTP_PROTECTED;
		}
		aspeed_otp_read_conf(28, scu_pro, 2);
	}
	if (ret < 0)
		return ret;

	if (otp_header->image_info & OTP_INC_DATA) {
		ret = _aspeed_otp_prog_data(&image_layout);
		if (ret != 0) {
			return OTP_PROG_FAILED;
		}
	}
	if (otp_header->image_info & OTP_INC_STRAP) {
		ret = _aspeed_otp_prog_strap(&image_layout, strap_status);
		if (ret != 0) {
			return OTP_PROG_FAILED;
		}
	}
	if (otp_header->image_info & OTP_INC_SCU_PRO) {
		ret = _aspeed_otp_prog_scu_protect(&image_layout, scu_pro);
		if (ret != 0) {
			return OTP_PROG_FAILED;
		}
	}
	if (otp_header->image_info & OTP_INC_CONFIG) {
		ret = _aspeed_otp_prog_conf(&image_layout, conf);
		if (ret != 0) {
			return OTP_PROG_FAILED;
		}
	}

	return OTP_SUCCESS;
}
#endif

