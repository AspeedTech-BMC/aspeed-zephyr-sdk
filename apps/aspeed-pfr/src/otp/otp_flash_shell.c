/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#if defined(CONFIG_OTP_SIM)
#if defined(CONFIG_OTP_SIM_SHELL)
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <zephyr/shell/shell.h>
#include <zephyr/storage/flash_map.h>
#include <stdio.h>
#include <stdlib.h>
#include <aspeed_util.h>
#include "otp/otp_sim.h"

#define shell_printf(_sh, _ft, ...) \
	shell_fprintf(_sh, SHELL_NORMAL, _ft, ##__VA_ARGS__)

static struct otp_info_cb info_cb;
static uint32_t g_data[2048] NON_CACHED_BSS_ALIGN16;

void aspeed_otpf_init(void)
{
	struct otp_pro_sts *pro_sts;
	uint32_t otp_conf0;

	info_cb.version = OTP_AST1060A1;
	info_cb.conf_info = ast1030a1_conf_info;
	info_cb.conf_info_len = ARRAY_SIZE(ast1030a1_conf_info);
	info_cb.strap_info = ast1030a0_strap_info;
	info_cb.strap_info_len = ARRAY_SIZE(ast1030a0_strap_info);
	info_cb.scu_info = ast1030a0_scu_info;
	info_cb.scu_info_len = ARRAY_SIZE(ast1030a0_scu_info);
	info_cb.key_info = ast10xxa1_key_type;
	info_cb.key_info_len = ARRAY_SIZE(ast10xxa1_key_type);
	sprintf(info_cb.ver_name, "AST1060A1");

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

static void buf_print(const struct shell *shell, uint8_t *buf, int len)
{
	int i;

	shell_printf(shell, "      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");
	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			shell_printf(shell, "%04X: ", i);
		shell_printf(shell, "%02X ", buf[i]);
		if ((i + 1) % 16 == 0)
			shell_printf(shell, "\n");
	}
	shell_printf(shell, "\n");
}

static void _otp_print_key(const struct shell *shell, uint32_t header,
			   uint32_t offset, uint8_t *data)
{
	const struct otpkey_type *key_info_array = info_cb.key_info;
	struct otpkey_type key_info;
	int key_id, key_offset, key_type, key_length, exp_length;
	int len = 0;
	int i;

	key_id = header & 0x7;
	key_offset = header & 0x1ff8;
	key_type = (header >> 14) & 0xf;
	key_length = (header >> 18) & 0x3;
	exp_length = (header >> 20) & 0xfff;

	shell_printf(shell, "\nKey[%d]:\n", offset);
	shell_printf(shell, "Header: %x\n", header);

	key_info.value = -1;
	for (i = 0; i < info_cb.key_info_len; i++) {
		if (key_type == key_info_array[i].value) {
			key_info = key_info_array[i];
			break;
		}
	}
	if (key_info.value == -1)
		return;

	shell_printf(shell, "Key Type: ");
	shell_printf(shell, "%s\n", key_info.information);

	if (key_info.key_type == OTP_KEY_TYPE_HMAC) {
		shell_printf(shell, "HMAC SHA Type: ");
		switch (key_length) {
		case 0:
			shell_printf(shell, "HMAC(SHA224)\n");
			break;
		case 1:
			shell_printf(shell, "HMAC(SHA256)\n");
			break;
		case 2:
			shell_printf(shell, "HMAC(SHA384)\n");
			break;
		case 3:
			shell_printf(shell, "HMAC(SHA512)\n");
			break;
		}
	} else if (key_info.key_type == OTP_KEY_TYPE_RSA_PRIV ||
			   key_info.key_type == OTP_KEY_TYPE_RSA_PUB) {
		shell_printf(shell, "RSA SHA Type: ");
		switch (key_length) {
		case 0:
			shell_printf(shell, "RSA1024\n");
			len = 0x100;
			break;
		case 1:
			shell_printf(shell, "RSA2048\n");
			len = 0x200;
			break;
		case 2:
			shell_printf(shell, "RSA3072\n");
			len = 0x300;
			break;
		case 3:
			shell_printf(shell, "RSA4096\n");
			len = 0x400;
			break;
		}
		shell_printf(shell, "RSA exponent bit length: %d\n", exp_length);
	} else if (key_info.key_type == OTP_KEY_ECDSA384) {
		shell_printf(shell, "Curve P-384\n");
		len = 0x60;
	}

	if (key_info.need_id)
		shell_printf(shell, "Key Number ID: %d\n", key_id);
	shell_printf(shell, "Key Value:\n");
	if (key_info.key_type == OTP_KEY_TYPE_HMAC) {
		buf_print(shell, &data[key_offset], 0x40);
	} else if (key_info.key_type == OTP_KEY_TYPE_AES) {
		shell_printf(shell, "AES Key:\n");
		buf_print(shell, &data[key_offset], 0x20);
	} else if (key_info.key_type == OTP_KEY_TYPE_VAULT) {
		shell_printf(shell, "AES Key 1:\n");
		buf_print(shell, &data[key_offset], 0x20);
		shell_printf(shell, "AES Key 2:\n");
		buf_print(shell, &data[key_offset + 0x20], 0x20);
	} else if (key_info.key_type == OTP_KEY_TYPE_RSA_PRIV) {
		shell_printf(shell, "RSA mod:\n");
		buf_print(shell, &data[key_offset], len / 2);
		shell_printf(shell, "RSA exp:\n");
		buf_print(shell, &data[key_offset + (len / 2)], len / 2);
	} else if (key_info.key_type == OTP_KEY_TYPE_RSA_PUB) {
		shell_printf(shell, "RSA mod:\n");
		buf_print(shell, &data[key_offset], len / 2);
		shell_printf(shell, "RSA exp:\n");
		buf_print(shell, (uint8_t *)"\x01\x00\x01", 3);
	} else if (key_info.key_type == OTP_KEY_ECDSA384) {
		shell_printf(shell, "Q.x:\n");
		buf_print(shell, &data[key_offset], len / 2);
		shell_printf(shell, "Q.y:\n");
		buf_print(shell, &data[key_offset + 0x30], len / 2);
	}
}

static void otp_print_key(const struct shell *shell, uint32_t *data)
{
	uint8_t *byte_buf;
	int empty;
	int last;
	int i;

	byte_buf = (uint8_t *)data;

	empty = 1;
	for (i = 0; i < 16; i++) {
		if (i % 2) {
			if (data[i] != 0xffffffff)
				empty = 0;
		} else {
			if (data[i] != 0)
				empty = 0;
		}
	}
	if (empty) {
		shell_printf(shell, "OTP data header is empty\n");
		return;
	}
	for (i = 0; i < 16; i++) {
		last = (data[i] >> 13) & 1;
		_otp_print_key(shell, data[i], i, byte_buf);
		if (last)
			break;
	}
}

static void otp_print_key_info(const struct shell *shell)
{
	uint32_t *data = g_data;

	memset(data, 0, sizeof(g_data));

	aspeed_otp_read_data(0, data, 2048);
	otp_print_key(shell, data);
}

static int otpf_print_conf_info(const struct shell *shell, int input_offset)
{
	const struct otpconf_info *conf_info = info_cb.conf_info;
	uint32_t OTPCFG[16];
	uint32_t mask;
	uint32_t dw_offset;
	uint32_t bit_offset;
	uint32_t otp_value;
	char valid_bit[20];
	int i, j;

	aspeed_otpf_init();

	for (i = 0; i < 16; i++)
		aspeed_otp_read_conf(i, &OTPCFG[i], 1);

	shell_printf(shell, "DW    BIT        Value       Description\n");
	shell_printf(shell,
		"__________________________________________________________________________\n");

	for (i = 0; i < info_cb.conf_info_len; i++) {
		if (input_offset != -1 && input_offset != conf_info[i].dw_offset)
			continue;
		dw_offset = conf_info[i].dw_offset;
		bit_offset = conf_info[i].bit_offset;
		mask = BIT(conf_info[i].length) - 1;
		otp_value = (OTPCFG[dw_offset] >> bit_offset) & mask;

		if (otp_value != conf_info[i].value &&
			conf_info[i].value != OTP_REG_RESERVED &&
			conf_info[i].value != OTP_REG_VALUE &&
			conf_info[i].value != OTP_REG_VALID_BIT)
			continue;
		shell_printf(shell, "0x%-4X", dw_offset);

		if (conf_info[i].length == 1) {
			shell_printf(shell, "0x%-9X", conf_info[i].bit_offset);
		} else {
			shell_printf(shell, "0x%-2X:0x%-4X",
						 conf_info[i].bit_offset + conf_info[i].length - 1,
						 conf_info[i].bit_offset);
		}
		shell_printf(shell, "0x%-10x", otp_value);

		if (conf_info[i].value == OTP_REG_RESERVED) {
			shell_printf(shell, "Reserved\n");
		} else if (conf_info[i].value == OTP_REG_VALUE) {
			shell_printf(shell, conf_info[i].information, otp_value);
			shell_printf(shell, "\n");
		} else if (conf_info[i].value == OTP_REG_VALID_BIT) {
			if (otp_value != 0) {
				for (j = 0; j < 7; j++) {
					if (otp_value & (1 << j))
						valid_bit[j * 2] = '1';
					else
						valid_bit[j * 2] = '0';
					valid_bit[j * 2 + 1] = ' ';
				}
				valid_bit[15] = 0;
			} else {
				strcpy(valid_bit, "0 0 0 0 0 0 0 0\0");
			}
			shell_printf(shell, conf_info[i].information, valid_bit);
			shell_printf(shell, "\n");
		} else {
			shell_printf(shell, "%s\n", conf_info[i].information);
		}
	}
	return OTP_SUCCESS;
}

static int otpf_print_strap_info(const struct shell *shell, int view)
{
	const struct otpstrap_info *strap_info = info_cb.strap_info;
	uint32_t bit_offset;
	uint32_t length;
	uint32_t otp_value;
	uint32_t otp_strap_buf[2] = {0};
	int fail = 0;
	int i;

	aspeed_otp_read_strap(otp_strap_buf);
	shell_printf(shell, "BIT(hex)   Value       Description\n");
	shell_printf(shell,
			"________________________________________________________________________________\n");

	for (i = 0; i < info_cb.strap_info_len; i++) {
		otp_value = 0;
		bit_offset = strap_info[i].bit_offset;
		length = strap_info[i].length;
		otp_value = (otp_strap_buf[bit_offset / 32] >> (bit_offset % 32)) &
			GENMASK(length, 0);
		if (otp_value != strap_info[i].value &&
			strap_info[i].value != OTP_REG_RESERVED)
			continue;
		if (length == 1) {
			shell_printf(shell, "0x%-9X", strap_info[i].bit_offset);
		} else {
			shell_printf(shell, "0x%-2X:0x%-4X",
					bit_offset + length - 1, bit_offset);
		}

		shell_printf(shell, "0x%-10X", otp_value);

		if (strap_info[i].value != OTP_REG_RESERVED)
			shell_printf(shell, "%s\n", strap_info[i].information);
		else
			shell_printf(shell, "Reserved\n");
	}

	if (fail)
		return OTP_FAILURE;

	return OTP_SUCCESS;
}

int otpf_print_conf(const struct shell *shell, uint32_t offset, int dw_count)
{
	uint32_t ret[1];
	int i;

	if (offset + dw_count > 32)
		return OTP_USAGE;

	//aspeed_otp_read_conf(offset, buf, dw_count);
	//shell_hexdump(shell, buf, dw_count);
	for (i = offset; i < offset + dw_count; i++) {
		aspeed_otp_read_conf(i, ret, 1);
		//otp_read_conf(i, ret);
		shell_printf(shell, "OTPCFG0x%X: 0x%08X\n", i, ret[0]);
	}

	return OTP_SUCCESS;
}

int otpf_print_data(const struct shell *shell, uint32_t offset, int dw_count)
{
	int i;
	uint32_t ret[2];

	if (offset + dw_count > 2048 || offset % 4 != 0)
		return OTP_USAGE;

	for (i = offset; i < offset + dw_count; i += 2) {
		aspeed_otp_read_data(i, ret, 2);
		if (i % 4 == 0)
			shell_printf(shell, "%03X: %08X %08X ", i * 4, ret[0], ret[1]);
		else
			shell_printf(shell, "%08X %08X\n", ret[0], ret[1]);
	}

	shell_printf(shell, "\n");

	return OTP_SUCCESS;
}

static int do_otpreadf(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t offset, count;
	int ret = 0;

	if (argc == 4) {
		offset = strtoul(argv[2], NULL, 16);
		count = strtoul(argv[3], NULL, 16);
	} else if (argc == 3) {
		offset = strtoul(argv[2], NULL, 16);
		count = 1;
	} else {
		return -EINVAL;
	}

	if (!strcmp(argv[1], "conf"))
		ret = otpf_print_conf(shell, offset, count);
	else if (!strcmp(argv[1], "data"))
		ret = otpf_print_data(shell, offset, count);
	else
		ret = -EINVAL;

	return ret;
}

static int do_otpinfof(const struct shell *shell, size_t argc, char **argv)
{
	int view = 0;
	int input;
	int ret = 0;

	if (argc != 2 && argc != 3)
		return -EINVAL;

	aspeed_otpf_init();

	if (!strcmp(argv[1], "conf")) {
		if (argc == 3) {
			input = strtoul(argv[2], NULL, 16);
			otpf_print_conf_info(shell, input);
		} else {
			otpf_print_conf_info(shell, -1);
		}
	} else if (!strcmp(argv[1], "strap")) {
		otpf_print_strap_info(shell, view);
	} else if (!strcmp(argv[1], "key")) {
		otp_print_key_info(shell);
	} else {
		ret = -EINVAL;
	}

	return ret;
}

#define SHELL_HELP_OTPREAD	\
	"Read OTP(in flash) conf/data/strap cmds\n"			\
	"- otpf read conf|data <otp_dw_offset> <dw_count>"

#define SHELL_HELP_OTPINFO	\
	"Show OTP information for strap/conf/scu/key\n"		\
	"- otpf info strap\n"				\
	"- otpf info conf [otp_dw_offset]"

SHELL_STATIC_SUBCMD_SET_CREATE(optf_cmds,
		SHELL_CMD_ARG(read, NULL, SHELL_HELP_OTPREAD, do_otpreadf, 3, 1),
		SHELL_CMD_ARG(info, NULL, SHELL_HELP_OTPINFO, do_otpinfof, 2, 1),
		//SHELL_CMD_ARG(pb, NULL, SHELL_HELP_OTPPB, do_otppb, 4, 2),
		SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(otpf, &optf_cmds, "Test OTP in Flash Commands", NULL);
#endif
#endif

