/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_OTP_SIM)
#include "otp_utils.h"

#define OTP_FLASH_DEV             "fmc@0"
#define OTP_SIM_BASE_ADDR         0xfc000

#define DWORD                       4
#define OTP_DATA_BASE_ADDR          0
#define OTP_DATA_DW_SIZE            0x800
#define OTP_DATA_SIZE               (OTP_DATA_DW_SIZE * DWORD)

#define OTP_CONF_BASE_DW_ADDR       0x800
#define OTP_CONF_BASE_ADDR          (OTP_CONF_BASE_DW_ADDR * DWORD)
#define OTP_CONF_DW_SIZE            0x800
#define OTP_CONF_SIZE               (OTP_CONF_DW_SIZE * DWORD)

#define OTP_MAGIC			"SOCOTP"
#define CHECKSUM_LEN			32
#define OTP_INC_DATA			BIT(31)
#define OTP_INC_CONFIG			BIT(30)
#define OTP_INC_STRAP			BIT(29)
#define OTP_ECC_EN			BIT(28)
#define OTP_INC_SCU_PRO			BIT(25)
#define OTP_REGION_SIZE(info)	(((info) >> 16) & 0xffff)
#define OTP_REGION_OFFSET(info)	((info) & 0xffff)
#define OTP_IMAGE_SIZE(info)	((info) & 0xffff)

#define OTP_AST1060A1	3
#define OTP_AST1060A2	4
#define SOC_AST1060A1	6
#define SOC_AST1060A2	7

#define OTP_REG_RESERVED	-1
#define OTP_REG_VALUE		-2
#define OTP_REG_VALID_BIT	-3

#define OTP_KEY_TYPE_RSA_PUB	1
#define OTP_KEY_TYPE_RSA_PRIV	2
#define OTP_KEY_TYPE_AES	3
#define OTP_KEY_TYPE_VAULT	4
#define OTP_KEY_TYPE_HMAC	5
#define OTP_KEY_ECDSA384	6
#define OTP_KEY_ECDSA384P	7

struct otpconf_info {
	signed char dw_offset;
	signed char bit_offset;
	signed char length;
	signed char value;
	const char *information;
};

struct otpstrap_info {
	signed char bit_offset;
	signed char length;
	signed char value;
	const char *information;
};


struct scu_info {
	signed char bit_offset;
	signed char length;
	const char *information;
};

static const struct otpstrap_info ast1030a0_strap_info[] = {
	{ 0, 1, 0, "Disable Secure Boot" },
	{ 0, 1, 1, "Enable Secure Boot" },
	{ 1, 2, OTP_REG_RESERVED, "Reserved" },
	{ 3, 1, 0, "Address offset of single chip ABR mode : 1/2" },
	{ 3, 1, 1, "Address offset of single chip ABR mode : 1/3" },
	{ 4, 13, OTP_REG_RESERVED, "Reserved" },
	{ 17, 1, 0, "Enable ARM JTAG debug" },
	{ 17, 1, 1, "Disable ARM JTAG debug" },
	{ 18, 14, OTP_REG_RESERVED, "Reserved" },
	{ 32, 4, OTP_REG_RESERVED, "Reserved" },
	{ 36, 1, 0, "Enable debug interfaces" },
	{ 36, 1, 1, "Disable debug interfaces" },
	{ 37, 3, OTP_REG_RESERVED, "Reserved" },
	{ 40, 1, 0, "Disable boot from uart5" },
	{ 40, 1, 1, "Enable boot from uart5" },
	{ 41, 2, OTP_REG_RESERVED, "Reserved" },
	{ 43, 1, 0, "Disable boot SPI ABR" },
	{ 43, 1, 1, "Enable boot SPI ABR" },
	{ 44, 1, 0, "Boot SPI ABR Mode : dual" },
	{ 44, 1, 1, "Boot SPI ABR Mode : single" },
	{ 45, 3, 0, "Boot SPI flash size : 0MB" },
	{ 45, 3, 1, "Boot SPI flash size : 2MB" },
	{ 45, 3, 2, "Boot SPI flash size : 4MB" },
	{ 45, 3, 3, "Boot SPI flash size : 8MB" },
	{ 45, 3, 4, "Boot SPI flash size : 16MB" },
	{ 45, 3, 5, "Boot SPI flash size : 32MB" },
	{ 45, 3, 6, "Boot SPI flash size : 64MB" },
	{ 45, 3, 7, "Boot SPI flash size : 128MB" },
	{ 48, 6, OTP_REG_RESERVED, "Reserved" },
	{ 54, 1, 0, "Disable boot SPI auxiliary control pins" },
	{ 54, 1, 1, "Enable boot SPI auxiliary control pins" },
	{ 57, 7, OTP_REG_RESERVED, "Reserved" },
	{ 62, 1, 0, "Disable dedicate GPIO strap pins" },
	{ 62, 1, 1, "Enable dedicate GPIO strap pins" },
	{ 63, 1, OTP_REG_RESERVED, "Reserved" }
};

static const struct scu_info ast1030a0_scu_info[] = {
	{ 0, 1, "Disable ARM CM4 CPU boot (TXD5)" },
	{ 1, 2, "Reserved" },
	{ 3, 1, "Address offset of single chip ABR mode" },
	{ 4, 13, "Reserved" },
	{ 17, 1, "Disabl3 ARM JTAG debug" },
	{ 18, 14, "Reserved" },
	{ 32, 4, "Reserved" },
	{ 36, 1, "Disable debug interfaces" },
	{ 37, 3, "Reserved" },
	{ 40, 1, "Enable boot from Uart5 by Pin Strap" },
	{ 41, 2, "Reserved" },
	{ 43, 1, "Enable boot SPI ABR" },
	{ 44, 1, "Boot SPI ABR Mode" },
	{ 45, 3, "Boot SPI flash size" },
	{ 48, 6, "Reserved" },
	{ 54, 1, "Enable boot SPI auxiliary control pins" },
	{ 57, 7, "Reserved" },
	{ 62, 1, "Enable dedicate GPIO strap pins" },
	{ 63, 1, "Enable Secure Boot by Pin Strap" }
};

static const struct otpconf_info ast1030a1_conf_info[] = {
	{ 0, 1, 1, 0, "Disable Secure Boot" },
	{ 0, 1, 1, 1, "Enable Secure Boot" },
	{ 0, 3, 1, 0, "User region ECC disable" },
	{ 0, 3, 1, 1, "User region ECC enable" },
	{ 0, 4, 1, 0, "Secure Region ECC disable" },
	{ 0, 4, 1, 1, "Secure Region ECC enable" },
	{ 0, 5, 1, 0, "Enable low security key" },
	{ 0, 5, 1, 1, "Disable low security key" },
	{ 0, 6, 1, 0, "Do not ignore Secure Boot hardware strap" },
	{ 0, 6, 1, 1, "Ignore Secure Boot hardware strap" },
	{ 0, 7, 1, 0, "Secure Boot Mode: Normal" },
	{ 0, 7, 1, 1, "Secure Boot Mode: Mode_PFR" },
	{ 0, 10, 4, 0, "Signature Scheme : ECDSA384" },
	{ 0, 10, 4, 1, "Signature Scheme : ECDSA384_RSA2048" },
	{ 0, 10, 4, 2, "Signature Scheme : ECDSA384_RSA3072" },
	{ 0, 10, 4, 3, "Signature Scheme : ECDSA384_RSA4096" },
	{ 0, 10, 4, 4, "Signature Scheme : RSAPSS_2048_SHA256" },
	{ 0, 10, 4, 8, "Signature Scheme : RSAPSS_3072_SHA384" },
	{ 0, 10, 4, 12, "Signature Scheme : RSAPSS_4096_SHA512" },
	{ 0, 10, 4, 5, "Signature Scheme : RSAPKCS1_2048_SHA256" },
	{ 0, 10, 4, 10, "Signature Scheme : RSAPKCS1_3072_SHA384" },
	{ 0, 10, 4, 15, "Signature Scheme : RSAPKCS1_4096_SHA512" },
	{ 0, 14, 1, 0, "Enable patch code" },
	{ 0, 14, 1, 1, "Disable patch code" },
	{ 0, 15, 1, 0, "Enable Boot from Uart" },
	{ 0, 15, 1, 1, "Disable Boot from Uart" },
	{ 0, 16, 6, OTP_REG_VALUE, "Secure Region size (DW): 0x%x" },
	{ 0, 22, 1, 0, "Secure Region : Writable" },
	{ 0, 22, 1, 1, "Secure Region : Write Protect" },
	{ 0, 23, 1, 0, "User Region : Writable" },
	{ 0, 23, 1, 1, "User Region : Write Protect" },
	{ 0, 24, 1, 0, "Configure Region : Writable" },
	{ 0, 24, 1, 1, "Configure Region : Write Protect" },
	{ 0, 25, 1, 0, "OTP strap Region : Writable" },
	{ 0, 25, 1, 1, "OTP strap Region : Write Protect" },
	{ 0, 26, 1, 0, "Copy Boot Image to Internal SRAM" },
	{ 0, 26, 1, 1, "Disable Copy Boot Image to Internal SRAM" },
	{ 0, 27, 1, 0, "Disable image encryption" },
	{ 0, 27, 1, 1, "Enable image encryption" },
	{ 0, 29, 1, 0, "OTP key retire Region : Writable" },
	{ 0, 29, 1, 1, "OTP key retire Region : Write Protect" },
	{ 0, 31, 1, 0, "OTP memory lock disable" },
	{ 0, 31, 1, 1, "OTP memory lock enable" },
	{ 2, 0, 16, OTP_REG_VALUE, "Vender ID : 0x%x" },
	{ 2, 16, 16, OTP_REG_VALUE, "Key Revision : 0x%x" },
	{ 3, 0, 16, OTP_REG_VALUE, "Secure boot header offset : 0x%x" },
	{ 4, 0, 8, OTP_REG_VALID_BIT, "Keys retire : %s" },
	{ 5, 0, 32, OTP_REG_VALUE, "User define data, random number low : 0x%x" },
	{ 6, 0, 32, OTP_REG_VALUE, "User define data, random number high : 0x%x" },
	{ 14, 0, 11, OTP_REG_VALUE, "Patch code location (DW): 0x%x" },
	{ 14, 11, 6, OTP_REG_VALUE, "Patch code size (DW): 0x%x" }
};

static const struct otpkey_type ast10xxa0_key_type[] = {
	{
		1, OTP_KEY_TYPE_VAULT, 0,
		"AES-256 as secret vault key"
	},
	{
		2, OTP_KEY_TYPE_AES,   1,
		"AES-256 as OEM platform key for image encryption/decryption in Mode 2 or AES-256 as OEM DSS keys for Mode GCM"
	},
	{
		8, OTP_KEY_TYPE_RSA_PUB,   1,
		"RSA-public as OEM DSS public keys in Mode 2"
	},
	{
		10, OTP_KEY_TYPE_RSA_PUB,  0,
		"RSA-public as AES key decryption key"
	},
	{
		14, OTP_KEY_TYPE_RSA_PRIV,  0,
		"RSA-private as AES key decryption key"
	},
};

static const struct otpkey_type ast10xxa1_key_type[] = {
	{
		1, OTP_KEY_TYPE_VAULT, 0,
		"AES-256 as secret vault key"
	},
	{
		2, OTP_KEY_TYPE_AES,   1,
		"AES-256 as OEM platform key for image encryption/decryption in Mode 2 or AES-256 as OEM DSS keys for Mode GCM"
	},
	{
		8, OTP_KEY_TYPE_RSA_PUB,   1,
		"RSA-public as OEM DSS public keys in Mode 2"
	},
	{
		9, OTP_KEY_TYPE_RSA_PUB,   1,
		"RSA-public as OEM DSS public keys in Mode 2(big endian)"
	},
	{
		10, OTP_KEY_TYPE_RSA_PUB,  0,
		"RSA-public as AES key decryption key"
	},
	{
		11, OTP_KEY_TYPE_RSA_PUB,  0,
		"RSA-public as AES key decryption key(big endian)"
	},
	{
		12, OTP_KEY_TYPE_RSA_PRIV,  0,
		"RSA-private as AES key decryption key"
	},
	{
		13, OTP_KEY_TYPE_RSA_PRIV,  0,
		"RSA-private as AES key decryption key(big endian)"
	},
	{
		5, OTP_KEY_ECDSA384P,  0,
		"ECDSA384 cure parameter"
	},
	{
		7, OTP_KEY_ECDSA384,  0,
		"ECDSA-public as OEM DSS public keys"
	}
};

int aspeed_otp_read_data(uint32_t offset, uint32_t *buf, uint32_t len);
int aspeed_otp_read_conf(uint32_t offset, uint32_t *buf, uint32_t len);
int aspeed_otp_prog_data(uint32_t offset, uint32_t *buf, uint32_t len);
int aspeed_otp_prog_conf(uint32_t offset, uint32_t *buf, uint32_t len);
int aspeed_otp_prog_image(uint32_t addr);
int aspeed_otp_prog_strap_bit(uint32_t bit_offset, int value);
int aspeed_otp_read_strap(uint32_t *buf);

#endif

