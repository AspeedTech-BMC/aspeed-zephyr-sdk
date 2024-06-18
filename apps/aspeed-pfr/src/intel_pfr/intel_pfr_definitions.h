/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <stdint.h>

#define BMC_FLASH_ID                    0
#define PCH_FLASH_ID                    1

#define UFM0                            4
#define UFM0_SIZE                       512

#define UFM1                            3

#define FALSE                           0
#define TRUE                            1
#define START                           2

#define PROVISION_UFM                   UFM0
#define PROVISION_UFM_SIZE              UFM0_SIZE

#define UPDATE_STATUS_UFM               UFM1
#define UPDATE_STATUS_ADDRESS           0x00
#define UPDATE_STATUS_ROT_HASH_ADDR     0x40
#define UPDATE_STATUS_BMC_HASH_ADDR     0x80
#define UPDATE_STATUS_PCH_HASH_ADDR     0xC0
#define UPDATE_STATUS_AFM_HASH_ADDR     0x100

// BIOS/BMC SPI Region information
#define PCH_ACTIVE_FW_UPDATE_ADDRESS    0x00000000
#define PCH_CAPSULE_STAGING_ADDRESS     0x007F0000
#define PCH_PFM_ADDRESS                 0x02FF0000
#define PCH_FVM_ADDRESS                 0x02FF1000
#define PCH_RECOVERY_AREA_ADDRESS       0x01BF0000

#define PBC_COMPRESSION_TAG             0x5F504243
#define PBC_VERSION                     2
#define PBC_PAGE_SIZE                   0x1000
#define PBC_PATTERN_SIZE                0x0001
#define PBC_PATTERN                     0xFF

#define BLOCK0TAG                       0xB6EAFD19
#define BLOCK0_RSA_TAG                  0x35C6B783
#define BLOCK1TAG                       0xF27F28D7
#define BLOCK1_RSA_TAG                  0xD1550984
#define BLOCK1_ROOTENTRY_TAG            0xA757A046
#define BLOCK1_ROOTENTRY_RSA_TAG        0x6CCDCAD7
#define BLOCK1CSKTAG                    0x14711C2F
#define BLOCK1_BLOCK0ENTRYTAG           0x15364367
#define SIGNATURE_SECP256_TAG           0xDE64437D
#define SIGNATURE_SECP384_TAG           0xEA2A50E9
#define SIGNATURE_RSA2K_256_TAG         0xee728a05
#define SIGNATURE_RSA3K_384_TAG         0x9432a93e
#define SIGNATURE_RSA4K_384_TAG         0xF61B70F3
#define SIGNATURE_RSA4K_512_TAG         0x383c5144
#define PUBLIC_SECP256_TAG              0xC7B88C74
#define PUBLIC_SECP384_TAG              0x08F07B47
#define PUBLIC_LMS384_TAG               0x413d858d
#define PUBLIC_LMS256_TAG               0xaa4aad02
#define SIGNATURE_LMS384_TAG            0x66600835
#define SIGNATURE_LMS256_TAG            0x5266b561
#define LMS_PFM_SIG_BLOCK_SIZE          5120
#define PUBLIC_RSA2K_TAG                0x7FAD5E14
#define PUBLIC_RSA3K_TAG                0x684694E6
#define PUBLIC_RSA4K_TAG                0xB73AA717
#define PEM_TAG                         0x02B3CE1D
#define AFM_TAG                         0x8883ce1d
#define AFM_PUBLIC_SECP256_TAG          0xC7B88C74
#define AFM_PUBLIC_SECP384_TAG          0x08F07B47
#define AFM_PUBLIC_RSA_2K_TAG           0x6EBCE216
#define AFM_PUBLIC_RSA_3K_TAG           0x6F37A4B5
#define AFM_PUBLIC_RSA_4K_TAG           0xC21BB545
#define PFM_SIG_BLOCK_SIZE              1024
#define PFM_SIG_BLOCK_SIZE_3K           3072
#define PFMTAG                          0x02B3CE1D
#define FVMTAG                          0xA8E7C2D4
#define CFMTAG                          0xA8E7C2D6
#define PFMTYPE                         0x01
#define UPDATE_CAPSULE                  1
#define ACTIVE_PFM                      2

#define SIGN_PCH_PFM_BIT0               0x00000001
#define SIGN_PCH_UPDATE_BIT1            0x00000002
#define SIGN_BMC_PFM_BIT2               0x00000004
#define SIGN_BMC_UPDATE_BIT3            0x00000008
#define SIGN_CPLD_UPDATE_BIT4           0x00000010
#define SIGN_AFM_UPDATE_BIT5            0x00000020
// Intel CPU/SCM/Debug CPLD capsule
#define SIGN_INTEL_CPLD_UPDATE_BIT6     0x00000040

#define SIGN_CPLD_UPDATE_BIT9           0x00000200

#define SHA384_SIZE                     48
#define SHA256_SIZE                     32

#define SHA256_DIGEST_LENGTH            32
#define SHA384_DIGEST_LENGTH            48
#define SHA512_DIGEST_LENGTH            64
#define SVN_MAX                         64
#define MAX_READ_SIZE                   0x1000
#define MAX_WRITE_SIZE                  0x1000
#define PAGE_SIZE                       0x1000
#define BLOCK_SIZE                      0x10000
#define UFM_PAGE_SIZE                   16

#define PCH1_AFM_BODY_OFFSET            0x0
#define PCH2_AFM_BODY_OFFSET            0x2000
#define BMC_AFM_BODY_OFFSET             0x4000
#define AFM_BODY_SIZE                   0x2000

#if (CONFIG_AFM_SPEC_VERSION == 4)
#define MEASUREMENT_PAYLOAD_SIZE 8
#elif (CONFIG_AFM_SPEC_VERSION == 3)
#define MEASUREMENT_PAYLOAD_SIZE 4
#endif

typedef enum {
	BMC_TYPE = 0,
	PCH_TYPE = 2,
        ROT_TYPE,
	AFM_TYPE,
	AFM_TYPE2,
	CPLD_TYPE,
	MAX_SUPPORTED_FW_TYPE,
} FW_TYPE;

/*
	Each AFM device data is 8 Kbytes
	In ROT_INTERNAL_AFM, its size is 64 Kbytes and it stores 3 AFM device data (CPU0, CPU1, BMC).
	In EXT_AFM_ACT_1, its size is 512 Kbytes and it stores 63 AFM device data (remaining 8 Kbytes are used for AFM capsule BLK0/BLK1 header overhead)
	In EXT_AFM_ACT_2, its size is 512 Kbytes and it stores 64 AFM device data
*/
typedef enum {
	afm_dev_idx_cpu0 = 0,
	afm_dev_idx_cpu1 = 1,
	afm_dev_idx_bmc = 2,
	afm_dev_idx_onboard_first = 3,
	afm_dev_idx_onboard_final = 16,
	afm_dev_idx_addon_first = 17,
	afm_dev_idx_addon_final = 32
} AFM_DEV_INDEX;

#define BLOCK_SUPPORT_1KB               1
#define BLOCK_SUPPORT_3KB               0

#define AFM_ACTIVE_PENDING_UPDATE       0x1
#define AFM_RECOVERY_PENDING_UPDATE     0x2
#define AFM_PENDING_UPDATE_STATE        (AFM_ACTIVE_PENDING_UPDATE | AFM_RECOVERY_PENDING_UPDATE)

enum CurveHashType {
	secp384r1 = 1,
	secp256r1,
	hash_sign_algo384,
	hash_sign_algo256
};

typedef enum {
	DECOMPRESSION_STATIC_REGIONS_MASK             = 0b1,
	DECOMPRESSION_DYNAMIC_REGIONS_MASK            = 0b10,
	DECOMPRESSION_STATIC_AND_DYNAMIC_REGIONS_MASK = 0b11,
} DECOMPRESSION_TYPE_MASK_ENUM;

typedef enum {
	ROT_REGION = 0,
	BMC_REGION,
	PCH_REGION,
	AFM_REGION,
} REGION_DEF;

typedef enum {
	BMC_INTENT_UPDATE_AT_RESET = 1,
	BMC_INTENT_RECOVERY_PENDING,
	PCH_INTENT_UPDATE_AT_RESET,
	PCH_INTENT_RECOVERY_PENDING,
	BMC_INTENT2_AFM_RECOVERY_PENDING,
	RECOVERY_PENDING_REQUEST_HANDLED,
	BMC_INTENT2_AFM_SVN_UPDATE,
	MAX_INTENT_TYPE_DEF,
} REGION_UPDATE_INTENT_TYPE_DEF;

typedef struct {
	uint8_t ActiveRegion;
	uint8_t Recoveryregion;
} UPD_REGION;

typedef struct {
	uint8_t CpldStatus;
	uint8_t BmcStatus;
	uint8_t PchStatus;
	uint8_t AfmStatus;
	UPD_REGION Region[4];
	uint8_t DecommissionFlag;
	uint8_t CpldRecovery;
	uint8_t BmcToPchStatus;
	uint8_t AttestationFlag;
	uint8_t Reserved[3];
} CPLD_STATUS;

