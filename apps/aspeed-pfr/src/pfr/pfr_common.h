/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "manifest/manifest_flash.h"
#include "manifest/manifest.h"
#include "keystore/keystore.h"
#include "flash/spi_flash.h"
#include "recovery/recovery_image.h"
#include "firmware/firmware_image.h"

struct pfr_manifest {
	// struct manifest_flash *base;
	struct manifest *base;

	struct active_image *active_image_base;
	struct recovery_image *recovery_base;
	struct pfr_firmware_image *update_fw;
	struct pfm_manager *recovery_pfm;

	struct hash_engine *hash;
	struct pfr_signature_verification *verification;
	struct spi_flash *flash;
	struct pfr_keystore *keystore;
	struct pfr_authentication *pfr_authentication;
	struct pfr_hash *pfr_hash;

	uint32_t image_type;                                    // BMC or PCH
	uint32_t state;                                         // VERIFY, UPDATE, RECOVERY
	uint32_t region;                                        // active, recovery, update
	uint32_t flash_id;                                      // spi a or b
	uint32_t address;                                       // START ADDRESS
	uint32_t recovery_address;                              // Recovery address
	uint32_t staging_address;                               // Staging Address
	uint32_t active_pfm_addr;                               // Active PFM address
	uint32_t pc_length;                                     // Protected Content Size
	uint32_t pc_type;                                       // manifest protected content type
	uint32_t kc_flag;                                       // Key Cancellation flag
	uint32_t hash_curve;                                    // Hash Curve
#if defined(CONFIG_SEAMLESS_UPDATE)
	uint32_t target_fvm_addr;                               // fvm region for seamless update
#endif
#if defined(CONFIG_CERBERUS_PFR)
	uint32_t i2c_filter_addr[2];                            // filter rule in BMC/PCH manifest
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	uint32_t intel_cpld_addr[3];                            // CPU/SCM/Debug CPLD firmware addr
	uint32_t intel_cpld_img_size[3];                        // CPU/SCM/Debug CPLD image size
#endif
	uint8_t update_intent1;
	uint8_t update_intent2;
};

struct active_image {
	int (*verify)(struct pfr_manifest *manifest);
};

struct pfr_firmware_image {
	struct firmware_image *base;
	uint32_t pc_length;
	uint32_t pfm_length;
};

struct pfr_signature_verification {
	struct signature_verification *base;
	struct pfr_pubkey *pubkey;
	uint32_t signature_type;                             // 0 -RSA, 1 - ECDSA, etc
};

struct pfr_pubkey {
	uint32_t length;
	uint8_t x[SHA512_HASH_LENGTH];
	uint8_t y[SHA512_HASH_LENGTH];
	uint8_t signature_r[SHA512_HASH_LENGTH];
	uint8_t signature_s[SHA512_HASH_LENGTH];
	uint8_t lms_key[64];
	int lms_key_len;
};

struct pfr_hash {
	uint32_t type;
	uint32_t start_address;
	uint32_t length;
	uint8_t hash_out[2 * SHA512_HASH_LENGTH];
};

struct key_cancellation_flag {
#if defined(CONFIG_INTEL_PFR)
	int (*verify_kc_flag)(struct pfr_manifest *manifest, uint8_t key_id);           // verifies key id
	int (*cancel_kc_flag)(struct pfr_manifest *manifest, uint8_t key_id);           // cancel key id
#endif
#if defined(CONFIG_CERBERUS_PFR)
	int (*verify_kc_flag)(struct pfr_manifest *manifest, uint8_t key_manifest_id, uint8_t key_id);           // verifies key id
	int (*cancel_kc_flag)(struct pfr_manifest *manifest, uint8_t key_manifest_id, uint8_t key_id);           // cancel key id
#endif
};

struct pfr_keystore {
	struct keystore *base;
	struct key_cancellation_flag *kc_flag;
};

void init_pfr_bases(void);
struct pfr_manifest *get_pfr_manifest(void);

