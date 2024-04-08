/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include "common/common.h"
#include "pfr_common.h"
#include "flash/flash_wrapper.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_verification.h"
#include "intel_pfr/intel_pfr_recovery.h"
#include "intel_pfr/intel_pfr_key_cancellation.h"
#include "intel_pfr/intel_pfr_update.h"
#include "intel_pfr/intel_pfr_authentication.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_verification.h"
#include "cerberus_pfr/cerberus_pfr_recovery.h"
#include "cerberus_pfr/cerberus_pfr_key_cancellation.h"
#include "cerberus_pfr/cerberus_pfr_update.h"
#include "cerberus_pfr/cerberus_pfr_authentication.h"
#endif

#include "recovery/recovery_image.h"
#include "pfr/pfr_recovery.h"
#include "pfr/pfr_verification.h"
#include "pfr/pfr_update.h"
#include "pfr_util.h"
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(pfr, CONFIG_LOG_DEFAULT_LEVEL);
struct pfr_manifest pfr_manifest;

// Block0-Block1 verification
struct active_image pfr_active_image;

// PFR_SIGNATURE
struct signature_verification pfr_verification;
struct pfr_pubkey pubkey;
struct pfr_signature_verification verification;

// PFR_MANIFEST
struct manifest manifest_base;

// PFR RECOVERY
struct recovery_image recovery_base;
struct pfm_manager recovery_pfm;

// PFR UPDATE
struct firmware_image update_base;
struct pfr_firmware_image update_fw;

// PFR_KEYSTORE
struct keystore keystore;
struct key_cancellation_flag kc_flag;
struct pfr_keystore pfr_keystore;

struct pfr_authentication pfr_authentication;
struct pfr_hash pfr_hash;

struct pfr_manifest *get_pfr_manifest(void)
{
	return &pfr_manifest;
}

struct active_image *get_active_image(void)
{
	return &pfr_active_image;
}

static struct manifest *get_manifest(void)
{
	return &manifest_base;
}

static struct signature_verification *get_signature_verification(void)
{
	return &pfr_verification;
}

static struct pfr_pubkey *get_pubkey(void)
{
	return &pubkey;
}

static struct pfr_signature_verification *get_pfr_signature_verification(void)
{
	return &verification;
}

static struct keystore *get_keystore(void)
{
	return &keystore;
}

static struct key_cancellation_flag *get_kc_flag(void)
{
	return &kc_flag;
}

static struct pfr_keystore *get_pfr_keystore(void)
{
	return &pfr_keystore;
}

static struct pfr_authentication *get_pfr_authentication(void)
{
	return &pfr_authentication;
}

static struct pfr_hash *get_pfr_hash(void)
{
	return &pfr_hash;
}

static struct hash_engine *get_pfr_hash_engine(void)
{
	return get_hash_engine_instance();
}

static struct spi_flash *get_pfr_spi_flash(void)
{
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	return &spi_flash->spi;
}

static struct recovery_image *get_recovery_base(void)
{
	return &recovery_base;
}


static struct pfm_manager *get_recovery_pfm(void)
{
	return &recovery_pfm;
}

static struct pfr_firmware_image *get_update_fw_base(void)
{
	return &update_fw;
}

static struct firmware_image *get_update_base(void)
{
	return &update_base;
}

static void init_pfr_firmware_image(struct pfr_firmware_image *update_fw, struct firmware_image *update_base)
{
	update_fw->base = update_base;
}

void init_active_image(struct active_image *active_image)
{
	active_image->verify = pfr_active_verify;
}

static int init_pfr_manifest(struct pfr_manifest *pfr_manifest,
				   struct manifest *manifest,
				   struct hash_engine *hash,
				   struct pfr_signature_verification *verification,
				   struct spi_flash *flash,
				   struct pfr_keystore *keystore,
				   struct pfr_authentication *pfr_authentication,
				   struct pfr_hash *pfr_hash,
				   struct recovery_image *recovery_base,
				   struct pfm_manager *recovery_pfm,
				   struct pfr_firmware_image *update_fw,
				   struct active_image *active_image)
{
	int status = 0;

	pfr_manifest->base = manifest;
	pfr_manifest->hash = hash;
	pfr_manifest->verification = verification;
	pfr_manifest->flash = flash;
	pfr_manifest->keystore = keystore;
	pfr_manifest->pfr_authentication = pfr_authentication;
	pfr_manifest->pfr_hash = pfr_hash;
	pfr_manifest->recovery_base = recovery_base;
	pfr_manifest->recovery_pfm = recovery_pfm;
	pfr_manifest->update_fw = update_fw;
	pfr_manifest->active_image_base = active_image;

	init_manifest(manifest);
	init_recovery_manifest(recovery_base);
	init_update_fw_manifest(update_fw->base);
	init_signature_verification(pfr_manifest->verification->base);
	init_active_image(pfr_manifest->active_image_base);

	return status;
}

static int init_pfr_signature(struct signature_verification *verification, struct pfr_pubkey *pubkey)
{
	int status = 0;

	struct pfr_signature_verification *pfr_verification = get_pfr_signature_verification();

	pfr_verification->base = verification;
	pfr_verification->pubkey = pubkey;

	return status;
}

static int init_pfr_keystore(struct keystore *keystore, struct key_cancellation_flag *kc_flag)
{

	int status = 0;

	struct pfr_keystore *pfr_keystore = get_pfr_keystore();

	pfr_keystore->base = keystore;
	pfr_keystore->kc_flag = kc_flag;

	pfr_keystore->kc_flag->verify_kc_flag = verify_csk_key_id;
	pfr_keystore->kc_flag->cancel_kc_flag = cancel_csk_key_id;

	return status;
}

void init_pfr_bases(void)
{
	init_pfr_keystore(get_keystore(), get_kc_flag());
	init_pfr_signature(get_signature_verification(), get_pubkey());
	init_pfr_firmware_image(get_update_fw_base(), get_update_base());

	init_pfr_manifest(get_pfr_manifest(),
			get_manifest(),
			get_pfr_hash_engine(),
			get_pfr_signature_verification(),
			get_pfr_spi_flash(),
			get_pfr_keystore(),
			get_pfr_authentication(),
			get_pfr_hash(),
			get_recovery_base(),
			get_recovery_pfm(),
			get_update_fw_base(),
			get_active_image());
}
