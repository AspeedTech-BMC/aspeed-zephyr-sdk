/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once


/* Cerberus Includes*/
#include <crypto/signature_verification.h>

#include <crypto/aes.h>
#include <asn1/base64.h>
#include <crypto/ecc.h>
#include <crypto/hash.h>
#include <crypto/rng.h>
#include <crypto/rsa.h>
#include <asn1/x509.h>

#include <crypto/rsa_wrapper.h>
#include <crypto/signature_verification_rsa_wrapper.h>

#include <flash/flash.h>
#include <flash/flash_master.h>
#include <flash/spi_flash.h>

#include <flash/flash_wrapper.h>
#include <spi_filter/spi_filter_wrapper.h>


#include <keystore/keystore.h>

#include <manifest/manifest.h>
#include <manifest/pfm/pfm_flash.h>
#include <manifest/pfm/pfm_manager_flash.h>

#define hashStorageLength 256
#define MAX_BIOS_BOOT_TIME 300

struct flash *getFlashDeviceInstance(void);
struct flash_master *getFlashMasterInstance(void);
struct hash_engine *get_hash_engine_instance(void);
struct host_state_manager *getHostStateManagerInstance(void);
struct pfm_flash *getPfmFlashInstance(void);
struct signature_verification *getSignatureVerificationInstance(void);
struct spi_flash *getSpiFlashInstance(void);
struct rsa_engine_wrapper *getRsaEngineInstance(void);
struct spi_filter_engine_wrapper *getSpiFilterEngineWrapper(void);
struct spi_engine_wrapper *getSpiEngineWrapper(void);
struct spi_engine_state_wrapper *getSpiEngineStateWrapper(void);
uint8_t *getNewHashStorage(void);
struct flash_master_wrapper *getFlashEngineWrapper(void);
struct manifest_flash *getManifestFlashInstance(void);
