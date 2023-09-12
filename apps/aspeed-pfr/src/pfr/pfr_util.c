/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

/*
 * mbedtls library for ECDSA.
 *
 */
#if defined(CONFIG_MBEDTLS)
#if !defined(CONFIG_MBEDTLS_CFG_FILE)
#include "mbedtls/config.h"
#else
#include CONFIG_MBEDTLS_CFG_FILE
#endif
#include "mbedtls/ecdsa.h"
#endif

#include <logging/log.h>

#include "common/common.h"
#include "flash/flash_wrapper.h"
#include "flash/flash_util.h"
#include "AspeedStateMachine/common_smc.h"
#include "pfr_common.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_definitions.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#endif
#include "crypto/ecdsa_aspeed.h"
#include <sys/reboot.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <soc.h>
#include <drivers/flash.h>
#include <storage/flash_map.h>

#define NON_CACHED_SRAM_START      DT_REG_ADDR_BY_IDX(DT_NODELABEL(sram0), 1)
#define NON_CACHED_SRAM_SIZE       DT_REG_SIZE_BY_IDX(DT_NODELABEL(sram0), 1)
#define NON_CACHED_SRAM_END        (NON_CACHED_SRAM_START + NON_CACHED_SRAM_SIZE)

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);
uint8_t buffer[PAGE_SIZE] NON_CACHED_BSS_ALIGN16;

int pfr_spi_read(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	int status = 0;

	if (device_id <= PCH_SPI) {
		status = bmc_pch_flash_read(device_id, address, data_length, data);
	} else {
		status = rot_flash_read(device_id, address, data_length, data);
	}

	return status;
}

int pfr_spi_write(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	int status = 0;

	if (device_id <= PCH_SPI) {
		status = bmc_pch_flash_write(device_id, address, data_length, data);
	} else {
		status = rot_flash_write(device_id, address, data_length, data);
	}

	return status;
}

int pfr_spi_erase_4k(uint8_t device_id, uint32_t address)
{
	int status;

	if (device_id <= PCH_SPI) {
		status = bmc_pch_flash_erase(device_id, address, SECTOR_SIZE, true);
	} else {
		status = rot_flash_erase(device_id, address, SECTOR_SIZE, true);
	}

	return status;
}

int pfr_spi_erase_block(uint8_t device_id, uint32_t address)
{
	int status;

	if (device_id <= PCH_SPI) {
		status = bmc_pch_flash_erase(device_id, address, BLOCK_SIZE, false);
	} else {
		status = rot_flash_erase(device_id, address, BLOCK_SIZE, false);
	}

	return status;
}

int pfr_spi_erase_region(uint8_t device_id,
		bool support_block_erase, uint32_t start_addr, uint32_t nbytes)
{
	uint32_t erase_addr = start_addr;
	uint32_t end_addr = start_addr + nbytes;

	while (erase_addr < end_addr) {
		if (support_block_erase && ((end_addr - erase_addr) >= BLOCK_SIZE) &&
				!(erase_addr & 0xffff)) {
			if (pfr_spi_erase_block(device_id, erase_addr))
				return Failure;
			erase_addr += BLOCK_SIZE;
		} else {
			if (pfr_spi_erase_4k(device_id, erase_addr))
				return Failure;
			erase_addr += PAGE_SIZE;
		}
	}

	return Success;
}

uint32_t pfr_spi_get_device_size(uint8_t device_id)
{
	uint32_t size;

	if (device_id < ROT_INTERNAL_ACTIVE) {
		size = bmc_pch_get_flash_size(device_id);
	} else {
		size = rot_get_region_size(device_id);
	}

	return size;
}

int pfr_spi_get_block_size(uint8_t device_id)
{
	uint32_t block_size;

	block_size = get_block_erase_size(device_id);

	return block_size;
}

int pfr_spi_page_read_write(uint8_t device_id, uint32_t source_address, uint32_t target_address)
{
	static uint8_t buffer[PAGE_SIZE] NON_CACHED_BSS_ALIGN16;
	if (pfr_spi_read(device_id, source_address, PAGE_SIZE, buffer))
		return Failure;
	if (pfr_spi_write(device_id, target_address, PAGE_SIZE, buffer))
		return Failure;

	return Success;
}

int pfr_spi_region_read_write_between_spi(uint8_t src_dev, uint32_t src_addr,
		uint8_t dest_dev, uint32_t dest_addr, size_t length)
{
	static uint8_t buffer[PAGE_SIZE] NON_CACHED_BSS_ALIGN16;
	int i;

	for (i = 0; i < length / PAGE_SIZE; i++) {
		if (pfr_spi_read(src_dev, src_addr, PAGE_SIZE, buffer))
			return Failure;
		if (pfr_spi_write(dest_dev, dest_addr, PAGE_SIZE, buffer))
			return Failure;

		src_addr += PAGE_SIZE;
		dest_addr += PAGE_SIZE;
	}

	return Success;
}

// Calculate hash digest
int get_hash(struct manifest *manifest, struct hash_engine *hash_engine, uint8_t *hash_out, size_t hash_length)
{
	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *)manifest;

	if (pfr_manifest == NULL || hash_engine == NULL ||
	    hash_out == NULL || hash_length < SHA256_HASH_LENGTH ||
	    (hash_length > SHA256_HASH_LENGTH && hash_length < SHA384_HASH_LENGTH)) {
		return Failure;
	}

	return flash_hash_contents((struct flash *)pfr_manifest->flash,
			pfr_manifest->pfr_hash->start_address,
			pfr_manifest->pfr_hash->length,
			pfr_manifest->hash,
			pfr_manifest->pfr_hash->type,
			hash_out,
			hash_length);
}

static int mbedtls_ecdsa_verify_middlelayer(struct pfr_pubkey *pubkey,
					    const uint8_t *digest, size_t length, uint8_t *signature_r,
					    uint8_t *signature_s)
{
	mbedtls_ecdsa_context ctx_verify;
	mbedtls_mpi r;
	mbedtls_mpi s;
	uint8_t z = 1;
	int ret = 0;

	mbedtls_ecdsa_init(&ctx_verify);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	mbedtls_mpi_read_binary(&ctx_verify.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), pubkey->x, length);
	mbedtls_mpi_read_binary(&ctx_verify.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), pubkey->y, length);
	mbedtls_mpi_read_binary(&ctx_verify.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Z), &z, 1);
	mbedtls_mpi_read_binary(&r, signature_r, length);
	mbedtls_mpi_read_binary(&s, signature_s, length);

	if (length == SHA256_HASH_LENGTH)
		mbedtls_ecp_group_load(&ctx_verify.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
	else if (length == SHA384_HASH_LENGTH)
		mbedtls_ecp_group_load(&ctx_verify.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP384R1);
	else
		LOG_ERR("Unsupported ECDSA curve length, %d", length);

	ret = mbedtls_ecdsa_verify(&ctx_verify.MBEDTLS_PRIVATE(grp), digest, length,
				   &ctx_verify.MBEDTLS_PRIVATE(Q), &r, &s);
	mbedtls_ecdsa_free(&ctx_verify);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return ret;

}

/**
 * Verify that a calculated digest matches a signature.
 *
 * @param verification The verification context to use for checking the signature.
 * @param digest The digest to verify.
 * @param digest_length The length of the digest.
 * @param signature The signature to compare against the digest.
 * @param sig_length The length of the signature.
 *
 * @return 0 if the digest matches the signature or an error code.
 */
int verify_signature(struct signature_verification *verification, const uint8_t *digest,
		     size_t length, const uint8_t *signature, size_t sig_length)
{
	struct pfr_manifest *manifest = (struct pfr_manifest *)verification;
	int status = Success;

	ARG_UNUSED(signature);
	ARG_UNUSED(sig_length);

	if (length == SHA256_HASH_LENGTH) {
		LOG_DBG("MBEDTLS ECDSA Start");
		status = mbedtls_ecdsa_verify_middlelayer(manifest->verification->pubkey,
							  digest,
							  length,
							  manifest->verification->pubkey->signature_r,
							  manifest->verification->pubkey->signature_s);
		LOG_DBG("MBEDTLS ECDSA End, status = %d", status);
	} else if (length == SHA384_HASH_LENGTH) {
		LOG_DBG("ASPEED ECDSA Start");
		status = aspeed_ecdsa_verify_middlelayer(manifest->verification->pubkey->x,
							 manifest->verification->pubkey->y,
							 digest,
							 length,
							 manifest->verification->pubkey->signature_r,
							 manifest->verification->pubkey->signature_s);
		LOG_DBG("ASPEED ECDSA End, status = %d", status);
	} else
		LOG_ERR("Unsupported digest length, %d", length);

	return status;
}

void pfr_cpld_update_reboot(void)
{
	LOG_INF("system going reboot ...");

#if (CONFIG_KERNEL_SHELL_REBOOT_DELAY > 0)
	k_sleep(K_MSEC(CONFIG_KERNEL_SHELL_REBOOT_DELAY));
#endif

	sys_reboot(SYS_REBOOT_COLD);

	CODE_UNREACHABLE;
}
