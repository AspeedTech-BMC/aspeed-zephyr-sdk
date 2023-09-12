/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <logging/log.h>
#include <zephyr.h>
#include <device.h>
#include <logging/log.h>
#include <drivers/i2c/pfr/i2c_filter.h>

#include "Smbus_mailbox/Smbus_mailbox.h"
#include "crypto/hash_wrapper.h"
#include "engine_manager.h"
#include "common/common.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_verification.h"
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_definitions.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_verification.h"
#include "cerberus_pfr/cerberus_pfr_provision.h"
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#endif
#include "manifestProcessor/manifestProcessor.h"
#include "flash/flash_wrapper.h"
#include "gpio/gpio_aspeed.h"
#include "pfr/pfr_util.h"

LOG_MODULE_REGISTER(engine, CONFIG_LOG_DEFAULT_LEVEL);

static int initialize_crypto(/*struct engine_instances *engineInstances*/)
{
	int status = 0;

	status = hash_wrapper_init(get_hash_engine_instance());
	if (status)
		return status;

	status = rsa_wrapper_init(getRsaEngineInstance());

	return status;
}

static int initialize_flash(void)
{
	int status = flash_master_wrapper_init(getFlashEngineWrapper());
	if (status)
		return status;

	status = flash_wrapper_init(getSpiEngineWrapper(), getFlashEngineWrapper(), getSpiEngineStateWrapper());

	return status;
}

int initializeEngines(void)
{
	int status = 0;

	status = initialize_flash();
	assert(status == 0);
	status = initialize_crypto();
	assert(status == 0);

	return status;
}

#if defined(CONFIG_SEAMLESS_UPDATE)
void apply_fvm_spi_protection(uint32_t fvm_addr)
{
	uint32_t fvm_offset = fvm_addr + PFM_SIG_BLOCK_SIZE;
	uint32_t fvm_body_offset = fvm_offset + sizeof(FVM_STRUCTURE);
	FVM_STRUCTURE fvm;
	PFM_SPI_DEFINITION spi_def;
	uint32_t fvm_body_end_addr;
	uint32_t region_start_address;
	uint32_t region_end_address;
	int region_length;
#if defined(CONFIG_CPU_DUAL_FLASH)
	int flash_size;
#endif
	int spi_id = 0;
	char *pch_spim_devs[2] = {
		"spi_m3",
		"spi_m4"
	};

	pfr_spi_read(PCH_SPI, fvm_offset, sizeof(FVM_STRUCTURE), (uint8_t *)&fvm);
	fvm_body_end_addr = fvm_offset + fvm.Length;

	while (fvm_body_offset < fvm_body_end_addr) {
		pfr_spi_read(PCH_SPI, fvm_body_offset, sizeof(PFM_SPI_DEFINITION),
				(uint8_t *)&spi_def);
		if (spi_def.PFMDefinitionType == SPI_REGION) {
			region_start_address = spi_def.RegionStartAddress;
			region_end_address = spi_def.RegionEndAddress;
			region_length = region_end_address - region_start_address;
#if defined(CONFIG_CPU_DUAL_FLASH)
			flash_size = pfr_spi_get_device_size(PCH_SPI);
			if (region_start_address >= flash_size && (region_end_address - 1) >= flash_size) {
				region_start_address -= flash_size;
				region_end_address -= flash_size;
				spi_id = 1;
			} else if (region_start_address < flash_size && (region_end_address - 1) >= flash_size) {
				LOG_ERR("ERROR: region start and end address should be in the same flash");
				return;
			} else {
				spi_id = 0;
			}
#endif
			if (spi_def.ProtectLevelMask.ReadAllowed) {
				Set_SPI_Filter_RW_Region(pch_spim_devs[spi_id], SPI_FILTER_READ_PRIV,
						SPI_FILTER_PRIV_ENABLE, region_start_address,
						region_length);
				LOG_INF("SPI_ID[2] fvm read enable 0x%08x to 0x%08x",
					region_start_address,
					region_end_address);
			} else {
				Set_SPI_Filter_RW_Region(pch_spim_devs[spi_id], SPI_FILTER_READ_PRIV,
						SPI_FILTER_PRIV_DISABLE, region_start_address,
						region_length);
				LOG_INF("SPI_ID[2] fvm read disable 0x%08x to 0x%08x",
					region_start_address,
					region_end_address);
			}

			if (spi_def.ProtectLevelMask.WriteAllowed) {
				Set_SPI_Filter_RW_Region(pch_spim_devs[spi_id], SPI_FILTER_WRITE_PRIV,
						SPI_FILTER_PRIV_ENABLE, region_start_address,
						region_length);
				LOG_INF("SPI_ID[2] fvm write enable 0x%08x to 0x%08x",
					region_start_address,
					region_end_address);
			} else {
				Set_SPI_Filter_RW_Region(pch_spim_devs[spi_id], SPI_FILTER_WRITE_PRIV,
						SPI_FILTER_PRIV_DISABLE, region_start_address,
						region_length);
				LOG_INF("SPI_ID[2] fvm write disable 0x%08x to 0x%08x",
					region_start_address,
					region_end_address);
			}

			if (spi_def.HashAlgorithmInfo.SHA256HashPresent) {
				fvm_body_offset += sizeof(PFM_SPI_DEFINITION) + SHA256_SIZE;
			} else if (spi_def.HashAlgorithmInfo.SHA384HashPresent) {
				fvm_body_offset += sizeof(PFM_SPI_DEFINITION) + SHA384_SIZE;
			} else {
				fvm_body_offset += SPI_REGION_DEF_MIN_SIZE;
			}
		} else if (spi_def.PFMDefinitionType == FVM_CAP) {
			fvm_body_offset += sizeof(FVM_CAPABLITIES);
		} else {
			break;
		}
	}
}
#endif

