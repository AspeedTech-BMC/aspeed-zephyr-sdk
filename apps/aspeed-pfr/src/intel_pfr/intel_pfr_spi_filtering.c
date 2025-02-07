/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/i2c/pfr/i2c_filter.h>
#include "common/common.h"
#include "engineManager/engine_manager.h"
#include "manifestProcessor/manifestProcessor.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "spi_filter/spim_util.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_spi_filtering.h"
#include "pfr/pfr_util.h"

#define SPIM_NUM  4

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

void apply_pfm_protection(int spi_device_id)
{

	int status = 0;
	int spi_id = spi_device_id;
	const char *spim_devs[SPIM_NUM] = {
		"spim@1",
		"spim@2",
		"spim@3",
		"spim@4"
	};

	char bus_dev_name[] = "i2cfilterx";
	const struct device *flt_dev = NULL;

	// read PFR_Manifest
	status = initializeEngines();
	status = initializeManifestProcessor();

	uint8_t pfm_length[4];
	uint32_t pfm_read_address = 0;

	if (spi_id == BMC_SPI)
		get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, (uint8_t *)&pfm_read_address, sizeof(pfm_read_address));
	else if (spi_id == PCH_SPI)
		get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)&pfm_read_address, sizeof(pfm_read_address));
	else {
		LOG_ERR("Incorrect spi_id %d", spi_id);
		return;
	}

	int offset = PFM_SIG_BLOCK_SIZE;
	struct pfr_manifest *pfr_manifest = get_pfr_manifest();

	if (pfr_manifest->hash_curve == hash_sign_algo384 || pfr_manifest->hash_curve == hash_sign_algo256)
		offset = LMS_PFM_SIG_BLOCK_SIZE;

	uint32_t pfm_region_Start = pfm_read_address + offset + 0x20;
	int default_region_length = 40;
	uint32_t region_start_address;
	uint32_t region_end_address;
	// Table 2-14  get Length
	uint32_t addr_size_of_pfm = pfm_read_address + offset + 0x1c;
	int region_length;
	uint8_t region_record[40];
#if defined(CONFIG_SEAMLESS_UPDATE)
	PFM_FVM_ADDRESS_DEFINITION *fvm_def;
#endif

#if defined(CONFIG_BMC_DUAL_FLASH) || defined(CONFIG_CPU_DUAL_FLASH)
	int flash_size;
#endif

	// assign the flash device id,  0:spi1_cs0, 1:spi2_cs0 , 2:spi2_cs1, 3:spi2_cs2, 4:fmc_cs0, 5:fmc_cs1
	pfr_spi_read(spi_device_id, addr_size_of_pfm, 4, pfm_length);

	int pfm_record_length = (pfm_length[0] & 0xff) | (pfm_length[1] << 8 & 0xff00) | (pfm_length[2] << 16 & 0xff0000) | (pfm_length[3] << 24 & 0xff000000);

	bool done = false;
	// TODO: Clear all setting before apply new setting

	while (!done) {
		/* Read PFM Record */
		pfr_spi_read(spi_device_id, pfm_region_Start, default_region_length, region_record);
		switch(region_record[0]) {
		case SPI_REGION:
			/* SPI Region: 0x01 */
			/* Region protect level mask:
			 * 0b00000001: Protect: Read allowed
			 * 0b00000010: Protect: Write allowed
			 * 0b00000100: Recover: recover on first recovery
			 * 0b00001000: Recover: recover on second recovery
			 * 0b00010000: Recover: Recover on third recovery
			 * 0b11100000: Reserved
			 */

			region_start_address = (region_record[8] & 0xff) | (region_record[9] << 8 & 0xff00) |
				(region_record[10] << 16 & 0xff0000) | (region_record[11] << 24 & 0xff000000);
			region_end_address = (region_record[12] & 0xff) | (region_record[13] << 8 & 0xff00) |
				(region_record[14] << 16 & 0xff0000) | (region_record[15] << 24 & 0xff000000);

#if defined(CONFIG_BMC_DUAL_FLASH)
			if (spi_device_id == BMC_SPI) {
				flash_size = pfr_spi_get_device_size(spi_device_id);
				if (region_start_address >= flash_size && (region_end_address - 1) >= flash_size) {
					region_start_address -= flash_size;
					region_end_address -= flash_size;
					spi_id = spi_device_id + 1;
				} else if (region_start_address < flash_size && (region_end_address - 1) >= flash_size) {
					LOG_ERR("ERROR: region start and end address should be in the same flash");
					return;
				} else {
					spi_id = spi_device_id;
				}
			}
#endif

#if defined(CONFIG_CPU_DUAL_FLASH)
			if (spi_device_id == PCH_SPI) {
				flash_size = pfr_spi_get_device_size(spi_device_id);
				if (region_start_address >= flash_size && (region_end_address - 1) >= flash_size) {
					region_start_address -= flash_size;
					region_end_address -= flash_size;
					spi_id = spi_device_id + 1;
				} else if (region_start_address < flash_size && (region_end_address - 1) >= flash_size) {
					LOG_ERR("ERROR: region start and end address should be in the same flash");
					return;
				} else {
					spi_id = spi_device_id;
				}
			}
#endif

			region_length = region_end_address - region_start_address;
			if (region_record[1] & 0x02) {
				/* Write allowed region */
				Set_SPI_Filter_RW_Region((char *)spim_devs[spi_id],
						SPI_FILTER_WRITE_PRIV, SPI_FILTER_PRIV_ENABLE,
						region_start_address, region_length);
				LOG_INF("SPI_ID[%d] write enable  0x%08x to 0x%08x",
					spi_id, region_start_address, region_end_address);
			} else {
				/* Write not allowed region */
				// Cerberus did not support write not allowed setting
				Set_SPI_Filter_RW_Region((char *)spim_devs[spi_id],
						SPI_FILTER_WRITE_PRIV, SPI_FILTER_PRIV_DISABLE,
						region_start_address, region_length);
				LOG_INF("SPI_ID[%d] write disable 0x%08x to 0x%08x",
					spi_id, region_start_address, region_end_address);
			}

			if (region_record[1] & 0x01) {
				/* Read allowed region */
				// Cerberus did not support read disabled
				Set_SPI_Filter_RW_Region((char *)spim_devs[spi_id],
						SPI_FILTER_READ_PRIV, SPI_FILTER_PRIV_ENABLE,
						region_start_address, region_length);
				LOG_INF("SPI_ID[%d] read  enable  0x%08x to 0x%08x",
					spi_id, region_start_address, region_end_address);
			} else {
				/* Read not allowed region */
				// Cerberus did not support read disabled
				Set_SPI_Filter_RW_Region((char *)spim_devs[spi_id],
						SPI_FILTER_READ_PRIV, SPI_FILTER_PRIV_DISABLE,
						region_start_address, region_length);
				LOG_INF("SPI_ID[%d] read  disable 0x%08x to 0x%08x",
					spi_id, region_start_address, region_end_address);
			}

			/* Hash Algorhtm 2 bytes:
			 * 0b00000001: SHA256 present
			 * 0b00000010: SHA384 present
			 * 0b00000100: SHA512 present
			 * Otherwise: Reserved
			 */
			if (region_record[2] & 0x01)
				pfm_region_Start = pfm_region_Start + 48;
			else if (region_record[2] & 0x02)
				pfm_region_Start = pfm_region_Start + 64;
			else if (region_record[2] & 0x04)
				pfm_region_Start = pfm_region_Start + 80;
			else
				pfm_region_Start = pfm_region_Start + 16;
			break;
		case SMBUS_RULE:
			// Ignore all smbus rules in pch flash.
			if (spi_device_id >= PCH_SPI) {
				LOG_WRN("Found SMBUS Rules in PCH SPI, ignoring the rule.");
				break;
			}
			/* SMBus Rule Definition: 0x02 */
			LOG_INF("SMBus Rule Bus[%d] RuleId[%d] DeviceAddr[%x]",
					region_record[5], region_record[6], region_record[7]);
			LOG_HEXDUMP_INF(&region_record[8], 32, "Whitelist: ");

			if (region_record[5] > 0 && region_record[5] < 6 && region_record[6] > 0 && region_record[6] < 17) {
				// Valid Bus ID should be 1~5 and reflect to I2C_FILTER_0 ~ I2C_FILTER_4
				// Valid Rule ID should be 1~16 and refect to I2C Filter Driver Rule 0~15

				bus_dev_name[9] = (region_record[5] - 1) + '0';
				flt_dev = device_get_binding(bus_dev_name);
				if (flt_dev) {
					status = ast_i2c_filter_en(
							flt_dev,
							true,
							true,
							0,
							0);
					LOG_DBG("ast_i2c_filter_en ret=%d", status);
					// The i2c device address in the manifest is 8-bit format.
					// It should be 7-bit format for i2c filter api.
					uint8_t slave_addr = region_record[7] >> 1;
					status = ast_i2c_filter_update(
							flt_dev,
							region_record[6] - 1, // Rule ID
							slave_addr,           // Device Address
							(struct ast_i2c_f_bitmap *)&region_record[8]     // cmd_whitelist
							);
					LOG_DBG("ast_i2c_filter_update ret=%d", status);
				} else {
					LOG_ERR("%s device not found", bus_dev_name);
				}
			} else {
				LOG_HEXDUMP_ERR(region_record, 40, "Invalid Bus ID or Rule ID");
			}

			pfm_region_Start += sizeof(PFM_SMBUS_RULE);
			break;
#if defined(CONFIG_SEAMLESS_UPDATE)
		case FVM_ADDR_DEF:
			fvm_def = (PFM_FVM_ADDRESS_DEFINITION *)region_record;
			apply_fvm_spi_protection(fvm_def->FVMAddress, offset);
			pfm_region_Start += sizeof(PFM_FVM_ADDRESS_DEFINITION);
			break;
#endif
		default:
			done = true;
			break;
		}
		if (pfm_region_Start >= pfm_read_address + offset + pfm_record_length)
			break;
	}

	SPI_Monitor_Enable(spim_devs[spi_id], true);
}

#if defined(CONFIG_SEAMLESS_UPDATE)
void apply_fvm_spi_protection(uint32_t fvm_addr, int offset)
{
	uint32_t fvm_offset = fvm_addr + offset;
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
		"spim@3",
		"spim@4"
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

	SPI_Monitor_Enable(pch_spim_devs[spi_id], true);
}
#endif

