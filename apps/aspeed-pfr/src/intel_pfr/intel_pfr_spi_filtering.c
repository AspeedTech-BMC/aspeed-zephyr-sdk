/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <device.h>
#include <logging/log.h>
#include <drivers/i2c/pfr/i2c_filter.h>
#include "common/common.h"
#include "engineManager/engine_manager.h"
#include "manifestProcessor/manifestProcessor.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "pfr/pfr_util.h"

#define SPIM_NUM  4

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

void init_i2c_filters(void)
{
	char bus_dev_name[] = "I2C_FILTER_x";
	const struct device *flt_dev = NULL;

	for (int i = 0; i < 4; i++) {
		bus_dev_name[11] = i + '0';
		flt_dev = device_get_binding(bus_dev_name);
		if (flt_dev) {
			ast_i2c_filter_init(flt_dev);
			ast_i2c_filter_en(flt_dev, true, false, true, true);
			ast_i2c_filter_default(flt_dev, 0);
		}
	}
}

void apply_pfm_protection(int spi_device_id)
{

	int status = 0;
	bool i2c_flt_init = false;
	int spi_id = spi_device_id;
	const char *spim_devs[SPIM_NUM] = {
		"spi_m1",
		"spi_m2",
		"spi_m3",
		"spi_m4"
	};

	status = spi_filter_wrapper_init(getSpiFilterEngineWrapper());
	struct spi_filter_engine_wrapper *spi_filter = getSpiFilterEngineWrapper();
	char bus_dev_name[] = "I2C_FILTER_x";
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

	// Block 0 + Block 1 = 1024 (0x400); PFM data(PFM Body = 0x20)
	uint32_t pfm_region_Start = pfm_read_address + 0x400 + 0x20;
	int default_region_length = 40;
	uint32_t region_start_address;
	uint32_t region_end_address;
	// Table 2-14  get Length
	uint32_t addr_size_of_pfm = pfm_read_address + 0x400 + 0x1c;
	int region_length;
	// cerberus define region_id start from 1
	int region_id = 1;
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

			spi_filter->dev_id = spi_id;
			region_length = region_end_address - region_start_address;
			if (region_record[1] & 0x02) {
				/* Write allowed region */
				spi_filter->base.set_filter_rw_region(&spi_filter->base,
						region_id, region_start_address, region_end_address);
				region_id++;
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
			if (!i2c_flt_init) {
				init_i2c_filters();
				i2c_flt_init = true;
			}
			/* SMBus Rule Definition: 0x02 */
			LOG_INF("SMBus Rule Bus[%d] RuleId[%d] DeviceAddr[%x]",
					region_record[5], region_record[6], region_record[7]);
			LOG_HEXDUMP_INF(&region_record[8], 32, "Whitelist: ");

			if (region_record[5] > 0 && region_record[5] < 6 && region_record[6] > 0 && region_record[6] < 17) {
				// Valid Bus ID should be 1~5 and reflect to I2C_FILTER_0 ~ I2C_FILTER_4
				// Valid Rule ID should be 1~16 and refect to I2C Filter Driver Rule 0~15

				bus_dev_name[11] = (region_record[5] - 1) + '0';
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
			apply_fvm_spi_protection(fvm_def->FVMAddress);
			pfm_region_Start += sizeof(PFM_FVM_ADDRESS_DEFINITION);
			break;
#endif
		default:
			done = true;
			break;
		}
		if (pfm_region_Start >= pfm_read_address + 0x400 + pfm_record_length)
			break;
	}

	spi_filter->base.enable_filter((struct spi_filter_interface *)spi_filter, true);
}

