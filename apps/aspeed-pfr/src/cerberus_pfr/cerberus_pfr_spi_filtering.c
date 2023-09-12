/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <logging/log.h>
#include "common/common.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_common.h"
#include "flash/flash_aspeed.h"
#include "pfr/pfr_util.h"
#include "Smbus_mailbox/Smbus_mailbox.h"

#define SPIM_NUM  4

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

void apply_pfm_protection(int spi_dev)
{
	char *spim_devs[SPIM_NUM] = {
		"spi_m1",
		"spi_m2",
		"spi_m3",
		"spi_m4"
	};

	struct pfm_firmware_version_element fw_ver_element;
	uint32_t region_start_address;
	uint32_t region_end_address;
	uint32_t pfm_addr;
	uint32_t rw_region_addr;
	int region_length;
	int spi_id = spi_dev;

#if defined(CONFIG_BMC_DUAL_FLASH) || defined(CONFIG_CPU_DUAL_FLASH)
	int flash_size;
#endif

	if (spi_dev == BMC_SPI)
		get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, (uint8_t *)&pfm_addr,
				sizeof(pfm_addr));
	else if (spi_dev == PCH_SPI)
		get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)&pfm_addr,
				sizeof(pfm_addr));
	else
		return;

	if (cerberus_get_rw_region_info(spi_dev, pfm_addr, &rw_region_addr, &fw_ver_element)) {
		LOG_ERR("Failed to get read write regions");
		return;
	}

	struct pfm_fw_version_element_rw_region rw_region;
	for (int i = 0; i < fw_ver_element.rw_count; i++) {
		if (pfr_spi_read(spi_dev, rw_region_addr, sizeof(rw_region), (uint8_t *)&rw_region)) {
			LOG_ERR("Failed to get read/write regions");
			return;
		}

		region_start_address = rw_region.region.start_addr;
		region_end_address = rw_region.region.end_addr;
		region_length = region_end_address - region_start_address + 1;

#if defined(CONFIG_BMC_DUAL_FLASH)
		if (spi_dev == BMC_SPI) {
			flash_size = pfr_spi_get_device_size(spi_dev);
			if (region_start_address >= flash_size && region_end_address >= flash_size) {
				region_start_address -= flash_size;
				region_end_address -= flash_size;
				spi_id = spi_dev + 1;
			} else if (region_start_address < flash_size && region_end_address >= flash_size) {
				LOG_ERR("ERROR: region start and end address should be in the same flash");
				return;
			} else {
				spi_id = spi_dev;
			}
		}
#endif

#if defined(CONFIG_CPU_DUAL_FLASH)
		if (spi_dev == PCH_SPI) {
			flash_size = pfr_spi_get_device_size(spi_dev);
			if (region_start_address >= flash_size && region_end_address >= flash_size) {
				region_start_address -= flash_size;
				region_end_address -= flash_size;
				spi_id = spi_dev + 1;
			} else if (region_start_address < flash_size && region_end_address >= flash_size) {
				LOG_ERR("ERROR: region start and end address should be in the same flash");
				return;
			} else {
				spi_id = spi_dev;
			}
		}
#endif

		Set_SPI_Filter_RW_Region(spim_devs[spi_id],
				SPI_FILTER_WRITE_PRIV, SPI_FILTER_PRIV_ENABLE,
				region_start_address, region_length);
		LOG_INF("SPI_ID[%d] write enable 0x%08x to 0x%08x",
				spi_id, region_start_address, region_end_address);
		rw_region_addr += sizeof(rw_region);
	}

	SPI_Monitor_Enable(spim_devs[spi_id], true);
}

