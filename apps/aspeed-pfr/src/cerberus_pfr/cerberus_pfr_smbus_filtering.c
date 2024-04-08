/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/i2c/pfr/i2c_filter.h>
#include "cerberus_pfr/cerberus_pfr_smbus_filtering.h"
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#include "flash/flash_aspeed.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

void apply_pfm_smbus_protection(uint8_t spi_dev)
{
	struct pfr_manifest *pfr_manifest = get_pfr_manifest();
	struct SMBUS_FILTER_RULE i2c_rule;
	struct SMBUS_FILTER_MANIFEST i2c_filter;
	struct SMBUS_FILTER_DEVICE i2c_device;
	const struct device *flt_dev = NULL;
	char bus_dev_name[] = "i2cfilterx";
	int status;

	uint32_t i2c_filter_addr;
	int id = (spi_dev == BMC_SPI) ? 0 : 1;

	i2c_filter_addr = pfr_manifest->i2c_filter_addr[id];
	if (i2c_filter_addr == 0) {
		LOG_INF("I2c Filtering rule not found");
		return;
	}

	pfr_spi_read(spi_dev, i2c_filter_addr, sizeof(struct SMBUS_FILTER_RULE),
			(uint8_t *)&i2c_rule);
	if ((i2c_rule.magic_number != I2C_FILTER_SECTION_MAGIC) || (i2c_rule.filter_count == 0))
		return;

	for (int i = 0; i < 4; i++) {
		bus_dev_name[9] = i + '0';
		flt_dev = device_get_binding(bus_dev_name);
		if (flt_dev) {
			ast_i2c_filter_init(flt_dev);
			ast_i2c_filter_en(flt_dev, true, false, true, true);
			ast_i2c_filter_default(flt_dev, 0);
		}
	}

	i2c_filter_addr += sizeof(struct SMBUS_FILTER_RULE);

	for (uint8_t fid = 0; fid < i2c_rule.filter_count; fid++) {
		pfr_spi_read(spi_dev, i2c_filter_addr, sizeof(struct SMBUS_FILTER_MANIFEST),
				(uint8_t *)&i2c_filter);

		bus_dev_name[9] = i2c_filter.filter_id + '0';
		flt_dev = device_get_binding(bus_dev_name);
		if (!flt_dev) {
			LOG_ERR("Failed to get i2c filter: %s", bus_dev_name);
			return;
		}

		i2c_filter_addr += sizeof(struct SMBUS_FILTER_MANIFEST);
		for (uint8_t devid = 0; devid < i2c_filter.device_count; devid++) {
			pfr_spi_read(spi_dev, i2c_filter_addr,
					sizeof(struct SMBUS_FILTER_DEVICE), (uint8_t *)&i2c_device);
			i2c_filter_addr += sizeof(struct SMBUS_FILTER_DEVICE);
			if (!i2c_device.enable) {
				continue;
			}
			LOG_INF("SMBus Rule Bus[%d] RuleId[%d] DeviceAddr[%x]",
					i2c_filter.filter_id, devid, i2c_device.slave_addr);
			status = ast_i2c_filter_en(flt_dev, true, true, 0, 0);
			LOG_INF("ast_i2c_filter_en ret=%d", status);
			status = ast_i2c_filter_update(flt_dev, devid, i2c_device.slave_addr >> 1,
					(struct ast_i2c_f_bitmap *)i2c_device.whitelist_cmd);
			LOG_INF("ast_i2c_filter_update ret=%d", status);
			LOG_HEXDUMP_INF(i2c_device.whitelist_cmd, sizeof(i2c_device.whitelist_cmd) ,
					"Whitelist");
		}
	}
}

