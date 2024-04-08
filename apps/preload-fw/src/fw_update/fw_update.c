/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <soc.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/drivers/spi_nor.h>
#include <zephyr/sys/crc.h>
#include "fw_update.h"
#include "gpio/gpio_ctrl.h"

LOG_MODULE_REGISTER(fwupdate);

char *flash_devices[6] = {
	"spi1@0",
	"spi1@1",
	"spi2@0",
	"spi2@1",
	"fmc@0",
	"fmc@1"
};

static uint32_t rot_fw_staging_addr = 0;
static uint32_t rot_fw_checksum = 0;
static uint32_t rot_fw_size = 0;

static uint8_t staging_src_flash_id = BMC_FLASH_ID;
static uint8_t ext_mux_level = 0;

uint8_t flash_buf[PAGE_SIZE] NON_CACHED_BSS_ALIGN16;

void configure_staging_source(union aspeed_event_data *data)
{
	if (data->bit8[1] & ROT_SETTING_FMC_SPI) {
		staging_src_flash_id = ROT_FMC_CS1;
	} else {
		staging_src_flash_id = ((data->bit8[1] & ROT_SETTING_SPI_SRC) << 1) |
			((data->bit8[1] & ROT_SETTING_CS_SRC) >> 1);
	}

	LOG_INF("flash id = %d\n",staging_src_flash_id);
	ext_mux_level = (data->bit8[1] & ROT_SETTING_MUX_INV) ? 1 : 0;
}

void set_fw_staging_source(union aspeed_event_data *data)
{
	switch(data->bit8[0]) {
	case RotCmdStagingOffset0:
		rot_fw_staging_addr &= 0xffffff00;
		rot_fw_staging_addr |= data->bit8[1];
		break;
	case RotCmdStagingOffset1:
		rot_fw_staging_addr &= 0xffff00ff;
		rot_fw_staging_addr |= (data->bit8[1] << 8);
		break;
	case RotCmdStagingOffset2:
		rot_fw_staging_addr &= 0xff00ffff;
		rot_fw_staging_addr |= (data->bit8[1] << 16);
		break;
	case RotCmdStagingOffset3:
		rot_fw_staging_addr &= 0x00ffffff;
		rot_fw_staging_addr |= (data->bit8[1] << 24);
		break;
	}
	LOG_INF("rot_fw_staging_addr : %x", rot_fw_staging_addr);
}

void set_fw_image_size(union aspeed_event_data *data)
{
	switch(data->bit8[0]) {
	case RotCmdImgSize0:
		rot_fw_size &= 0xffffff00;
		rot_fw_size |= data->bit8[1];
		break;
	case RotCmdImgSize1:
		rot_fw_size &= 0xffff00ff;
		rot_fw_size |= (data->bit8[1] << 8);
		break;
	case RotCmdImgSize2:
		rot_fw_size &= 0xff00ffff;
		rot_fw_size |= (data->bit8[1] << 16);
		break;
	case RotCmdImgSize3:
		rot_fw_size &= 0x00ffffff;
		rot_fw_size |= (data->bit8[1] << 24);
		break;
	}
	LOG_INF("rot_fw_size : %x", rot_fw_size);
}

void set_fw_image_checksum(union aspeed_event_data *data)
{
	switch(data->bit8[0]) {
	case RotCmdChecksum0:
		rot_fw_checksum &= 0xffffff00;
		rot_fw_checksum |= data->bit8[1];
		break;
	case RotCmdChecksum1:
		rot_fw_checksum &= 0xffff00ff;
		rot_fw_checksum |= (data->bit8[1] << 8);
		break;
	case RotCmdChecksum2:
		rot_fw_checksum &= 0xff00ffff;
		rot_fw_checksum |= (data->bit8[1] << 16);
		break;
	case RotCmdChecksum3:
		rot_fw_checksum &= 0x00ffffff;
		rot_fw_checksum |= (data->bit8[1] << 24);
		break;
	}
	LOG_INF("rot_fw_checksum : %x", rot_fw_checksum);
}

uint32_t cal_checksum(const struct device *dev, uint32_t addr, uint32_t size)
{
	uint32_t read_addr = addr;
	uint32_t read_size;
	uint32_t remaining = size;
	uint32_t crc = 0;

	while (remaining) {
		read_size = (remaining >= PAGE_SIZE) ? PAGE_SIZE : remaining;
		flash_read(dev, read_addr, flash_buf, read_size);
		crc = crc32_ieee_update(crc, flash_buf, read_size);
		read_addr += read_size;
		remaining -= read_size;
	}

	return crc;
}

const struct device *get_flash_dev(uint8_t flash_id)
{
	const struct device *flash_dev;
	flash_dev = device_get_binding(flash_devices[flash_id]);

	return flash_dev;
}

int rot_fw_update(void)
{
	const struct flash_area *fa;
	const struct device *stg_flash_dev;
	const struct device *rot_flash_dev;
	uint32_t flash_sz;
	uint32_t checksum = 0;
	uint8_t fw_update_status = 0;

	fw_update_status = ROT_FW_UPDATE_INPROGRESS;
	SetRotCmdStatus(fw_update_status);

	LOG_INF("ROT FW Start Addr: 0x%08x", rot_fw_staging_addr);
	if (rot_fw_staging_addr == 0) {
		LOG_ERR("Invalid staging address");
		goto fwu_error;
	}

	if (flash_area_open(FIXED_PARTITION_ID(active_partition), &fa)) {
		LOG_ERR("Unknown partition");
		goto fwu_error;
	}

	BMCSPIHold(ext_mux_level);
	LOG_INF("flash dev : %s", flash_devices[staging_src_flash_id]);
	stg_flash_dev = device_get_binding(flash_devices[staging_src_flash_id]);
	if (stg_flash_dev == NULL) {
		LOG_ERR("Failed to get BMC flash device");
		goto fwu_error;
	}

	flash_sz = flash_get_flash_size(stg_flash_dev);

	if (rot_fw_size > fa->fa_size) {
		LOG_ERR("Firmware size > active partition size");
		goto fwu_error;
	}

	if (rot_fw_staging_addr > flash_sz ||
			flash_sz - rot_fw_staging_addr < rot_fw_size) {
		LOG_ERR("Invalid address");
		goto fwu_error;
	}

	checksum = cal_checksum(stg_flash_dev, rot_fw_staging_addr, rot_fw_size);
	if (checksum != rot_fw_checksum) {
		LOG_ERR("Invalid checksum, expected : %x, actual : %x", rot_fw_checksum, checksum);
		fw_update_status = ROT_FW_CHECKSUM_FAIl;
		SetRotCmdStatus(fw_update_status);
		BMCSPIRelease(ext_mux_level);
		return -1;
	}

	flash_area_erase(fa, 0, fa->fa_size);
	uint32_t read_addr = rot_fw_staging_addr;
	uint32_t write_addr = fa->fa_off;
	uint32_t remaining = rot_fw_size;
	uint32_t read_size;

	rot_flash_dev = device_get_binding(flash_devices[ROT_FLASH_ID]);

	while(remaining) {
		read_size = (remaining >= PAGE_SIZE) ? PAGE_SIZE : remaining;
		flash_read(stg_flash_dev, read_addr, flash_buf, PAGE_SIZE);
		flash_write(rot_flash_dev, write_addr, flash_buf, PAGE_SIZE);
		read_addr += read_size;
		write_addr += read_size;
		remaining -= read_size;
	}

	SetRotCmdStatus(ROT_FW_UPDATE_DONE);
	BMCSPIRelease(ext_mux_level);
	LOG_INF("ROT firmware update successful");

	return 0;
fwu_error:
	SetRotCmdStatus(ROT_FW_UPDATE_FAIl);
	BMCSPIRelease(ext_mux_level);
	return -1;
}
