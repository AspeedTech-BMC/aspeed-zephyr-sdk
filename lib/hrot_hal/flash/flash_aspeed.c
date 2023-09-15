/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <drivers/flash.h>
#include <drivers/spi_nor.h>
#include <flash/flash_aspeed.h>
#include <kernel.h>
#include <sys/util.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr.h>
#include <flash_map.h>
#include <soc.h>

#define LOG_MODULE_NAME spi_api
#define NON_CACHED_SRAM_START      DT_REG_ADDR_BY_IDX(DT_NODELABEL(sram0), 1)
#define NON_CACHED_SRAM_SIZE       DT_REG_SIZE_BY_IDX(DT_NODELABEL(sram0), 1)
#define NON_CACHED_SRAM_END        (NON_CACHED_SRAM_START + NON_CACHED_SRAM_SIZE)

#include <logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME, LOG_LEVEL_DBG);

static char *Flash_Devices_List[6] = {
	"spi1_cs0",
	"spi1_cs1",
	"spi2_cs0",
	"spi2_cs1",
	"fmc_cs0",
	"fmc_cs1"
};

#if defined(CONFIG_SPI_DMA_SUPPORT_ASPEED) || defined(CONFIG_SPI_WRITE_DMA_SUPPORT_ASPEED)
struct k_mutex flash_rw_mutex;
static bool mutex_init = false;
static uint8_t flash_rw_buf[16384] NON_CACHED_BSS_ALIGN16;
#endif

#if defined(CONFIG_SPI_DMA_SUPPORT_ASPEED) || defined(CONFIG_SPI_WRITE_DMA_SUPPORT_ASPEED)
void init_flash_rw_buf_mutex(void)
{
	if (!mutex_init) {
		k_mutex_init(&flash_rw_mutex);
		mutex_init = true;
	}
}
#endif

int get_rot_region(uint8_t device_id, const struct flash_area **fa);

int BMC_PCH_SPI_Command(struct pspi_flash *flash, struct pflash_xfer *xfer)
{
	uint8_t DeviceId = flash->state->device_id[0];
	int AdrOffset = xfer->address;
	int Datalen = xfer->length;
	uint32_t FlashSize = 0;
	int ret = 0;

	switch (xfer->cmd) {
	case SPI_APP_CMD_GET_FLASH_SIZE:
		return bmc_pch_get_flash_size(DeviceId);
	break;
	case MIDLEY_FLASH_CMD_WREN:
		ret = 0;	// bypass as write enabled
	break;
	case SPI_APP_CMD_GET_FLASH_BLOCK_SIZE:
		return get_block_erase_size(DeviceId);
	break;
	case MIDLEY_FLASH_CMD_READ:
		ret = bmc_pch_flash_read(DeviceId, AdrOffset, Datalen, xfer->data);
	break;
	case MIDLEY_FLASH_CMD_PP://Flash Write
		ret = bmc_pch_flash_write(DeviceId, AdrOffset, Datalen, xfer->data);
	break;
	case MIDLEY_FLASH_CMD_4K_ERASE:
		ret = bmc_pch_flash_erase(DeviceId, AdrOffset, SECTOR_SIZE, true);
	break;
	case MIDLEY_FLASH_CMD_BLOCK_ERASE:
		ret = bmc_pch_flash_erase(DeviceId, AdrOffset, BLOCK_SIZE, false);
	break;
	case MIDLEY_FLASH_CMD_CE:
		FlashSize = bmc_pch_get_flash_size(DeviceId);
		ret = bmc_pch_flash_erase(DeviceId, AdrOffset, FlashSize, false);
	break;
	case MIDLEY_FLASH_CMD_RDSR:
		// bypass as flash status are write enabled and not busy
		*xfer->data = 0x02;
		ret = 0;
	break;
	default:
		LOG_DBG("%d Command is not supported\n", xfer->cmd);
	break;
	}

	return ret;
}

int FMC_SPI_Command(struct pspi_flash *flash, struct pflash_xfer *xfer)
{
	uint8_t DeviceId = flash->state->device_id[0];
	uint32_t AdrOffset = xfer->address;
	uint32_t Datalen = xfer->length;
	int ret = -1;

	switch (xfer->cmd) {
	case SPI_APP_CMD_GET_FLASH_SIZE:
		return rot_get_region_size(DeviceId);
	break;
	case MIDLEY_FLASH_CMD_WREN:
		ret = 0;	// bypass as write enabled
	break;
	case MIDLEY_FLASH_CMD_READ:
		ret = rot_flash_read(DeviceId, AdrOffset, Datalen, xfer->data);
	break;
	case MIDLEY_FLASH_CMD_PP://Flash Write
		ret = rot_flash_write(DeviceId, AdrOffset, Datalen, xfer->data);
	break;
	case MIDLEY_FLASH_CMD_4K_ERASE:
		ret = rot_flash_erase(DeviceId, AdrOffset, SECTOR_SIZE, true);
	break;
	case MIDLEY_FLASH_CMD_BLOCK_ERASE:
		ret = rot_flash_erase(DeviceId, AdrOffset, BLOCK_SIZE, false);
	break;
	case MIDLEY_FLASH_CMD_CE:
		LOG_DBG("%d Command is not supported\n", xfer->cmd);
		ret = 0;
	break;
	case MIDLEY_FLASH_CMD_RDSR:
		// bypass as flash status are write enabled and not busy
		*xfer->data = 0x02;
		ret = 0;
	break;
	default:
		LOG_ERR("%d Command is not supported\n", xfer->cmd);
	break;
	}

	return ret;
}

int SPI_Command_Xfer(struct pspi_flash *flash, struct pflash_xfer *xfer)
{
	uint8_t DeviceId = flash->state->device_id[0];
	int ret  = 0;

	if (DeviceId <= PCH_SPI)
		ret = BMC_PCH_SPI_Command(flash, xfer);
	else
		ret = FMC_SPI_Command(flash, xfer);
	return ret;
}

int get_flash_dev(uint8_t device_id, uint32_t *address, const struct device **dev)
{
	uint32_t flash_sz = 0;

	*dev = device_get_binding(Flash_Devices_List[device_id]);
	if (*dev == NULL)
		return -1;

#if defined(CONFIG_BMC_DUAL_FLASH)
	if (device_id == BMC_SPI) {
		flash_sz = flash_get_flash_size(*dev);
		if (*address >= flash_sz) {
			device_id += 1;
			*address -= flash_sz;
			*dev = device_get_binding(Flash_Devices_List[device_id]);
		}
	}
#endif
#if defined(CONFIG_CPU_DUAL_FLASH)
	if (device_id == PCH_SPI) {
		flash_sz = flash_get_flash_size(*dev);
		if (*address >= flash_sz) {
			device_id += 1;
			*address -= flash_sz;
			*dev = device_get_binding(Flash_Devices_List[device_id]);
		}
	}
#endif
	return 0;
}

int get_rot_region(uint8_t device_id, const struct flash_area **fa)
{
	int ret = 0;

	switch (device_id) {
	case ROT_INTERNAL_ACTIVE:
		ret = flash_area_open(FLASH_AREA_ID(active), fa);
		break;
	case ROT_INTERNAL_RECOVERY:
		ret = flash_area_open(FLASH_AREA_ID(recovery), fa);
		break;
	case ROT_INTERNAL_STATE:
		ret = flash_area_open(FLASH_AREA_ID(state), fa);
		break;
	case ROT_INTERNAL_INTEL_STATE:
		ret = flash_area_open(FLASH_AREA_ID(intel_state), fa);
		break;
	case ROT_INTERNAL_KEY:
		ret = flash_area_open(FLASH_AREA_ID(key), fa);
		break;
#if defined(CONFIG_BOOTLOADER_MCUBOOT)
	case ROT_INTERNAL_CERTIFICATE:
		ret = flash_area_open(FLASH_AREA_ID(certificate), fa);
		break;
#endif
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	case ROT_INTERNAL_AFM:
		ret = flash_area_open(FLASH_AREA_ID(afm_act_1), fa);
		break;
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	case ROT_EXT_CPLD_ACT:
		ret = flash_area_open(FLASH_AREA_ID(intel_cpld_act), fa);
		break;
	case ROT_EXT_CPLD_RC:
		ret = flash_area_open(FLASH_AREA_ID(intel_cpld_rc), fa);
		break;
#endif
	default:
		ret = -1;
		break;
	}

	return ret;
}

int bmc_pch_flash_read(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	const struct device *flash_dev;
	int ret;

	ret = get_flash_dev(device_id, &address, &flash_dev);
	if (ret)
		return ret;

#if defined(CONFIG_SPI_DMA_SUPPORT_ASPEED)
	if (data >= (uint8_t *)NON_CACHED_SRAM_START && data < (uint8_t *)NON_CACHED_SRAM_END) {
		ret = flash_read(flash_dev, address, data, data_length);
	} else {
		if (k_mutex_lock(&flash_rw_mutex, K_MSEC(1000)))
			return -1;
		ret = flash_read(flash_dev, address, flash_rw_buf, data_length);
		memcpy(data, flash_rw_buf, data_length);
		k_mutex_unlock(&flash_rw_mutex);
	}
#else
	ret = flash_read(flash_dev, address, data, data_length);
#endif

	return ret;
}

int rot_flash_read(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	int ret = 0;
	const struct flash_area *fa;

	ret = get_rot_region(device_id, &fa);
	if (ret)
		return ret;

#if defined(CONFIG_SPI_DMA_SUPPORT_ASPEED)
	if (data >= (uint8_t *)NON_CACHED_SRAM_START && data < (uint8_t *)NON_CACHED_SRAM_END) {
		ret = flash_area_read(fa, address, data, data_length);
	} else {
		if (k_mutex_lock(&flash_rw_mutex, K_MSEC(1000)))
			return -1;
		ret = flash_area_read(fa, address, flash_rw_buf, data_length);
		memcpy(data, flash_rw_buf, data_length);
		k_mutex_unlock(&flash_rw_mutex);
	}
#else
	ret = flash_area_read(fa, address, data, data_length);
#endif

	return ret;
}

int bmc_pch_flash_write(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	const struct device *flash_dev;
	int ret;

	ret = get_flash_dev(device_id, &address, &flash_dev);
	if (ret)
		return ret;

#if defined(CONFIG_SPI_DMA_WRITE_SUPPORT_ASPEED)
	if (data >= (uint8_t *)NON_CACHED_SRAM_START && data < (uint8_t *)NON_CACHED_SRAM_END) {
		ret = flash_write(flash_dev, address, data, data_length);
	} else {
		if (k_mutex_lock(&flash_rw_mutex, K_MSEC(1000)))
			return -1;
		ret = flash_write(flash_dev, address, flash_rw_buf, data_length);
		memcpy(data, flash_rw_buf, data_length);
		k_mutex_unlock(&flash_rw_mutex);
	}
#else
	ret = flash_write(flash_dev, address, data, data_length);
#endif

	return ret;
}

int rot_flash_write(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	int ret = 0;
	const struct flash_area *fa;

	ret = get_rot_region(device_id, &fa);
	if (ret)
		return ret;

#if defined(CONFIG_SPI_DMA_WRITE_SUPPORT_ASPEED)
	if (data >= (uint8_t *)NON_CACHED_SRAM_START && data < (uint8_t *)NON_CACHED_SRAM_END) {
		ret = flash_area_write(fa, address, data, data_length);
	} else {
		if (k_mutex_lock(&flash_rw_mutex, K_MSEC(1000)))
			return -1;
		ret = flash_area_write(fa, address, flash_rw_buf, data_length);
		memcpy(data, flash_rw_buf, data_length);
		k_mutex_unlock(&flash_rw_mutex);
	}
#else
	ret = flash_area_write(fa, address, data, data_length);
#endif

	return ret;
}

int bmc_pch_flash_erase(uint8_t device_id, uint32_t address, uint32_t size, bool sector_erase)
{
	const struct device *flash_dev;
	int ret = get_flash_dev(device_id, &address, &flash_dev);
	if (ret)
		return ret;

	if (sector_erase) {
		if (size % SECTOR_SIZE)
			return -1;
		ret = spi_nor_erase_by_cmd(flash_dev, address, size,
				MIDLEY_FLASH_CMD_4K_ERASE);
	} else {
		if (size % BLOCK_SIZE)
			return -1;
		ret = spi_nor_erase_by_cmd(flash_dev, address, size,
				MIDLEY_FLASH_CMD_BLOCK_ERASE);
	}

	return ret;
}

int rot_flash_erase(uint8_t device_id, uint32_t address, uint32_t size, bool sector_erase)
{
	const struct flash_area *fa;
	const struct device *flash_dev;
	int ret = 0;

	ret = get_rot_region(device_id, &fa);
	if (ret)
		return ret;

	flash_dev = device_get_binding(fa->fa_dev_name);
	if (!flash_dev)
		return -1;

	if (sector_erase) {
		if (size % SECTOR_SIZE)
			return -1;
		ret = spi_nor_erase_by_cmd(flash_dev, fa->fa_off + address, size,
				MIDLEY_FLASH_CMD_4K_ERASE);
	} else {
		if (size % BLOCK_SIZE)
			return -1;
		ret = spi_nor_erase_by_cmd(flash_dev, fa->fa_off + address, size,
				MIDLEY_FLASH_CMD_BLOCK_ERASE);
	}


	return ret;
}

int bmc_pch_get_flash_size(uint8_t device_id)
{
	const struct device *flash_dev;
	uint32_t flash_sz;
	uint32_t address = 0;
	int ret = get_flash_dev(device_id, &address, &flash_dev);
	if (ret)
		return ret;

	flash_sz = flash_get_flash_size(flash_dev);
	return flash_sz;
}

int rot_get_region_size(uint8_t device_id)
{
	const struct flash_area *fa;
	int ret = 0;

	ret = get_rot_region(device_id, &fa);
	if (ret)
		return ret;

	return fa->fa_size;
}

int get_block_erase_size(uint8_t device_id)
{
	int block_erase_sz = 0;
	const struct device *flash_device = device_get_binding(Flash_Devices_List[device_id]);

	block_erase_sz = spi_nor_get_erase_sz(flash_device, MIDLEY_FLASH_CMD_BLOCK_ERASE);

	return block_erase_sz;
}
