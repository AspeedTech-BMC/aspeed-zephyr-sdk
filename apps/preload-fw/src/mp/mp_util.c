/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <soc.h>
#include <stdint.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi_nor.h>
#include <zephyr/drivers/misc/aspeed/otp_aspeed.h>
#include <zephyr/logging/log.h>

#include "gpio/gpio_ctrl.h"

#define FLASH_ADDR_BASE  0x80000000
#define SECTOR_SIZE 0x1000
#define BLOCK_SIZE  0x10000
#define SPI_CMD_SECTOR_ERASE  0x20
#define SPI_CMD_BLOCK_ERASE   0xd8

static uint8_t buffer[SECTOR_SIZE] NON_CACHED_BSS_ALIGN16;

LOG_MODULE_REGISTER(mp, CONFIG_LOG_DEFAULT_LEVEL);

int mp_erase_spi_region(const struct device *dev, uint32_t offset, uint32_t size)
{
	uint32_t erase_addr = offset;
	uint32_t end_addr = offset + size;

	while (erase_addr < end_addr) {
		if (((end_addr - erase_addr) >= BLOCK_SIZE) && !(erase_addr & 0xffff)) {
			if (spi_nor_erase_by_cmd(dev, erase_addr, BLOCK_SIZE, SPI_CMD_BLOCK_ERASE))
				return -1;
			erase_addr += BLOCK_SIZE;
		} else {
			if (spi_nor_erase_by_cmd(dev, erase_addr, SECTOR_SIZE, SPI_CMD_SECTOR_ERASE))
				return -1;
			erase_addr += SECTOR_SIZE;
		}
	}

	return 0;
}

int mp_replace_rot_fw(const struct device *dev, uint32_t dst_addr, uint32_t src_addr,
		uint32_t size)
{
	if (dst_addr % SECTOR_SIZE) {
		LOG_ERR("Destination address is not 4k aligned");
		return -1;
	}

	if (src_addr % SECTOR_SIZE) {
		LOG_ERR("Source address is not 4k aligned");
		return -1;
	}

	if (size % SECTOR_SIZE) {
		LOG_ERR("Size is not 4k aligned");
		return -1;
	}

	for (int i = 0; i < size / SECTOR_SIZE; i++) {
		if (flash_read(dev, src_addr, buffer, SECTOR_SIZE)) {
			LOG_ERR("Failed to read ROT firmware from offset 0x%X", src_addr);
			return -1;
		}
		if (flash_write(dev, dst_addr, buffer, SECTOR_SIZE)) {
			LOG_ERR("Failed to write ROT image to offset 0x%X", dst_addr);
			return -1;
		}
		src_addr += SECTOR_SIZE;
		dst_addr += SECTOR_SIZE;
	}

	return 0;
}

int prog_otp_and_rot(void)
{
	enum otp_status otp_rc = OTP_SUCCESS;
	const struct device *flash_dev;
	uint32_t rot_fw_addr = CONFIG_MP_ROT_IMAGE_OFFSET;
	uint32_t rot_fw_size = CONFIG_MP_ROT_IMAGE_SIZE;
	uint32_t otp_image_offset = CONFIG_MP_OTP_IMAGE_OFFSET;
	uint32_t otp_image_size = CONFIG_MP_OTP_IMAGE_SIZE;
	uint32_t otp_image_addr;

	// get flash address of otp image
	otp_image_addr = FLASH_ADDR_BASE | CONFIG_MP_OTP_IMAGE_OFFSET;
	// prog otp
	otp_rc = aspeed_otp_prog_image(otp_image_addr);
	if (otp_rc) {
		set_mp_status(0, 1);
		LOG_ERR("Failed to program OTP image");
		goto error;
	}

	flash_dev = device_get_binding("fmc@0");
	// erase otp image
	if (mp_erase_spi_region(flash_dev, otp_image_offset, otp_image_size)) {
		LOG_ERR("Failed to erase otp image");
		set_mp_status(1, 0);
		goto error;
	}

	// prog rot firmware
	if (mp_erase_spi_region(flash_dev, 0, rot_fw_size)) {
		LOG_ERR("Failed to erase active region");
		set_mp_status(1, 0);
		goto error;
	}

	if (mp_replace_rot_fw(flash_dev, 0, rot_fw_addr, rot_fw_size)) {
		LOG_ERR("Failed to update ROT firmware");
		set_mp_status(1, 0);
		goto error;
	}

	set_mp_status(1, 1);

	return 0;
error:
	return -1;
}
