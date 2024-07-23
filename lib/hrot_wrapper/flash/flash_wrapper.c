/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/drivers/flash.h>
#include <zephyr/drivers/spi_nor.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <stdlib.h>
#include <string.h>

#include "flash/flash_common.h"
#include "flash/flash_logging.h"
#include <flash/flash_wrapper.h>
#include <flash/flash_aspeed.h>


/**
 * Get the size of the flash device.
 *
 * @param flash The flash to query.
 * @param bytes The buffer that will hold the number of bytes in the device.
 *
 * @return 0 if the device size was successfully read or an error code.
 */
int Wrapper_spi_flash_get_device_size(struct spi_flash *flash, uint32_t *bytes)
{
	struct flash_xfer xfer = {0};

	if ((flash == NULL) || (bytes == NULL)) {
		return SPI_FLASH_INVALID_ARGUMENT;
	}

	xfer.cmd = SPI_APP_CMD_GET_FLASH_SIZE;


	*bytes = SPI_Command_Xfer(flash, &xfer);

	return 0;
}

/**
 * Read data from the SPI flash.
 *
 * @param flash The flash to read from.
 * @param address The address to start reading from.
 * @param data The buffer to hold the data that has been read.
 * @param length The number of bytes to read.
 *
 * @return 0 if the bytes were read from flash or an error code.
 */
int Wrapper_spi_flash_read(struct spi_flash *flash, uint32_t address, uint8_t *data, size_t length)
{

	struct flash_xfer xfer;
	int status;
	int read_dummy = 0, read_mode = 0;
	int read_flags = 0, addr_mode = 0;

	// if ((flash == NULL) || (data == NULL)) {
	//      if(flash == NULL){
	//              printk("flash is NULL\n");
	//      }
	//      if(data == NULL){
	//              printk("data is NULL\n");
	//      }
	//      return SPI_FLASH_INVALID_ARGUMENT;
	// }
	if ((flash == NULL)) {
		return SPI_FLASH_INVALID_ARGUMENT;
	}
	//Wrapper_spi_flash_get_device_size(flash, &bytes);

	//SPI_FLASH_BOUNDS_CHECK(bytes, address, length);

	FLASH_XFER_INIT_READ(xfer, FLASH_CMD_READ, address, read_dummy, read_mode, data, length, read_flags | addr_mode);



	status = SPI_Command_Xfer(flash, &xfer);

	return status;
}

/**
 * Get the size of a flash page for write operations.
 *
 * @param flash The flash to query.
 * @param bytes Output for the number of bytes in a flash page.
 *
 * @return 0 if the page size was successfully read or an error code.
 */
int Wrapper_spi_flash_get_page_size(struct spi_flash *flash, uint32_t *bytes)
{
	if ((flash == NULL) || (bytes == NULL)) {
		return SPI_FLASH_INVALID_ARGUMENT;
	}

	/* All supported devices use a 256 byte page size.  If necessary, this value can be read from
	 * the SFDP tables. */
	*bytes = FLASH_PAGE_SIZE;

	return 0;
}

/**
 * Get the minimum number of bytes that must be written to a single flash page.  Writing fewer bytes
 * than the minimum to any page will still result in a minimum sized write to flash. The extra bytes
 * that were written must be erased before they can be written again.
 *
 * @param flash The flash to query.
 * @param bytes Output for the minimum number of bytes for a page write.
 *
 * @return 0 if the minimum write size was successfully read or an error code.
 */
int Wrapper_spi_flash_minimum_write_per_page(struct spi_flash *flash, uint32_t *bytes)
{
	if ((flash == NULL) || (bytes == NULL)) {
		return SPI_FLASH_INVALID_ARGUMENT;
	}

	*bytes = 1;
	return 0;

}

/**
 * Write data to the SPI flash.  The flash needs to be erased prior to writing.
 *
 * @param flash The flash to write to.
 * @param address The address to start writing to.
 * @param data The data to write.
 * @param length The number of bytes to write.
 *
 * @return The number of bytes written to the flash or an error code.  Use ROT_IS_ERROR to check the
 * return value.
 */
int Wrapper_spi_flash_write(struct spi_flash *flash, uint32_t address, const uint8_t *data, size_t length)
{
	struct flash_xfer xfer;
	uint32_t page = FLASH_PAGE_BASE(address);
	uint32_t next = page + FLASH_PAGE_SIZE;
	size_t remaining = length;
	int status = 0;
	int write_flags = 0, addr_mode = 0;

	if ((flash == NULL)) {
		return SPI_FLASH_INVALID_ARGUMENT;
	}
	// Wrapper_spi_flash_get_device_size(flash, &bytes);
	// SPI_FLASH_BOUNDS_CHECK (flash->device_size, address, length);

	while ((status == 0) && remaining) {
		uint32_t end = address + remaining;
		size_t write_len;

		if (page != FLASH_PAGE_BASE(end)) {
			write_len = next - address;
		} else   {
			write_len = remaining;
		}


		FLASH_XFER_INIT_WRITE(xfer, FLASH_CMD_PP, address, 0, (uint8_t *) data, write_len,
				      write_flags | addr_mode);


		status = SPI_Command_Xfer(flash, &xfer);

		// if (status == 0) {
		// status = spi_flash_wait_for_write_completion (flash, -1, 1);
		if (status == 0) {
			remaining -= write_len;
			data += write_len;
			page = next;
			address = next;
			next += FLASH_PAGE_SIZE;
		}
	}

	length = length - remaining;

	if (length) {
		if (status != 0) {
			printk("debug_log_create_entry\n");
			// debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_FLASH,
			// FLASH_LOGGING_INCOMPLETE_WRITE, address, status);
		}
		return length;
	} else   {
		return status;
	}

}

/**
 * Get the size of a flash sector for erase operations.
 *
 * @param flash The flash to query.
 * @param bytes Output for the number of bytes in a flash sector.
 *
 * @return 0 if the sector size was successfully read or an error code.
 */
int Wrapper_spi_flash_get_sector_size(struct spi_flash *flash, uint32_t *bytes)
{
	struct flash_xfer xfer = {0};

	if ((flash == NULL) || (bytes == NULL)) {
		return SPI_FLASH_INVALID_ARGUMENT;
	}

	xfer.cmd = SPI_APP_CMD_GET_FLASH_SECTOR_SIZE;


	*bytes = SPI_Command_Xfer(flash, &xfer);


	return 0;
}

/**
 * Erase a 4kB sector of flash.
 *
 * @param flash The flash to erase.
 * @param sector_addr An address within the sector to erase.
 *
 * @return 0 if the sector was erased or an error code.
 */
int Wrapper_spi_flash_sector_erase(struct spi_flash *flash, uint32_t sector_addr)
{
	struct flash_xfer xfer = {0};
	int status = 0;

	if (flash == NULL) {
		return SPI_FLASH_INVALID_ARGUMENT;
	}
	xfer.cmd = MIDLEY_FLASH_CMD_4K_ERASE;
	xfer.address = sector_addr;
	xfer.length = SECTOR_SIZE;

	status = SPI_Command_Xfer(flash, &xfer);

	return status;
}

/**
 * Get the size of a flash block for erase operations.
 *
 * @param flash The flash to query.
 * @param bytes Output for the number of bytes in a flash block.
 *
 * @return 0 if the block size was successfully read or an error code.
 */
int Wrapper_spi_flash_get_block_size(struct spi_flash *flash, uint32_t *bytes)
{
	struct flash_xfer xfer = {0};

	if ((flash == NULL) || (bytes == NULL)) {
		return SPI_FLASH_INVALID_ARGUMENT;
	}

	xfer.cmd = SPI_APP_CMD_GET_FLASH_BLOCK_SIZE;

	*bytes = SPI_Command_Xfer(flash, &xfer);

	return 0;
}

/**
 * Erase a 64kB block of flash.
 *
 * @param flash The flash to erase.
 * @param block_addr An address within the block to erase.
 *
 * @return 0 if the block was erased or an error code.
 */
int Wrapper_spi_flash_block_erase(struct spi_flash *flash, uint32_t block_addr)
{
	struct flash_xfer xfer = {0};
	int status = 0;

	if (flash == NULL) {
		return SPI_FLASH_INVALID_ARGUMENT;
	}
	xfer.cmd = MIDLEY_FLASH_CMD_BLOCK_ERASE;
	xfer.address = block_addr;
	xfer.length = BLOCK_SIZE;

	status = SPI_Command_Xfer(flash, &xfer);

	return status;

}

/**
 * Erase the entire flash chip.
 *
 * @param flash The flash to erase.
 *
 * @return 0 if the flash chip was erased or an error code.
 */
int Wrapper_spi_flash_chip_erase(struct spi_flash *flash)
{
	struct flash_xfer xfer = {0};
	int status = 0;

	if (flash == NULL) {
		return SPI_FLASH_INVALID_ARGUMENT;
	}
	xfer.cmd = MIDLEY_FLASH_CMD_CE;

	status = SPI_Command_Xfer(flash, &xfer);

	return status;
}

int  flash_wrapper_init(struct spi_engine_wrapper *flash, struct flash_master_wrapper *spi, struct spi_engine_state_wrapper *flash_state)
{
	int status;

	if ((flash == NULL) || (spi == NULL)) {
		return SPI_FLASH_INVALID_ARGUMENT;
	}

	memset(flash, 0, sizeof(struct spi_engine_wrapper));
	memset(flash_state, 0, sizeof(struct spi_engine_state_wrapper));
	flash->spi.state = &flash_state->state;

	status = platform_mutex_init(&flash->spi.state->lock);
	if (status != 0) {
		return status;
	}

	flash->spi.state->command.read = FLASH_CMD_READ;
	flash->spi.state->command.write = FLASH_CMD_PP;
	flash->spi.state->command.erase_sector = FLASH_CMD_4K_ERASE;
	flash->spi.state->command.erase_block = FLASH_CMD_64K_ERASE;
	flash->spi.state->command.enter_pwrdown = FLASH_CMD_DP;
	flash->spi.state->command.release_pwrdown = FLASH_CMD_RDP;

	flash->spi.spi->xfer =  spi->base.xfer;
	flash->spi.spi->capabilities = spi->base.capabilities;
	flash->spi.state->device_id[0] = 0xff;
	flash->spi.state->capabilities = (FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	flash->spi.base.get_device_size = (int (*)(struct flash *, uint32_t *))Wrapper_spi_flash_get_device_size;
	flash->spi.base.read = (int (*)(struct flash *, uint32_t, uint8_t *, size_t))Wrapper_spi_flash_read;
	flash->spi.base.get_page_size = (int (*)(struct flash *, uint32_t *))Wrapper_spi_flash_get_page_size;
	flash->spi.base.minimum_write_per_page =
		(int (*)(struct flash *, uint32_t *))Wrapper_spi_flash_minimum_write_per_page;
	flash->spi.base.write = (int (*)(struct flash *, uint32_t, const uint8_t *, size_t))Wrapper_spi_flash_write;
	flash->spi.base.get_sector_size = (int (*)(struct flash *, uint32_t *))Wrapper_spi_flash_get_sector_size;
	flash->spi.base.sector_erase = (int (*)(struct flash *, uint32_t))Wrapper_spi_flash_sector_erase;
	flash->spi.base.get_block_size = (int (*)(struct flash *, uint32_t *))Wrapper_spi_flash_get_block_size;
	flash->spi.base.block_erase = (int (*)(struct flash *, uint32_t))Wrapper_spi_flash_block_erase;
	flash->spi.base.chip_erase = (int (*)(struct flash *))Wrapper_spi_flash_chip_erase;

	return 0;
}
