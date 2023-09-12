/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "pfr_common.h"

int pfr_spi_read(uint8_t device_id, uint32_t address,
		 uint32_t data_length, uint8_t *data);

int pfr_spi_write(uint8_t device_id, uint32_t address,
		  uint32_t data_length, uint8_t *data);

int pfr_spi_page_read_write(uint8_t device_id, uint32_t source_address, uint32_t target_address);

int pfr_spi_erase_4k(uint8_t device_id, uint32_t address);

int pfr_spi_erase_block(uint8_t device_id, uint32_t address);

int pfr_spi_erase_region(uint8_t device_id,
		bool support_block_erase, uint32_t start_addr, uint32_t nbytes);

int pfr_spi_region_read_write_between_spi(uint8_t src_dev, uint32_t src_addr,
		uint8_t dest_dev, uint32_t dest_addr, size_t length);

uint32_t pfr_spi_get_device_size(uint8_t device_id);

int pfr_spi_get_block_size(uint8_t device_id);

int get_hash(struct manifest *manifest, struct hash_engine *hash_engine, uint8_t *hash_out,
	     size_t hash_length);

int verify_signature(struct signature_verification *verification, const uint8_t *digest,
		     size_t length, const uint8_t *signature, size_t sig_length);

void pfr_cpld_update_reboot(void);

