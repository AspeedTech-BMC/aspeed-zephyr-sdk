/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <zephyr/kernel.h>
#include "sw_mailbox/sw_mailbox.h"

#define PAGE_SIZE 4096

enum {
	BMC_FLASH_ID = 0,
	BMC_FLASH_ID_2 = 1,
	PCH_FLASH_ID = 2,
	PCH_FLASH_ID_2 = 3,
	ROT_FLASH_ID = 4,
	ROT_FMC_CS1  = 5,
};

void configure_staging_source(union aspeed_event_data *data);
void set_fw_staging_source(union aspeed_event_data *data);
void set_fw_image_size(union aspeed_event_data *data);
void set_fw_image_checksum(union aspeed_event_data *data);
const struct device *get_flash_dev(uint8_t flash_id);
int rot_fw_update(void);

