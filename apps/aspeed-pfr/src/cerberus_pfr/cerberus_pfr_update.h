/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include "cerberus_pfr_definitions.h"
#include "firmware/firmware_image.h"
#include "pfr/pfr_common.h"

int cerberus_pfr_update_verify(struct firmware_image *fw, struct hash_engine *hash, struct rsa_engine *rsa);

int firmware_image_verify(const struct firmware_image *fw, struct hash_engine *hash);
int update_firmware_image(uint32_t image_type, void *AoData, void *EventContext, CPLD_STATUS *cpld_update_status, struct event_context *evt_ctx);

