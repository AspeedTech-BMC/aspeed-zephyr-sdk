/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>

#pragma once
extern struct k_fifo REQ_TO_RSP;
extern struct k_fifo RSP_TO_REQ;

struct spdm_fifo_item_t {
	void *fifo_reserved;
	uint8_t *message;
	size_t message_size;
};
