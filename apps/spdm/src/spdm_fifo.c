/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>

K_FIFO_DEFINE(REQ_TO_RSP);
K_FIFO_DEFINE(RSP_TO_REQ);
