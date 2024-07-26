/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/i3c.h>

#if DT_NODE_EXISTS(DT_NODELABEL(i3c0_tmq))
#define DEV_I3C_TMQ_0
#endif

#if DT_NODE_EXISTS(DT_NODELABEL(i3c1_tmq))
#define DEV_I3C_TMQ_1
#endif

#if DT_NODE_EXISTS(DT_NODELABEL(i3c2_tmq))
#define DEV_I3C_TMQ_2
#endif

#if DT_NODE_EXISTS(DT_NODELABEL(i3c3_tmq))
#define DEV_I3C_TMQ_3
#endif

#define I3C_MAX_NUM           4
#define I3C_MAX_DATA_SIZE     256

typedef struct _I3C_MSG_ {
	uint8_t bus;
	uint8_t tx_len;
	uint8_t rx_len;
	uint8_t data[I3C_MAX_DATA_SIZE];
} I3C_MSG;

void util_init_I3C(void);
int i3c_get_assigned_addr(uint8_t bus, uint8_t *address);
int i3c_tmq_read(I3C_MSG *msg);
int i3c_tmq_write(I3C_MSG *msg);

