/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once
#include "mctp/mctp_interface.h"
#include "mctp/mctp.h"
#include "mctp/plat_mctp.h"

struct spdm_mctp_connection_data {
	mctp *mctp_inst;
	uint8_t dst_addr;
	uint8_t dst_eid;
	uint8_t request_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
};

int spdm_mctp_send_recv(void *ctx, void *request_buf, void *response_buf);
int spdm_mctp_recv(void *ctx, void *buffer, size_t *buffer_size);
bool spdm_mctp_init_req(void *ctx, SPDM_MEDIUM medium, uint8_t bus, uint8_t dst_sa, uint8_t dst_eid);
void spdm_mctp_release_req(void *ctx);
