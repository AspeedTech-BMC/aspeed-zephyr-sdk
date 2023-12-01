/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <stdlib.h>

#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMMctpBinding.h"

LOG_MODULE_REGISTER(spdm_mctp, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_mctp_send_recv(void *ctx, void *request_buf, void *response_buf)
{
	struct spdm_context *context = (struct spdm_context*)ctx;
	struct spdm_mctp_connection_data *conn =
		(struct spdm_mctp_connection_data *)context->connection_data;
	struct spdm_message *req_msg = (struct spdm_message *)request_buf;
	struct spdm_message *rsp_msg = (struct spdm_message *)response_buf;
	int ret;

	memset(conn->request_buf, 0, sizeof(conn->request_buf));

	conn->request_buf[0] = 0x05;
	memcpy(conn->request_buf + 1, &req_msg->header, sizeof(req_msg->header));
	memcpy(conn->request_buf + 1 + sizeof(req_msg->header), req_msg->buffer.data, req_msg->buffer.write_ptr);

	LOG_HEXDUMP_DBG(conn->request_buf, 1 + sizeof(req_msg->header) + req_msg->buffer.write_ptr, "MCTP REQ:");

	ret = mctp_interface_issue_request(
			&conn->mctp_inst->mctp_wrapper.mctp_interface,
			&conn->mctp_inst->mctp_cmd_channel,
			conn->dst_addr, conn->dst_eid,
			conn->request_buf, 1 + sizeof(req_msg->header) + req_msg->buffer.write_ptr,
			conn->request_buf, sizeof(conn->request_buf),
			1000
			);
	if (ret == 0) {
		// SPDM Header
		memcpy(&rsp_msg->header, conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.data + 1,
				sizeof(rsp_msg->header));

		// SPDM Payload
		spdm_buffer_init(&rsp_msg->buffer,
				conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.length - 1 - 4);
		spdm_buffer_append_array(&rsp_msg->buffer,
				conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.data + 1 + 4,
				conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.length - 1 - 4);
		LOG_HEXDUMP_DBG(rsp_msg->buffer.data, rsp_msg->buffer.write_ptr, "MCTP BUF SEND_RECV:");
		LOG_HEXDUMP_DBG(conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.data,
				conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.length,
				"MCTP RAW SEND_RECV:");
	} else {
		LOG_ERR("mctp_interface_issue_request ret=%x", ret);
	}

	return ret;
}

int spdm_mctp_recv(void *ctx, void *buffer, size_t *buffer_size)
{
	*buffer_size = 0;
	return 0;
}

#if defined(CONFIG_PFR_MCTP_I3C)
extern mctp *mctp_i3c_bmc_inst;
#endif

bool spdm_mctp_init_req(void *ctx, SPDM_MEDIUM medium, uint8_t bus, uint8_t dst_sa, uint8_t dst_eid)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_mctp_connection_data *conn = malloc(sizeof(struct spdm_mctp_connection_data));
	mctp *mctp_inst = NULL;

	switch (medium) {
	case SPDM_MEDIUM_SMBUS:
		mctp_inst = find_mctp_by_smbus(bus);
		break;
#if defined(CONFIG_PFR_MCTP_I3C) && defined(CONFIG_I3C_ASPEED)
	case SPDM_MEDIUM_I3C:
		mctp_inst = mctp_i3c_bmc_inst;
		break;
#endif
	default:
		LOG_ERR("Unsupported Binding Spec 0x%02x", medium);
		return;
	}

	if (mctp_inst != NULL) {
		conn->mctp_inst = mctp_inst;
		conn->dst_addr = dst_sa;
		conn->dst_eid = dst_eid;

		context->connection_data = conn;
		context->send_recv = spdm_mctp_send_recv;
	}

	return mctp_inst != NULL;
}

void spdm_mctp_release_req(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_mctp_connection_data *conn = context->connection_data;
	free(conn);
}
