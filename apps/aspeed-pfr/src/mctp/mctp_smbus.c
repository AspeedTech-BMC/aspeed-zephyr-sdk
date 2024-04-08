/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/i2c/pfr/swmbx.h>
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "cmd_interface/cmd_channel.h"
#include "i2c/hal_i2c.h"
#include "mctp_utils.h"

LOG_MODULE_DECLARE(mctp, CONFIG_LOG_DEFAULT_LEVEL);

static uint16_t mctp_smbus_read(void *mctp_p, void *msg_p)
{
	if (!mctp_p || !msg_p)
		return MCTP_ERROR;

	mctp *mctp_inst = (mctp *)mctp_p;
	int status;

	status = k_sem_take(&mctp_inst->rx_fifo_in_data_sem, K_FOREVER);
	if (status != 0)
		return MCTP_ERROR;

	struct cmd_packet *packet = (struct cmd_packet *)msg_p;
	uint8_t fifo_data;
	uint8_t max_idx = ARRAY_SIZE(packet->data);
	int data_idx = 1;

	// mctp smbus command code
	packet->data[0] = MCTPWriteFIFO;
	packet->dest_addr = mctp_inst->medium_conf.smbus_conf.rot_addr;
	packet->pkt_size = 1;
	packet->timeout_valid = 0;
	packet->pkt_timeout = 0;
	packet->state = CMD_VALID_PACKET;

	do {
		status = swmbx_read(mctp_inst->sw_mbx_dev, true, MCTPWriteFIFO, &fifo_data);
		if (status == 0) {
			packet->data[data_idx++] = fifo_data;
			packet->pkt_size++;
		}
	} while (!status && (data_idx < max_idx));

	if (data_idx > max_idx) {
		packet->state = CMD_OVERFLOW_PACKET;
		LOG_ERR("packet data overflow");
		return MCTP_ERROR;
	}

	return MCTP_SUCCESS;
}

static uint16_t mctp_smbus_write(void *mctp_p, void *msg_p)
{
	if (!mctp_p || !msg_p)
		return MCTP_ERROR;

	mctp *mctp_inst = (mctp *)mctp_p;
	mctp_tx_msg *tx_msg = (mctp_tx_msg *)msg_p;

	if (tx_msg->ext_params.type != MCTP_MEDIUM_TYPE_SMBUS)
		return MCTP_ERROR;

	if (!tx_msg->buf)
		return MCTP_ERROR;

	if (!tx_msg->len)
		return MCTP_ERROR;

	LOG_DBG("smbus dest_addr = %x", tx_msg->ext_params.smbus_ext_params.addr);
	LOG_HEXDUMP_DBG(tx_msg->buf, tx_msg->len, "receive data:");

	int status;
	I2C_MSG i2c_msg;

	i2c_msg.bus = mctp_inst->medium_conf.smbus_conf.bus;
	i2c_msg.target_addr = tx_msg->ext_params.smbus_ext_params.addr;
	i2c_msg.tx_len = tx_msg->len;
	memcpy(&i2c_msg.data[0], tx_msg->buf, tx_msg->len);
	status = i2c_master_write(&i2c_msg, 5);
	if (status)
		LOG_ERR("i2c_master_write failt, ret %d", status);

	return MCTP_SUCCESS;
}

uint8_t mctp_smbus_init(mctp *mctp_inst, mctp_medium_conf medium_conf)
{
	if (!mctp_inst)
		return MCTP_ERROR;

	mctp_inst->medium_conf = medium_conf;
	mctp_inst->read_data = mctp_smbus_read;
	mctp_inst->write_data = mctp_smbus_write;

	return MCTP_SUCCESS;
}

uint8_t mctp_smbus_deinit(mctp *mctp_inst)
{
	if (!mctp_inst)
		return MCTP_ERROR;

	mctp_inst->read_data = NULL;
	mctp_inst->write_data = NULL;
	memset(&mctp_inst->medium_conf, 0, sizeof(mctp_inst->medium_conf));

	return MCTP_SUCCESS;
}

