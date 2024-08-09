/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>
#include "cmd_interface/cmd_channel.h"
#include "cmd_channel_mctp.h"
#include "mctp.h"

LOG_MODULE_REGISTER(cmd_channel_mctp, CONFIG_LOG_DEFAULT_LEVEL);

/**
 * Receive a command packet from a communication channel.  This call will block until a packet
 * has been received or the timeout has expired.
 *
 * @param channel The channel to receive a packet from.
 * @param packet Output for the packet data being received.
 * @param ms_timeout The amount of time to wait for a received packet, in milliseconds.  A
 * negative value will wait forever, and a value of 0 will return immediately.
 *
 * @return 0 if a packet was successfully received or an error code.
 */
int cmd_channel_mctp_receive_packet(struct cmd_channel *channel, struct cmd_packet *packet, int ms_timeout)
{
	if (channel == NULL)
		return CMD_CHANNEL_INVALID_ARGUMENT;

	if (packet == NULL)
		return CMD_CHANNEL_INVALID_ARGUMENT;

	mctp *mctp_inst = CONTAINER_OF(channel, mctp, mctp_cmd_channel);
	int status;

	status = mctp_recv_msg(mctp_inst, packet);
	LOG_HEXDUMP_DBG(packet->data, packet->pkt_size, "rx packet:");
	LOG_DBG("pkt_size = %d", packet->pkt_size);
	LOG_DBG("dest_addr = %x", packet->dest_addr);
	LOG_DBG("state = %d", packet->state);
	LOG_DBG("pkt_timeout = %lld", packet->pkt_timeout);
	LOG_DBG("timeout_valid = %d", packet->timeout_valid);

	if (packet->state == CMD_OVERFLOW_PACKET)
		return CMD_CHANNEL_PKT_OVERFLOW;
	if (packet->state != CMD_VALID_PACKET)
		return CMD_CHANNEL_INVALID_PKT_STATE;

	if (status != MCTP_SUCCESS)
		return CMD_CHANNEL_RX_FAILED;

	return 0;
}

/**
 * Send a command packet over a communication channel.
 *
 * Returning from this function does not guarantee the packet has been fully transmitted.
 * Depending on the channel implementation, it is possible the packet is still in flight with
 * the data buffered in the channel driver.
 *
 * @param channel The channel to send a packet on.
 * @param packet The packet to send.
 *
 * @return 0 if the packet was successfully sent or an error code.
 */
int cmd_channel_mctp_send_packet(struct cmd_channel *channel, struct cmd_packet *packet)
{
	if (channel == NULL)
		return CMD_CHANNEL_INVALID_ARGUMENT;

	if (packet == NULL)
		return CMD_CHANNEL_INVALID_ARGUMENT;

	LOG_HEXDUMP_DBG(packet->data, packet->pkt_size, "tx packet:");
	LOG_DBG("pkt_size = %d", packet->pkt_size);
	LOG_DBG("dest_addr = %x", packet->dest_addr);
	LOG_DBG("state = %d", packet->state);
	LOG_DBG("pkt_timeout = %lld", packet->pkt_timeout);
	LOG_DBG("timeout_valid = %d", packet->timeout_valid);

	if (packet->state != CMD_VALID_PACKET)
		return CMD_CHANNEL_INVALID_PKT_STATE;

	mctp *mctp_inst = CONTAINER_OF(channel, mctp, mctp_cmd_channel);

	if (mctp_send_msg(mctp_inst, packet) != MCTP_SUCCESS)
		return CMD_CHANNEL_TX_FAILED;

	return 0;
}

/**
 * Initialize the base channel components.
 *
 * @param channel The channel to initialize.
 * @param id An ID to associate with this command channel.
 *
 * @return 0 if the channel was successfully initialized or an error code.
 */
int cmd_channel_mctp_init(struct cmd_channel *channel, int id)
{
	if (channel == NULL)
		return CMD_CHANNEL_INVALID_ARGUMENT;

	int status = cmd_channel_init(channel, id);

	if (status != 0) {
		LOG_ERR("cmd channel[%d]: init failed", id);
		return status;
	}

	channel->receive_packet = cmd_channel_mctp_receive_packet;
	channel->send_packet = cmd_channel_mctp_send_packet;

	return 0;
}

