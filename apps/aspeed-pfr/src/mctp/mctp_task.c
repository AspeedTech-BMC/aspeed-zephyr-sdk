/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <stdlib.h>
#include "mctp_utils.h"

LOG_MODULE_DECLARE(mctp, CONFIG_LOG_DEFAULT_LEVEL);

/* set thread name */
static uint8_t set_thread_name(mctp *mctp_inst)
{
	int status;
	if (!mctp_inst)
		return MCTP_ERROR;

	if (mctp_inst->medium_type <= MCTP_MEDIUM_TYPE_UNKNOWN ||
	    mctp_inst->medium_type >= MCTP_MEDIUM_TYPE_MAX)
		return MCTP_ERROR;

	uint8_t ret = MCTP_ERROR;

	switch (mctp_inst->medium_type) {
	case MCTP_MEDIUM_TYPE_SMBUS:
		LOG_INF("medium_type: smbus");
		mctp_smbus_conf *smbus_conf = (mctp_smbus_conf *)&mctp_inst->medium_conf;

		status = snprintf(mctp_inst->mctp_rx_task_name, sizeof(mctp_inst->mctp_rx_task_name),
			 "mctprx_%02x_%02x_%02x", mctp_inst->medium_type, smbus_conf->bus, smbus_conf->rot_addr);
		if (status < 0) {
			LOG_WRN("Failed to set smbus mctprx thread name for %02x:%02x:%02x",
					mctp_inst->medium_type, smbus_conf->bus, smbus_conf->rot_addr);
		}
		status = snprintf(mctp_inst->mctp_tx_task_name, sizeof(mctp_inst->mctp_tx_task_name),
			 "mctptx_%02x_%02x", mctp_inst->medium_type, smbus_conf->bus);
		if (status < 0) {
			LOG_WRN("Failed to set smbus mctptx thread name for %02x:%02x",
					mctp_inst->medium_type, smbus_conf->bus);
		}
		ret = MCTP_SUCCESS;
		break;
#if defined(CONFIG_PFR_MCTP_I3C) && defined(CONFIG_I3C_ASPEED)
	case MCTP_MEDIUM_TYPE_I3C:
		LOG_INF("medium_type: i3c");
		mctp_i3c_conf *i3c_conf = (mctp_i3c_conf *)&mctp_inst->medium_conf;

		status = snprintf(mctp_inst->mctp_rx_task_name, sizeof(mctp_inst->mctp_rx_task_name),
				"mctprx_%02x_%02x_%02x", mctp_inst->medium_type, i3c_conf->bus,
				i3c_conf->addr);
		if (status < 0) {
			LOG_WRN("Failed to set i3c mctprx thread name for %02x:%02x:%02x",
					mctp_inst->medium_type, i3c_conf->bus, i3c_conf->addr);
		}
		status = snprintf(mctp_inst->mctp_tx_task_name, sizeof(mctp_inst->mctp_tx_task_name),
				"mctptx_%02x_%02x_%02x", mctp_inst->medium_type, i3c_conf->bus,
				i3c_conf->addr);
		if (status < 0) {
			LOG_WRN("Failed to set i3c mctptx thread name for %02x:%02x:%02x",
					mctp_inst->medium_type, i3c_conf->bus, i3c_conf->addr);
		}
		ret = MCTP_SUCCESS;
		break;
#endif
	default:
		break;
	}

	return ret;
}

/* init the medium related resources */
static uint8_t mctp_medium_init(mctp *mctp_inst, mctp_medium_conf medium_conf)
{
	if (!mctp_inst)
		return MCTP_ERROR;

	uint8_t ret = MCTP_ERROR;

	switch (mctp_inst->medium_type) {
	case MCTP_MEDIUM_TYPE_SMBUS:
		ret = mctp_smbus_init(mctp_inst, medium_conf);
		break;
#if defined(CONFIG_PFR_MCTP_I3C) && defined(CONFIG_I3C_ASPEED)
	case MCTP_MEDIUM_TYPE_I3C:
		ret = mctp_i3c_init(mctp_inst, medium_conf);
		break;
#endif
	default:
		break;
	}

	return ret;
}

static uint8_t mctp_medium_deinit(mctp *mctp_inst)
{
	if (!mctp_inst)
		return MCTP_ERROR;

	switch (mctp_inst->medium_type) {
	case MCTP_MEDIUM_TYPE_SMBUS:
		mctp_smbus_deinit(mctp_inst);
		break;
#if defined(CONFIG_PFR_MCTP_I3C) && defined(CONFIG_I3C_ASPEED)
	case MCTP_MEDIUM_TYPE_I3C:
		mctp_i3c_deinit(mctp_inst);
		break;
#endif
	default:
		break;
	}

	return MCTP_SUCCESS;
}

/* mctp rx task */
static void mctp_rx_task(void *arg, void *dummy0, void *dummy1)
{
	ARG_UNUSED(dummy0);
	ARG_UNUSED(dummy1);

	if (!arg) {
		LOG_WRN("%s without mctp_inst!", __func__);
		return;
	}

	mctp *mctp_inst = (mctp *)arg;

	if (!mctp_inst->read_data) {
		LOG_WRN("%s without medium read function!", __func__);
		return;
	}

	if (!mctp_inst->mctp_cmd_channel.receive_packet) {
		LOG_WRN("%s without channel receive function!", __func__);
		return;
	}

	LOG_INF("%s start %p", __func__, mctp_inst);

	while (1)
		cmd_channel_receive_and_process(&mctp_inst->mctp_cmd_channel, &mctp_inst->mctp_wrapper.mctp_interface, -1);
}

/* mctp tx task */
static void mctp_tx_task(void *arg, void *dummy0, void *dummy1)
{
	ARG_UNUSED(dummy0);
	ARG_UNUSED(dummy1);

	if (!arg) {
		LOG_WRN("%s without mctp_inst!", __func__);
		return;
	}

	mctp *mctp_inst = (mctp *)arg;

	if (!mctp_inst->write_data) {
		LOG_WRN("%s without medium write function!", __func__);
		return;
	}

	LOG_INF("%s start %p ", __func__, mctp_inst);

	while (1) {
		mctp_tx_msg mctp_msg = { 0 };
		int ret = k_msgq_get(&mctp_inst->mctp_tx_queue, &mctp_msg, K_FOREVER);

		if (ret)
			continue;

		if (!mctp_msg.buf)
			continue;

		if (!mctp_msg.len) {
			free(mctp_msg.buf);
			continue;
		}

		LOG_HEXDUMP_DBG(mctp_msg.buf, mctp_msg.len, "mctp tx task receive data");

		mctp_inst->write_data(mctp_inst, &mctp_msg);
		free(mctp_msg.buf);
	}
}

/* mctp handle initial */
mctp *mctp_init(void)
{
	mctp *mctp_inst = (mctp *)malloc(sizeof(*mctp_inst));

	if (!mctp_inst)
		return NULL;

	memset(mctp_inst, 0, sizeof(*mctp_inst));
	mctp_inst->medium_type = MCTP_MEDIUM_TYPE_UNKNOWN;

	LOG_DBG("mctp_inst = %p", mctp_inst);
	return mctp_inst;
}

/* mctp handle deinitial */
uint8_t mctp_deinit(mctp *mctp_inst)
{
	if (!mctp_inst)
		return MCTP_ERROR;

	LOG_DBG("mctp_inst = %p", mctp_inst);

	mctp_stop(mctp_inst);
	if (mctp_medium_deinit(mctp_inst) == MCTP_ERROR)
		LOG_WRN("mctp deinit failed ");

	mctp_interface_wrapper_deinit(&mctp_inst->mctp_wrapper);

	free(mctp_inst);
	return MCTP_SUCCESS;
}

/* configure mctp handle with specific medium type */
uint8_t mctp_set_medium_configure(mctp *mctp_inst, MCTP_MEDIUM_TYPE medium_type,
				  mctp_medium_conf medium_conf)
{
	if (!mctp_inst)
		return MCTP_ERROR;

	if (medium_type <= MCTP_MEDIUM_TYPE_UNKNOWN || medium_type >= MCTP_MEDIUM_TYPE_MAX)
		return MCTP_ERROR;

	mctp_inst->medium_type = medium_type;
	if (mctp_medium_init(mctp_inst, medium_conf) == MCTP_ERROR)
		goto error;
	return MCTP_SUCCESS;

error:
	if (mctp_medium_deinit(mctp_inst) == MCTP_ERROR)
		LOG_WRN("mctp deinit failed ");
	mctp_inst->medium_type = MCTP_MEDIUM_TYPE_UNKNOWN;
	return MCTP_ERROR;
}

uint8_t mctp_get_medium_configure(mctp *mctp_inst, MCTP_MEDIUM_TYPE *medium_type,
				  mctp_medium_conf *medium_conf)
{
	if (!mctp_inst || !medium_type || !medium_conf)
		return MCTP_ERROR;

	*medium_type = mctp_inst->medium_type;
	*medium_conf = mctp_inst->medium_conf;
	return MCTP_SUCCESS;
}

uint8_t mctp_stop(mctp *mctp_inst)
{
	if (!mctp_inst)
		return MCTP_ERROR;

	if (mctp_inst->mctp_rx_task_tid) {
		k_thread_abort(mctp_inst->mctp_rx_task_tid);
		mctp_inst->mctp_rx_task_tid = NULL;
	}

	if (mctp_inst->mctp_tx_task_tid) {
		k_thread_abort(mctp_inst->mctp_tx_task_tid);
		mctp_inst->mctp_tx_task_tid = NULL;
	}

	if (mctp_inst->mctp_tx_queue.buffer_start) {
		free(mctp_inst->mctp_tx_queue.buffer_start);
		mctp_inst->mctp_tx_queue.buffer_start = NULL;
	}

	mctp_inst->is_servcie_start = 0;
	return MCTP_SUCCESS;
}

uint8_t mctp_start(mctp *mctp_inst)
{
	if (!mctp_inst)
		return MCTP_ERROR;

	if (mctp_inst->is_servcie_start) {
		LOG_INF("The mctp_inst is already start!");
		return MCTP_SUCCESS;
	}

	set_thread_name(mctp_inst);

	uint8_t *tx_msgq_buf = (uint8_t *)malloc(MCTP_TX_QUEUE_SIZE * sizeof(mctp_tx_msg));

	if (!tx_msgq_buf) {
		LOG_WRN("tx msgq alloc failed!!");
		goto error;
	}

	k_msgq_init(&mctp_inst->mctp_tx_queue, tx_msgq_buf, sizeof(mctp_tx_msg), MCTP_TX_QUEUE_SIZE);

	/* create rx service */
	mctp_inst->mctp_rx_task_tid =
		k_thread_create(&mctp_inst->rx_task_thread_data, mctp_inst->rx_task_stack_area,
				K_KERNEL_STACK_SIZEOF(mctp_inst->rx_task_stack_area), mctp_rx_task,
				mctp_inst, NULL, NULL, K_PRIO_PREEMPT(10), 0, K_MSEC(1));
	if (!mctp_inst->mctp_rx_task_tid)
		goto error;
	k_thread_name_set(mctp_inst->mctp_rx_task_tid, mctp_inst->mctp_rx_task_name);

	/* create tx service */
	mctp_inst->mctp_tx_task_tid =
		k_thread_create(&mctp_inst->tx_task_thread_data, mctp_inst->tx_task_stack_area,
				K_KERNEL_STACK_SIZEOF(mctp_inst->tx_task_stack_area), mctp_tx_task,
				mctp_inst, NULL, NULL, K_PRIO_PREEMPT(10), 0, K_MSEC(1));

	if (!mctp_inst->mctp_tx_task_tid)
		goto error;
	k_thread_name_set(mctp_inst->mctp_tx_task_tid, mctp_inst->mctp_tx_task_name);

	mctp_inst->is_servcie_start = 1;
	return MCTP_SUCCESS;

error:
	LOG_ERR("%s failed!!", __func__);
	mctp_stop(mctp_inst);
	return MCTP_ERROR;
}

uint8_t mctp_send_msg(mctp *mctp_inst, struct cmd_packet *packet)
{
	if (!mctp_inst || !packet)
		return MCTP_ERROR;

	if (!mctp_inst->is_servcie_start) {
		LOG_WRN("The mctp_inst isn't start service!");
		return MCTP_ERROR;
	}

	mctp_tx_msg mctp_msg = { 0 };

	mctp_msg.len = packet->pkt_size;
	mctp_msg.buf = (uint8_t *)malloc(packet->pkt_size);
	if (!mctp_msg.buf) {
		LOG_WRN("can't alloc buf!!");
		goto error;
	}

	memcpy(mctp_msg.buf, packet->data, packet->pkt_size);

	// TODO only support smbus
	mctp_msg.ext_params.type = mctp_inst->medium_type;
	mctp_msg.ext_params.smbus_ext_params.addr = packet->dest_addr;

	int ret = k_msgq_put(&mctp_inst->mctp_tx_queue, &mctp_msg, K_NO_WAIT);

	if (ret) {
		LOG_ERR("can't put msgq(%d)", ret);
		goto error;
	}

	return MCTP_SUCCESS;

error:
	if (mctp_msg.buf)
		free(mctp_msg.buf);

	return MCTP_ERROR;
}

uint8_t mctp_recv_msg(mctp *mctp_inst, struct cmd_packet *packet)
{
	if (!mctp_inst || !packet)
		return MCTP_ERROR;

	if (!mctp_inst->is_servcie_start) {
		LOG_WRN("The mctp_inst isn't start service!");
		return MCTP_ERROR;
	}

	return mctp_inst->read_data(mctp_inst, packet);
}

