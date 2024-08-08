/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include "i3c/i3c_util.h"
#include "mctp.h"
#include "mctp_i3c.h"
#include "cmd_channel_mctp.h"
#include "gpio/gpio_aspeed.h"
#include "Smbus_mailbox/Smbus_mailbox.h"

LOG_MODULE_REGISTER(mctp_i3c_target);

extern const struct device dev_i3c_tmq[I3C_MAX_NUM];

#define I3C_BUS_CPU          0x00
#define I3C_BUS_BMC          0x02

typedef struct _mctp_i3c_dev {
	mctp_i3c mctp_i3c_inst;
	mctp_i3c_conf i3c_conf;
} mctp_i3c_dev;

mctp_i3c_dev i3c_devs[] = {
	{
		// For BMC to brige CPU's mctp msg to PFR
		.i3c_conf.bus = I3C_BUS_CPU,
		.i3c_conf.addr = 0, // will be assigned by BMC
	},
	{
		// For BMC to send mctp msg to PFR
		.i3c_conf.bus = I3C_BUS_BMC,
		.i3c_conf.addr = 0, // will be assigned by BMC
	},
};

static uint16_t mctp_i3c_tmq_read(void *mctp_p, void *msg_p)
{
	// Add sleep here for preventing cpu stuck in while loop.
	// i3c target only supports polling mode.
	k_msleep(1);

	struct cmd_packet *packet = (struct cmd_packet *)msg_p;
	uint8_t max_idx = ARRAY_SIZE(packet->data);
	int ret = 0;
	I3C_MSG i3c_msg;
	mctp *mctp_inst = (mctp *)mctp_p;

	if (mctp_p == NULL || msg_p == NULL)
		return MCTP_ERROR;

	i3c_msg.bus = mctp_inst->medium_conf.i3c_conf.bus;
	ret = i3c_tmq_read(&i3c_msg);

	/** mctp rx keep polling, return length 0 directly if no data or invalid data **/
	if (ret <= 0) {
		memset(packet, 0, sizeof(struct cmd_packet));
		return 0;
	}

	packet->dest_addr = mctp_inst->medium_conf.i3c_conf.addr;
	packet->pkt_size = ret;
	packet->timeout_valid = 0;
	packet->pkt_timeout = 0;
	packet->state = CMD_VALID_PACKET;

	i3c_msg.rx_len = ret;
	if (ret > max_idx) {
		packet->state = CMD_OVERFLOW_PACKET;
		return MCTP_ERROR;
	}

	LOG_HEXDUMP_INF(&i3c_msg.data[0], i3c_msg.rx_len, "mctp_i3c_read_smq msg dump");

	memcpy(packet->data, &i3c_msg.data[0], i3c_msg.rx_len);
	return MCTP_SUCCESS;
}

static uint16_t mctp_i3c_tmq_write(void *mctp_p, void *msg_p)
{
	int ret;
	mctp *mctp_instance = (mctp *)mctp_p;
	mctp_tx_msg *tx_msg = (mctp_tx_msg *)msg_p;
	uint32_t len = tx_msg->len;
	I3C_MSG i3c_msg;

	if (mctp_p == NULL || msg_p == NULL)
		return MCTP_ERROR;

	if (!tx_msg->buf)
		return MCTP_ERROR;

	if (!tx_msg->len)
		return MCTP_ERROR;

	i3c_msg.bus = mctp_instance->medium_conf.i3c_conf.bus;
	/** mctp package **/
	memcpy(&i3c_msg.data[0], tx_msg->buf, len);
	i3c_msg.tx_len = len;

	LOG_HEXDUMP_INF(&i3c_msg.data[0], i3c_msg.tx_len, "mctp_i3c_write_tmq msg dump");

	ret = i3c_tmq_write(&i3c_msg);
	if (ret) {
		LOG_ERR("mctp_i3c_write_tmq write failed, ret = %d", ret);
		return MCTP_ERROR;
	}

	return MCTP_SUCCESS;
}

uint8_t mctp_i3c_target_init(mctp *mctp_instance, mctp_medium_conf medium_conf)
{
	if (mctp_instance == NULL)
		return MCTP_ERROR;

	mctp_instance->medium_conf = medium_conf;
	mctp_instance->read_data = mctp_i3c_tmq_read;
	mctp_instance->write_data = mctp_i3c_tmq_write;

	if (mctp_instance->is_servcie_start)
		return MCTP_SUCCESS;

	return MCTP_SUCCESS;
}

uint8_t mctp_i3c_target_mctp_stop(void)
{
	int i;
	mctp_i3c_dev *i3c_dev_p;
	mctp_i3c *mctp_i3c_inst;
	mctp *mctp_inst;
	struct mctp_interface_wrapper *mctp_wrapper;
	struct device_manager *device_mgr;

	for (i = 0; i < ARRAY_SIZE(i3c_devs); i++) {
		i3c_dev_p = &i3c_devs[i];
		mctp_i3c_inst = &i3c_dev_p->mctp_i3c_inst;
		if (mctp_i3c_inst->state != MCTP_I3C_TARGET_ATTACHED)
			return 0;

		mctp_i3c_inst->state = MCTP_I3C_TARGET_INITIALIZED_DETACHED;
		k_timer_stop(&mctp_i3c_inst->i3c_state_timer);

		mctp_inst = mctp_i3c_inst->mctp_inst;
		mctp_wrapper = &mctp_inst->mctp_wrapper;
		device_mgr = mctp_wrapper->mctp_interface.device_manager;
		device_manager_update_device_state(device_mgr,
				DEVICE_MANAGER_SELF_DEVICE_NUM, DEVICE_MANAGER_SEND_DISCOVERY_NOTIFY);
	}
	return 0;
}

void mctp_i3c_target_intf_init(void)
{
	int i;
	int rc;
	mctp_i3c_dev *i3c_dev_p;
	mctp_i3c *mctp_i3c_instance;
	mctp *mctp_instance;

	int mctp_channel_id;

	LOG_INF("mctp_i3c_target_intf_init");

	for (i = 0; i < ARRAY_SIZE(i3c_devs); i++) {
		i3c_dev_p = &i3c_devs[i];
		mctp_i3c_instance = &i3c_dev_p->mctp_i3c_inst;
		if (mctp_i3c_instance->mctp_inst != NULL)
			if (!mctp_i3c_instance->mctp_inst->is_servcie_start)
				free(mctp_i3c_instance->mctp_inst);

		if (mctp_i3c_instance->mctp_inst == NULL) {
			mctp_i3c_instance->mctp_inst = mctp_init();
			mctp_i3c_instance->state = MCTP_I3C_TARGET_DETACHED;
		}

		mctp_instance = mctp_i3c_instance->mctp_inst;
		if (!mctp_instance) {
			LOG_ERR("Failed to allocate mctp instance for i3c");
			return;
		}
		mctp_set_medium_configure(mctp_instance, MCTP_MEDIUM_TYPE_I3C_TARGET,
				mctp_instance->medium_conf);

		if (i3c_get_assigned_addr(i3c_dev_p->i3c_conf.bus, &i3c_dev_p->i3c_conf.addr)) {
			LOG_ERR("Failed to get assigned i3c device address");
			goto error;
		}
		mctp_instance->medium_conf.i3c_conf.bus = i3c_dev_p->i3c_conf.bus;
		mctp_instance->medium_conf.i3c_conf.addr = i3c_dev_p->i3c_conf.addr;
		mctp_channel_id = CMD_CHANNEL_I3C_BASE | CMD_CHANNEL_I3C_TARGET |
			mctp_instance->medium_conf.i3c_conf.bus;
		rc = cmd_channel_mctp_init(&mctp_instance->mctp_cmd_channel,
				mctp_channel_id);
		if (rc != MCTP_SUCCESS) {
			LOG_ERR("i3c mctp cmd channel init failed");
			goto error;
		}

		rc = mctp_i3c_wrapper_init(&mctp_instance->mctp_wrapper,
				mctp_instance->medium_conf.i3c_conf.addr);
		if (rc != MCTP_SUCCESS) {
			LOG_ERR("i3c mctp interface wrapper init failed!!");
			goto error;
		}

		mctp_interface_set_channel_id(&mctp_instance->mctp_wrapper.mctp_interface,
				mctp_channel_id);

		mctp_start(mctp_instance);
		if (mctp_i3c_instance->state == MCTP_I3C_TARGET_INITIALIZED_DETACHED) {
			if (mctp_i3c_instance->i3c_state_sem.count <= 0)
				k_sem_give(&mctp_i3c_instance->i3c_state_sem);
		} else {
			k_sem_init(&mctp_i3c_instance->i3c_state_sem, 1, 1);
			k_timer_init(&mctp_i3c_instance->i3c_state_timer, mctp_i3c_state_expiry_fn,
					NULL);
			k_timer_user_data_set(&mctp_i3c_instance->i3c_state_timer,
					&mctp_i3c_instance->i3c_state_sem);
			mctp_i3c_eid_assignment_thread_create(&i3c_dev_p->mctp_i3c_inst);
		}

		mctp_i3c_instance->state = MCTP_I3C_TARGET_ATTACHED;
		LOG_INF("MCTP over I3C for bus %02x start", i3c_dev_p->i3c_conf.bus);
	}

	return;
error:
	for (i = 0; i < ARRAY_SIZE(i3c_devs); i++) {
		i3c_dev_p = &i3c_devs[i];
		mctp_i3c_instance = &i3c_dev_p->mctp_i3c_inst;
		if (mctp_i3c_instance->mctp_inst != NULL)
				free(mctp_i3c_instance->mctp_inst);
	}
}
