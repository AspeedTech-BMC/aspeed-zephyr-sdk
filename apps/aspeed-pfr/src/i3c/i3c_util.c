/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/i3c/target/i3c_target_mqueue.h>
#include <zephyr/logging/log.h>
#include "i3c_util.h"
#include "gpio/gpio_aspeed.h"
#if defined(CONFIG_PFR_MCTP_I3C)
#include "mctp/mctp_i3c.h"
#endif

LOG_MODULE_REGISTER(util_i3c);
static const struct device *dev_i3c_tmq[I3C_MAX_NUM];
K_SEM_DEFINE(pltrst_sem, 0, 1);

struct k_thread cpu_i3c_setup_thread;
#define CPU_I3C_SETUP_STACK_SIZE 1024
K_THREAD_STACK_DEFINE(cpu_i3c_setup_stack, CPU_I3C_SETUP_STACK_SIZE);

struct i3c_target_mqueue_data {
	struct i3c_target_config target_config;
	const struct i3c_target_mqueue_config *config;
	struct mq_msg *msg_curr;
	struct mq_msg *msg_queue;
	int in;
	int out;
	int wr_index;
};

#if defined(CONFIG_PFR_MCTP_I3C)
void i3c_util_cpu_i3c_setup(void *a, void *b, void *c)
{
	while (1)
	{
		k_sem_take(&pltrst_sem, K_FOREVER);
		mctp_i3c_configure_cpu_i3c_devs();
	}
}
#endif

void util_init_I3C(void)
{
	const struct i3c_target_driver_api *api;
#ifdef DEV_I3C_TMQ_0
	dev_i3c_tmq[0] = device_get_binding("i3c-tmq@7eca0030000");
	api = dev_i3c_tmq[0]->api;
	api->driver_register(dev_i3c_tmq[0]);
#endif
#ifdef DEV_I3C_TMQ_1
	dev_i3c_tmq[1] = device_get_binding("i3c-tmq@7eca0031000");
	api = dev_i3c_tmq[1]->api;
	api->driver_register(dev_i3c_tmq[1]);
#endif
#ifdef DEV_I3C_TMQ_2
	dev_i3c_tmq[2] = device_get_binding("i3c-tmq@7eca0032000");
	api = dev_i3c_tmq[2]->api;
	api->driver_register(dev_i3c_tmq[2]);
#endif
#ifdef DEV_I3C_TMQ_3
	dev_i3c_tmq[3] = device_get_binding("i3c-tmq@7eca0033000");
	api = dev_i3c_tmq[3]->api;
	api->driver_register(dev_i3c_tmq[3]);
#endif
#if defined(CONFIG_PFR_MCTP_I3C)
	k_tid_t swmbx_tid = k_thread_create(
		&cpu_i3c_setup_thread,
		cpu_i3c_setup_stack,
		CPU_I3C_SETUP_STACK_SIZE,
		i3c_util_cpu_i3c_setup,
		NULL, NULL, NULL,
		5, 0, K_NO_WAIT);
	k_thread_name_set(swmbx_tid, "CPU I3C Configuration Handler");
#endif

}

int i3c_get_assigned_addr(uint8_t bus, uint8_t *address)
{
	const struct i3c_target_mqueue_data *tmq_data;
	if (!dev_i3c_tmq[bus])
		return -ENODEV;


	tmq_data = dev_i3c_tmq[bus]->data;
	*address = tmq_data->target_config.address;

	return 0;
}

int i3c_tmq_read(I3C_MSG *msg)
{
	if (!dev_i3c_tmq[msg->bus])
		return -ENODEV;

	msg->rx_len =
		i3c_target_mqueue_read(dev_i3c_tmq[msg->bus], &msg->data[0], I3C_MAX_DATA_SIZE);
	if (msg->rx_len == 0) {
		return -ENODATA;
	}

	return msg->rx_len;
}

int i3c_tmq_write(I3C_MSG *msg)
{
	int ret;
	if (!dev_i3c_tmq[msg->bus])
		return -ENODEV;

	ret = i3c_target_mqueue_write(dev_i3c_tmq[msg->bus], &msg->data[0], msg->tx_len);
	return ret;
}

