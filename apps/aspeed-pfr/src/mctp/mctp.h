/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include "mctp/mctp_interface_wrapper.h"
#include "cmd_interface/cmd_channel.h"

#define MCTP_SUCCESS 0
#define MCTP_ERROR 1

#define MCTP_TX_QUEUE_SIZE 16
#define MCTP_RX_TASK_STACK_SIZE 2048
#define MCTP_TX_TASK_STACK_SIZE 2048
#define MCTP_TASK_NAME_LEN 32

#define MCTP_I3C_STATE_HANDLER_STACK_SIZE    4096

typedef enum {
	MCTP_MEDIUM_TYPE_UNKNOWN = 0,
	MCTP_MEDIUM_TYPE_SMBUS,
	MCTP_MEDIUM_TYPE_I3C,
	MCTP_MEDIUM_TYPE_I3C_TARGET,
	MCTP_MEDIUM_TYPE_MAX
} MCTP_MEDIUM_TYPE;

/* smbus extra medium data of endpoint */
typedef struct _mctp_smbus_ext_params {
	uint8_t addr; /* 7 bit address */
} mctp_smbus_ext_params;

/* mctp extra parameters prototype */
typedef struct _mctp_ext_params {
	/* medium parameters */
	MCTP_MEDIUM_TYPE type;
	union {
		mctp_smbus_ext_params smbus_ext_params;
	};
} mctp_ext_params;

/* medium write/read function prototype */
typedef uint16_t (*medium_tx)(void *mctp_p, void *msg_p);
typedef uint16_t (*medium_rx)(void *mctp_p, void *msg_p);

/* i3c config for mctp medium_conf */
typedef struct _mctp_i3c_conf {
	uint8_t bus;
	uint8_t addr;
	uint8_t dummy;
} mctp_i3c_conf;

/* smbus config for mctp medium_conf */
typedef struct _mctp_smbus_conf {
	uint8_t bus;
	uint8_t rot_addr;
	uint8_t mbx_port;
} mctp_smbus_conf;

/* mctp medium conf */
typedef union {
	mctp_smbus_conf smbus_conf;
	mctp_i3c_conf i3c_conf;
} mctp_medium_conf;

/* mctp tx message struct */
typedef struct _mctp_tx_msg {
	uint8_t *buf;
	size_t len;
	mctp_ext_params ext_params;
} mctp_tx_msg;

/* mctp main struct */
typedef struct _mctp {
	uint8_t is_servcie_start;
	MCTP_MEDIUM_TYPE medium_type;

	/* medium related */
	mctp_medium_conf medium_conf;
	medium_rx read_data;
	medium_tx write_data;

	/* read/write task */
	k_tid_t mctp_rx_task_tid;
	k_tid_t mctp_tx_task_tid;
	struct k_thread rx_task_thread_data;
	struct k_thread tx_task_thread_data;

	K_KERNEL_STACK_MEMBER(rx_task_stack_area, MCTP_RX_TASK_STACK_SIZE);
	K_KERNEL_STACK_MEMBER(tx_task_stack_area, MCTP_TX_TASK_STACK_SIZE);
	uint8_t mctp_rx_task_name[MCTP_TASK_NAME_LEN];
	uint8_t mctp_tx_task_name[MCTP_TASK_NAME_LEN];

	/* queue */
	struct k_msgq mctp_tx_queue;

	/* interface */
	struct mctp_interface_wrapper mctp_wrapper;

	/* command channel */
	struct cmd_channel mctp_cmd_channel;

	/* semaphore */
	struct k_sem rx_fifo_in_data_sem;

	/* sw mailbox device */
	const struct device *sw_mbx_dev;
} mctp;

/* public function */
void init_pfr_mctp(void);

mctp *mctp_init(void);
uint8_t mctp_deinit(mctp *mctp_inst);
uint8_t mctp_set_medium_configure(mctp *mctp_inst, MCTP_MEDIUM_TYPE medium_type,
				  mctp_medium_conf medium_conf);

/* medium_conf should be freed by application */
uint8_t mctp_get_medium_configure(mctp *mctp_inst, MCTP_MEDIUM_TYPE *medium_type,
				  mctp_medium_conf *medium_conf);
/* mctp service start */
uint8_t mctp_start(mctp *mctp_inst);

/* mctp service stop */
uint8_t mctp_stop(mctp *mctp_inst);

/* send/receive message to destination endpoint */
uint8_t mctp_send_msg(mctp *mctp_inst, struct cmd_packet *packet);
uint8_t mctp_recv_msg(mctp *mctp_inst, struct cmd_packet *packet);

/* medium init/deinit */
uint8_t mctp_smbus_init(mctp *mctp_inst, mctp_medium_conf medium_conf);
uint8_t mctp_smbus_deinit(mctp *mctp_inst);

