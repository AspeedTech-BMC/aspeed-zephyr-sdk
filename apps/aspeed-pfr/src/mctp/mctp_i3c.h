/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <zephyr/kernel.h>
#include <zephyr/drivers/i3c/ibi.h>
#include "mctp.h"
#include "cmd_interface/device_manager.h"

#define MCTP_I3C_MSG_RETRY_INTERVAL         12

enum {
	MCTP_I3C_TARGET_DETACHED,
	MCTP_I3C_TARGET_INITIALIZED_DETACHED,
	MCTP_I3C_TARGET_ATTACHED,
};

typedef struct _mctp_i3c {
	mctp *mctp_inst;
	uint8_t state;
	uint8_t i3c_state_task_name[MCTP_TASK_NAME_LEN];
	struct k_sem i3c_state_sem;
	struct k_timer i3c_state_timer;
	k_tid_t i3c_state_tid;
	struct k_thread i3c_state_thread;
	K_KERNEL_STACK_MEMBER(i3c_state_handler_stack, MCTP_I3C_STATE_HANDLER_STACK_SIZE);
} mctp_i3c;

uint8_t mctp_i3c_init(mctp *mctp_instance, mctp_medium_conf medium_conf);
uint8_t mctp_i3c_target_init(mctp *mctp_instance, mctp_medium_conf medium_conf);
uint8_t mctp_i3c_deinit(mctp *mctp_instance);

void set_prev_mctp_i3c_state(int state);
int mctp_i3c_detach_slave_dev(uint8_t bus, uint64_t pid);
int mctp_i3c_attach_target_dev(uint8_t bus, uint64_t pid);
void mctp_i3c_stop_discovery_notify(struct device_manager *mgr);
void mctp_i3c_hub_configuration(void);
const struct device *get_mctp_i3c_dev(uint8_t bus_num);
int mctp_i3c_ibi_cb(struct i3c_device_desc *target, struct i3c_ibi_payload *payload);

uint8_t mctp_i3c_eid_assignment_thread_create(mctp_i3c *mctp_i3c_inst);
void mctp_i3c_state_expiry_fn(struct k_timer *tmr);
void mctp_i3c_pre_attestation(struct device_manager *mgr, int *duration);
void mctp_i3c_attestation(struct device_manager *mgr, int *duration);
int mctp_i3c_send_discovery_notify(mctp *mctp_instance, int *duration);
int mctp_i3c_send_eid_announcement(mctp *mctp_instance, int *duration);

void mctp_i3c_send_rstdaa(uint8_t bus);
void mctp_i3c_send_entdaa(uint8_t bus);
void mctp_i3c_configure_cpu_i3c_devs(void);
#if defined(CONFIG_PFR_MCTP_I3C_5_0)
void mctp_i3c_target_intf_init(void);
uint8_t mctp_i3c_target_mctp_stop(void);
#endif
