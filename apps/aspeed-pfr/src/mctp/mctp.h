/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <stdio.h>
#include "cmd_interface/device_manager.h"

void set_prev_mctp_i3c_state(int state);
int mctp_i3c_detach_slave_dev(uint8_t bus, uint64_t pid);
int mctp_i3c_attach_target_dev(uint8_t bus, uint64_t pid);
void mctp_i3c_stop_discovery_notify(struct device_manager *mgr);

void init_pfr_mctp(void);

