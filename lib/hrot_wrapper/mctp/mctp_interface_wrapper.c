/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_PFR_MCTP)
#include <zephyr.h>
#include <logging/log.h>
#include "cmd_interface/device_manager.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/cmd_interface_system.h"
#include "mctp/mctp_base_protocol.h"
#include "mctp/cmd_interface_mctp_control.h"
#include "mctp_interface_wrapper.h"

extern int device_manager_update_not_attestable_device_entry (struct device_manager *mgr, int device_num,
	uint8_t eid, uint8_t smbus_addr, uint8_t pcd_component_index);
#define NOT_USED 0 // currently, pcd_component_index doesn't have any functionality in code, to set it to zero

LOG_MODULE_REGISTER(mctp_interface_wrapper, CONFIG_LOG_DEFAULT_LEVEL);

/**
 * Helper function to setup the MCTP interface
 *
 * @param mctp The instances to initialize.
 *
 */
int mctp_interface_wrapper_init(struct mctp_interface_wrapper *mctp_wrapper, uint8_t rot_addr)
{
	if (mctp_wrapper == NULL)
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;

	int status;

	status = device_manager_init(&mctp_wrapper->device_mgr, 2, 0, DEVICE_MANAGER_PA_ROT_MODE,
			DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE, 1000, 0, 0, 0, 0, 0, 0);

	if (status != 0) {
		LOG_ERR("device manager init failed");
		return status;
	}

	status = device_manager_update_not_attestable_device_entry(&mctp_wrapper->device_mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, rot_addr, NOT_USED);
	if (status != 0) {
		LOG_ERR("update self device failed");
		return status;
	}

	status = device_manager_update_not_attestable_device_entry(&mctp_wrapper->device_mgr,
			DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM, MCTP_BASE_PROTOCOL_BMC_EID, 0x10, NOT_USED);
	if (status != 0) {
		LOG_ERR("update bridge device failed");
		return status;
	}

	status = cmd_interface_mctp_control_init(&mctp_wrapper->cmd_mctp_control, &mctp_wrapper->device_mgr,
			0x1414, 0x04);
	if (status != 0) {
		LOG_ERR("mctp control command interface init failed");
		goto error_device_mgr;
	}

	// TODO: if wants to fully support cerberus system commands,
	// it should be changed to init cerberus protocol command cmd_interface_system_init.
	// However, its code size is very large. Only support mctp control commands.
	// mctp->cmd_cerberus.process_request = cmd_interface_system_process_request;
	// mctp->cmd_cerberus.process_response = cmd_interface_system_process_response;
	mctp_wrapper->cmd_cerberus.process_request = cmd_interface_system_process_request;
	mctp_wrapper->cmd_cerberus.generate_error_packet = cmd_interface_generate_error_packet;

	status = mctp_interface_init(&mctp_wrapper->mctp_interface, &mctp_wrapper->cmd_cerberus,
			&mctp_wrapper->cmd_mctp_control.base, NULL, &mctp_wrapper->device_mgr);
	if (status != 0) {
		LOG_ERR("mctp interface init failed");
		goto error_cmd_interface;
	}

	return 0;

error_cmd_interface:
	cmd_interface_mctp_control_deinit(&mctp_wrapper->cmd_mctp_control);
error_device_mgr:
	device_manager_release(&mctp_wrapper->device_mgr);

	return status;
}

int mctp_i3c_wrapper_init(struct mctp_interface_wrapper *mctp_wrapper, uint8_t rot_addr)
{
	if (mctp_wrapper == NULL)
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;

	int status;
	struct device_manager *device_mgr = &mctp_wrapper->device_mgr;

	status = device_manager_init(device_mgr, 2, 0, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_I3C_SLAVE_BUS_ROLE, 1000, 0, 0, 0, 0, 0, 0);
	if (status != 0) {
		LOG_ERR("device manager init failed");
		return status;
	}

	status = device_manager_update_not_attestable_device_entry(device_mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM, MCTP_BASE_PROTOCOL_NULL_EID, 0, NOT_USED);
	if (status != 0) {
		LOG_ERR("update self device failed");
		return status;
	}

	// Send discovery notify after BMC bootup
	status = device_manager_update_device_state(device_mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM, DEVICE_MANAGER_SEND_DISCOVERY_NOTIFY);
	if (status != 0) {
		LOG_ERR("update self device state failed");
		return status;
	}

	status = device_manager_update_not_attestable_device_entry(device_mgr,
			DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM, MCTP_BASE_PROTOCOL_NULL_EID, 0, NOT_USED);
	if (status != 0) {
		LOG_ERR("update self device failed");
		return status;
	}

	status = cmd_interface_mctp_control_init(&mctp_wrapper->cmd_mctp_control,
			device_mgr, 0x8086, 0x01);
	if (status != 0) {
		LOG_ERR("mctp control command interface init failed");
		goto error_device_mgr;
	}

	mctp_wrapper->cmd_cerberus.process_request = cmd_interface_system_process_request;
	mctp_wrapper->cmd_cerberus.process_response = cmd_interface_system_process_response;
	mctp_wrapper->cmd_cerberus.generate_error_packet = cmd_interface_generate_error_packet;

	status = mctp_interface_init(&mctp_wrapper->mctp_interface, &mctp_wrapper->cmd_cerberus,
			&mctp_wrapper->cmd_mctp_control.base, NULL, device_mgr);
	if (status != 0) {
		LOG_ERR("mctp interface init failed");
		goto error_cmd_interface;
	}

	return 0;

error_cmd_interface:
	cmd_interface_mctp_control_deinit(&mctp_wrapper->cmd_mctp_control);
error_device_mgr:
	device_manager_release(device_mgr);

	return status;
}

void mctp_interface_wrapper_deinit(struct mctp_interface_wrapper *mctp_wrapper)
{
	device_manager_release(&mctp_wrapper->device_mgr);
	cmd_interface_mctp_control_deinit(&mctp_wrapper->cmd_mctp_control);
	mctp_interface_deinit(&mctp_wrapper->mctp_interface);
}

#endif // CONFIG_PFR_MCTP
