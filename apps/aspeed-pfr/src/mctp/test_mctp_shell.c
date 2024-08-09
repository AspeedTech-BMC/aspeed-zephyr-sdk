/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <stdlib.h>
#include "mctp/mctp_interface.h"
#include "mctp.h"
#include "plat_mctp.h"
#include "cmd_interface/device_manager.h"
#include "logging/logging_wrapper.h"

// #define MCTP_TEST_DEBUG
static uint8_t request_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
static uint8_t message_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};

static int cmd_mctp_send_msg(const struct shell *shell, size_t argc, char **argv)
{
	struct mctp_interface *mctp_interface = NULL;
	mctp *mctp_inst = NULL;
	int req_len = argc - 4;
	int argc_req_idx = 4;
	uint8_t dst_addr;
	uint8_t dst_eid;
	uint8_t bus_num;
	int status;
	int i;

	bus_num = strtol(argv[1], NULL, 16);
	dst_addr = strtol(argv[2], NULL, 16);
	dst_eid = strtol(argv[3], NULL, 16);

	mctp_inst = find_mctp_by_smbus(bus_num);
	if (mctp_inst == NULL) {
		shell_error(shell, "mctp instance not fould");
		return 0;
	}

	mctp_interface = &mctp_inst->mctp_wrapper.mctp_interface;
	// request
	// request_buf[0] = message type
	// request_buf[1] = rq
	// request_buf[2] = command code
	memset(request_buf, 0, sizeof(request_buf));
	for (i = 0; i < req_len; i++)
		request_buf[i] = strtol(argv[argc_req_idx++], NULL, 16);

#ifdef MCTP_TEST_DEBUG
	shell_print(shell, "request:");
	shell_hexdump(shell, request_buf, req_len);
#endif
	status = mctp_interface_issue_request(mctp_interface, &mctp_inst->mctp_cmd_channel,
		dst_addr, dst_eid, request_buf, req_len, message_buf, sizeof(message_buf), 1000);

	if (status != 0)
		shell_print(shell, "mctp issue request failed(%x)", status);
	else {
		shell_print(shell, "response:");
		shell_hexdump(shell, mctp_interface->req_buffer.data, mctp_interface->req_buffer.length);
	}

	return 0;
}

#if defined(CONFIG_PFR_MCTP_I3C) && defined(CONFIG_I3C_ASPEED)
static int cmd_mctp_send_msg_i3c(const struct shell *shell, size_t argc, char **argv)
{
	extern mctp *mctp_i3c_bmc_inst;
	struct mctp_interface *mctp_interface = NULL;
	mctp *mctp_inst = NULL;
	int req_len = argc - 4;
	int argc_req_idx = 4;
	uint8_t dst_addr;
	uint8_t dst_eid;
	uint8_t bus_num;
	int status;
	int i;

	bus_num = strtol(argv[1], NULL, 16);
	dst_addr = strtol(argv[2], NULL, 16);
	dst_eid = strtol(argv[3], NULL, 16);

	mctp_inst = mctp_i3c_bmc_inst;
	if (mctp_inst == NULL) {
		shell_error(shell, "mctp instance not fould");
		return 0;
	}

	mctp_interface = &mctp_inst->mctp_wrapper.mctp_interface;
	// request
	// request_buf[0] = message type
	// request_buf[1] = rq
	// request_buf[2] = command code
	memset(request_buf, 0, sizeof(request_buf));
	for (i = 0; i < req_len; i++)
		request_buf[i] = strtol(argv[argc_req_idx++], NULL, 16);

#if 1 || MCTP_TEST_DEBUG
	shell_print(shell, "request:");
	shell_hexdump(shell, request_buf, req_len);
#endif
	status = mctp_interface_issue_request(mctp_interface, &mctp_inst->mctp_cmd_channel,
		dst_addr, dst_eid, request_buf, req_len, message_buf, sizeof(message_buf), 1000);

	if (status != 0)
		shell_print(shell, "mctp issue request failed(%x)", status);
	else {
		shell_print(shell, "response:");
		shell_hexdump(shell, mctp_interface->req_buffer.data, mctp_interface->req_buffer.length);
	}

	return 0;
}
#endif

static int cmd_mctp_echo_test(const struct shell *shell, size_t argc, char **argv)
{
	struct mctp_interface *mctp_interface = NULL;
	uint8_t resp_header[4] = { 0 };
	uint32_t payload_length;
	uint32_t test_time = 1;
	mctp *mctp_inst = NULL;
	int argc_req_idx = 3;
	uint32_t time_start;
	uint32_t time_end;
	uint32_t req_len;
	uint8_t dst_addr;
	uint8_t dst_eid;
	uint8_t bus_num;
	int status;
	int i;

	if (argc == 6) {
		test_time = strtol(argv[5], NULL, 10);
		if (test_time < 1) {
			shell_print(shell, "test_time(%d) is invalid", test_time);
			goto exit;
		}
	}

	bus_num = strtol(argv[1], NULL, 16);
	dst_addr = strtol(argv[2], NULL, 16);
	dst_eid = strtol(argv[3], NULL, 16);
	payload_length = strtol(argv[4], NULL, 10);

	// message type
	// rq
	// command code
	// completion code
	if ((payload_length + 4) > sizeof(request_buf)) {
		shell_print(shell, "payload count(%d) is too big", payload_length);
		goto exit;
	}

	mctp_inst = find_mctp_by_smbus(bus_num);
	if (mctp_inst == NULL) {
		shell_error(shell, "mctp instance not found");
		goto exit;
	}

	mctp_interface = &mctp_inst->mctp_wrapper.mctp_interface;
	// request
	// request_buf[0] = message type
	// request_buf[1] = rq
	// requaet_buf[2] = command code
	memset(request_buf, 0, sizeof(request_buf));
	request_buf[0] = 0x7c;
	request_buf[1] = 0x80;
	request_buf[2] = 0x01;

	for (i = 0; i < payload_length; i++)
		request_buf[argc_req_idx++] = i % 0x100;

	req_len = 3 + payload_length;

	// resp
	resp_header[0] = request_buf[0]; //message type
	resp_header[1] = request_buf[1] & 0x7f; // rq
	resp_header[2] = request_buf[2]; // command code
	resp_header[3] = 0; // completion code

	for (i = 1; i <= test_time; i++) {
		shell_print(shell, "test time(%d)...", i);
		time_start = k_uptime_get_32();
		status = mctp_interface_issue_request(mctp_interface, &mctp_inst->mctp_cmd_channel,
			dst_addr, dst_eid, request_buf, req_len, message_buf, sizeof(message_buf), 3000);
		time_end = k_uptime_get_32();
		shell_print(shell, "elapsed time = %u milliseconds", (time_end - time_start));
		if (status != 0) {
			shell_error(shell, "mctp issue request failed(%x)", status);
			goto dump_req_msg;
		} else {
			if (mctp_interface->req_buffer.length != (req_len + 1)) {
				shell_error(shell, "failed: response length(%d)", mctp_interface->req_buffer.length);
					goto dump_msg;
			}
			if (memcmp(mctp_interface->req_buffer.data, resp_header, sizeof(resp_header))) {
				shell_error(shell, "failed: response headr");
					goto dump_msg;
			}
			if (memcmp(&mctp_interface->req_buffer.data[4], &request_buf[3], (mctp_interface->req_buffer.length - 4))) {
				shell_error(shell, "failed: response payload");
					goto dump_msg;
			}
			shell_print(shell, "pass");
		}
	}

#ifndef MCTP_TEST_DEBUG
	return 0;
#endif

dump_msg:
	shell_print(shell, "response:");
	shell_hexdump(shell, mctp_interface->req_buffer.data, mctp_interface->req_buffer.length);
dump_req_msg:
	shell_print(shell, "request:");
	shell_hexdump(shell, request_buf, req_len);
exit:
	return 0;
}

static int cmd_mctp_show_device(const struct shell *shell, size_t argc, char **argv)
{
	struct device_manager *device_mgr = NULL;
	mctp *mctp_inst = NULL;
	uint8_t bus_num;
	int i;

	bus_num = strtol(argv[1], NULL, 16);

	mctp_inst = find_mctp_by_smbus(bus_num);
	if (mctp_inst == NULL) {
		shell_error(shell, "mctp instance not found");
		goto exit;
	}

	device_mgr = &mctp_inst->mctp_wrapper.device_mgr;
	for (i = 0; i < device_mgr->num_devices; i++) {
		shell_print(shell, "device %d:", i);
		shell_print(shell, "          addr = 0x%02x", device_manager_get_device_addr(device_mgr, i));
		shell_print(shell, "          eid = %d", device_manager_get_device_eid(device_mgr, i));
		shell_print(shell, "          max_message_len = %d", device_manager_get_max_message_len(device_mgr, i));
		shell_print(shell, "          max_transmission_unit = %d", device_manager_get_max_transmission_unit(device_mgr, i));
	}
exit:
	return 0;
}

static int cmd_mctp_dump_log(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	debug_msg_display();
	return 0;
}

static int cmd_mctp_clear_log(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	debug_log_clear();
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_mctp_log_cmds,
	SHELL_CMD_ARG(dump, NULL, "dump log", cmd_mctp_dump_log, 1, 0),
	SHELL_CMD_ARG(clear, NULL, "clear log", cmd_mctp_clear_log, 1, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_mctp_cmds,
	SHELL_CMD_ARG(send, NULL, "<bus> <dest_addr> <dest_eid> <msg_type> <rq/d/ins> <cmd_code> <option:payload>", cmd_mctp_send_msg, 7, 255),
#if defined(CONFIG_PFR_MCTP_I3C) && defined(CONFIG_I3C_ASPEED)
	SHELL_CMD_ARG(send_i3c, NULL, "<bus> <dest_addr> <dest_eid> <payload>", cmd_mctp_send_msg_i3c, 4, 255),
#endif
	SHELL_CMD_ARG(echo, NULL, "<bus> <dest_addr> <dest_eid> <payload_length> <option:default 1 time>", cmd_mctp_echo_test, 5, 1),
	SHELL_CMD_ARG(device, NULL, "<bus>", cmd_mctp_show_device, 2, 0),
	SHELL_CMD(log, &sub_mctp_log_cmds, "Log Commands", NULL),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(mctp, &sub_mctp_cmds, "MCTP Commands", NULL);

