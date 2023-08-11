/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <zephyr.h>
#include <stdint.h>
#include <assert.h>

#include <logging/log.h>
LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

#include <spdm_req.h>
#include <spdm_rsp.h>

#define SPDM_REQUESTER_PRIO 4
#define SPDM_REQUESTER_STACK_SIZE 16384
K_THREAD_STACK_DEFINE(spdm_requester_stack, SPDM_REQUESTER_STACK_SIZE);
struct k_thread spdm_requester_thread_data;
k_tid_t spdm_requester_tid;

#define SPDM_RESPONDER_PRIO 4
#define SPDM_RESPONDER_STACK_SIZE 16384
K_THREAD_STACK_DEFINE(spdm_responder_stack, SPDM_RESPONDER_STACK_SIZE);
struct k_thread spdm_responder_thread_data;
k_tid_t spdm_responder_tid;

int main()
{
	spdm_responder_tid = k_thread_create(
		&spdm_responder_thread_data,
		spdm_responder_stack,
		K_THREAD_STACK_SIZEOF(spdm_responder_stack),
		//spdm_responder_main,
		spdm_responder_main,
		NULL, NULL, NULL,
		SPDM_RESPONDER_PRIO, 0, K_MSEC(10));
	k_thread_name_set(spdm_responder_tid, "SPDM RSP");

	spdm_requester_tid = k_thread_create(
		&spdm_requester_thread_data,
		spdm_requester_stack,
		K_THREAD_STACK_SIZEOF(spdm_requester_stack),
		//spdm_requester_main,
		spdm_requester_main,
		NULL, NULL, NULL,
		SPDM_REQUESTER_PRIO, 0, K_MSEC(20));
	k_thread_name_set(spdm_requester_tid, "SPDM REQ");

	return 0;
}
