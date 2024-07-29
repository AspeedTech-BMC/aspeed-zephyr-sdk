/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include "logging_wrapper.h"

LOG_MODULE_REGISTER(logging_wrapper, CONFIG_LOG_DEFAULT_LEVEL);

struct logging_memory_wrapper logging_wrapper;
uint8_t logging_dump[LOGGING_BUF_SIZE];

static int logging_memory_wrapper_init(struct logging_memory_wrapper *logging_wrapper)
{
	int status;

	debug_log = &logging_wrapper->logging.base;
	logging_wrapper->logging.state = &logging_wrapper->state;
	status = logging_memory_init(&logging_wrapper->logging, &logging_wrapper->state,
			LOGGING_ENTRY_COUNT, LOGGING_ENTRY_LENGTH);
	if (status != 0) {
		LOG_ERR("logging memory init failed(%x)", status);
		return status;
	}

	status = debug_log_clear();
	if (status != 0) {
		LOG_ERR("debug log clear failed(%x)", status);
		return status;
	}

	return 0;
}

void debug_msg_display(void)
{
	struct logging_entry_header *header;
	struct debug_log_entry_info *entry;
	int offset = 0;
	int len = 0;
	uint32_t total_seconds;
	uint32_t freq = 1000;
	uint32_t remainder;
	uint32_t seconds;
	uint32_t hours;
	uint32_t mins;
	uint32_t ms;
	uint32_t us;

	len = debug_log_read_contents(0, logging_dump, sizeof(logging_dump));

	if (len > 0)
		LOG_HEXDUMP_DBG(logging_dump, len, "log dump:");

	while (offset < len) {
		header = (struct logging_entry_header *)&logging_dump[offset];
		LOG_INF("header id[%d]:", header->entry_id);
		LOG_INF("	length:%d", header->length);
		LOG_INF("	logic_magic:0x%02x", header->log_magic);
		offset += sizeof(struct logging_entry_header);

		entry = (struct debug_log_entry_info *)&logging_dump[offset];
		total_seconds = entry->time / freq;
		seconds = total_seconds;
		hours = seconds / 3600U;
		seconds -= hours * 3600U;
		mins = seconds / 60U;
		seconds -= mins * 60U;

		remainder = entry->time % freq;
		ms = (remainder * 1000U) / freq;
		us = (1000 * (remainder * 1000U - (ms * freq))) / freq;

		LOG_INF("entry:");
		LOG_INF("	[%02d:%02d:%02d.%03d,%03d]", hours, mins, seconds, ms, us);
		LOG_INF("	format = 0x%x", entry->format);
		LOG_INF("	severity = 0x%x", entry->severity);
		LOG_INF("	component = 0x%x", entry->component);
		LOG_INF("	msg_index = 0x%x", entry->msg_index);
		LOG_INF("	arg1 = 0x%x", entry->arg1);
		LOG_INF("	arg2 = 0x%x", entry->arg2);
		LOG_DBG("	time_ms = %lld", entry->time);
		offset += sizeof(struct debug_log_entry_info);
	}
}

int debug_log_init(void)
{
	return logging_memory_wrapper_init(&logging_wrapper);
}

void debug_log_release(void)
{
	logging_memory_release(&logging_wrapper.logging);
}

