/**
 * Copyright Notice:
 * Copyright 2022 DMTF. All rights reserved.
 * License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include <zephyr/kernel.h>
#include <base.h>

/**
 * Suspends the execution of the current thread until the time-out interval elapses.
 *
 * @param microseconds     The time interval for which execution is to be suspended, in microseconds.
 *
 **/
void libspdm_sleep(uint64_t microseconds)
{
	uint32_t high_byte = (uint32_t)(microseconds >> 32);
	uint32_t low_byte = (uint32_t)(microseconds & 0xffffffff);
	k_msleep(low_byte);

	while (high_byte) {
		k_msleep(0xffffffff);
		--high_byte;
	}
}
