/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <zephyr/kernel.h>
#include <logging/log.h>

LOG_MODULE_REGISTER(spdm_debug, CONFIG_LOG_DEFAULT_LEVEL);

#include <base.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include "library/debuglib.h"

#if LIBSPDM_DEBUG_ASSERT_ENABLE
#define LIBSPDM_DEBUG_LIBSPDM_ASSERT_NATIVE 0
#define LIBSPDM_DEBUG_LIBSPDM_ASSERT_DEADLOOP 1
#define LIBSPDM_DEBUG_LIBSPDM_ASSERT_BREAKPOINT 2
#define LIBSPDM_DEBUG_LIBSPDM_ASSERT_EXIT 3

#ifndef LIBSPDM_DEBUG_LIBSPDM_ASSERT_CONFIG
#define LIBSPDM_DEBUG_LIBSPDM_ASSERT_CONFIG LIBSPDM_DEBUG_LIBSPDM_ASSERT_DEADLOOP
#endif

void libspdm_debug_assert(const char *file_name, size_t line_number, const char *description)
{
	LOG_ERR("LIBSPDM_ASSERT: %s(%zu): %s", file_name, line_number, description);

#if (LIBSPDM_DEBUG_LIBSPDM_ASSERT_CONFIG == LIBSPDM_DEBUG_LIBSPDM_ASSERT_DEADLOOP)
	{
		volatile int32_t ___i = 1;
		while (___i)
			k_msleep(100);
	}
#endif
}
#endif /* LIBSPDM_DEBUG_ASSERT_ENABLE */

#if LIBSPDM_DEBUG_PRINT_ENABLE

/* Define the maximum debug and assert message length that this library supports. */
#define LIBSPDM_MAX_DEBUG_MESSAGE_LENGTH 0x100

#ifndef LIBSPDM_DEBUG_LEVEL_CONFIG
#define LIBSPDM_DEBUG_LEVEL_CONFIG (LIBSPDM_DEBUG_INFO | LIBSPDM_DEBUG_ERROR)
#endif

void libspdm_debug_print(size_t error_level, const char *format, ...)
{
	return ;
	char buffer[LIBSPDM_MAX_DEBUG_MESSAGE_LENGTH];
	va_list marker;

	if ((error_level & LIBSPDM_DEBUG_LEVEL_CONFIG) == 0) {
		return;
	}

	va_start(marker, format);

	vsnprintf(buffer, sizeof(buffer), format, marker);

	va_end(marker);

	printk("%s", buffer);
}
#endif /* LIBSPDM_DEBUG_PRINT_ENABLE */
