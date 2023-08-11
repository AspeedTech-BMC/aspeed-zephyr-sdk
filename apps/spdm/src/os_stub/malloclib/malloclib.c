/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <zephyr.h>
#include <logging/log.h>

LOG_MODULE_REGISTER(ALLOC, CONFIG_LOG_DEFAULT_LEVEL);

void *allocate_pool(size_t AllocationSize)
{
	void *buffer = malloc(AllocationSize);
	if (buffer == NULL) {
		LOG_ERR("Failed to alloc memory size=%zu", AllocationSize);
	}
	return buffer;
}

void *allocate_zero_pool(size_t AllocationSize)
{
	void *buffer;
	buffer = malloc(AllocationSize);
	if (buffer == NULL) {
		LOG_ERR("Failed to alloc memory size=%zu", AllocationSize);
		return NULL;
	}
	memset(buffer, 0, AllocationSize);
	return buffer;
}

void free_pool(void *buffer)
{
	free(buffer);
}

// void mbedtls_platform_zeroize(void *buf, size_t len)
// {
// 	libspdm_zero_mem(buf, len);
// }
