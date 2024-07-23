/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/random/rand32.h>
#include <stdlib.h>

#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMBuffer.h"

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

LOG_MODULE_REGISTER(spdm_buffer, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_buffer_init(struct spdm_buffer *buffer, size_t size)
{
	if (buffer == NULL) {
		return -1;
	}

	if (size > 0) {
		buffer->data = malloc(size);
		memset(buffer->data, 0, size);
	} else {
		buffer->data = NULL;
	}
	buffer->size = size;
	buffer->write_ptr = 0;
	buffer->read_ptr = 0;


	return 0;
}

int spdm_buffer_resize(struct spdm_buffer *buffer, size_t size)
{
	if (buffer == NULL || size == 0 || buffer->size >= size) {
		return -1;
	}

	void *temp = malloc(size);
	memset(temp, 0, size);
	if (buffer->data != NULL && buffer->size > 0) {
		memcpy(temp, buffer->data, MIN(size, buffer->size));
		free(buffer->data);
	}
	buffer->data = temp;
	buffer->size = size;

	return 0;
}

int spdm_buffer_release(struct spdm_buffer *buffer)
{
	if (buffer == NULL || buffer->data == NULL) {
		return -1;
	}

	free(buffer->data);
	buffer->size = 0;
	buffer->write_ptr = 0;
	buffer->read_ptr = 0;
	buffer->data = NULL;

	return 0;
}

int spdm_buffer_append_array(struct spdm_buffer *buffer, void *data, size_t size)
{
	if (buffer == NULL || buffer->write_ptr + size > buffer->size) {
		return -1;
	}

	memcpy((uint8_t *)buffer->data + buffer->write_ptr, data, size);
	buffer->write_ptr += size;

	return 0;
}

int spdm_buffer_append_u8(struct spdm_buffer *buffer, uint8_t data)
{
	return spdm_buffer_append_array(buffer, &data, 1);
}

int spdm_buffer_append_u16(struct spdm_buffer *buffer, uint16_t data)
{
	return spdm_buffer_append_array(buffer, &data, 2);
}

int spdm_buffer_append_u24(struct spdm_buffer *buffer, uint32_t data)
{
	return spdm_buffer_append_array(buffer, &data, 3);
}

int spdm_buffer_append_u32(struct spdm_buffer *buffer, uint32_t data)
{
	return spdm_buffer_append_array(buffer, &data, 4);
}

int spdm_buffer_append_nonce(struct spdm_buffer *buffer)
{
	uint8_t nonce[SPDM_NONCE_SIZE];
	sys_rand_get(nonce, sizeof(nonce));

	return spdm_buffer_append_array(buffer, nonce, sizeof(nonce));
}

int spdm_buffer_append_reserved(struct spdm_buffer *buffer, size_t size)
{
	int ret = 0;
	for (size_t i=0; i<size; ++i)
		ret = spdm_buffer_append_u8(buffer, 0);
	return ret;
}

int spdm_buffer_get_array(struct spdm_buffer *buffer, void *data, size_t size)
{
	if (buffer == NULL) {
		LOG_ERR("spdm_buffer_get_array buffer=NULL data=%p size=%d", data, size);
		return -1;
	} else if (buffer->read_ptr + size > buffer->size) {
		LOG_ERR("spdm_buffer_get_array buffer=%p data=%p read_ptr=%d size=%d buf->size=%d",
				buffer, data, buffer->read_ptr, size, buffer->size);
		return -1;
	}

	memcpy(data, (uint8_t *)buffer->data + buffer->read_ptr, size);
	buffer->read_ptr += size;

	return 0;
}

int spdm_buffer_get_u8(struct spdm_buffer *buffer, uint8_t *data)
{
	return spdm_buffer_get_array(buffer, data, 1);
}

int spdm_buffer_get_u16(struct spdm_buffer *buffer, uint16_t *data)
{
	return spdm_buffer_get_array(buffer, data, 2);
}

int spdm_buffer_get_u24(struct spdm_buffer *buffer, uint32_t *data)
{
	return spdm_buffer_get_array(buffer, data, 3);
}

int spdm_buffer_get_u32(struct spdm_buffer *buffer, uint32_t *data)
{
	return spdm_buffer_get_array(buffer, data, 4);
}

int spdm_buffer_get_reserved(struct spdm_buffer *buffer, size_t size)
{
	uint8_t tmp;
	int ret = 0;
	for (size_t i=0; i<size; ++i)
		ret = spdm_buffer_get_u8(buffer, &tmp);
	return ret;
}
