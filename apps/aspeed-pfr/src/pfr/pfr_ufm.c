/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <soc.h>
#include "common/common.h"
#include "flash/flash_wrapper.h"
#include "AspeedStateMachine/common_smc.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_definitions.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#endif
#include "pfr/pfr_util.h"
#include "Smbus_mailbox/Smbus_mailbox.h"

#include <logging/log.h>
LOG_MODULE_REGISTER(ufm, CONFIG_LOG_DEFAULT_LEVEL);

int get_cpld_status(uint32_t offset, uint8_t *data, uint32_t data_length)
{
	int status;

	status = pfr_spi_read(ROT_INTERNAL_STATE, offset, data_length, data);

	return status;
}

int set_cpld_status(uint32_t offset, uint8_t *data, uint32_t data_length)
{
	static uint8_t buffer[PAGE_SIZE] NON_CACHED_BSS_ALIGN16;
	int status;

	if (offset + data_length > sizeof(buffer))
		return Failure;

	status = pfr_spi_read(ROT_INTERNAL_STATE, 0, sizeof(buffer), buffer);
	if (status)
		return Failure;

	memcpy(buffer + offset, data, data_length);
	status = pfr_spi_erase_4k(ROT_INTERNAL_STATE, 0);
	if (status != Success)
		return Failure;

	status = pfr_spi_write(ROT_INTERNAL_STATE, 0, sizeof(buffer), buffer);

	return status;
}

int ufm_read(uint32_t ufm_id, uint32_t offset, uint8_t *data, uint32_t data_length)
{

	if (ufm_id == PROVISION_UFM)
		return get_provision_data_in_flash(offset, data, data_length);
	else if (ufm_id == UPDATE_STATUS_UFM)
		return get_cpld_status(offset, data, data_length);
	else
		return Failure;
}

int ufm_write(uint32_t ufm_id, uint32_t offset, uint8_t *data, uint32_t data_length)
{

	if (ufm_id == PROVISION_UFM)
		return set_provision_data_in_flash(offset, data, data_length);
	else if (ufm_id == UPDATE_STATUS_UFM)
		return set_cpld_status(offset, data, data_length);
	else
		return Failure;
}

int ufm_erase(uint32_t ufm_id)
{
	if (ufm_id == PROVISION_UFM)
		return pfr_spi_erase_4k(ROT_INTERNAL_INTEL_STATE, 0);
	else if (ufm_id == UPDATE_STATUS_UFM)
		return pfr_spi_erase_4k(ROT_INTERNAL_STATE, 0);
	else
		return Failure;
}
