/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <spi_filter/spi_filter_wrapper.h>
#include <string.h>

#define SPIM_NUM  4

static char *spim_devs[SPIM_NUM] = {
	"spim@1",
	"spim@2",
	"spim@3",
	"spim@4"
};

int Wrapper_spi_filter_enable(struct spi_filter_interface *spi_filter, bool enable)
{
	struct spi_filter_engine_wrapper *spi_filter_wrapper =
		(struct spi_filter_engine_wrapper*) spi_filter;

	SPI_Monitor_Enable(spim_devs[spi_filter_wrapper->dev_id], enable);

	return 0;
}

int Wrapper_spi_filter_rw_region(struct spi_filter_interface *spi_filter, uint8_t region, uint32_t start_addr, uint32_t end_addr)
{
	int ret = 0;
	struct spi_filter_engine_wrapper *spi_filter_wrapper = (struct spi_filter_engine_wrapper *) spi_filter;

	uint32_t length = end_addr - start_addr;

	ret = Set_SPI_Filter_RW_Region(spim_devs[spi_filter_wrapper->dev_id], SPI_FILTER_WRITE_PRIV, SPI_FILTER_PRIV_ENABLE, start_addr, length);

	return ret;
}


int  spi_filter_wrapper_init(struct spi_filter_engine_wrapper *spi_filter)
{
	if (spi_filter == NULL) {
		return SPI_FILTER_INVALID_ARGUMENT;
	}

	memset(spi_filter, 0, sizeof(struct spi_filter_engine_wrapper));

	spi_filter->base.enable_filter = (int (*)(struct spi_filter_interface *, bool))Wrapper_spi_filter_enable;
	spi_filter->base.set_filter_rw_region = (int (*)(struct spi_filter_interface *, uint8_t, uint32_t, uint32_t))Wrapper_spi_filter_rw_region;

	return 0;
}
