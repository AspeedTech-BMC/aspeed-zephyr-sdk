/*
 * Copyright (c) 2019 Alexander Wachter
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr.h>
#include <storage/flash_map.h>
#include <drivers/i2c.h>
#include <drivers/i2c/pfr/swmbx.h>
#include <drivers/spi_nor.h>
#include <logging/log.h>
#include <drivers/gpio.h>
#include <shell/shell.h>
#include "Smbus_mailbox.h"
#include "common/common.h"

#define PROVISION_ERASE_COMMAND 0

static int cmd_provision_show(const struct shell *shell, size_t argc, char **argv)
{
	show_provision_info();
	return 0;
}

#if PROVISION_ERASE_COMMAND
extern int erase_provision_flash(void);
static int cmd_provision_erase(const struct shell *shell, size_t argc, char **argv)
{
	erase_provision_flash();
	return 0;
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(sub_provision,
	SHELL_CMD(show, NULL, "Show provision data", cmd_provision_show),
#if PROVISION_ERASE_COMMAND
	SHELL_CMD(erase, NULL, "Erase provision data", cmd_provision_erase),
#endif
	SHELL_SUBCMD_SET_END /* Array terminated. */
);

SHELL_CMD_REGISTER(provision, &sub_provision, "provision commands", NULL);
