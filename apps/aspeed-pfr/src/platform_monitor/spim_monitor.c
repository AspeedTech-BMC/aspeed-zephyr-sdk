/*
 * Copyright (c) 2021 Aspeed Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This work is ported from Aspeed Zephyr SDK sample code.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/types.h>
#include <zephyr/sys/printk.h>
#include <zephyr/drivers/misc/aspeed/pfr_aspeed.h>
#include <zephyr/sys/sys_io.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/util.h>
#include <errno.h>

LOG_MODULE_REGISTER(spim, CONFIG_LOG_DEFAULT_LEVEL);

struct demo_spim_log_ctrl {
	struct k_work log_work;
	struct spim_log_info info;
	const struct device *dev;
	uint32_t cur_off;
	uint32_t pre_off;
};

struct k_work log_bmc_rst_work;
struct k_sem sem_demo_log_op;
struct demo_spim_log_ctrl log_ctrls[4];
const struct device *spim_devs[4];

static void spim_log_parser(const struct device *dev, uint32_t idx, uint32_t log_val)
{
	switch ((log_val & 0x000c0000) >> 18) {
	case 0x0:
		/* block command */
		LOG_ERR("[%s][b][%03d][cmd] %02xh",
				dev->name, idx, log_val & 0xFF);
		break;
	case 0x1:
		/* block write command */
		LOG_ERR("[%s][b][%03d][w_addr] 0x%08x",
				dev->name, idx, (log_val & 0x3FFFF) << 14);
		break;
	case 0x2:
		/* block read command */
		LOG_ERR("[%s][b][%03d][r_addr] 0x%08x",
				dev->name, idx, (log_val & 0x3FFFF) << 14);
		break;
	default:
		LOG_ERR("[%s][%03d]invalid ctx: 0x%08x", dev->name, idx, log_val);
	}
}

void demo_rst_log_ptr(const struct device *dev)
{
	uint32_t ctrl_idx = spim_get_ctrl_idx(dev);
	if (IS_ENABLED(CONFIG_MULTITHREADING))
		k_sem_take(&sem_demo_log_op, K_FOREVER);
	log_ctrls[ctrl_idx - 1].pre_off = 0;
	if (IS_ENABLED(CONFIG_MULTITHREADING))
		k_sem_give(&sem_demo_log_op);
}

static void demo_spim_log_work(struct k_work *item)
{
	uint32_t i;
	struct demo_spim_log_ctrl *log_ctrl =
		CONTAINER_OF(item, struct demo_spim_log_ctrl, log_work);
	if (IS_ENABLED(CONFIG_MULTITHREADING))
		k_sem_take(&sem_demo_log_op, K_FOREVER);
	spim_get_log_info(log_ctrl->dev, &log_ctrl->info);
	log_ctrl->cur_off = log_ctrl->info.log_idx_reg;
	if (log_ctrl->cur_off < log_ctrl->pre_off) {
		for (i = log_ctrl->pre_off; i < log_ctrl->info.log_max_sz / 4; i++) {
			spim_log_parser(log_ctrl->dev, i,
				sys_read32(log_ctrl->info.log_ram_addr + i * 4));
		}
		log_ctrl->pre_off = 0;
	}
	for (i = log_ctrl->pre_off; i < log_ctrl->cur_off; i++) {
		spim_log_parser(log_ctrl->dev, i,
			sys_read32(log_ctrl->info.log_ram_addr + i * 4));
	}
	log_ctrl->pre_off = log_ctrl->cur_off;
	if (IS_ENABLED(CONFIG_MULTITHREADING))
		k_sem_give(&sem_demo_log_op);
}

static void demo_spim_log_bmc_rst_work(struct k_work *item)
{
	ARG_UNUSED(item);
	int i;
	const struct device *spim_dev;
	static char *spim_dev_names[2] = {
		"spim@1",
		"spim@2",
	};

	for (i = 0; i < 2; i++) {
		spim_dev = device_get_binding(spim_dev_names[i]);
		if (!spim_dev) {
			LOG_ERR("Cannot get device, %s, skipped.", spim_dev_names[i]);
			continue;
		}
		demo_rst_log_ptr(spim_dev);
	}
}

static void demo_spim_isr_callback(const struct device *dev)
{
	uint32_t ctrl_idx = spim_get_ctrl_idx(dev);
	/* notice: the ctrl_idx is from 1 to 4 */
	k_work_submit(&log_ctrls[ctrl_idx - 1].log_work);
}

void spim_irq_init(void)
{
	uint32_t i;
	static char *spim_dev_names[4] = {
		"spim@1",
		"spim@2",
		"spim@3",
		"spim@4"
	};
	if (IS_ENABLED(CONFIG_MULTITHREADING))
		k_sem_init(&sem_demo_log_op, 1, 1);
	memset(log_ctrls, 0x0, sizeof(struct demo_spim_log_ctrl));
	for (i = 0; i < 4; i++) {
		spim_devs[i] = device_get_binding(spim_dev_names[i]);
		if (!spim_devs[i]) {
			LOG_ERR("Cannot get device, %s, skipped.", spim_dev_names[i]);
			continue;
		}
		log_ctrls[i].dev = spim_devs[i];
		spim_isr_callback_install(spim_devs[i], demo_spim_isr_callback);
		k_work_init(&log_ctrls[i].log_work, demo_spim_log_work);
	}
	k_work_init(&log_bmc_rst_work, demo_spim_log_bmc_rst_work);
}
