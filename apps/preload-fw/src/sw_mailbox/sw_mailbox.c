/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/drivers/i2c/pfr/swmbx.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/reboot.h>
#include "sw_mailbox.h"
#include "fw_update/fw_update.h"

LOG_MODULE_REGISTER(mailbox, CONFIG_LOG_DEFAULT_LEVEL);

#define TOTAL_MBOX_EVENT              14
#define SWMBX_NOTIFYEE_STACK_SIZE     1024

const struct device *swmbx_dev = NULL;

#define SWMBX_SLAVE_BMC DEVICE_DT_NAME(DT_NODELABEL(swmbx1))
#define SWMBX_SLAVE_CPU DEVICE_DT_NAME(DT_NODELABEL(swmbx0))

#define MBX_REG_SETTER(REG) \
	void Set##REG(uint8_t Data) \
	{ \
		swmbx_write(swmbx_dev, false, REG, &Data); \
	}

#define MBX_REG_GETTER(REG) \
	uint8_t Get##REG(void) \
	{ \
		uint8_t data; \
		swmbx_read(swmbx_dev, false, REG, &data); \
		return data; \
	}

#define MBX_REG_SETTER_GETTER(REG) \
	MBX_REG_SETTER(REG) \
	MBX_REG_GETTER(REG)

MBX_REG_SETTER_GETTER(RotCmdPreloadImgId);
MBX_REG_SETTER_GETTER(RotCmdSetting);
MBX_REG_SETTER_GETTER(RotCmdCommand);
MBX_REG_SETTER_GETTER(RotCmdStatus);
MBX_REG_SETTER_GETTER(RotCmdStagingOffset0);
MBX_REG_SETTER_GETTER(RotCmdStagingOffset1);
MBX_REG_SETTER_GETTER(RotCmdStagingOffset2);
MBX_REG_SETTER_GETTER(RotCmdStagingOffset3);
MBX_REG_SETTER_GETTER(RotCmdImgSize0);
MBX_REG_SETTER_GETTER(RotCmdImgSize1);
MBX_REG_SETTER_GETTER(RotCmdImgSize2);
MBX_REG_SETTER_GETTER(RotCmdImgSize3);
MBX_REG_SETTER_GETTER(RotCmdChecksum0);
MBX_REG_SETTER_GETTER(RotCmdChecksum1);
MBX_REG_SETTER_GETTER(RotCmdChecksum2);
MBX_REG_SETTER_GETTER(RotCmdChecksum3);

struct k_thread swmbx_notifyee_thread;

K_THREAD_STACK_DEFINE(swmbx_notifyee_stack, SWMBX_NOTIFYEE_STACK_SIZE);
K_SEM_DEFINE(rot_setting_sem, 0, 1);
K_SEM_DEFINE(rot_command_sem, 0, 1);
K_SEM_DEFINE(rot_staging_offset0_sem, 0, 1);
K_SEM_DEFINE(rot_staging_offset1_sem, 0, 1);
K_SEM_DEFINE(rot_staging_offset2_sem, 0, 1);
K_SEM_DEFINE(rot_staging_offset3_sem, 0, 1);
K_SEM_DEFINE(rot_image_size0_sem, 0, 1);
K_SEM_DEFINE(rot_image_size1_sem, 0, 1);
K_SEM_DEFINE(rot_image_size2_sem, 0, 1);
K_SEM_DEFINE(rot_image_size3_sem, 0, 1);
K_SEM_DEFINE(rot_checksum0_sem, 0, 1);
K_SEM_DEFINE(rot_checksum1_sem, 0, 1);
K_SEM_DEFINE(rot_checksum2_sem, 0, 1);
K_SEM_DEFINE(rot_checksum3_sem, 0, 1);

void swmbx_notifyee_main(void *a, void *b, void *c)
{
	int ret;
	union aspeed_event_data data = {0};

	struct k_poll_event events[TOTAL_MBOX_EVENT];
	k_poll_event_init(&events[0], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_setting_sem);
	k_poll_event_init(&events[1], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_command_sem);
	k_poll_event_init(&events[2], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_staging_offset0_sem);
	k_poll_event_init(&events[3], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_staging_offset1_sem);
	k_poll_event_init(&events[4], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_staging_offset2_sem);
	k_poll_event_init(&events[5], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_staging_offset3_sem);
	k_poll_event_init(&events[6], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_image_size0_sem);
	k_poll_event_init(&events[7], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_image_size1_sem);
	k_poll_event_init(&events[8], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_image_size2_sem);
	k_poll_event_init(&events[9], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_image_size3_sem);
	k_poll_event_init(&events[10], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_checksum0_sem);
	k_poll_event_init(&events[11], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_checksum1_sem);
	k_poll_event_init(&events[12], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_checksum2_sem);
	k_poll_event_init(&events[13], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			&rot_checksum3_sem);

	while (1) {
		ret = k_poll(events, TOTAL_MBOX_EVENT, K_FOREVER);

		if (ret < 0) {
			LOG_ERR("k_poll error ret=%d", ret);
			continue;
		}

		if (events[0].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[0].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdSetting;
			swmbx_get_msg(0, RotCmdSetting, &data.bit8[1]);
			configure_staging_source(&data);
		} else if (events[1].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[1].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdCommand;
			swmbx_get_msg(0, RotCmdCommand, &data.bit8[1]);
			if (data.bit8[1] == 1){
				if (rot_fw_update()) {
					LOG_ERR("Failed to update ROT firmware");
				}
			}
		} else if (events[2].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[2].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdStagingOffset0;
			swmbx_get_msg(0, RotCmdStagingOffset0, &data.bit8[1]);
			set_fw_staging_source(&data);
		} else if (events[3].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[3].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdStagingOffset1;
			swmbx_get_msg(0, RotCmdStagingOffset1, &data.bit8[1]);
			set_fw_staging_source(&data);
		} else if (events[4].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[4].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdStagingOffset2;
			swmbx_get_msg(0, RotCmdStagingOffset2, &data.bit8[1]);
			set_fw_staging_source(&data);
		} else if (events[5].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[5].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdStagingOffset3;
			swmbx_get_msg(0, RotCmdStagingOffset3, &data.bit8[1]);
			set_fw_staging_source(&data);
		} else if (events[6].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[6].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdImgSize0;
			swmbx_get_msg(0, RotCmdImgSize0, &data.bit8[1]);
			set_fw_image_size(&data);
		} else if (events[7].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[7].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdImgSize1;
			swmbx_get_msg(0, RotCmdImgSize1, &data.bit8[1]);
			set_fw_image_size(&data);
		} else if (events[8].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[8].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdImgSize2;
			swmbx_get_msg(0, RotCmdImgSize2, &data.bit8[1]);
			set_fw_image_size(&data);
		} else if (events[9].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[9].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdImgSize3;
			swmbx_get_msg(0, RotCmdImgSize3, &data.bit8[1]);
			set_fw_image_size(&data);
		} else if (events[10].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[10].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdChecksum0;
			swmbx_get_msg(0, RotCmdChecksum0, &data.bit8[1]);
			set_fw_image_checksum(&data);
		} else if (events[11].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[11].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdChecksum1;
			swmbx_get_msg(0, RotCmdChecksum1, &data.bit8[1]);
			set_fw_image_checksum(&data);
		} else if (events[12].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[12].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdChecksum2;
			swmbx_get_msg(0, RotCmdChecksum2, &data.bit8[1]);
			set_fw_image_checksum(&data);
		} else if (events[13].state == K_POLL_STATE_SEM_AVAILABLE) {
			k_sem_take(events[13].sem, K_NO_WAIT);
			data.bit8[0] = RotCmdChecksum3;
			swmbx_get_msg(0, RotCmdChecksum3, &data.bit8[1]);
			set_fw_image_checksum(&data);
		}

		for (size_t i = 0; i < TOTAL_MBOX_EVENT; ++i)
			events[i].state = K_POLL_STATE_NOT_READY;
	}
}

void init_sw_mailbox(void)
{
	swmbx_dev = device_get_binding("swmbx-ctrl");
	if (swmbx_dev == NULL) {
		LOG_ERR("%s: fail to bind %s", __func__, "SWMBX");
		return;
	}
	SetRotCmdPreloadImgId(0xa3);
	/* Enable mailbox read/write notifiaction and FIFO */
	swmbx_enable_behavior(swmbx_dev, SWMBX_PROTECT | SWMBX_NOTIFY | SWMBX_FIFO, 1);

	/* swmbx_update_notify(dev, port, sem, addr, enable) */
	/* From BMC */
	swmbx_update_notify(swmbx_dev, 0x0, &rot_setting_sem, RotCmdSetting, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_command_sem, RotCmdCommand, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_staging_offset0_sem, RotCmdStagingOffset0, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_staging_offset1_sem, RotCmdStagingOffset1, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_staging_offset2_sem, RotCmdStagingOffset2, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_staging_offset3_sem, RotCmdStagingOffset3, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_image_size0_sem, RotCmdImgSize0, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_image_size1_sem, RotCmdImgSize1, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_image_size2_sem, RotCmdImgSize2, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_image_size3_sem, RotCmdImgSize3, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_checksum0_sem, RotCmdChecksum0, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_checksum1_sem, RotCmdChecksum1, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_checksum2_sem, RotCmdChecksum2, true);
	swmbx_update_notify(swmbx_dev, 0x0, &rot_checksum3_sem, RotCmdChecksum3, true);

	/* Protect bit:
	 * 0 means readable/writable
	 * 1 means read-only
	 */
	uint32_t access_control[8] = {
		0xffff0009, // 1fh ~ 00h
		0xffffffff,
		0xffffffff,
		0xffffffff,
		0xffffffff,
		0xffffffff,
		0xffffffff,
		0xffffffff,
	};
	swmbx_apply_protect(swmbx_dev, 0, access_control, 0, 8);

	/* Register slave device to bus device */
	const struct device *dev = NULL;

	dev = device_get_binding(SWMBX_SLAVE_BMC);
	if (dev)
		i2c_target_driver_register(dev);

	k_tid_t swmbx_tid = k_thread_create(
		&swmbx_notifyee_thread,
		swmbx_notifyee_stack,
		SWMBX_NOTIFYEE_STACK_SIZE,
		swmbx_notifyee_main,
		NULL, NULL, NULL,
		5, 0, K_NO_WAIT);
	k_thread_name_set(swmbx_tid, "Software Mailbox Handler");
}
