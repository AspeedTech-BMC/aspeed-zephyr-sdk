/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mctp.h"

#include <stdlib.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/crc.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/i3c.h>
#include <zephyr/drivers/i3c/ibi.h>
#include <zephyr/drivers/i3c/ccc.h>
#include "mctp.h"
#include "mctp_i3c.h"
#include "gpio/gpio_aspeed.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "SPDM/SPDMRequester.h"
#include "i3c/i3c_util.h"

#include "mctp/mctp_base_protocol.h"
#include "cmd_channel_mctp.h"

LOG_MODULE_REGISTER(mctp_i3c);

#define I3C_0 DEVICE_DT_NAME(DT_NODELABEL(i3c0))
#define I3C_1 DEVICE_DT_NAME(DT_NODELABEL(i3c1))
#define I3C_2 DEVICE_DT_NAME(DT_NODELABEL(i3c2))
#define I3C_3 DEVICE_DT_NAME(DT_NODELABEL(i3c3))

#define MCTP_I3C_CPU0_EID                   0x1D
#define MCTP_I3C_CPU1_EID                   0x9D
#define MCTP_I3C_REGISTRATION_EID           0x1D
#define MCTP_DOE_REGISTRATION_CMD           0x4

static uint8_t i3c_data_in[256];
static uint8_t mctp_msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN];
mctp_i3c mctp_i3c_bmc_inst = {0};
mctp_i3c mctp_i3c_cpu0_inst = {0};
mctp_i3c mctp_i3c_cpu1_inst = {0};
bool i3c_hub_configured = false;

static void mctp_i3c_req_timeout_callback(struct k_timer *tmr);
K_TIMER_DEFINE(mctp_i3c_req_timer, mctp_i3c_req_timeout_callback, NULL);
K_SEM_DEFINE(ibi_complete, 0, 1);
K_SEM_DEFINE(cpu0_ibi_complete, 0, 1);
K_SEM_DEFINE(cpu1_ibi_complete, 0, 1);
K_SEM_DEFINE(hub_ibi_complete, 0, 1);
K_SEM_DEFINE(mctp_i3c_sem, 0, 1);


static int mctp_i3c_sem_give(struct i3c_device_desc *target)
{
	switch(target->pid) {
	case CONFIG_PFR_SPDM_I3C_BMC_DEV_PID:
		k_sem_give(&ibi_complete);
		break;
	case CONFIG_PFR_SPDM_I3C_CPU0_DEV_PID:
		k_sem_give(&cpu0_ibi_complete);
		break;
	case CONFIG_PFR_SPDM_I3C_CPU1_DEV_PID:
		k_sem_give(&cpu1_ibi_complete);
		break;
	case CONFIG_PFR_SPDM_I3C_HUB_DEV_PID:
		k_sem_give(&hub_ibi_complete);
		break;
	default:
		LOG_ERR("Unknown pid");
		break;
	}

	return 0;
}

static int mctp_i3c_sem_take(struct i3c_device_desc *target)
{
	switch(target->pid) {
	case CONFIG_PFR_SPDM_I3C_BMC_DEV_PID:
		k_sem_take(&ibi_complete, K_FOREVER);
		break;
	case CONFIG_PFR_SPDM_I3C_CPU0_DEV_PID:
		k_sem_take(&cpu0_ibi_complete, K_FOREVER);
		break;
	case CONFIG_PFR_SPDM_I3C_CPU1_DEV_PID:
		k_sem_take(&cpu1_ibi_complete, K_FOREVER);
		break;
	case CONFIG_PFR_SPDM_I3C_HUB_DEV_PID:
		k_sem_take(&hub_ibi_complete, K_FOREVER);
		break;
	default:
		LOG_ERR("Unknown pid");
		break;
	}

	return 0;
}

const struct device *get_mctp_i3c_dev(uint8_t bus_num)
{
	switch(bus_num) {
	case 0:
		return device_get_binding(I3C_0);
	case 1:
		return device_get_binding(I3C_1);
	case 2:
		return device_get_binding(I3C_2);
	case 3:
		return device_get_binding(I3C_3);
	}

	return NULL;
}

void trigger_mctp_i3c_state_handler(void)
{
	k_sem_give(&mctp_i3c_sem);
}

void mctp_i3c_stop_discovery_notify(struct device_manager *mgr)
{
	int status;
	k_timer_stop(&mctp_i3c_req_timer);
	status = device_manager_update_device_state(mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM,
			DEVICE_MANAGER_EID_ANNOUNCEMENT);
	if (status != 0)
		LOG_ERR("update self device state failed");

	// Start eid announcement
	k_timer_start(&mctp_i3c_req_timer, K_SECONDS(2), K_NO_WAIT);
}

void mctp_i3c_pre_attestation(struct device_manager *mgr, int *duration)
{
	uint8_t provision_state = GetUfmStatusValue();

	if (provision_state & UFM_PROVISIONED) {
		if (is_pltrst_sync()) {
			LOG_WRN("Pre-attestation");
			device_manager_update_device_state(mgr,
				      DEVICE_MANAGER_SELF_DEVICE_NUM,
				      DEVICE_MANAGER_ATTESTATION);
		}
		*duration = 1;
	} else {
		// Unprovisioned, Enter Runtime
		LOG_DBG("Unprovisioned, skip attestation, wait for PLTRST_SYNC#");
		if (is_pltrst_sync()) {
			LOG_WRN("PLTRST_SYNC# Asserted, go next state");
			device_manager_update_device_state(mgr,
				      DEVICE_MANAGER_SELF_DEVICE_NUM,
				      DEVICE_MANAGER_RUNTIME);
			k_sem_give(&mctp_i3c_sem);
			*duration = 0;
		} else {
			*duration = 1;
		}
	}

}

void mctp_i3c_attestation(struct device_manager *mgr, int *duration)
{
	uint32_t event = spdm_get_attester();
	if (event & SPDM_REQ_EVT_ENABLE) {
		if (!(event & SPDM_REQ_EVT_T0_I3C)) {
			LOG_WRN("I3C Device Attestation start");
			spdm_run_attester_i3c();
			*duration = 10;
		} else if (!(event & SPDM_REQ_EVT_ATTESTED_CPU)) {
			LOG_WRN("I3C Device Attestation running");
			*duration = 10;
		} else {
			LOG_INF("I3C Device Attestation done");
			device_manager_update_device_state(mgr,
				      DEVICE_MANAGER_SELF_DEVICE_NUM,
				      DEVICE_MANAGER_RUNTIME);
			k_sem_give(&mctp_i3c_sem);
		}
	} else {

		LOG_WRN("SPDM Not enabled, skip attestation");
		device_manager_update_device_state(mgr,
				     DEVICE_MANAGER_SELF_DEVICE_NUM,
				     DEVICE_MANAGER_RUNTIME);
		k_sem_give(&mctp_i3c_sem);

	}
}

int mctp_i3c_send_discovery_notify(mctp *mctp_instance, int *duration)
{
	struct mctp_interface_wrapper *mctp_wrapper = &mctp_instance->mctp_wrapper;
	struct mctp_interface *mctp_interface = &mctp_wrapper->mctp_interface;
	// { message_type, rq bit, command_code}
	uint8_t req_buf[3] = {MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, 0x81, 0x0d};

	mctp_interface_issue_request(mctp_interface, &mctp_instance->mctp_cmd_channel,
			mctp_instance->medium_conf.i3c_conf.addr, 0, req_buf, sizeof(req_buf),
			mctp_msg_buf, sizeof(mctp_msg_buf), 1);

	*duration = MCTP_I3C_MSG_RETRY_INTERVAL;

	return 0;
}

int mctp_i3c_send_eid_announcement(mctp *mctp_instance, int *duration)
{
	int status = -1;
	uint8_t dest_eid;

	struct mctp_interface_wrapper *mctp_wrapper = &mctp_instance->mctp_wrapper;
	struct mctp_interface *mctp_interface = &mctp_wrapper->mctp_interface;
	struct device_manager *device_mgr = mctp_interface->device_manager;
	uint8_t src_eid = device_manager_get_device_eid(device_mgr,
				DEVICE_MANAGER_SELF_DEVICE_NUM);
	uint8_t req_buf[14] = {MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, 0x80, 0x86, 0x80, 0x0a, 0x00,
		0x00, 0x00, 0x00, MCTP_DOE_REGISTRATION_CMD, 0x00, 0x00, 0x01, src_eid};

	if (mctp_instance == mctp_i3c_bmc_inst.mctp_inst) {
		dest_eid = MCTP_I3C_REGISTRATION_EID;
	} else if (mctp_instance == mctp_i3c_cpu0_inst.mctp_inst) {
		dest_eid = MCTP_I3C_CPU0_EID;
	} else if (mctp_instance == mctp_i3c_cpu1_inst.mctp_inst) {
		dest_eid = MCTP_I3C_CPU1_EID;
	} else {
		return status;
	}

	status = mctp_interface_issue_request(mctp_interface, &mctp_instance->mctp_cmd_channel,
			mctp_instance->medium_conf.i3c_conf.addr, dest_eid, req_buf,
			sizeof(req_buf), mctp_msg_buf, sizeof(mctp_msg_buf), 12000);

	if (status == 0) {
		device_manager_update_device_state(device_mgr,
				DEVICE_MANAGER_SELF_DEVICE_NUM,
				DEVICE_MANAGER_PRE_ATTESTATION);
	}

	*duration = 2;

	return status;
}

void mctp_i3c_state_handler(void *a, void *b, void *c)
{
	mctp_i3c *mctp_i3c_instance = a;
	mctp *mctp_instance = mctp_i3c_instance->mctp_inst;
	struct mctp_interface_wrapper *mctp_wrapper = &mctp_instance->mctp_wrapper;
	struct device_manager *device_mgr = mctp_wrapper->mctp_interface.device_manager;
	int dev_state;
	int duration = MCTP_I3C_MSG_RETRY_INTERVAL;
	int owner;
	uint8_t stat;

	while (1) {
		k_sem_take(&mctp_i3c_instance->i3c_state_sem, K_FOREVER);
		owner = get_i3c_mng_owner();
		dev_state = device_manager_get_device_state(device_mgr,
				DEVICE_MANAGER_SELF_DEVICE_NUM);
		if (dev_state == DEVICE_MANAGER_SEND_DISCOVERY_NOTIFY) {
			LOG_DBG("Send discovery notify");
			stat = (I3C_MNG_OWNER_BMC == owner) ?
				PFR_ACT1_DAA_I3C_BMC : PFR_ACT1_DAA_I3C_CPU;
			SetPfrActivityInfo1(stat);
			mctp_i3c_send_discovery_notify(mctp_instance, &duration);
		} else if (dev_state == DEVICE_MANAGER_EID_ANNOUNCEMENT) {
			LOG_DBG("Announce EID");
			stat = (I3C_MNG_OWNER_BMC == owner) ?
				PFR_ACT1_SET_EID_I3C_BMC : PFR_ACT1_SET_EID_I3C_CPU;
			SetPfrActivityInfo1(stat);
			mctp_i3c_send_eid_announcement(mctp_instance, &duration);
		}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
		else if (dev_state == DEVICE_MANAGER_PRE_ATTESTATION) {
			stat = (I3C_MNG_OWNER_BMC == owner) ?
				PFR_ACT1_EID_REGISTRATION_I3C_BMC : PFR_ACT1_EID_REGISTRATION_I3C_CPU;
			SetPfrActivityInfo1(stat);
			mctp_i3c_pre_attestation(device_mgr, &duration);
		} else if (dev_state == DEVICE_MANAGER_ATTESTATION) {
			/* Start S3M attestation then release PLTRST_CPU0_N */
			mctp_i3c_attestation(device_mgr, &duration);
		} else if (dev_state == DEVICE_MANAGER_RUNTIME) {
			/* TODO: Start S3M attestation then release PLTRST_CPU0_N */
			RSTPlatformReset(false);
			duration = 0;
		}
#endif
		else {
			duration = 0;
		}

		if (duration > 0 && mctp_i3c_instance->state == MCTP_I3C_TARGET_ATTACHED) {
			k_timer_start(&mctp_i3c_instance->i3c_state_timer, K_SECONDS(duration), K_NO_WAIT);
		}
	}
}

static uint16_t mctp_i3c_read(void *mctp_p, void *msg_p)
{
	struct cmd_packet *packet = (struct cmd_packet *)msg_p;
	mctp *mctp_inst = (mctp *)mctp_p;
	struct i3c_msg xfer;
	const struct device *dev;
	struct i3c_driver_data* data;
	struct i3c_device_desc* desc;

	// read request from slave device.
	dev = get_mctp_i3c_dev(mctp_inst->medium_conf.i3c_conf.bus);
	if (dev == NULL) {
		LOG_ERR("Failed to get i3c dev");
		return MCTP_ERROR;
	}
	data = (struct i3c_driver_data *)dev->data;
	desc = i3c_dev_list_i3c_addr_find(&data->attached_dev, mctp_inst->medium_conf.i3c_conf.addr);
	if (desc == NULL) {
		LOG_ERR("Device not found");
		return MCTP_ERROR;
	}

	mctp_i3c_sem_take(desc);
	memset(i3c_data_in, 0, sizeof(i3c_data_in));

	xfer.flags = I3C_MSG_READ | I3C_MSG_STOP;
	xfer.buf = i3c_data_in;
	xfer.len = sizeof(i3c_data_in);
	i3c_transfer(desc, &xfer, 1);

	LOG_DBG("xfer.len = %d", xfer.len);
	LOG_HEXDUMP_DBG(xfer.buf, xfer.len, "i3c read : ");
	packet->dest_addr = mctp_inst->medium_conf.i3c_conf.addr;
	packet->pkt_size = xfer.len;
	packet->timeout_valid = 0;
	packet->pkt_timeout = 0;
	packet->state = CMD_VALID_PACKET;

	if (xfer.len > CMD_MAX_PACKET_SIZE) {
		LOG_WRN("Buffer is smaller than received data");
		xfer.len = CMD_MAX_PACKET_SIZE;
	}

	memcpy(packet->data, xfer.buf, xfer.len);

	return 0;
}

static uint16_t mctp_i3c_write(void *mctp_p, void *msg_p)
{
	mctp_tx_msg *tx_msg = (mctp_tx_msg *)msg_p;
	mctp *mctp_inst = (mctp *)mctp_p;
	struct i3c_msg xfer;
	const struct device *dev;
	struct i3c_driver_data* data;
	struct i3c_device_desc* desc;

	if (tx_msg->ext_params.type != MCTP_MEDIUM_TYPE_I3C)
		return MCTP_ERROR;

	if (tx_msg->buf == NULL)
		return MCTP_ERROR;

	if (!tx_msg->len)
		return MCTP_ERROR;

	dev = get_mctp_i3c_dev(mctp_inst->medium_conf.i3c_conf.bus);
	data = (struct i3c_driver_data *)dev->data;
	desc = i3c_dev_list_i3c_addr_find(&data->attached_dev, mctp_inst->medium_conf.i3c_conf.addr);
	if (desc == NULL) {
		LOG_ERR("Device not found");
		return MCTP_ERROR;
	}

	xfer.flags = I3C_MSG_WRITE | I3C_MSG_STOP;
	xfer.buf = tx_msg->buf;
	xfer.len = tx_msg->len;
	LOG_DBG("write len : %d", xfer.len);
	LOG_HEXDUMP_DBG(xfer.buf, xfer.len, "i3c write : ");
	i3c_transfer(desc, &xfer, 1);

	return MCTP_SUCCESS;
}

int mctp_i3c_detach_slave_dev(uint8_t bus, uint64_t pid)
{
	const struct device *dev;
	struct i3c_device_desc *desc;
	const struct i3c_device_id i3c_id = I3C_DEVICE_ID(pid);
	mctp_i3c *mctp_i3c_inst;
	mctp *mctp_inst;
	struct mctp_interface_wrapper *mctp_wrapper;
	struct device_manager *device_mgr;

	if (pid != CONFIG_PFR_SPDM_I3C_BMC_DEV_PID && pid != CONFIG_PFR_SPDM_I3C_CPU0_DEV_PID &&
			pid != CONFIG_PFR_SPDM_I3C_CPU1_DEV_PID) {
		LOG_ERR("Invalid i3c pid");
		goto error;
	}

	dev = get_mctp_i3c_dev(bus);
	if (dev == NULL) {
		LOG_ERR("Failed to open i3c device");
		goto error;
	}

	desc = i3c_device_find(dev, &i3c_id);
	if (desc == NULL) {
		LOG_ERR("Failed to find i3c device");
		goto error;
	}

	if (pid == CONFIG_PFR_SPDM_I3C_BMC_DEV_PID) {
		mctp_i3c_inst = &mctp_i3c_bmc_inst;
	} else if (pid == CONFIG_PFR_SPDM_I3C_CPU0_DEV_PID) {
		mctp_i3c_inst = &mctp_i3c_cpu0_inst;
	} else if (pid == CONFIG_PFR_SPDM_I3C_CPU1_DEV_PID) {
		mctp_i3c_inst = &mctp_i3c_cpu1_inst;
	} else {
		goto error;
	}
	if (mctp_i3c_inst->state != MCTP_I3C_TARGET_ATTACHED) {
		LOG_WRN("Device is not attached");
		goto error;
	}

	k_timer_stop(&mctp_i3c_inst->i3c_state_timer);
	mctp_inst = mctp_i3c_inst->mctp_inst;
	mctp_wrapper = &mctp_inst->mctp_wrapper;
	device_mgr = mctp_wrapper->mctp_interface.device_manager;

	device_manager_update_device_state(device_mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM, DEVICE_MANAGER_SEND_DISCOVERY_NOTIFY);
	mctp_i3c_inst->state = MCTP_I3C_TARGET_INITIALIZED_DETACHED;

	return 0;
error:
	return -1;
}

static void mctp_i3c_req_timeout_callback(struct k_timer *tmr)
{
	trigger_mctp_i3c_state_handler();
}

#define IBI_MDB_GROUP                           GENMASK(7, 5)
#define   IBI_MDB_GROUP_PENDING_READ_NOTI       5
int mctp_i3c_ibi_cb(struct i3c_device_desc *target, struct i3c_ibi_payload *payload)
{
        if (payload->payload_len) {
		LOG_HEXDUMP_DBG(payload->payload, payload->payload_len, "IBI payload:");

                if (FIELD_GET(IBI_MDB_GROUP, payload->payload[0]) ==
                    IBI_MDB_GROUP_PENDING_READ_NOTI) {
			mctp_i3c_sem_give(target);
                }
        }

        return 0;
}

uint8_t mctp_i3c_init(mctp *mctp_instance, mctp_medium_conf medium_conf)
{
	if (mctp_instance == NULL)
		return MCTP_ERROR;

	mctp_instance->medium_conf = medium_conf;
	mctp_instance->read_data = mctp_i3c_read;
	mctp_instance->write_data = mctp_i3c_write;

	return MCTP_SUCCESS;
}

uint8_t mctp_i3c_eid_assignment_thread_create(mctp_i3c *mctp_i3c_inst)
{

	mctp_i3c_inst->i3c_state_tid = k_thread_create(&mctp_i3c_inst->i3c_state_thread,
			mctp_i3c_inst->i3c_state_handler_stack,
			MCTP_I3C_STATE_HANDLER_STACK_SIZE,
			mctp_i3c_state_handler,
			mctp_i3c_inst, NULL, NULL, 5, 0, K_NO_WAIT);

	snprintf(mctp_i3c_inst->i3c_state_task_name, sizeof(mctp_i3c_inst->i3c_state_task_name),
			"MCTP I3C State Handler B%02xA%02x",
			mctp_i3c_inst->mctp_inst->medium_conf.i3c_conf.bus,
			mctp_i3c_inst->mctp_inst->medium_conf.i3c_conf.addr);
	k_thread_name_set(mctp_i3c_inst->i3c_state_tid, mctp_i3c_inst->i3c_state_task_name);

	return 0;
}

void mctp_i3c_state_expiry_fn(struct k_timer *tmr)
{
	struct k_sem *state_sem;
	state_sem = (struct k_sem *)k_timer_user_data_get(tmr);
	k_sem_give(state_sem);
}

uint8_t mctp_i3c_deinit(mctp *mctp_instance)
{
	if (mctp_instance == NULL)
		return MCTP_ERROR;

	mctp_instance->read_data = NULL;
	mctp_instance->write_data = NULL;
	memset(&mctp_instance->medium_conf, 0, sizeof(mctp_instance->medium_conf));
	return MCTP_SUCCESS;
}

int mctp_i3c_attach_target_dev(uint8_t bus, uint64_t pid)
{
	struct i3c_device_desc *desc;
	struct i3c_ccc_mrl mrl;
	const struct device *dev;
	const struct i3c_device_id i3c_id = I3C_DEVICE_ID(pid);
	mctp_i3c *mctp_i3c_inst;
	mctp *mctp_inst;
	int mctp_channel_id;
	int rc;

	if (pid != CONFIG_PFR_SPDM_I3C_BMC_DEV_PID &&
			pid != CONFIG_PFR_SPDM_I3C_CPU0_DEV_PID &&
			pid != CONFIG_PFR_SPDM_I3C_CPU1_DEV_PID) {
		LOG_ERR("Invalid i3c pid");
		goto error;
	}

	dev = get_mctp_i3c_dev(bus);
	if (dev == NULL) {
		LOG_ERR("Failed to open i3c device");
		goto error;
	}

	desc = i3c_device_find(dev, &i3c_id);
	if (desc == NULL) {
		LOG_ERR("Failed to find i3c device");
		goto error;
	}

	if (pid == CONFIG_PFR_SPDM_I3C_BMC_DEV_PID) {
		if (mctp_i3c_bmc_inst.mctp_inst == NULL) {
			mctp_i3c_bmc_inst.state = MCTP_I3C_TARGET_DETACHED;
			mctp_i3c_bmc_inst.mctp_inst = mctp_init();
		}
		mctp_i3c_inst = &mctp_i3c_bmc_inst;
	} else if (pid == CONFIG_PFR_SPDM_I3C_CPU0_DEV_PID) {
		if (mctp_i3c_cpu0_inst.mctp_inst == NULL) {
			mctp_i3c_cpu0_inst.state = MCTP_I3C_TARGET_DETACHED;
			mctp_i3c_cpu0_inst.mctp_inst = mctp_init();
		}
		mctp_i3c_inst = &mctp_i3c_cpu0_inst;
		mrl.len = 0x45;
		mrl.ibi_len = 2;
		i3c_ccc_do_setmrl(desc, &mrl);
	} else if (pid == CONFIG_PFR_SPDM_I3C_CPU1_DEV_PID) {
		if (mctp_i3c_cpu1_inst.mctp_inst == NULL) {
			mctp_i3c_cpu1_inst.state = MCTP_I3C_TARGET_DETACHED;
			mctp_i3c_cpu1_inst.mctp_inst = mctp_init();
		}
		mctp_i3c_inst = &mctp_i3c_cpu1_inst;
		mrl.len = 0x45;
		mrl.ibi_len = 2;
		i3c_ccc_do_setmrl(desc, &mrl);
	} else {
		goto error;
	}

	desc->ibi_cb = mctp_i3c_ibi_cb;
	if (i3c_ibi_enable(desc)) {
		LOG_ERR("Failed to enable ibi");
		goto error;
	}

	mrl.len = 0x45;
	mrl.ibi_len = 2;
	int ret = ret = i3c_ccc_do_setmrl(desc, &mrl);
	if (mctp_i3c_inst->state == MCTP_I3C_TARGET_ATTACHED) {
		LOG_WRN("I3C device is attached");
		return 0;
	}

	mctp_inst = mctp_i3c_inst->mctp_inst;
	if (mctp_inst == NULL)
		goto error;


	mctp_set_medium_configure(mctp_inst, MCTP_MEDIUM_TYPE_I3C, mctp_inst->medium_conf);
	mctp_inst->medium_conf.i3c_conf.bus = bus;
	mctp_inst->medium_conf.i3c_conf.addr = desc->dynamic_addr;
	mctp_channel_id = CMD_CHANNEL_I3C_BASE | mctp_inst->medium_conf.i3c_conf.bus;
	rc = cmd_channel_mctp_init(&mctp_inst->mctp_cmd_channel,
			mctp_channel_id);
	if (rc != MCTP_SUCCESS) {
		LOG_ERR("I3C Command Channel initialization failed");
		goto error;
	}

	rc = mctp_i3c_wrapper_init(&mctp_inst->mctp_wrapper, mctp_inst->medium_conf.i3c_conf.addr);
	if (rc != MCTP_SUCCESS) {
		LOG_ERR("I3C MCTP interface wrapper initialization failed");
		goto error;
	}

	mctp_interface_set_channel_id(&mctp_inst->mctp_wrapper.mctp_interface, mctp_channel_id);
	mctp_start(mctp_inst);
	if (mctp_i3c_inst->state == MCTP_I3C_TARGET_INITIALIZED_DETACHED) {
		k_sem_give(&mctp_i3c_inst->i3c_state_sem);
	} else {
		k_sem_init(&mctp_i3c_inst->i3c_state_sem, 1, 1);
		k_timer_init(&mctp_i3c_inst->i3c_state_timer, mctp_i3c_state_expiry_fn,
				NULL);
		k_timer_user_data_set(&mctp_i3c_inst->i3c_state_timer,
				&mctp_i3c_inst->i3c_state_sem);
		mctp_i3c_eid_assignment_thread_create(mctp_i3c_inst);
	}

	mctp_i3c_inst->state = MCTP_I3C_TARGET_ATTACHED;
	k_timer_start(&mctp_i3c_inst->i3c_state_timer, K_SECONDS(12), K_NO_WAIT);

	return 0;
error:
	if (pid == CONFIG_PFR_SPDM_I3C_BMC_DEV_PID) {
		if (mctp_i3c_bmc_inst.mctp_inst)
			free(mctp_i3c_bmc_inst.mctp_inst);
	} else if (pid == CONFIG_PFR_SPDM_I3C_CPU0_DEV_PID) {
		if (mctp_i3c_cpu0_inst.mctp_inst)
			free(mctp_i3c_cpu0_inst.mctp_inst);
	} else if (pid == CONFIG_PFR_SPDM_I3C_CPU1_DEV_PID) {
		if (mctp_i3c_cpu1_inst.mctp_inst)
			free(mctp_i3c_cpu1_inst.mctp_inst);
	}

	return -1;
}

void mctp_i3c_send_entdaa(uint8_t bus)
{
	const struct device *dev;

	dev = get_mctp_i3c_dev(bus);
	if (dev == NULL) {
		LOG_ERR("Failed to get i3c dev");
		return;
	}

	i3c_do_daa(dev);
}

void mctp_i3c_send_rstdaa(uint8_t bus)
{
	const struct device *dev;
	struct i3c_driver_data *data;
	sys_snode_t *node;

	dev = get_mctp_i3c_dev(bus);
	if (dev == NULL) {
		LOG_ERR("Failed to get i3c dev");
		return;
	}

	data = dev->data;
	i3c_ccc_do_rstdaa_all(dev);

	/* reset all devices DA */
	if (!sys_slist_is_empty(&data->attached_dev.devices.i3c)) {
		SYS_SLIST_FOR_EACH_NODE(&data->attached_dev.devices.i3c, node) {
			struct i3c_device_desc *desc =
				CONTAINER_OF(node, struct i3c_device_desc, node);
			desc->dynamic_addr = 0;
			LOG_INF("Reset dynamic address for device %s", desc->dev->name);
                  }
          }
}

// The function is used to configure RG3MxxB12 i3c hub
int mctp_i3c_hub_configuration(void)
{
	const struct device *dev;
	struct i3c_device_desc* desc;
	struct i3c_msg xfer;
	uint8_t i3c_conf_buf[2] = {0x10, 0x69};
	uint8_t read_back[1] = {0};
	uint64_t pid = CONFIG_PFR_SPDM_I3C_HUB_DEV_PID;
	const struct i3c_device_id i3c_id = I3C_DEVICE_ID(pid);

	LOG_INF("Configuring I3C hub");
	dev = get_mctp_i3c_dev(CONFIG_PFR_SPDM_CPU_I3C_BUS);
	desc = i3c_device_find(dev, &i3c_id);
	if (desc == NULL) {
		LOG_ERR("I3C Hub not found");
		goto end;
	}

	desc->ibi_cb = mctp_i3c_ibi_cb;
	xfer.flags = I3C_MSG_WRITE | I3C_MSG_STOP;
	xfer.buf = i3c_conf_buf;
	xfer.len = sizeof(i3c_conf_buf);

	// 79 c7
	i3c_conf_buf[0] = 0x79;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);
	LOG_INF("Hub power good status : %x", read_back[0]);

	// 10 69
	i3c_conf_buf[0] = 0x10;
	i3c_conf_buf[1] = 0x69;
	if (i3c_transfer(desc, &xfer, 1)) {
		LOG_ERR("Failed to unlock register protection");
		goto end;
	}

	//read PID reg 2 ~ 7
	// uint8_t pid_reg[1] = {2};
	// for (int i = 2; i < 8; i++) {
	// 	pid_reg[0] = i;
	// 	i3c_write_read(desc, pid_reg, 1, read_back, 1);
	// 	LOG_INF("pid = %x", read_back[0]);
	// }

	// 16 00
	i3c_conf_buf[0] = 0x16;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);

	// 19 50
	i3c_conf_buf[0] = 0x19;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);

	// 16 00
	i3c_conf_buf[0] = 0x16;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);

	// 19 50
	i3c_conf_buf[0] = 0x19;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);

	// 14 00
	i3c_conf_buf[0] = 0x14;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);

	// 14 00
	i3c_conf_buf[0] = 0x14;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);
	if (read_back[0] != 0xf) {
		// 14 0f
		i3c_conf_buf[0] = 0x14;
		i3c_conf_buf[1] = 0x0f;
		if (i3c_transfer(desc, &xfer, 1)) {
			LOG_ERR("Failed to setup io drive strength");
			goto end;
		}
	}

	// 19 50
	i3c_conf_buf[0] = 0x19;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);
	if (read_back[0] != 0xf0) {
		// 19 f0
		i3c_conf_buf[0] = 0x19;
		i3c_conf_buf[1] = 0xf0;
		if (i3c_transfer(desc, &xfer, 1)) {
			LOG_ERR("Failed to disable LDO");
			goto end;
		}
	}

	// 17 ff
	i3c_conf_buf[0] = 0x17;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);
	if (read_back[0] != 0x0) {
		// 17 00
		xfer.len = sizeof(i3c_conf_buf);
		i3c_conf_buf[0] = 0x17;
		i3c_conf_buf[1] = 0x00;
		if (i3c_transfer(desc, &xfer, 1)) {
			LOG_ERR("Failed to enable compatible mode");
			goto end;
		}
	}

	// 53 ff
	i3c_conf_buf[0] = 0x53;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);
	if (read_back[0] != 0xff) {
		i3c_conf_buf[0] = 0x53;
		i3c_conf_buf[1] = 0xff;
		if (i3c_transfer(desc, &xfer, 1)) {
			LOG_ERR("Failed to setup pull up resistor connection");
			goto end;
		}
	}

	// 18 00
	i3c_conf_buf[0] = 0x18;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);
	if (read_back[0] != 0) {
		i3c_conf_buf[0] = 0x18;
		i3c_conf_buf[1] = 0x00;
		if (i3c_transfer(desc, &xfer, 1)) {
			LOG_ERR("Failed to disable SMBus agent");
			goto end;
		}
	}

	// 1e 00
	i3c_conf_buf[0] = 0x1e;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);
	if (read_back[0] != 0) {
		i3c_conf_buf[0] = 0x1e;
		i3c_conf_buf[1] = 0x00;
		if (i3c_transfer(desc, &xfer, 1)) {
			LOG_ERR("Failed to disable GPIO mode");
			goto end;
		}
	}

	// 38 01
	i3c_conf_buf[0] = 0x38;
	i3c_conf_buf[1] = 0x01;
	if (i3c_transfer(desc, &xfer, 1)) {
		LOG_ERR("Failed to request HUB control");
		goto end;
	}

	// 12 00
	i3c_conf_buf[0] = 0x12;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);
	if (read_back[0] != 5) {
		// 12 05
		i3c_conf_buf[0] = 0x12;
		i3c_conf_buf[1] = 0x05;
		if (i3c_transfer(desc, &xfer, 1)) {
			LOG_ERR("Failed to enable ports");
			goto end;
		}
	}

	// 51 00
	i3c_conf_buf[0] = 0x51;
	i3c_write_read(desc, i3c_conf_buf, 1, read_back, 1);
	if (read_back[0] != 5) {
		// 51 05
		if (i3c_transfer(desc, &xfer, 1)) {
			LOG_ERR("Failed to setup slave port connection");
			goto end;
		}
	}

	// 10 00
	i3c_conf_buf[0] = 0x10;
	i3c_conf_buf[1] = 0x00;
	if (i3c_transfer(desc, &xfer, 1)) {
		LOG_ERR("Failed to lock register protection");
		goto end;
	}

	LOG_INF("I3C hub initialization succeed");
	return 0;
end:
	LOG_ERR("Failed to configure i3c hub");
	return -1;
}

void mctp_i3c_configure_cpu_i3c_devs(void)
{
	if (!is_pltrst_sync())
		return;
	if (get_i3c_mng_owner() == I3C_MNG_OWNER_ROT) {
		LOG_INF("Enable CPU i3c");
		if (!i3c_hub_configured) {
			mctp_i3c_send_rstdaa(CONFIG_PFR_SPDM_CPU_I3C_BUS);
			mctp_i3c_send_entdaa(CONFIG_PFR_SPDM_CPU_I3C_BUS);
			if (mctp_i3c_hub_configuration())
				return;
			i3c_hub_configured = true;
		}
		mctp_i3c_send_rstdaa(CONFIG_PFR_SPDM_CPU_I3C_BUS);
		mctp_i3c_send_entdaa(CONFIG_PFR_SPDM_CPU_I3C_BUS);

		mctp_i3c_attach_target_dev(CONFIG_PFR_SPDM_CPU_I3C_BUS,
				CONFIG_PFR_SPDM_I3C_CPU0_DEV_PID);
		mctp_i3c_attach_target_dev(CONFIG_PFR_SPDM_CPU_I3C_BUS,
				CONFIG_PFR_SPDM_I3C_CPU1_DEV_PID);
	}
}
