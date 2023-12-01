/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr/portability/cmsis_os2.h>
#include <zephyr/storage/flash_map.h>
#include <aspeed_util.h>

#include "SPDM/SPDMRequester.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "SPDM/SPDMCommon.h"
#include "SPDM/RequestCmd/SPDMRequestCmd.h"

#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "include/SmbusMailBoxCom.h"
#include "mctp/mctp_base_protocol.h"
#include "AspeedStateMachine/AspeedStateMachine.h"

#define SPDM_REQUESTER_STACK_SIZE 1024
#define SPDM_REQUESTER_PRIO 3

LOG_MODULE_REGISTER(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

static void spdm_attester_tick(struct k_timer *timeer);

osEventFlagsId_t spdm_attester_event;
K_TIMER_DEFINE(spdm_attester_timer, spdm_attester_tick, NULL);

/* Storing the offset in afm_act_1 partition */
static off_t afm_list[CONFIG_PFR_SPDM_ATTESTATION_MAX_DEVICES] = {0};

enum ATTEST_RESULT {
	ATTEST_SUCCEEDED,
	ATTEST_FAILED_VCA = 1,
	ATTEST_FAILED_DIGEST = 2,
	ATTEST_FAILED_CERTIFICATE = 3,
	ATTEST_FAILED_CHALLENGE_AUTH = 4,
	ATTEST_FAILED_MEASUREMENTS_MISMATCH = 5,
};

void spdm_stop_attester()
{
	k_timer_stop(&spdm_attester_timer);
	osEventFlagsClear(spdm_attester_event, SPDM_REQ_EVT_T0);
}

uint32_t spdm_get_attester()
{
	return osEventFlagsGet(spdm_attester_event);
}

void spdm_request_tick()
{
	osEventFlagsSet(spdm_attester_event, SPDM_REQ_EVT_TICK);
}

int spdm_send_request(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	int ret;

	if (context->send_recv != NULL) {
		ret = context->send_recv(ctx, req_msg, rsp_msg);
	} else {
		// TODO: timeout required!
		context->send(ctx, req_msg, sizeof(req_msg->header) + req_msg->buffer.size);

		size_t length;
		context->recv(ctx, rsp_msg, &length);
		ret = 0;
	}
	return ret;
}

static int spdm_attest_device(void *ctx, AFM_DEVICE_STRUCTURE *afm_body)
{
	int ret = 0;
	struct spdm_context *context = (struct spdm_context *)ctx;

	do {
		if (context == NULL)
			break;

		// TODO: Get from context->connetion_data
		uint8_t bus=0, eid=0;

		/* VCA: Initiate Connection */
		ret = spdm_get_version(context);
		if (ret < 0) {
			LOG_ERR("SPDM[%d,%02x] GET_VERSION Failed", bus, eid);
			ret = ATTEST_FAILED_VCA;
			break;
		}
		ret = spdm_get_capabilities(context);
		if (ret < 0) {
			LOG_ERR("SPDM[%d,%02x] GET_CAPABILITIES Failed", bus, eid);
			ret = ATTEST_FAILED_VCA;
			break;
		}
		ret = spdm_negotiate_algorithms(context);
		if (ret < 0) {
			LOG_ERR("SPDM[%d,%02x] NEGOTIATE_ALGORITHMS Failed", bus, eid);
			ret = ATTEST_FAILED_VCA;
			break;
		}

		/* Device identities */
		if (context->remote.capabilities.flags & SPDM_CERT_CAP) {
			ret = spdm_get_digests(context);
			if (ret != 0) {
				ret = ATTEST_FAILED_DIGEST;
				break;
			}

			for (uint8_t slot_id = 0; slot_id < 8; ++slot_id) {
				if (context->remote.certificate.slot_mask & (1 << slot_id)) {
					LOG_INF("Getting Certificate Slot[%d]", slot_id);
					ret = spdm_get_certificate(context, slot_id);
					if (ret != 0) {
						LOG_ERR("SPDM[%d,%02x] GET_CERTIFICATE Failed", bus, eid);
						break;
					}
				}
			}
			if (ret != 0) {
				ret = ATTEST_FAILED_CERTIFICATE;
				break;
			}
		} else {
			LOG_ERR("SPDM[%d,%02x] Device doesn't support GET_CERTIFICATE", bus, eid);
			break;
		}

		/* Device Authentication */
		ret = spdm_challenge(context, 0x01, 0x00);
		if (ret < 0) {
			LOG_ERR("SPDM[%d,%02x] CHALLENGE Failed", bus, eid);
			ret = ATTEST_FAILED_CHALLENGE_AUTH;
			break;
		}

		/* Device Attestation */
		uint8_t number_of_blocks = 0, measurement_block;
		bool signature_verified = false;

		spdm_context_reset_l1l2_hash(context);
		if (context->local.version.version_number_selected == SPDM_VERSION_12) {
			LOG_HEXDUMP_INF(context->message_a.data, context->message_a.write_ptr, "VCA");
			spdm_context_update_l1l2_hash_buffer(context, &context->message_a);
		}
		ret = spdm_get_measurements(context, 0,
				SPDM_MEASUREMENT_OPERATION_TOTAL_NUMBER, &number_of_blocks, NULL);

		if (ret != 0 || number_of_blocks < afm_body->TotalMeasurements) {
			LOG_ERR("AFM expecting %d but got %d measurements",
					afm_body->TotalMeasurements, number_of_blocks);

			ret = ATTEST_FAILED_MEASUREMENTS_MISMATCH;
			break;
		}

		uint8_t afm_index = 0;
		uint8_t meas_index = 0;
		AFM_DEVICE_MEASUREMENT_VALUE *possible_measure = afm_body->Measurements;
		uint8_t request_attribute = 0;
		if (context->remote.capabilities.flags & SPDM_MEAS_CAP_SIG) {
			request_attribute = SPDM_MEASUREMENT_REQ_ATTR_GEN_SIGNATURE;
		}

		/* This is Intel EGS style of measurement attestation, the AFM device structure
		 * doesn't contain measurement block index, so we need to scan through it.
		 *
		 * TODO: In Intel BHS, the AFM device structure has extended to include
		 * measurement block index, so we could directly ask for it.
		 */
		while (afm_body->TotalMeasurements != afm_index) {
			if (++meas_index == SPDM_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
				/* Reach the end of measurement */
				LOG_ERR("Measurement block reach to the end");
				break;
			}

			ret = spdm_get_measurements(context, request_attribute, meas_index,
					&measurement_block, possible_measure);
			LOG_DBG("spdm_get_measurements idx=%d ret=%d", meas_index, ret);
			if (ret == 0) {
				/* Measurement and signature matched */
				LOG_INF("AFM[%02x] measured at measurement block [%02x]", afm_index, meas_index);
				afm_index++;
				if (afm_index == afm_body->TotalMeasurements) {
					signature_verified = true;
					break;
				} else {
					possible_measure = (AFM_DEVICE_MEASUREMENT_VALUE *)(
						(uint8_t *)possible_measure + 4 +
						possible_measure->ValueSize * possible_measure->PossibleMeasurements);
				}
			} else if (ret == -1) {
				/* Measurement not found check next one */
				LOG_DBG("AFM[%02x] measurement block [%02x] not exist", afm_index, meas_index);
			} else if (ret == -2) {
				/* Signature invalid */
				signature_verified = false;
				break;
			} else {
				LOG_ERR("AFM[%02x] measurement block [%02x] failed", afm_index, meas_index);
				break;
			}

		}

		if (signature_verified == false) {
			/* Recovery the firmware ?? */
			ret = ATTEST_FAILED_MEASUREMENTS_MISMATCH;
			break;
		}
	} while (0);

	return ret;
}

static void spdm_attester_tick(struct k_timer *timeer)
{
	spdm_request_tick();
}

void spdm_attester_main(void *a, void *b, void *c)
{
	static uint8_t buffer[CONFIG_PFR_SPDM_ATTESTATION_DEVICE_OFFSET] NON_CACHED_BSS_ALIGN16;
	uint32_t events;

	osEventFlagsWait(spdm_attester_event, SPDM_REQ_EVT_ENABLE, osFlagsNoClear, osWaitForever);
	LOG_INF("SPDM Attester Thread Enabled");

	uint32_t RUNNING_COUNT = 0;
	while(1) {
		/* Wait for the next tick */
		events = osEventFlagsWait(spdm_attester_event,
				SPDM_REQ_EVT_TICK | SPDM_REQ_EVT_T0 | SPDM_REQ_EVT_ENABLE,
				osFlagsWaitAll | osFlagsNoClear,
				osWaitForever);
		LOG_INF("Start SPDM attestation events=%08x count=%u", events, ++RUNNING_COUNT);

		const struct flash_area *afm_flash;
		int ret = flash_area_open(FIXED_PARTITION_ID(afm_act_1_partition), &afm_flash);
		if (ret != 0) {
			LOG_ERR("Unable to open afm partition ret=%d", ret);
			continue;
		}

		for (size_t device = 0; device < CONFIG_PFR_SPDM_ATTESTATION_MAX_DEVICES; ++device) {
			/* Make sure current state can run attestation */
			events = osEventFlagsGet(spdm_attester_event);
			if (!(events & SPDM_REQ_EVT_T0)) {
				/* Attestation is stopped by Aspeed State Machine */
				LOG_ERR("T0 FLAG is cleared. Stop attestation at device[%d]", device);
				break;
			}

			if (afm_list[device]) {
				AFM_DEVICE_STRUCTURE *afm_device = (AFM_DEVICE_STRUCTURE *)buffer;

				ret = flash_area_read(afm_flash,
						afm_list[device],
						buffer,
						CONFIG_PFR_SPDM_ATTESTATION_DEVICE_OFFSET);

				LOG_INF("Attestation device[%d][%08x] events=%08x",
						device, afm_list[device], events);
				LOG_INF("UUID=%04x, BusId=%02x, DeviceAddress=%02x, BindingSpec=%02x, Policy=%02x",
						afm_device->UUID,
						afm_device->BusID,
						afm_device->DeviceAddress,
						afm_device->BindingSpec,
						afm_device->Policy);

				if (!(events & SPDM_REQ_EVT_T0_I3C) && afm_device->BindingSpec == SPDM_MEDIUM_I3C) {
					LOG_WRN("I3C Discovery not done, skip attestation");
					continue;
				}

				/* Create context */
				struct spdm_context *context = NULL;
				int ret;

				/* DEST_EID using NULL EID due to AFM device structure design */
				context = spdm_context_create();
				if (context == NULL) {
					LOG_ERR("Failed to allocate SPDM Context");
					continue;
				}
				ret = init_requester_context(context,
						afm_device->BindingSpec,
						afm_device->BusID,
						afm_device->DeviceAddress,
						MCTP_BASE_PROTOCOL_NULL_EID);
				if (ret) {
					/* Attested the device */
					ret = spdm_attest_device(context, afm_device);
					union aspeed_event_data event;
					/* Defined in Intel SPEC
					 * AFM1: CPU0 (1-based, but device in 0-based)
					 * AFM2: CPU1
					 * AFM3: BMC
					 * afmn: Devices 
					 */
					event.bit8[0] = device;
					event.bit8[1] = afm_device->BindingSpec; 
					event.bit8[2] = afm_device->Policy;
					event.bit8[3] = ret;

					/* Check Policy */
#if defined(CONFIG_PFR_MCTP_I3C)
					if (afm_device->BindingSpec == SPDM_MEDIUM_I3C) {
						if (ret == ATTEST_SUCCEEDED) {
							osEventFlagsSet(spdm_attester_event, SPDM_REQ_EVT_ATTESTED_CPU);
						} else {
							osEventFlagsClear(spdm_attester_event, SPDM_REQ_EVT_ATTESTED_CPU);
						}
					}
#endif

					switch (ret) {
						case ATTEST_SUCCEEDED:
							LOG_INF("ATTEST UUID[%04x] Succeeded", afm_device->UUID);
							break;
						case ATTEST_FAILED_VCA:
							/* Protocol Error */
							LOG_ERR("ATTEST UUID[%04x] Protocol Error", afm_device->UUID);
							LogErrorCodes(SPDM_PROTOCOL_ERROR_FAIL, SPDM_CONNECTION_FAIL);
							if (afm_device->Policy & BIT(2)) {
								/* Lock down in reset */
								GenerateStateMachineEvent(ATTESTATION_FAILED, event.ptr);
							}
							break;
						case ATTEST_FAILED_DIGEST:
							LOG_ERR("ATTEST UUID[%04x] Challenge Error", afm_device->UUID);
							LogErrorCodes(ATTESTATION_CHALLENGE_FAIL, SPDM_DIGEST_FAIL);
							if (afm_device->Policy & BIT(1)) {
								/* Lock down in reset */
								GenerateStateMachineEvent(ATTESTATION_FAILED, event.ptr);
							}
							break;
						case ATTEST_FAILED_CERTIFICATE:
							LOG_ERR("ATTEST UUID[%04x] Challenge Error", afm_device->UUID);
							LogErrorCodes(ATTESTATION_CHALLENGE_FAIL, SPDM_CERTIFICATE_FAIL);
							if (afm_device->Policy & BIT(1)) {
								/* Lock down in reset */
								GenerateStateMachineEvent(ATTESTATION_FAILED, event.ptr);
							}
							break;
						case ATTEST_FAILED_CHALLENGE_AUTH:
							/* Challenge Error */
							LOG_ERR("ATTEST UUID[%04x] Challenge Error", afm_device->UUID);
							LogErrorCodes(ATTESTATION_CHALLENGE_FAIL, SPDM_CHALLENGE_FAIL);
							if (afm_device->Policy & BIT(1)) {
								/* Lock down in reset */
								GenerateStateMachineEvent(ATTESTATION_FAILED, event.ptr);
							}
							break;
						case ATTEST_FAILED_MEASUREMENTS_MISMATCH:
							/* Measurement unexpected or mismatch */
							LOG_ERR("ATTEST UUID[%04x] Measurement Error", afm_device->UUID);
							LogErrorCodes(ATTESTATION_MEASUREMENT_FAIL, SPDM_MEASUREMENT_FAIL);
							if (afm_device->Policy & BIT(0)) {
								/* Lock down in reset */
								GenerateStateMachineEvent(ATTESTATION_FAILED, event.ptr);
							}
							break;
						default:
							break;
					}
				} else {
					LOG_ERR("Failed to initiate SPDM connection context");
				}
				spdm_context_release(context);
			}
		}
		osEventFlagsClear(spdm_attester_event, SPDM_REQ_EVT_TICK);
	}
}

void spdm_enable_attester()
{
	osEventFlagsSet(spdm_attester_event, SPDM_REQ_EVT_ENABLE);
}

void spdm_run_attester_i3c()
{
	LOG_WRN("Ready to run I3C Attestation");
	osEventFlagsSet(spdm_attester_event, SPDM_REQ_EVT_T0_I3C);
	spdm_request_tick();
}

void spdm_run_attester()
{
	/* AFM Active is already verified during Tmin1, and the AFM structure are
	 * aligned at 4KB, so we scan through the partition for it */

	const struct flash_area *afm_flash = NULL;
	int ret;
	int max_afm = CONFIG_PFR_SPDM_ATTESTATION_MAX_DEVICES;

	uint32_t event = osEventFlagsGet(spdm_attester_event);
	struct pfr_manifest *pfr_manifest = get_pfr_manifest();
	int offset = PFM_SIG_BLOCK_SIZE;

	if (pfr_manifest->hash_curve == hash_sign_algo384 || pfr_manifest->hash_curve == hash_sign_algo256)
		offset = LMS_PFM_SIG_BLOCK_SIZE;
	if (!(event & SPDM_REQ_EVT_ENABLE)) {
		LOG_WRN("SPDM Requester not enabled");
	} else if (!(event & SPDM_REQ_EVT_T0)) {
		ret = flash_area_open(FIXED_PARTITION_ID(afm_act_1_partition), &afm_flash);
		if (ret) {
			LOG_ERR("Failed to open AFM partition ret=%d", ret);
			return;
		}

		/* First page is the block0/block1, start from page 1. */
		for (uint8_t i = 1; i<max_afm; ++i) {
			uint32_t magic_num;
			ret = flash_area_read(afm_flash,
					i * CONFIG_PFR_SPDM_ATTESTATION_DEVICE_OFFSET,
					&magic_num, sizeof(magic_num));
			if (ret) {
				LOG_ERR("Failed to read AFM partition offset [%08x] ret=%d",
						i * CONFIG_PFR_SPDM_ATTESTATION_DEVICE_OFFSET, ret);
				afm_list[i] = 0x00000000;
				continue;
			}
			if (magic_num == BLOCK0TAG) {
				afm_list[i] = (i * CONFIG_PFR_SPDM_ATTESTATION_DEVICE_OFFSET) + offset;
				LOG_INF("Add afm device offset [%08x]", afm_list[i]);
				} else {
				/* Offset 0x0000 is block0/1 header not AFM device structure,
				 * so use this value as an empty slot */
				afm_list[i] = 0x00000000;
			}
		}


		osEventFlagsSet(spdm_attester_event, SPDM_REQ_EVT_T0);

		k_timer_start(&spdm_attester_timer,
				K_SECONDS(CONFIG_PFR_SPDM_ATTESTATION_DURATION),
				K_SECONDS(CONFIG_PFR_SPDM_ATTESTATION_PERIOD));
	}
}

