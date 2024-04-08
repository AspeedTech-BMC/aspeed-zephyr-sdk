/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509.h>
#include <mbedtls/ecp.h>

#include <soc.h>
#include <zephyr/portability/cmsis_os2.h>

#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMMctpBinding.h"

// Root CA
#include "Certificates/ca.cert.der.h"
#include "Certificates/ca1.cert.der.h"
#include "Certificates/inter.cert.der.h"
#include "Certificates/inter1.cert.der.h"

// Private/Public key pair
#include "Certificates/end_responder.key.der.h"

// Certificate Chain
#include "Certificates/bundle_responder.certchain.der.h"
#include "Certificates/bundle_responder.certchain1.der.h"

LOG_MODULE_REGISTER(spdm, CONFIG_LOG_DEFAULT_LEVEL);


#define SHA384_HASH_LENGTH 			(384 / 8)
#define ECDSA384_PRIVATE_KEY_SIZE         SHA384_HASH_LENGTH + 1
#define ECDSA384_PUBLIC_KEY_SIZE          SHA384_HASH_LENGTH * 2 + 1

#include <zephyr/storage/flash_map.h>
#include <mbedtls/sha512.h>

int get_measurement_by_index(uint8_t measurement_index, uint8_t *measurement, size_t *measurement_size)
{
	/* Calculate specific measurement */
	const struct flash_area *area_measured = NULL;
	size_t area_size = 0;

	int ret;

	/* TODO: Measurement blocks
	 * 1: MCUBoot bootloader, measured by secure boot engine (ROT)
	 * 2: Primary firmware, measured by MCUBoot bootloader (COT1)
	 * 3: Secondary firmware, measured by MCUBoot bootloader (COT2)
	 */

	LOG_INF("MEASURE Index[%d]", measurement_index);
	switch (measurement_index) {
		case 1:
			ret = flash_area_open(FIXED_PARTITION_ID(active_partition), &area_measured);
			area_size = FIXED_PARTITION_SIZE(active_partition);
			break;
#if 0
		case 2:
			ret = flash_area_open(FIXED_PARTITION_ID(active_partition), &area_measured);
			area_size = FIXED_PARTITION_SIZE(active_partition);
			break;
		case 3:
			ret = flash_area_open(FIXED_PARTITION_ID(recovery_partition), &area_measured);
			area_size = FIXED_PARTITION_SIZE(recovery_partition);
			break;
#endif
		default:
			ret = -1;
			break;
	}

	if (ret != 0) {
		LOG_ERR("Failed to open flash area");
		*measurement_size = 0;
		return -1;
	}


	mbedtls_sha512_context sha_ctx;
	mbedtls_sha512_init(&sha_ctx);
	mbedtls_sha512_starts(&sha_ctx, 1 /* SHA-384 */);

	size_t offset = 0, read_size;
	static uint8_t buffer[4096] NON_CACHED_BSS_ALIGN16;
	while (offset < area_size) {
		read_size = (area_size - offset) > sizeof(buffer) ?
			sizeof(buffer) : (area_size - offset);
		ret = flash_area_read(area_measured, offset, buffer, read_size);
		if (ret != 0) {
			LOG_ERR("flash_area_read offset=0x%x read_size=%d ret=%d", offset, read_size, ret);
			break;
		}
		mbedtls_sha512_update(&sha_ctx, buffer, read_size);
		offset += read_size;
	}
	flash_area_close(area_measured);

	/* Measurement block:
	 * 0x00 - Index, Shall represent the index of the measurement
	 * 0x01 - MeasurementSpecification (Bit[0] DMTF MeasurementSpec)
	 * 0x02 - MeasurementSize in bytes
	 * 0x04 - Measurement
	 *        0x00 - DMTFSpecMeasurementValueType
	 *               Bit[7]:   0b Hash, 1b Raw bit stream
	 *               Bit[6:0]: 00h Immutable ROM
	 *                         01h Mutable firmware
	 *                         02h Hardware configuration, such as straps, debug modes
	 *                         03h Firmware configuration, such as configurable firmware policy
	 *        0x01 - DMTFSpecMeasurementValueSize, uint16_t
	 *        0x03 - DMTFSpecMeasureMentValue
	 */
	measurement[0] = measurement_index;
	measurement[1] = SPDM_MEASUREMENT_BLOCK_DMTF_SPEC; // Bit 0=DMTF
	measurement[2] = 48;
	measurement[3] = 0;
	measurement[4 + 0] = SPDM_MEASUREMENT_BLOCK_DMTF_TYPE_MUTABLE_FIRMWARE; // Hashed mutable firmware
	measurement[4 + 1] = 48;
	measurement[4 + 2] = 0;
	mbedtls_sha512_finish(&sha_ctx, measurement + 4 + 3);

	mbedtls_sha512_free(&sha_ctx);
	LOG_HEXDUMP_DBG(measurement, 48+4, "Measurement SHA-384:");


	*measurement_size = 48+4;

	return 0;
}

int get_measurement(void *context,
		uint8_t measurement_index, uint8_t* measurement_count,
		uint8_t* measurement, size_t* measurement_size)
{
	int ret = 0;

	if (measurement_index == SPDM_MEASUREMENT_OPERATION_TOTAL_NUMBER) {
		/* Return the number of measurements in count */
		*measurement_count = 1;
		*measurement_size = 0;
	} else if (measurement_index == SPDM_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
		/* Calculate all measurements */
		size_t offset = 0, remain_size = *measurement_size;
		get_measurement_by_index(1, measurement + offset, measurement_size);
		offset += *measurement_size;
		remain_size -= *measurement_size;
		*measurement_size = remain_size;
#if 0
		get_measurement_by_index(2, measurement + offset, measurement_size);
		offset += *measurement_size;
		remain_size -= *measurement_size;
		*measurement_size = remain_size;
		get_measurement_by_index(3, measurement + offset, measurement_size);
		offset += *measurement_size;
		*measurement_count = 3;
		*measurement_size = offset;
#endif
	} else {
		ret = get_measurement_by_index(measurement_index, measurement, measurement_size);
		if (ret == 0)
			*measurement_count = 1;
		else
			*measurement_count = 0;
	}
	return ret;
}

bool init_requester_context(struct spdm_context *context, SPDM_MEDIUM medium, uint8_t bus, uint8_t dst_sa, uint8_t dst_eid)
{
	int ret;
	ret = spdm_mctp_init_req(context, medium, bus, dst_sa, dst_eid);
	if (ret == 0) {
		return false;
	}

	context->release_connection_data = spdm_mctp_release_req;

	/* Set private/public key pair for signing */
	ret = mbedtls_ecp_group_load(&context->key_pair.MBEDTLS_PRIVATE(grp),
			MBEDTLS_ECP_DP_SECP384R1);
	LOG_INF("mbedtls_ecp_group_load ret=%x", -ret);
	ret = mbedtls_mpi_read_binary(&context->key_pair.MBEDTLS_PRIVATE(d),
			end_responder_key_der + 8, 48);
	LOG_INF("mbedtls_mpi_read_binary ret=%x", -ret);
	ret = mbedtls_ecp_point_read_binary(&context->key_pair.MBEDTLS_PRIVATE(grp),
			&context->key_pair.MBEDTLS_PRIVATE(Q),
			end_responder_key_der + end_responder_key_der_len - 97,  97);
	LOG_INF("mbedtls_ecp_point_read_binary ret=%x", -ret);

	ret = mbedtls_ecp_check_pub_priv(
			&context->key_pair,
			&context->key_pair,
			context->random_callback,
			context);
	LOG_INF("mbedtls_ecp_check_pub_priv ret=%x", -ret);

	return true;
}

void init_responder_context(struct spdm_context *context)
{

	// Only load the leaf certificate for now
#if 1
	spdm_load_certificate(context, false, 0, bundle_responder_certchain_der, bundle_responder_certchain_der_len);
	spdm_load_certificate(context, false, 1, bundle_responder_certchain1_der, bundle_responder_certchain1_der_len);
#else
	spdm_load_certificate(context, false, 0, devid_cert_der, devid_cert_der_len);
	spdm_load_certificate(context, false, 1, alias_cert_der, alias_cert_der_len);
#endif
	context->get_measurement = get_measurement;

	int ret;
	ret = mbedtls_ecp_group_load(&context->key_pair.MBEDTLS_PRIVATE(grp),
			MBEDTLS_ECP_DP_SECP384R1);
	LOG_INF("mbedtls_ecp_group_load ret=%x", -ret);
	ret = mbedtls_mpi_read_binary(&context->key_pair.MBEDTLS_PRIVATE(d),
			end_responder_key_der + 8, 48);
	LOG_INF("mbedtls_mpi_read_binary ret=%x", -ret);
	ret = mbedtls_ecp_point_read_binary(&context->key_pair.MBEDTLS_PRIVATE(grp),
			&context->key_pair.MBEDTLS_PRIVATE(Q),
			end_responder_key_der + end_responder_key_der_len - 97,  97);
	LOG_INF("mbedtls_ecp_point_read_binary ret=%x", -ret);

	ret = mbedtls_ecp_check_pub_priv(&context->key_pair, &context->key_pair, context->random_callback, context);
	LOG_INF("mbedtls_ecp_check_pub_priv ret=%x", -ret);
}


#define SPDM_REQUESTER_PRIO 4
#define SPDM_REQUESTER_STACK_SIZE 8192
extern void spdm_requester_main(void *ctx, void *b, void *c);
extern void spdm_attester_main(void *ctx, void *b, void *c);
K_THREAD_STACK_DEFINE(spdm_requester_stack, SPDM_REQUESTER_STACK_SIZE);
struct k_thread spdm_requester_thread_data;
k_tid_t spdm_requester_tid;

struct spdm_context *context_rsp_oo;

void init_spdm()
{
	struct spdm_context *context_rsp = spdm_context_create();

	mbedtls_x509_crt_init(spdm_get_root_certificate());
	spdm_load_root_certificate(ca_cert_der, ca_cert_der_len);
	spdm_load_root_certificate(inter_cert_der, inter_cert_der_len);
	spdm_load_root_certificate(ca1_cert_der, ca1_cert_der_len);
	spdm_load_root_certificate(inter1_cert_der, inter1_cert_der_len);

	init_responder_context(context_rsp);
	context_rsp_oo = context_rsp;

	spdm_requester_tid = k_thread_create(
			&spdm_requester_thread_data,
			spdm_requester_stack,
			K_THREAD_STACK_SIZEOF(spdm_requester_stack),
			//spdm_requester_main,
			spdm_attester_main,
			NULL, NULL, NULL,
			SPDM_REQUESTER_PRIO, 0, K_NO_WAIT);
	k_thread_name_set(spdm_requester_tid, "SPDM REQ");

	extern osEventFlagsId_t spdm_attester_event;
	spdm_attester_event = osEventFlagsNew(NULL);
}

#if defined(CONFIG_SHELL)
#include <zephyr/shell/shell.h>
#include <zephyr/portability/cmsis_os2.h>
static int cmd_spdm_run(const struct shell *shell, size_t argc, char **argv)
{
	spdm_run_attester();
	return 0;
}

static int cmd_spdm_stop(const struct shell *shell, size_t argc, char **argv)
{
	spdm_stop_attester();
	return 0;
}

static int cmd_spdm_enable(const struct shell *shell, size_t argc, char **argv)
{
	spdm_enable_attester();
	return 0;
}

static int cmd_spdm_get(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t event = spdm_get_attester();
	shell_print(shell, "SPDM Event=%08x", event);
	return 0;
}

static int cmd_spdm_tick(const struct shell *shell, size_t argc, char **argv)
{
	spdm_request_tick();
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_spdm_cmds,
	SHELL_CMD(enable, NULL, "Stop attestation", cmd_spdm_enable),
	SHELL_CMD(run, NULL, "Run attestation", cmd_spdm_run),
	SHELL_CMD(stop, NULL, "Stop attestation", cmd_spdm_stop),
	SHELL_CMD(get, NULL, "Stop attestation", cmd_spdm_get),
	SHELL_CMD(tick, NULL, "Tick", cmd_spdm_tick),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(spdm, &sub_spdm_cmds, "SPDM Commands", NULL);
#endif
