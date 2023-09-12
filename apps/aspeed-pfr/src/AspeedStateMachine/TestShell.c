/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include <zephyr.h>
#include <sys/sys_heap.h>
#include <smf.h>
#include <shell/shell.h>
#include <logging/log.h>
#include <drivers/flash.h>
#include <drivers/misc/aspeed/abr_aspeed.h>
#include <drivers/i2c/pfr/i2c_filter.h>

#include "AspeedStateMachine/AspeedStateMachine.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "device.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#include "cerberus_pfr/cerberus_pfr_provision.h"
#endif
#include "flash/flash_aspeed.h"
#include "flash/flash_wrapper.h"
#include "gpio/gpio_aspeed.h"
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_util.h"

#include "sys/base64.h"
#include "net/net_ip.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/oid.h"
#include "mbedtls/base64.h"
#include "mbedtls/asn1write.h"
#include <crypto/hash.h>
#include <crypto/hash_aspeed.h>

LOG_MODULE_REGISTER(asm_test, LOG_LEVEL_DBG);

#if defined(CONFIG_ASPEED_STATE_MACHINE_SHELL)
static int cmd_asm_event(const struct shell *shell,
			size_t argc, char **argv, void *data)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	enum aspeed_pfr_event evt = (enum aspeed_pfr_event)((uint32_t)data & 0x000000FF);
	uint32_t evt_data = ((uint32_t)data & 0xFFFFFF00) >> 8;

	shell_print(shell, "Sending event[%d] evt_data[%08x]\n", evt, evt_data);
	GenerateStateMachineEvent(evt, (void *)evt_data);

	return 0;
}

static int cmd_asm_log(const struct shell *shell, size_t argc,
			char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	shell_print(shell, "Event Count = %d\n", event_log_idx);
	shell_hexdump(shell, event_log, sizeof(event_log));
	return 0;
}

static int cmd_asm_abr(const struct shell *shell, size_t argc,
			char **argv)
{
	if (argc > 1 && !strncmp(argv[1], "enable", 6)) {
		shell_print(shell, "Enable ABR FMCWDT2");
#define ABR_CTRL_REG    0x7e620064
		uint32_t reg_val;

		reg_val = sys_read32(ABR_CTRL_REG);
		reg_val |= BIT(0);
		sys_write32(reg_val, ABR_CTRL_REG);
	} else {
		shell_print(shell, "Disable ABR FMCWDT2");
		disable_abr_wdt();
	}

	return 0;
}

static int cmd_asm_flash_cmp(const struct shell *shell, size_t argc,
			char **argv)
{
	if (argc < 4) {
		shell_print(shell, "asm flash_cmp DEVICE OFFSET_A OFFSET_B LENGTH");
		return 0;
	}
	char *dev_name = argv[1];
	size_t offset_a = strtol(argv[2], NULL, 16);
	size_t offset_b = strtol(argv[3], NULL, 16);
	size_t length = strtol(argv[4], NULL, 16);

	shell_print(shell, "Hash Dev:%s Offset_A:%p Offset_B:%p Length:%p", dev_name, offset_a, offset_b, length);

	const struct device *dev = device_get_binding(dev_name);

	if (dev == NULL) {
		shell_print(shell, "Failed to bind device:%s", dev_name);
		return 0;
	}

	char buffer_a[128] = {0};
	char buffer_b[128] = {0};
	size_t byte_read = 0;

	while (byte_read <= length) {
		size_t len = MIN(128, length - byte_read);

		if (len == 0)
			break;
		flash_read(dev, offset_a + byte_read, buffer_a, len);
		flash_read(dev, offset_b + byte_read, buffer_b, len);
		if (memcmp(buffer_a, buffer_b, len) != 0) {
			LOG_ERR("Offset_A=%08x Offset_B=%08x Different", offset_a + byte_read, offset_b + byte_read);
			LOG_HEXDUMP_ERR(buffer_a, len, "Buffer A");
			LOG_HEXDUMP_ERR(buffer_b, len, "Buffer B");
		}
		byte_read += len;
	}

	return 0;
}

static int cmd_asm_flash_copy(const struct shell *shell, size_t argc,
			char **argv)
{
	if (argc < 5) {
		shell_print(shell, "asm flash_cmp DEVICE_SRC OFFSET_SRC DEVICE_DEST OFFSET_DEST LENGTH");
		return 0;
	}

	char *dev_name_a = argv[1];
	size_t offset_a = strtol(argv[2], NULL, 16);
	char *dev_name_b = argv[3];
	size_t offset_b = strtol(argv[4], NULL, 16);
	size_t length = strtol(argv[5], NULL, 16);

	shell_print(shell, "Hash Dev_src:%s Offset_src:%p Dev_dest:%s Offset_dest:%p Length:%p",
			dev_name_a, offset_a, dev_name_b, offset_b, length);

	const struct device *dev_a = device_get_binding(dev_name_a);
	const struct device *dev_b = device_get_binding(dev_name_b);

	if (dev_a == NULL) {
		shell_print(shell, "Failed to bind device:%s", dev_name_a);
		return 0;
	}

	if (dev_b == NULL) {
		shell_print(shell, "Failed to bind device:%s", dev_name_b);
		return 0;
	}

	char buffer_a[128] = {0};
	size_t byte_read = 0;

	flash_erase(dev_b, offset_b, length);

	while (byte_read <= length) {
		size_t len = MIN(128, length - byte_read);

		if (len == 0)
			break;
		flash_read(dev_a,  offset_a + byte_read, buffer_a, len);
		flash_write(dev_b, offset_b + byte_read, buffer_a, len);
		byte_read += len;
	}

	return 0;
}

static int cmd_asm_flash_rebind(const struct shell *shell, size_t argc,
			char **argv)
{
	if (argc != 2) {
		shell_print(shell, "asm flash_rebind spiN_csX");
		return 0;
	}

	const struct device *dev = device_get_binding(argv[1]);
	if (dev == NULL) {
		shell_print(shell, "Device %s not found", argv[1]);
		return 0;
	}

	int ret = spi_nor_re_init(dev);
	shell_print(shell, "spi_nor_re_init(%s) return %d", argv[1], ret);
	return 0;
}

static int cmd_asm_rot_recovery(const struct shell *shell, size_t argc,
			char **argv)
{
	uint8_t status;
	uint32_t region_size = pfr_spi_get_device_size(ROT_INTERNAL_RECOVERY);

	LOG_INF("Erase PFR Active region size=%08x", region_size);
	if (pfr_spi_erase_region(ROT_INTERNAL_ACTIVE, true, 0, region_size)) {
		LOG_ERR("Erase PFR active region failed");
		return 0;
	}

	LOG_INF("Copy PFR Recovery region to Active region");
	status = pfr_spi_region_read_write_between_spi(ROT_INTERNAL_RECOVERY, 0,
			ROT_INTERNAL_ACTIVE, 0, region_size);

	if (!status)
		LOG_INF("Copy PFR Recovery region to Active region done");
	else
		LOG_ERR("Recover PFR active region failed");

	return 0;
}

static int cmd_asm_ufm_status(const struct shell *shell, size_t argc,
			char **argv)
{
	CPLD_STATUS cpld_update_status;

	ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));

	shell_print(shell, "CpldStatus = 0x%02x", cpld_update_status.CpldStatus);
	shell_print(shell, "BmcStatus = 0x%02x", cpld_update_status.BmcStatus);
	shell_print(shell, "PchStatus = 0x%02x", cpld_update_status.PchStatus);
	shell_print(shell, "DecommissionFlag = 0x%02x", cpld_update_status.DecommissionFlag);
	shell_print(shell, "CpldRecovery = 0x%02x", cpld_update_status.CpldRecovery);
	shell_print(shell, "BmcToPchStatus = 0x%02x", cpld_update_status.BmcToPchStatus);

	shell_print(shell, "Region[0].ActiveRegion = %02x", cpld_update_status.Region[0].ActiveRegion);
	shell_print(shell, "Region[0].Recoveryregion = %02x", cpld_update_status.Region[0].Recoveryregion);

	shell_print(shell, "Region[1].ActiveRegion = %02x", cpld_update_status.Region[1].ActiveRegion);
	shell_print(shell, "Region[2].Recoveryregion = %02x", cpld_update_status.Region[1].Recoveryregion);

	shell_print(shell, "Region[1].ActiveRegion = %02x", cpld_update_status.Region[2].ActiveRegion);
	shell_print(shell, "Region[2].Recoveryregion = %02x", cpld_update_status.Region[2].Recoveryregion);

	shell_print(shell, "Attestation = %02x", cpld_update_status.AttestationFlag);


	return 0;
}

static void inject_spi_error(const struct shell *shell, uint32_t flag)
{
	/* Flag defined as:
	 * 0x0F000000: BMC Active PFM
	 * 0x00F00000: BMC Recovery
	 * 0x000F0000: BMC Staging
	 * 0x0000F000: PCH Staging in BMC Flash
	 * 0x00000F00: PCH Active PFM
	 * 0x000000F0: PCH Recovery
	 * 0x0000000F: PCH Staging
	 */
	if (flag & 0x0FFFF000) {
		/* BMC Flash */
		const struct device *dev_mon = device_get_binding("spi_m1");
		const struct device *dev_flash = device_get_binding("spi1_cs0");
		spim_ext_mux_config(dev_mon, SPIM_EXT_MUX_ROT);
		if (flag & 0x0F000000) {
			/* ACT */
			uint32_t address;
			ufm_read(PROVISION_UFM, BMC_ACTIVE_PFM_OFFSET,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "Erase dev:%s offset:%08x size:%08x",
					"spi1_cs0", address, 0x10000);
		}
		if (flag & 0x00F00000) {
			/* RCV */
			uint32_t address;
			ufm_read(PROVISION_UFM, BMC_RECOVERY_REGION_OFFSET,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "Erase dev:%s offset:%08x size:%08x",
					"spi1_cs0", address, 0x10000);
		}
		if (flag & 0x000F0000) {
			/* STG */
			uint32_t address;
			ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "Erase dev:%s offset:%08x size:%08x",
					"spi1_cs0", address, 0x10000);
		}
		if (flag & 0x0000F000) {
			/* PCH STG */
			uint32_t address;
			ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET + CONFIG_BMC_STAGING_SIZE,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "Erase dev:%s offset:%08x size:%08x",
					"spi1_cs0", address, 0x10000);
		}
		spim_ext_mux_config(dev_mon, SPIM_EXT_MUX_BMC_PCH);
	}

	if (flag & 0x00000FFF) {
		/* PCH Flash */
		const struct device *dev_mon = device_get_binding("spi_m3");
		const struct device *dev_flash = device_get_binding("spi2_cs0");
		spim_ext_mux_config(dev_mon, SPIM_EXT_MUX_ROT);
		if (flag & 0x00000F00) {
			/* ACT */
			uint32_t address;
			ufm_read(PROVISION_UFM, PCH_ACTIVE_PFM_OFFSET,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "erase dev:%s offset:%08x size:%08x",
					"spi2_cs0", address, 0x10000);
		}
		if (flag & 0x000000F0) {
			/* RCV */
			uint32_t address;
			ufm_read(PROVISION_UFM, PCH_RECOVERY_REGION_OFFSET,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "Erase dev:%s offset:%08x size:%08x",
					"spi2_cs0", address, 0x10000);
		}
		if (flag & 0x0000000F) {
			/* STG */
			uint32_t address;
			ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "Erase dev:%s offset:%08x size:%08x",
					"spi2_cs0", address, 0x10000);
		}
		spim_ext_mux_config(dev_mon, SPIM_EXT_MUX_BMC_PCH);
	}
}

static int cmd_asm_spi_error(const struct shell *shell,
			size_t argc, char **argv, void *data)
{
	shell_print(shell, "Test scenario:");
	shell_print(shell, "BMC[ACT:%c RCV:%c STG:%c P-STG:%c] PCH[ACT:%c RCV:%c STG:%c]",
			argv[0][0], argv[0][1], argv[0][2],
			argv[0][3], argv[0][4], argv[0][5], argv[0][6]);

	inject_spi_error(shell, (uint32_t)data);
	GenerateStateMachineEvent(RESET_DETECTED, NULL);

	return 0;
}

SHELL_SUBCMD_DICT_SET_CREATE(sub_event, cmd_asm_event,
	(INIT_DONE, INIT_DONE),
	(VERIFY_UNPROVISIONED, VERIFY_UNPROVISIONED),
	(VERIFY_FAILED, VERIFY_FAILED),
	(VERIFY_DONE, VERIFY_DONE),
	(RECOVERY_DONE, RECOVERY_DONE),
	(RECOVERY_FAILED, RECOVERY_FAILED),
	(RESET_DETECTED, RESET_DETECTED),
	(UPDATE_DONE, UPDATE_DONE),
	(UPDATE_FAILED, UPDATE_FAILED),
	(PROVISION_CMD, PROVISION_CMD),
	(WDT_TIMEOUT_BMC, (WDT_TIMEOUT | BMC_EVENT << 8)),
	(WDT_TIMEOUT_PCH, (WDT_TIMEOUT | PCH_EVENT << 8)),

	/* BMC Update Intent */
	(UPDATE_REQUESTED_BMC_BMC_ACT, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | BmcActiveUpdate << 16)))),
	(UPDATE_REQUESTED_BMC_BMC_RCV, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | BmcRecoveryUpdate << 16)))),
	(UPDATE_REQUESTED_BMC_PCH_ACT, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | PchActiveUpdate << 16)))),
	(UPDATE_REQUESTED_BMC_PCH_RCV, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | PchRecoveryUpdate << 16)))),
	(UPDATE_REQUESTED_BMC_PFR_ACT, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | HROTActiveUpdate << 16)))),
	(UPDATE_REQUESTED_BMC_PFR_RCV, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | HROTRecoveryUpdate << 16)))),
	(UPDATE_REQUESTED_BMC_PFR_ACTRCV, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | HROTActiveAndRecoveryUpdate << 16)))),

	/* PCH Update Intent */
	(UPDATE_REQUESTED_PCH_PCH_ACT, (UPDATE_REQUESTED | ((PchUpdateIntent << 8 | PchActiveUpdate << 16)))),
	(UPDATE_REQUESTED_PCH_PCH_RCV, (UPDATE_REQUESTED | ((PchUpdateIntent << 8 | PchRecoveryUpdate << 16))))
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	,(ATTESTATION_FAILED, ATTESTATION_FAILED)
#endif

);



SHELL_SUBCMD_DICT_SET_CREATE(sub_spi_error, cmd_asm_spi_error,
	(GGGGGGG, 0x00000000),
	(BGGGGGG, 0x0F000000),
	(GBGGGGG, 0x00F00000),
	(BBGGGGG, 0x0FF00000),
	(GGGGBGG, 0x00000F00),
	(GGGGGBG, 0x000000F0),
	(GGGGBBG, 0x00000FF0),
	(GGGGBBB, 0x00000FFF),
	(GGGBBBB, 0x0000FFFF),
	(BGGGBGG, 0x0F000F00),
	(BGGGBBG, 0x0F000FF0),
	(BBGGBGG, 0x0FF00F00),
	(BBGGBBG, 0x0FF00FF0),
	(BBGGBBB, 0x0FF00FFF),
	(BBBBBBB, 0x0FFFFFFF)
);

static int cmd_test_plat_state_led(const struct shell *shell, size_t argc,
			char **argv)
{
	if (argc != 2) {
		shell_print(shell, "asm pstate STATE");
		return 0;
	}

	size_t pstate = strtol(argv[1], NULL, 16);

	if (pstate > LOCKDOWN_ON_PIT_L2_BMC_HASH_MISMATCH) {
		shell_print(shell, "State is not supported");
		return 0;
	}

	SetPlatformState(pstate);
	return 0;
}

#if defined(CONFIG_INTEL_PFR)
static int cmd_afm(const struct shell *shell, size_t argc, char **argv)
{
	if (argc != 3) {
		shell_print(shell, "afm FLASH_DEV FLASH_OFFSET");
		return 0;
	}

	const struct device *dev = device_get_binding(argv[1]);
	if (dev == NULL) {
		shell_print(shell, "Unable to find device: %s", argv[1]);
		return 0;
	}

	size_t offset = strtol(argv[2], NULL, 16);

	PFR_AUTHENTICATION_BLOCK0 block0;
	flash_read(dev, offset, (uint8_t *)&block0, sizeof(block0));

	shell_print(shell, "--- BLOCK 0 ---");
	shell_print(shell, "Tag:0x%08x  PCLength:0x%08x PCType:0x%08x",
		block0.Block0Tag, block0.PcLength, block0.PcType);
	shell_print(shell, "Sha256Pc:");
	shell_hexdump(shell, block0.Sha256Pc, sizeof(block0.Sha256Pc));
	shell_print(shell, "Sha384Pc:");
	shell_hexdump(shell, block0.Sha384Pc, sizeof(block0.Sha384Pc));

	if (block0.Block0Tag != BLOCK0TAG) {
		shell_print(shell, "Block 0 tag mismatch.");
		return 0;
	}

	PFR_AUTHENTICATION_BLOCK1 block1;
	flash_read(dev, offset + 128, (uint8_t *)&block1, sizeof(block1));
	shell_print(shell, "--- BLOCK 1 ---");
	shell_print(shell, "Tag:0x%08x", block1.TagBlock1);
	shell_print(shell, "KEY Tag:0x%08x CurveMagic:0x%08x Permission:0x%08x KeyId:0x%08x",
		block1.RootEntry.Tag, block1.RootEntry.PubCurveMagic, block1.RootEntry.KeyPermission, block1.RootEntry.KeyId);
	shell_print(shell, "Pubkey X:");
	shell_hexdump(shell, block1.RootEntry.PubKeyX, sizeof(block1.RootEntry.PubKeyX));
	shell_print(shell, "Pubkey Y:");
	shell_hexdump(shell, block1.RootEntry.PubKeyY, sizeof(block1.RootEntry.PubKeyY));

	if (block1.TagBlock1 != BLOCK1TAG) {
		shell_print(shell, "Block 1 tag mismatch.");
		return 0;
	}

	AFM_STRUCTURE afm;
	flash_read(dev, offset + 1024, (uint8_t *)&afm, sizeof(afm));
	shell_print(shell, "--- AFM ---");
	shell_print(shell, "Tag:0x%08x SVN:0x%02x Revision:0x%04x Length:0x%08x",
		afm.AfmTag, afm.SVN, afm.AfmRevision, afm.Length);

	if (afm.AfmTag != AFM_TAG) {
		shell_print(shell, "AFM tag mismatch.");
		return 0;
	}

	shell_print(shell, "OEM Speicific Data");
	shell_hexdump(shell, afm.OemSpecificData, sizeof(afm.OemSpecificData));

	for (size_t i=0; i < afm.Length/sizeof(AFM_ADDRESS_DEFINITION); ++i) {
		AFM_ADDRESS_DEFINITION addr;
		const size_t partition_offset = 0x80000000;
		flash_read(dev, offset + 1024 + sizeof(AFM_STRUCTURE) + i*sizeof(AFM_ADDRESS_DEFINITION), &addr, sizeof(AFM_ADDRESS_DEFINITION));
		shell_print(shell, "+++ AFM ADDR DEFINITION[%d] +++", i);
		shell_print(shell, "-> Type:0x%02x DevAddr:0x%02x UUID:0x%04x Length:0x%08x AfmAdd:0x%08x",
			addr.AfmDefinitionType, addr.DeviceAddress, addr.UUID, addr.Length, addr.AfmAddress - partition_offset);

		PFR_AUTHENTICATION_BLOCK0 afm_block0;
		flash_read(dev, offset + (addr.AfmAddress - partition_offset),
			(uint8_t *)&afm_block0, sizeof(PFR_AUTHENTICATION_BLOCK0));

		shell_print(shell, "--- AFM[%d] BLOCK 0 ---", i);
		shell_print(shell, "Tag:0x%08x  PCLength:0x%08x PCType:0x%08x",
			afm_block0.Block0Tag, afm_block0.PcLength, afm_block0.PcType);
		shell_print(shell, "Sha256Pc:");
		shell_hexdump(shell, afm_block0.Sha256Pc, sizeof(afm_block0.Sha256Pc));
		shell_print(shell, "Sha384Pc:");
		shell_hexdump(shell, afm_block0.Sha384Pc, sizeof(afm_block0.Sha384Pc));

		if (afm_block0.Block0Tag != BLOCK0TAG) {
			shell_print(shell, "Block 0 tag mismatch.");
			return 0;
		}

		PFR_AUTHENTICATION_BLOCK1 afm_block1;
		flash_read(dev, offset + (addr.AfmAddress - partition_offset) + sizeof(PFR_AUTHENTICATION_BLOCK0),
			(uint8_t *)&afm_block1, sizeof(PFR_AUTHENTICATION_BLOCK1));

		shell_print(shell, "--- AFM[%d] BLOCK 1 ---", i);

		shell_print(shell, "Tag:0x%08x", afm_block1.TagBlock1);
		shell_print(shell, "KEY Tag:0x%08x CurveMagic:0x%08x Permission:0x%08x KeyId:0x%08x",
			afm_block1.RootEntry.Tag, afm_block1.RootEntry.PubCurveMagic, afm_block1.RootEntry.KeyPermission, afm_block1.RootEntry.KeyId);
		shell_print(shell, "Pubkey X:");
		shell_hexdump(shell, afm_block1.RootEntry.PubKeyX, sizeof(afm_block1.RootEntry.PubKeyX));
		shell_print(shell, "Pubkey Y:");
		shell_hexdump(shell, afm_block1.RootEntry.PubKeyY, sizeof(afm_block1.RootEntry.PubKeyY));

		if (afm_block1.TagBlock1 != BLOCK1TAG) {
			shell_print(shell, "Block 1 tag mismatch.");
			return 0;
		}

		AFM_DEVICE_STRUCTURE afm_dev;
		shell_print(shell, "AFM OFFSET 0x%08x", offset + (addr.AfmAddress - partition_offset) + 1024);
		flash_read(dev, offset + (addr.AfmAddress - partition_offset) + 1024,
			&afm_dev, sizeof(AFM_DEVICE_STRUCTURE));
		shell_print(shell, "----> UUID:0x%04x BusID:0x%02x DevAddr:0x%02x Binding:%d BindingRev:0x%04x Policy:0x%02x SVN:0x%02x",
			afm_dev.UUID, afm_dev.BusID, afm_dev.DeviceAddress, afm_dev.BindingSpec, afm_dev.BindingSpecVersion,
			afm_dev.Policy, afm_dev.SVN);
		shell_print(shell, "AfmVer:0x%04x CurveMagic:0x%08x ManuStr:0x%04x ManuId:0x%04x PublicKeyExp:0x%08x",
			afm_dev.AfmVersion, afm_dev.CurveMagic, afm_dev.PlatformManufacturerStr, afm_dev.PlatformManufacturerIDModel,
			afm_dev.PublicKeyExponent);
		shell_print(shell, "PublicKeyXY:");
		shell_hexdump(shell, afm_dev.PublicKeyModuleXY, 96);

		shell_print(shell, "Total Measurements:%u", afm_dev.TotalMeasurements);

		size_t offs_measurem = offset + (addr.AfmAddress - partition_offset) + 1024 + sizeof(AFM_DEVICE_STRUCTURE);
		for (size_t j=0; j<afm_dev.TotalMeasurements; ++j) {
			AFM_DEVICE_MEASUREMENT_VALUE measurement;
			flash_read(dev, offs_measurem, &measurement, sizeof(AFM_DEVICE_MEASUREMENT_VALUE));

			shell_print(shell, "Possible Measurements:%d ValueType:0x%02x ValueSize:0x%04x",
				measurement.PossibleMeasurements, measurement.ValueType, measurement.ValueSize);
			offs_measurem += sizeof(AFM_DEVICE_MEASUREMENT_VALUE);
			for (size_t k=0; k<measurement.PossibleMeasurements; ++k) {
				uint8_t buffer[128];
				shell_print(shell, "Measurement[%d][%d]:", j, k);
				flash_read(dev, offs_measurem, buffer, measurement.ValueSize);
				shell_hexdump(shell, buffer, measurement.ValueSize);
				offs_measurem += measurement.ValueSize;
			}
		}
	}

	return 0;
}
#endif // CONFIG_INTEL_PFR

#if defined(CONFIG_ASPEED_DICE_SHELL)

uint8_t buffer[PAGE_SIZE] __aligned(16);

#define CDI_LENGTH                        64
#define CDI_ADDRESS                       0x79001800
#define DEVICE_FIRMWARE_START_ADDRESS     0x10000
#define DEVICE_FIRMWARE_SIZE              0x60000
#define ECDSA384_PRIVATE_KEY_SIZE         SHA384_HASH_LENGTH + 1
#define ECDSA384_PUBLIC_KEY_SIZE          SHA384_HASH_LENGTH * 2 + 1

#define X509_KEY_USAGE                    0x04
#define X509_SERIAL_NUM_LENGTH            8

#define DER_MAX_PEM                       0x500
#define DER_MAX_DER                       0x500

static mbedtls_hmac_drbg_context hmac_drbg_ctx = {0};
static uint8_t cdi_digest[SHA384_HASH_LENGTH] = {0};
static uint8_t dev_fwid[SHA384_HASH_LENGTH] = {0};
static uint8_t alias_digest[SHA384_HASH_LENGTH] = {0};

uint8_t devid_priv_key_buf[ECDSA384_PRIVATE_KEY_SIZE] = {0};
uint8_t devid_pub_key_buf[ECDSA384_PUBLIC_KEY_SIZE] = {0};
uint8_t alias_priv_key_buf[ECDSA384_PRIVATE_KEY_SIZE] = {0};
uint8_t alias_pub_key_buf[ECDSA384_PUBLIC_KEY_SIZE] = {0};
uint8_t alias_cert_pem[DER_MAX_PEM];
uint8_t devid_cert_pem[DER_MAX_PEM];
uint8_t alias_cert_der[DER_MAX_DER];
uint8_t devid_cert_der[DER_MAX_DER];

// TODO:
// Since srand() is not supported in current zephyr, we use the hash of cdi digest
// as the seed of mbedtls random number generator.
#if 0
int get_rand_bytes( void *rngState, uint8_t *output, size_t length)
{
	ARG_UNUSED(rngState);
	for (; length; length--)
		*output++ = (uint8_t)rand();

	return 0;
}

int seed_drbg(uint8_t *digest, uint32_t digest_len)
{
	uint32_t i, seed;
	mbedtls_md_info_t *md_sha384;
	int ret = -1;

	for (i = 0; i < digest_len; i++) {
		seed += ~(digest[i]);
	}
	srand(~seed);

	mbedtls_hmac_drbg_init(&hmac_drbg_ctx);

	if (!(md_sha384 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384)))
		goto free_drbg;

	if (mbedtls_hmac_drbg_seed(&hmac_drbg_ctx, md_sha384, get_rand_bytes, NULL, NULL, 0))
		goto free_drbg;

	ret = 0;

free_drbg:
	if (ret)
		mbedtls_hmac_drbg_free(&hmac_drbg_ctx);

	return ret;
}
#else

// Temporary solution
int get_rand_bytes_by_cdi(void *rngState, uint8_t *output, size_t length)
{
	uint8_t cdi_digest_digest[SHA384_HASH_LENGTH];
	ARG_UNUSED(rngState);
	hash_engine_sha_calculate(HASH_SHA384, (uint8_t *)cdi_digest, SHA384_HASH_LENGTH,
			cdi_digest_digest, sizeof(cdi_digest_digest));
	memset(output, 0, length);
	memcpy(output, cdi_digest_digest,
			(length <= SHA384_HASH_LENGTH) ? length : SHA384_HASH_LENGTH);

	return 0;
}

int get_rand_bytes_by_cdi_fwid(void *rngState, uint8_t *output, size_t length)
{
	ARG_UNUSED(rngState);

	// Combine CDI and FWID for deriving alias key
	hash_engine_start(HASH_SHA384);
	hash_engine_update(cdi_digest, SHA384_HASH_LENGTH);
	hash_engine_update(dev_fwid, SHA384_HASH_LENGTH);
	hash_engine_finish(alias_digest, sizeof(alias_digest));
	memset(output, 0, length);
	memcpy(output, alias_digest,
			(length <= SHA384_HASH_LENGTH) ? length : SHA384_HASH_LENGTH);

	return 0;
}

int seed_drbg(int (*f_entropy)(void *, unsigned char *, size_t), void *p_entropy)
{
	mbedtls_md_info_t *md_sha384;
	int ret = -1;

	if (hmac_drbg_ctx.MBEDTLS_PRIVATE(entropy_len))
		mbedtls_hmac_drbg_free(&hmac_drbg_ctx);

	mbedtls_hmac_drbg_init(&hmac_drbg_ctx);

	if (!(md_sha384 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384)))
		goto free_drbg;

	if (mbedtls_hmac_drbg_seed(&hmac_drbg_ctx, md_sha384, f_entropy,
				p_entropy, NULL, 0))
		goto free_drbg;

	ret = 0;

free_drbg:
	if (ret)
		mbedtls_hmac_drbg_free(&hmac_drbg_ctx);

	return ret;
}

#endif

int hash_device_firmware(uint32_t addr, uint32_t fw_size, uint8_t *hash, uint32_t hash_len,
		enum hash_algo algo)
{
	const struct device *flash_dev;
	uint32_t read_len;
	flash_dev = device_get_binding("fmc_cs0");
	hash_engine_start(algo);
	while (fw_size > 0) {
		read_len = (fw_size < PAGE_SIZE) ? fw_size : PAGE_SIZE;
		flash_read(flash_dev, addr, buffer, read_len);
		hash_engine_update(buffer, read_len);
		addr += read_len;
		fw_size -= read_len;
	}

	hash_engine_finish(hash, hash_len);

	return 0;
}

void x509_set_serial_number(mbedtls_mpi *serial_num, uint8_t *digest, uint8_t digest_len)
{
	uint8_t dice_seed[9] = "DICE_SEED";
	uint8_t dice_seed_digest[SHA384_HASH_LENGTH];
	uint8_t final_digest[SHA384_HASH_LENGTH];
	hash_engine_sha_calculate(HASH_SHA384, dice_seed, sizeof(dice_seed),
			dice_seed_digest, sizeof(dice_seed_digest));
	hash_engine_start(HASH_SHA384);
	hash_engine_update(dice_seed_digest, sizeof(dice_seed_digest));
	hash_engine_update(digest, digest_len);
	hash_engine_finish(final_digest, sizeof(final_digest));

	// DER encoded serial number must be positive and the first byte must not be zero
	final_digest[0] &= 0x7f;
	final_digest[0] |= 0x01;
	mbedtls_mpi_read_binary(serial_num, final_digest, X509_SERIAL_NUM_LENGTH);
}

void derive_key_pair(mbedtls_ecdsa_context *ctx_sign, uint8_t *privkey_buf,
		uint8_t *pubkey_buf, int (*f_entropy)(void *, unsigned char *, size_t),
		void *p_entropy)
{
	size_t len;
	// Seed drbg with cdi digest
	seed_drbg(f_entropy, p_entropy);

	if (mbedtls_ecdsa_genkey(ctx_sign, MBEDTLS_ECP_DP_SECP384R1, mbedtls_hmac_drbg_random,
				&hmac_drbg_ctx)) {
		return;
	}

	if (mbedtls_mpi_write_binary(&ctx_sign->MBEDTLS_PRIVATE(d), privkey_buf,
				ECDSA384_PRIVATE_KEY_SIZE)) {
		LOG_ERR("Failed to get ecdsa privkey");
		return;
	}

	if (mbedtls_ecp_point_write_binary(&ctx_sign->MBEDTLS_PRIVATE(grp),
			&ctx_sign->MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED,
			&len, pubkey_buf, ECDSA384_PUBLIC_KEY_SIZE)) {
		LOG_ERR("Failed to get ecdsa pubkey");
		return;
	}
}


// Porting from upstream mbedtls pull request, it should be removed after
// Mbedtls supports this api.
int mbedtls_x509write_crt_set_ext_key_usage( mbedtls_x509write_cert *ctx,
		const mbedtls_asn1_sequence *exts )
{
	unsigned char buf[256];
	unsigned char *c = buf + sizeof(buf);
	int ret;
	size_t len = 0;
	const mbedtls_asn1_sequence *last_ext = 0, *ext;

	/* We need at least one extension: SEQUENCE SIZE (1..MAX) OF KeyPurposeId */
	if( exts == NULL )
		return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

	/* Iterate over exts backwards, so we write them out in the requested order */
	while( last_ext != exts )
	{
		for( ext = exts; ext->next != last_ext; ext = ext->next ) {}
		if( ext->buf.tag != MBEDTLS_ASN1_OID )
			return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
		MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( &c, buf, ext->buf.p, ext->buf.len ) );
		MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, ext->buf.len ) );
		MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_OID ) );
		last_ext = ext;
	}

	MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
	MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

	ret = mbedtls_x509write_crt_set_extension( ctx,
			MBEDTLS_OID_EXTENDED_KEY_USAGE,
			MBEDTLS_OID_SIZE( MBEDTLS_OID_EXTENDED_KEY_USAGE ),
			1, c, len );
	if( ret != 0 )
		return( ret );

	return( 0 );
}
int convert_pem_to_der(const unsigned char *input, size_t ilen,
		unsigned char *output, size_t *olen)
{
	int ret;
	const unsigned char *s1, *s2, *end = input + ilen;
	size_t len = 0;
	s1 = (unsigned char *) strstr((const char *) input, "-----BEGIN");
	if( s1 == NULL )
		return -1;

	s2 = (unsigned char *) strstr((const char *) input, "-----END");
	if(s2 == NULL)
		return -1;

	s1 += 10;
	while(s1 < end && *s1 != '-')
		s1++;
	while(s1 < end && *s1 == '-')
		s1++;

	if( *s1 == '\r' ) s1++;
	if( *s1 == '\n' ) s1++;
	if( s2 <= s1 || s2 > end )
		return -1;
	ret = mbedtls_base64_decode( NULL, 0, &len, (const unsigned char *)s1, s2 - s1 );
	if(ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER)
		return ret;
	if( len > *olen )
		return -1;
	if((ret = mbedtls_base64_decode(output, len, &len, (const unsigned char *)s1,
					s2 - s1)) != 0) {
		return ret;
	}
	*olen = len;
	return( 0 );
}

#define M_CHECK(f) do {if((ret = (f)) != 0 ) {goto mbedtls_cleanup;}}while (0)

int dice_start(size_t cert_type)
{
	mbedtls_x509write_cert alias_crt, devid_crt;
	mbedtls_asn1_sequence *ext_key_usage= NULL;
	mbedtls_x509write_csr devid_csr;
	mbedtls_pk_context devid_key;
	mbedtls_pk_context alias_key;
	mbedtls_mpi serial_num;
	int ret = 0;

	memset(devid_cert_pem, 0, sizeof(devid_cert_pem));
	memset(alias_cert_pem, 0, sizeof(alias_cert_pem));
	memset(devid_cert_der, 0, sizeof(devid_cert_der));
	memset(alias_cert_der, 0, sizeof(alias_cert_der));

	hash_engine_sha_calculate(HASH_SHA384, (uint8_t *)CDI_ADDRESS, CDI_LENGTH,
			cdi_digest, sizeof(cdi_digest));
	mbedtls_pk_init(&devid_key);
	mbedtls_pk_init(&alias_key);
	mbedtls_pk_setup(&devid_key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	mbedtls_pk_setup(&alias_key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

	mbedtls_mpi_init(&serial_num);
	derive_key_pair(mbedtls_pk_ec(devid_key), devid_priv_key_buf, devid_pub_key_buf,
			get_rand_bytes_by_cdi, NULL);
	hash_device_firmware(DEVICE_FIRMWARE_START_ADDRESS, DEVICE_FIRMWARE_SIZE, dev_fwid,
			SHA384_HASH_LENGTH, HASH_SHA384);
	derive_key_pair(mbedtls_pk_ec(alias_key), alias_priv_key_buf, alias_pub_key_buf,
			get_rand_bytes_by_cdi_fwid, NULL);

	// Alias certificate
	mbedtls_x509write_crt_init(&alias_crt);
	x509_set_serial_number(&serial_num, alias_digest, sizeof(alias_digest));
	mbedtls_x509write_crt_set_subject_key(&alias_crt, &alias_key);
	mbedtls_x509write_crt_set_issuer_key(&alias_crt, &devid_key);
	mbedtls_x509write_crt_set_md_alg(&alias_crt, MBEDTLS_MD_SHA384);
	mbedtls_x509write_crt_set_version(&alias_crt, MBEDTLS_X509_CRT_VERSION_3);
	M_CHECK(mbedtls_x509write_crt_set_serial(&alias_crt, &serial_num));
	M_CHECK(mbedtls_x509write_crt_set_validity(&alias_crt,
				CONFIG_ASPEED_DICE_CERT_VALID_FROM,
				CONFIG_ASPEED_DICE_CERT_VALID_TO));
	M_CHECK(mbedtls_x509write_crt_set_subject_name(&alias_crt,
				CONFIG_ASPEED_DICE_CERT_ALIAS_SUBJECT_NAME));
	M_CHECK(mbedtls_x509write_crt_set_issuer_name(&alias_crt,
				CONFIG_ASPEED_DICE_CERT_ALIAS_ISSUER_NAME));

	// Alias certificate extensions
	M_CHECK(mbedtls_x509write_crt_set_basic_constraints(&alias_crt, 0, 1));
	M_CHECK(mbedtls_x509write_crt_set_authority_key_identifier(&alias_crt));
	M_CHECK(mbedtls_x509write_crt_set_key_usage(&alias_crt, X509_KEY_USAGE));

	ext_key_usage = calloc(1, sizeof(mbedtls_asn1_sequence));
	ext_key_usage->next = NULL;
	ext_key_usage->buf.tag = MBEDTLS_ASN1_OID;
	ext_key_usage->buf.len = MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH);
	ext_key_usage->buf.p = MBEDTLS_OID_CLIENT_AUTH;
	M_CHECK(mbedtls_x509write_crt_set_ext_key_usage(&alias_crt, ext_key_usage));
	M_CHECK(mbedtls_x509write_crt_pem(&alias_crt, alias_cert_pem, DER_MAX_PEM,
				mbedtls_hmac_drbg_random, &hmac_drbg_ctx));
	size_t olen = sizeof(alias_cert_der);
	M_CHECK(convert_pem_to_der(alias_cert_pem, sizeof(alias_cert_pem), alias_cert_der, &olen));

	if (cert_type) {
		// Self-Signed DevID certificate
		mbedtls_x509write_crt_init(&devid_crt);
		x509_set_serial_number(&serial_num, cdi_digest, sizeof(cdi_digest));
		mbedtls_x509write_crt_set_subject_key(&devid_crt, &devid_key);
		mbedtls_x509write_crt_set_issuer_key(&devid_crt, &devid_key);
		mbedtls_x509write_crt_set_md_alg(&devid_crt, MBEDTLS_MD_SHA384);
		mbedtls_x509write_crt_set_version(&devid_crt, MBEDTLS_X509_CRT_VERSION_3);
		M_CHECK(mbedtls_x509write_crt_set_serial(&devid_crt, &serial_num));
		M_CHECK(mbedtls_x509write_crt_set_validity(&devid_crt,
					CONFIG_ASPEED_DICE_CERT_VALID_FROM,
					CONFIG_ASPEED_DICE_CERT_VALID_TO));
		M_CHECK(mbedtls_x509write_crt_set_subject_name(&devid_crt,
					CONFIG_ASPEED_DICE_CERT_DEVID_ISSUER_NAME));
		M_CHECK(mbedtls_x509write_crt_set_issuer_name(&devid_crt,
					CONFIG_ASPEED_DICE_CERT_DEVID_ISSUER_NAME));

		// DevID certificate extensions
		M_CHECK(mbedtls_x509write_crt_set_key_usage(&devid_crt, X509_KEY_USAGE));
		M_CHECK(mbedtls_x509write_crt_set_basic_constraints(&devid_crt, 1, 1));
		M_CHECK(mbedtls_x509write_crt_pem(&devid_crt, devid_cert_pem, DER_MAX_PEM,
				mbedtls_hmac_drbg_random, &hmac_drbg_ctx));
	} else {
		// DevID CSR
		mbedtls_x509write_csr_init(&devid_csr);
		mbedtls_x509write_csr_set_md_alg(&devid_csr, MBEDTLS_MD_SHA384);
		mbedtls_x509write_csr_set_key(&devid_csr, &devid_key);
		M_CHECK(mbedtls_x509write_csr_set_subject_name(&devid_csr,
					CONFIG_ASPEED_DICE_CERT_ALIAS_ISSUER_NAME));
		M_CHECK(mbedtls_x509write_csr_pem(&devid_csr, devid_cert_pem, DER_MAX_PEM,
				mbedtls_hmac_drbg_random, &hmac_drbg_ctx));
	}
	olen = sizeof(devid_cert_der);
	M_CHECK(convert_pem_to_der(devid_cert_pem, sizeof(devid_cert_pem), devid_cert_der, &olen));

mbedtls_cleanup:
	if (ext_key_usage)
		free(ext_key_usage);
	mbedtls_pk_free(&devid_key);
	mbedtls_pk_free(&alias_key);
	mbedtls_mpi_free(&serial_num);
	mbedtls_hmac_drbg_free(&hmac_drbg_ctx);
	mbedtls_x509write_crt_free(&alias_crt);
	if (cert_type)
		mbedtls_x509write_crt_free(&devid_crt);
	else
		mbedtls_x509write_csr_free(&devid_csr);

	if (ret)
		LOG_ERR("Failed to generate certificate, ret : -0x%2x", ret);

	return ret;
}

static int cmd_dice(const struct shell *shell, size_t argc, char **argv)
{
	int ret;

	if (argc != 2) {
		shell_print(shell, "asm dice <0/1> for generating device id CSR(0) or CERT(1)");
		return 0;
	}

	size_t cert_type = strtol(argv[1], NULL, 16);

	LOG_INF("dice start");
	ret = dice_start(cert_type);
	if (ret)
		return 0;
	LOG_INF("dice done");

	shell_print(shell, "DeviceID PRIV KEY :");
	shell_hexdump(shell, devid_priv_key_buf, ECDSA384_PRIVATE_KEY_SIZE);
	shell_print(shell, "DeviceID PUB KEY :");
	shell_hexdump(shell, devid_pub_key_buf, ECDSA384_PUBLIC_KEY_SIZE);
	shell_print(shell, "Alias PRIV KEY :");
	shell_hexdump(shell, alias_priv_key_buf, ECDSA384_PRIVATE_KEY_SIZE);
	shell_print(shell, "Alias PUB KEY :");
	shell_hexdump(shell, alias_pub_key_buf, ECDSA384_PUBLIC_KEY_SIZE);

	shell_print(shell, "Alias CERT DER :");
	shell_hexdump(shell,alias_cert_der, sizeof(alias_cert_der));
	shell_print(shell, "DevID CERT DER :");
	shell_hexdump(shell,devid_cert_der, sizeof(devid_cert_der));
	shell_print(shell, "Alias CERT PEM :");
	shell_print(shell, "%s", alias_cert_pem);
	shell_print(shell, "DevID %s PEM :", (cert_type) ? "CERT" : "CSR");
	shell_print(shell, "%s", devid_cert_pem);

	return 0;
}
#endif // CONFIG_ASPEED_DICE_SHELL

extern struct sys_heap _system_heap;
static int cmd_heap(const struct shell *shell, size_t argc, char **argv)
{
	sys_heap_print_info(&_system_heap, true);
	return 0;
}

struct ast_i2c_filter_child_data {
	uint32_t        filter_dev_base;        /* i2c filter device base */
	uint8_t filter_dev_en;  /* i2cflt04 : filter enable */
	uint8_t filter_en;              /* i2cflt0c : white list */
	uint8_t filter_idx[16];
	uint8_t *filter_buf;
};

extern struct ast_i2c_f_tbl filter_tbl[5];

static int cmd_i2c_filter_dump(const struct shell *shell, size_t argc, char **argv)
{
	const struct device *flt_dev = NULL;
	struct ast_i2c_filter_child_data *data;
	char bus_dev_name[] = "I2C_FILTER_x";

	if (argc > 1) {
		size_t filter_id = strtol(argv[1], NULL, 16);
		bus_dev_name[11] = filter_id + '0';
		flt_dev = device_get_binding(bus_dev_name);
		if (!flt_dev || filter_id > 3) {
			shell_print(shell, "Invalid filter id");
			return 0;
		}

		data = (struct ast_i2c_filter_child_data *)flt_dev->data;

		if (argc == 2) {
			for (int devid = 0; devid < 16; devid++) {
				shell_print(shell, "I2C_FILTER_%d Rule[%02d] Addr[%02x] :",
						filter_id, devid, data->filter_idx[devid] << 1);
				shell_hexdump(shell, &filter_tbl[filter_id].filter_tbl[devid + 1],
						sizeof(struct ast_i2c_f_bitmap));
				shell_print(shell,"\n");
			}
		} else if (argc == 3) {
			size_t devid = strtol(argv[2], NULL, 16);
			shell_print(shell, "I2C_FILTER_%d Rule[%02d] Addr[%02x] :",
					filter_id, devid, data->filter_idx[devid] << 1);
			shell_hexdump(shell, &filter_tbl[filter_id].filter_tbl[devid + 1],
					sizeof(struct ast_i2c_f_bitmap));
			shell_print(shell,"\n");
		}


		return 0;
	}

	for (int i = 0; i < 4; i++) {
		bus_dev_name[11] = i + '0';
		flt_dev = device_get_binding(bus_dev_name);
		if (!flt_dev) {
			continue;
		}
		data = (struct ast_i2c_filter_child_data *)flt_dev->data;
		for (int devid = 0; devid < 16; devid++) {
			shell_print(shell, "I2C_FILTER_%d Rule[%02d] Addr[%02x] :", i, devid,
					data->filter_idx[devid] << 1);
			shell_hexdump(shell, &filter_tbl[i].filter_tbl[devid + 1],
					sizeof(struct ast_i2c_f_bitmap));
			shell_print(shell,"\n");
		}
	}

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_asm,
	SHELL_CMD(log, NULL, "Show state machine event log", cmd_asm_log),
	SHELL_CMD(event, &sub_event, "State Machine Event", NULL),
	SHELL_CMD(abr, NULL, "Control FMCWDT2 timer manually: enable or disable", cmd_asm_abr),
	SHELL_CMD(rot_rc, NULL, "ROT firmware recoery", cmd_asm_rot_recovery),
	SHELL_CMD(ufm_status, NULL, "Dump UFM status flag for update flow", cmd_asm_ufm_status),
	SHELL_CMD(spi_error_inject, &sub_spi_error, "Inject error to SPI for testing", NULL),
	SHELL_CMD(flash_cmp, NULL, "Flash content compairson", cmd_asm_flash_cmp),
	SHELL_CMD(flash_copy, NULL, "Copy data between Flash", cmd_asm_flash_copy),
	SHELL_CMD(flash_rebind, NULL, "Rebind SPI Flash", cmd_asm_flash_rebind),
	SHELL_CMD(pstate, NULL, "Test Platform State LED", cmd_test_plat_state_led),
#if defined(CONFIG_INTEL_PFR)
	SHELL_CMD(afm, NULL, "Dump AFM Structure: DEVICE OFFSET", cmd_afm),
#endif
#if defined(CONFIG_ASPEED_DICE_SHELL)
	SHELL_CMD(dice, NULL, "Generate Cert Chain", cmd_dice),
#endif
	SHELL_CMD(heap, NULL, "Show system heap statistic", cmd_heap),
	SHELL_CMD_ARG(flt_dump, NULL, "Dump i2c filter table\n"
				       "Usage: asm flt_dump\n"
				       "asm flt_dump <filter_id>\n"
				       "asm flt_dump <filter_id> <rule_id>\n",
		cmd_i2c_filter_dump, 0, 2),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(asm, &sub_asm, "Aspeed PFR State Machine Commands", NULL);
#endif
