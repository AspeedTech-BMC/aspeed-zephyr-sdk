/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <stdlib.h>
#include "pfr/pfr_common.h"
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_util.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_pfm_manifest.h"
#include "intel_pfr_svn.h"
#include "intel_pfr_key_cancellation.h"
#include "intel_pfr_cpld_utils.h"

// key cancellation
static int cmd_cancel_csk_key_id(const struct shell *shell, size_t argc, char **argv)
{
	struct pfr_manifest test_manifest;
	uint8_t key_id;

	test_manifest.pc_type = strtoul(argv[1], NULL, 16);
	key_id = strtoul(argv[2], NULL, 10);

	cancel_csk_key_id(&test_manifest, key_id);

	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	return 0;
}

static int cmd_verify_csk_key_id(const struct shell *shell, size_t argc, char **argv)
{
	struct pfr_manifest test_manifest;
	uint8_t key_id;

	test_manifest.pc_type = strtoul(argv[1], NULL, 16);
	key_id = strtoul(argv[2], NULL, 10);

	if (!verify_csk_key_id(&test_manifest, key_id))
		shell_print(shell, "This CSK key is not cancelled.., PC type = 0x%x, Key Id = %d", test_manifest.pc_type, key_id);

	ARG_UNUSED(argc);
	return 0;
}

static int cmd_dump_key_cancellation_policy(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t buffer[4] = { 0 };
	uint32_t offset = 0;
	uint32_t pc_type;

	pc_type = strtoul(argv[1], NULL, 16);
	offset = get_cancellation_policy_offset(pc_type);

	if (!offset) {
		shell_error(shell, "Invalid provisioned UFM offset for key cancellation");
		return 0;
	}

	shell_print(shell, "UFM Offeset = %x", offset);
	ufm_read(PROVISION_UFM, offset, (uint8_t *)buffer, sizeof(buffer));
	shell_hexdump(shell, (uint8_t *)buffer, sizeof(buffer));

	ARG_UNUSED(argc);
	return 0;
}

// svn
static int cmd_get_svn(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t svn_policy[2];
	uint32_t offset;
	uint8_t svn;

	if (strncmp(argv[1], "rot", 3) == 0)
		offset = SVN_POLICY_FOR_CPLD_UPDATE;
	else if (strncmp(argv[1], "pch", 3) == 0)
		offset = SVN_POLICY_FOR_PCH_FW_UPDATE;
	else if (strncmp(argv[1], "bmc", 3) == 0)
		offset = SVN_POLICY_FOR_BMC_FW_UPDATE;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (strncmp(argv[1], "afm", 3) == 0)
		offset = SVN_POLICY_FOR_AFM;
#endif
	else {
		shell_error(shell, "unsupported svn policy");
		return 0;
	}

	shell_print(shell, "svn policy offset = 0x%x", offset);
	ufm_read(PROVISION_UFM, offset, (uint8_t *)svn_policy, sizeof(svn_policy));
	shell_hexdump(shell, (uint8_t *)svn_policy, sizeof(svn_policy));
	svn = get_ufm_svn(offset);
	shell_print(shell, "svn policy for %s is %d", argv[1], svn);

	ARG_UNUSED(argc);
	return 0;
}

static int cmd_set_svn(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t offset;
	uint8_t svn;

	if (strncmp(argv[1], "rot", 3) == 0)
		offset = SVN_POLICY_FOR_CPLD_UPDATE;
	else if (strncmp(argv[1], "pch", 3) == 0)
		offset = SVN_POLICY_FOR_PCH_FW_UPDATE;
	else if (strncmp(argv[1], "bmc", 3) == 0)
		offset = SVN_POLICY_FOR_BMC_FW_UPDATE;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (strncmp(argv[1], "afm", 3) == 0)
		offset = SVN_POLICY_FOR_AFM;
#endif
	else {
		shell_error(shell, "unsupported svn policy");
		return 0;
	}

	svn = strtoul(argv[2], NULL, 10);

	if (set_ufm_svn(offset, svn) != 0)
		shell_error(shell, "set svn policy for %s to %d failed", argv[1], svn);

	ARG_UNUSED(argc);
	return 0;
}

#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
static int cmd_get_rsu_reg(const struct shell *shell, size_t argc, char **argv)
{
	uint8_t rsu_type;
	uint8_t reg;
	uint16_t val;

	intel_rsu_unhide_rsu();

	if (strncmp(argv[1], "scm", 3) == 0)
		rsu_type = SCM_CPLD;
	else if (strncmp(argv[1], "cpu", 3) == 0)
		rsu_type = CPU_CPLD;
	else if (strncmp(argv[1], "dbg", 3) == 0)
		rsu_type = DEBUG_CPLD;
	else {
		shell_error(shell, "unsupported rsu type");
		goto error;
	}

	reg = strtoul(argv[2], NULL, 16);

	if (intel_rsu_read_ctrl_reg(rsu_type, reg, &val))
		shell_error(shell, "failed to get rsu ctrl register");
	else
		shell_print(shell, "%04x", val);

error:
	intel_rsu_hide_rsu();

	return 0;
}

static int cmd_set_rsu_reg(const struct shell *shell, size_t argc, char **argv)
{
	uint8_t rsu_type;
	uint8_t reg;
	uint8_t data_h;
	uint8_t data_l;

	intel_rsu_unhide_rsu();

	if (strncmp(argv[1], "scm", 3) == 0)
		rsu_type = SCM_CPLD;
	else if (strncmp(argv[1], "cpu", 3) == 0)
		rsu_type = CPU_CPLD;
	else if (strncmp(argv[1], "dbg", 3) == 0)
		rsu_type = DEBUG_CPLD;
	else {
		shell_error(shell, "unsupported rsu type");
		goto error;
	}

	reg = strtoul(argv[2], NULL, 16);
	data_h = strtoul(argv[3], NULL, 16);
	data_l = strtoul(argv[4], NULL, 16);

	if (intel_rsu_write_ctrl_reg(rsu_type, reg, data_h, data_l))
		shell_error(shell, "failed to set rsu ctrl register");

error:
	intel_rsu_hide_rsu();

	return 0;
}

static int cmd_cpld_fw_dump(const struct shell *shell, size_t argc, char **argv)
{
	uint8_t rsu_type;
	uint32_t addr;
	uint32_t dw_len;

	if (strncmp(argv[1], "scm", 3) == 0)
		rsu_type = SCM_CPLD;
	else if (strncmp(argv[1], "cpu", 3) == 0)
		rsu_type = CPU_CPLD;
	else if (strncmp(argv[1], "dbg", 3) == 0)
		rsu_type = DEBUG_CPLD;
	else {
		shell_error(shell, "unsupported rsu type");
		return 0;
	}
	addr = strtoul(argv[2], NULL, 16);
	dw_len = strtoul(argv[3], NULL, 10);

	if (intel_rsu_dump_cpld_flash(rsu_type, addr, dw_len))
		shell_error(shell, "failed to dump %s cpld flash", argv[1]);

	return 0;
}
#if defined (CONFIG_BOARD_AST1060_PROT)
static int cmd_get_hs_reg(const struct shell *shell, size_t argc, char **argv)
{
	uint8_t reg;
	uint16_t val;

	intel_rsu_unhide_rsu();

	reg = strtoul(argv[1], NULL, 16);

	if (intel_cpld_read_hs_reg(reg, &val))
		shell_error(shell, "failed to get handshake register");
	else
		shell_print(shell, "%04x", val);

	return 0;
}

static int cmd_set_hs_reg(const struct shell *shell, size_t argc, char **argv)
{
	uint8_t reg;
	uint8_t data_h;
	uint8_t data_l;

	intel_rsu_unhide_rsu();

	reg = strtoul(argv[1], NULL, 16);
	data_h = strtoul(argv[2], NULL, 16);
	data_l = strtoul(argv[3], NULL, 16);

	if (intel_cpld_write_hs_reg(reg, data_h, data_l))
		shell_error(shell, "failed to set handshake register");

	intel_rsu_hide_rsu();

	return 0;
}

static int cmd_do_handshake(const struct shell *shell, size_t argc, char **argv)
{
	intel_rsu_unhide_rsu();

	if (intel_plat_cpld_handshake())
		shell_error(shell, "failed to perform cpld handshake");

	intel_rsu_hide_rsu();

	return 0;
}
#endif
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(sub_kc_cmds,
	SHELL_CMD_ARG(verify, NULL, "<pc_type> <key_id>", cmd_verify_csk_key_id, 3, 0),
	SHELL_CMD_ARG(cancel, NULL, "<pc_type> <key_id>", cmd_cancel_csk_key_id, 3, 0),
	SHELL_CMD_ARG(dump, NULL, "<pc_type>", cmd_dump_key_cancellation_policy, 2, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_svn_cmds,
	SHELL_CMD_ARG(get, NULL, "<svn policy>: rot, pch, bmc, afm", cmd_get_svn, 2, 0),
	SHELL_CMD_ARG(set, NULL, "<svn policy>: rot, pch, bmc, afm", cmd_set_svn, 3, 0),
	SHELL_SUBCMD_SET_END
);

#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
SHELL_STATIC_SUBCMD_SET_CREATE(sub_rsu_cmds,
	SHELL_CMD_ARG(get, NULL, "<rsu type> <reg>", cmd_get_rsu_reg, 3, 0),
	SHELL_CMD_ARG(set, NULL, "<rsu type> <reg> <data_h> <data_l>", cmd_set_rsu_reg, 5, 0),
	SHELL_CMD_ARG(dump_fl, NULL, "<rsu type> <addr> <word_len>", cmd_cpld_fw_dump, 4, 0),
	SHELL_SUBCMD_SET_END
);
#if defined (CONFIG_BOARD_AST1060_PROT)
SHELL_STATIC_SUBCMD_SET_CREATE(sub_hs_cmds,
	SHELL_CMD_ARG(get, NULL, "<reg>", cmd_get_hs_reg, 2, 0),
	SHELL_CMD_ARG(set, NULL, "<reg> <data_h> <data_l>", cmd_set_hs_reg, 4, 0),
	SHELL_CMD_ARG(handshake, NULL, "", cmd_do_handshake, 1, 0),
	SHELL_SUBCMD_SET_END
);
#endif
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(sub_intel_pfr_cmds,
	SHELL_CMD(kc, &sub_kc_cmds, "Key Cancellation Commands", NULL),
	SHELL_CMD(svn, &sub_svn_cmds, "SVN Commands", NULL),
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	SHELL_CMD(rsu, &sub_rsu_cmds, "CPLD RSU Commands", NULL),
#if defined (CONFIG_BOARD_AST1060_PROT)
	SHELL_CMD(hs, &sub_hs_cmds, "CPLD Handshake Commands", NULL),
#endif
#endif
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(intel_pfr, &sub_intel_pfr_cmds, "Intel PFR Commands", NULL);

