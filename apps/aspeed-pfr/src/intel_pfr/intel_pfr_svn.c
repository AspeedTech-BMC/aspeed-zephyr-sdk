/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>
#include <logging/log.h>
#include <stdint.h>
#include "pfr/pfr_common.h"
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_util.h"
#include "AspeedStateMachine/common_smc.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_pfm_manifest.h"
#include "intel_pfr_svn.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int set_ufm_svn(uint32_t offset, uint8_t svn)
{
	uint32_t new_svn_policy;
	uint32_t svn_policy[2];
	uint8_t current_svn;
	int status = 0;

	if (svn > SVN_MAX) {
		LOG_ERR("SVN number(%d) exceed SVN max(%d)", svn, SVN_MAX);
		return Failure;
	}

	current_svn = get_ufm_svn(offset);

	if (current_svn == svn)
		return Success;

	memset(svn_policy, 0xff, sizeof(svn_policy));
	new_svn_policy = ~((1 << (svn % 32)) - 1);
	if (svn < 32)
		svn_policy[0] = new_svn_policy;
	else {
		svn_policy[0] = 0;
		if (svn < 64)
			svn_policy[1] = new_svn_policy;
		else if (svn == 64)
			svn_policy[1] = 0;
	}

	status = ufm_write(PROVISION_UFM, offset, (uint8_t *)svn_policy, sizeof(svn_policy));
	if (status != Success) {
		LOG_ERR("Set SVN number to UFM failed");
		return Failure;
	}

	return Success;
}

uint8_t get_ufm_svn(uint32_t offset)
{
	uint32_t svn_policy[2];
	uint8_t index;

	ufm_read(PROVISION_UFM, offset, (uint8_t *)svn_policy, sizeof(svn_policy));
	for (index = 0; index < 64; index++) {
		if ((svn_policy[(index / 32)] & (1 << (index % 32))) != 0)
			return index;
	}

	return 64;
}

int svn_policy_verify(uint32_t offset, uint32_t svn)
{
	uint8_t current_svn;

	current_svn = get_ufm_svn(offset);

	if (svn > SVN_MAX) {
		LOG_ERR("Invalid SVN Number(%d)", svn);
		return Failure;
	} else if (svn < current_svn) {
		LOG_ERR("Invalid SVN number, current=%d verify_svn=%d",
				current_svn, svn);
		return Failure;
	}

	return Success;
}

int read_statging_area_pfm_svn(struct pfr_manifest *manifest, uint8_t *svn_version)
{
	int status = 0;
	uint32_t pfm_start_address = 0;
	uint8_t buffer[sizeof(PFM_STRUCTURE)];

	// PFM data start address after Staging block and PFM block
	if (manifest->hash_curve == hash_sign_algo384 || manifest->hash_curve == hash_sign_algo256)
		pfm_start_address = manifest->address + LMS_PFM_SIG_BLOCK_SIZE + LMS_PFM_SIG_BLOCK_SIZE;
	else
		pfm_start_address = manifest->address + PFM_SIG_BLOCK_SIZE + PFM_SIG_BLOCK_SIZE;

	if (manifest->image_type == AFM_TYPE)
		status = pfr_spi_read(BMC_TYPE, pfm_start_address, sizeof(PFM_STRUCTURE),
				buffer);
	else
		status = pfr_spi_read(manifest->image_type, pfm_start_address, sizeof(PFM_STRUCTURE),
				buffer);
	if (status != Success) {
		LOG_ERR("Invalid Staging Area Pfm imgtype=%d pfr=%08x", manifest->image_type, pfm_start_address);
		return Failure;
	}

	*svn_version = ((PFM_STRUCTURE *)buffer)->SVN;
	LOG_HEXDUMP_DBG(buffer, sizeof(PFM_STRUCTURE), "PFM:");

	return Success;
}

