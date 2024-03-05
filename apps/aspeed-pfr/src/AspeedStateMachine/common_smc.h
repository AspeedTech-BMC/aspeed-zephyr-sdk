/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

typedef enum {
	Success,
	Failure,
	ManifestCorruption,
	VerifyRecovery,
	VerifyActive,
	UnSupported,
	Decommission_Success,
	Lockdown
} Verification_Status;

enum _hrot_event {
	BMC_EVENT = 1,
	PCH_EVENT,
	AFM_EVENT,
	CPLD_EVENT,
	AFM_EVENT2,
};

