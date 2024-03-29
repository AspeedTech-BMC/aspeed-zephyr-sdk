/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <zephyr/kernel.h>
#include <zephyr/drivers/misc/aspeed/otp_aspeed.h>

#define OTP_IMAGE_ADDR 0x800e0000

bool is_otp_secureboot_en(enum otp_status *otp_rc);
int otp_prog(uint32_t addr);
