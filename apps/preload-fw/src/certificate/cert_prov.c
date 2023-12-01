/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/drivers/misc/aspeed/abr_aspeed.h>
#include <aspeed_util.h>
#include "cert_verify.h"
#include "cert_prov.h"
#include "gpio/gpio_ctrl.h"
#include "otp/otp_utils.h"
#include "sw_mailbox/sw_mailbox.h"

LOG_MODULE_REGISTER(prov, CONFIG_LOG_DEFAULT_LEVEL);
PFR_DEVID_CERT_INFO devid_cert_info NON_CACHED_BSS_ALIGN16;
uint8_t cert_chain[CERT_CHAIN_SIZE];

PROV_STATUS cert_provision(void)
{
	enum otp_status otp_rc;
	bool is_secureboot_en;

	is_secureboot_en = is_otp_secureboot_en(&otp_rc);
	if (otp_rc) {
		goto out;
	}

	if (is_secureboot_en) {
		// Secure boot is enabled
		// Get device id certificate from internal flash
		LOG_INF("Secure boot is enabled, handling certificate");
		if (get_certificate_info(&devid_cert_info, sizeof(devid_cert_info))) {
			//DEBUG_HALT();
			LOG_ERR("Failed to get certificate!");
			set_mp_status(0, 1);
			goto out;
		}

		LOG_INF("Certificate verified successfully");
#if defined(CONFIG_ODM_ROT_REPLACEMENT)
		// 2nd bootup
		// Erase the 1st slot firmware, the 1st slot firmware will be replaced by
		// the 2nd slot firmeware(customer's firmware) by mcuboot's recovery mechanism
		// in the next bootup.

		const struct flash_area *fa;
		if (flash_area_open(FIXED_PARTITION_ID(active_partition), &fa)) {
			LOG_ERR("Failed to find active fw region");
			set_mp_status(1, 0);
			goto out;
		}
		if (flash_area_erase(fa, 0, fa->fa_size)) {
			set_mp_status(1, 0);
			goto out;
		}

		// *** IMPORTANT ***
		// DevID certificate can be a self-signed certificate or CSR after 2nd bootup.
		// If the generated DevID certificate is CSR,
		// programmer MUST do the following actions BEFORE next bootup:
		//   1. hold GPIOR6
		//   2. get DevID CSR from certificate partition
		//   3. send the CSR to HSM for signing
		//   4. put the signed certificate chain to fmc_cs0's certificate partition.
		LOG_INF("Preload fw is erased");
		set_mp_status(1, 1);
		return PROV_DONE;
#else
		if (IS_CSR(devid_cert_info)) {
			// 2nd bootup, CSR is generated and waiting for signing by HSM
			LOG_WRN("Certificate is not signed");
		} else {
			// 3rd bootup, certificate chain is generated and waiting for
			// firmware replacement
			LOG_INF("Verify certificate chain...");
			if (verify_certificate(devid_cert_info.cert.data,
						devid_cert_info.cert.length)) {
				LOG_ERR("Invalid certificate chain");
				cleanup_cert_info();
				goto out;
			}

			cleanup_cert_info();
#if defined(CONFIG_PFR_SW_MAILBOX)
			init_sw_mailbox();
#endif
			LOG_INF("Ready for ROT firmware replacement");
			return PROV_ROT_UPDATE;
		}
#endif
	} else {
		// 1st bootup:
		// Secure Boot is not enabled
		// Write necessary info to OTP memory
		//
		// otp_prog() does the following process:
		//   1. Update OTP image from flash to OTP memory
		//   2. Generate vault key
		//   3. Enable secure boot
		//   4. Enable CDI
		//   5. Erase OTP image in flash
		if (otp_prog(OTP_IMAGE_ADDR)) {
			LOG_ERR("OTP image update failed");
			set_mp_status(0, 1);
			goto out;
		} else {
			set_mp_status(1, 1);
		}
	}

	return PROV_DONE;
out:
	memset(cert_chain, 0, sizeof(cert_chain));
	memset(&devid_cert_info, 0, sizeof(devid_cert_info));
#if defined(CONFIG_ABR_FLOW_CTRL_ASPEED)
	// Remove this if abr is not enabled.
	disable_abr_wdt();
	return PROV_FAIL;
#endif
}
