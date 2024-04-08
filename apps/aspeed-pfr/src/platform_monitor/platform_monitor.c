/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "watchdog_timer/wdt_utils.h"
#include "watchdog_timer/wdt_handler.h"
#include "platform_monitor.h"
#include "mctp/mctp.h"

LOG_MODULE_REGISTER(monitor, CONFIG_LOG_DEFAULT_LEVEL);

extern struct k_work log_bmc_rst_work;
extern uint8_t gWdtBootStatus;
static struct gpio_callback bmc_rstind_cb_data;
static void platform_reset_monitor_remove(void);

static void bmc_rstind_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);
	LOG_INF("[BMC->PFR] RSTIND[%s %d] = %d", dev->name, gpio_pin, ret);

	k_work_submit(&log_bmc_rst_work);
	GenerateStateMachineEvent(RESET_DETECTED, NULL);
}

/* Monitor BMC Reset Status */
void bmc_reset_monitor_init(void)
{
	int ret;
	struct gpio_dt_spec bmc_rstind =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common), bmc_rst_ind_in_gpios, 0);
	ret = gpio_pin_configure_dt(&bmc_rstind, GPIO_INPUT);
	LOG_INF("BMC: gpio_pin_configure_dt[%s %d] = %d", bmc_rstind.port->name, bmc_rstind.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&bmc_rstind, GPIO_INT_EDGE_FALLING);
	LOG_INF("BMC: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&bmc_rstind_cb_data, bmc_rstind_handler, BIT(bmc_rstind.pin));
	ret = gpio_add_callback(bmc_rstind.port, &bmc_rstind_cb_data);
	LOG_INF("BMC: gpio_add_callback = %d", ret);
}

void bmc_reset_monitor_remove(void)
{
	struct gpio_dt_spec bmc_rstind =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common), bmc_rst_ind_in_gpios, 0);
	gpio_pin_interrupt_configure_dt(&bmc_rstind, GPIO_INT_DISABLE);
	gpio_remove_callback(bmc_rstind.port, &bmc_rstind_cb_data);
}

#ifdef SUPPORT_PLTRST
static struct gpio_callback rst_pltrst_cb_data;

/**
 * Arm the ACM watchdog timer when ROT firmware detects a platform reset
 * through PLTRST# GPI signal.
 */
static void platform_reset_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
#ifdef INTEL_BHS
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);
	LOG_INF("[CPU->PFR] PLTRST_SYNC[%s %d] = %d", dev->name, gpio_pin, ret);

	platform_reset_monitor_remove();
	extern bool pltrst_sync;
	pltrst_sync = true;

#endif
#ifdef INTEL_EGS
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);
	uint32_t ms_timeout = WDT_ACM_TIMER_MAXTIMEOUT;
	int type = ACM_TIMER;

	LOG_INF("[Platform->PFR] PLTRST[%s %d] = %d", dev->name, gpio_pin, ret);

	// Clear previous boot done status
	gWdtBootStatus &= ~WDT_ACM_BIOS_BOOT_DONE_MASK;
	// Start ACM watchdog timer
	pfr_start_timer(type, ms_timeout);
#endif
#ifdef AMD_GENOA
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);

	LOG_INF("[Platform->PFR] PLTRST[%s %d] = %d", dev->name, gpio_pin, ret);
#endif
}

/* Monitor Platform Reset Status */
static void platform_reset_monitor_init(void)
{
#ifdef INTEL_BHS
	int ret;
	struct gpio_dt_spec rst_pltrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), rst_pltrst_in_gpios, 0);

	ret = gpio_pin_configure_dt(&rst_pltrst, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", rst_pltrst.port->name, rst_pltrst.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&rst_pltrst, GPIO_INT_EDGE_RISING);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&rst_pltrst_cb_data, platform_reset_handler, BIT(rst_pltrst.pin));
	ret = gpio_add_callback(rst_pltrst.port, &rst_pltrst_cb_data);
	LOG_INF("Platform: gpio_add_callback = %d", ret);
#endif
#ifdef INTEL_EGS
	int ret;
	struct gpio_dt_spec rst_pltrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_egs), rst_pltrst_in_gpios, 0);

	ret = gpio_pin_configure_dt(&rst_pltrst, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", rst_pltrst.port->name, rst_pltrst.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&rst_pltrst, GPIO_INT_EDGE_RISING);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&rst_pltrst_cb_data, platform_reset_handler, BIT(rst_pltrst.pin));
	ret = gpio_add_callback(rst_pltrst.port, &rst_pltrst_cb_data);
	LOG_INF("Platform: gpio_add_callback = %d", ret);
#endif
#ifdef AMD_GENOA
	int ret;
	struct gpio_dt_spec rst_pltrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_genoa), rst_pltrst_in_gpios, 0);

	ret = gpio_pin_configure_dt(&rst_pltrst, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", rst_pltrst.port->name, rst_pltrst.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&rst_pltrst, GPIO_INT_EDGE_RISING);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&rst_pltrst_cb_data, platform_reset_handler, BIT(rst_pltrst.pin));
	ret = gpio_add_callback(rst_pltrst.port, &rst_pltrst_cb_data);
	LOG_INF("Platform: gpio_add_callback = %d", ret);
#endif
}

static void platform_reset_monitor_remove(void)
{
#ifdef INTEL_BHS
	struct gpio_dt_spec rst_pltrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), rst_pltrst_in_gpios, 0);

	gpio_pin_interrupt_configure_dt(&rst_pltrst, GPIO_INT_DISABLE);
	gpio_remove_callback(rst_pltrst.port, &rst_pltrst_cb_data);
#endif
#ifdef INTEL_EGS
	struct gpio_dt_spec rst_pltrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_egs), rst_pltrst_in_gpios, 0);

	gpio_pin_interrupt_configure_dt(&rst_pltrst, GPIO_INT_DISABLE);
	gpio_remove_callback(rst_pltrst.port, &rst_pltrst_cb_data);
#endif
#ifdef AMD_GENOA
	struct gpio_dt_spec rst_pltrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_genoa), rst_pltrst_in_gpios, 0);

	gpio_pin_interrupt_configure_dt(&rst_pltrst, GPIO_INT_DISABLE);
	gpio_remove_callback(rst_pltrst.port, &rst_pltrst_cb_data);
#endif
}
#endif

#ifdef SUPPORT_ME
static struct gpio_callback me_authn_fail_cb_data;
static struct gpio_callback me_bt_done_cb_data;

/**
 * ME_AUTHN_FAIL: 1 means ME Authentication Failed
 */
static void me_auth_fail_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);

	LOG_INF("[ME->PFR] ME_AUTHN_FAIL[%s %d] = %d", dev->name, gpio_pin, ret);
	me_wdt_timer_handler(AUTHENTICATION_FAILED);
}

/**
 * ME_BT_DONE: 1 means ME Boot Done
 */
static void me_boot_done_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);

	LOG_INF("[ME->PFR] ME_BT_DONE[%s %d] = %d", dev->name, gpio_pin, ret);
	me_wdt_timer_handler(EXECUTION_BLOCK_COMPLETED);
}

/* Monitor ME boot Status */
static void me_boot_monitor_init(void)
{
#ifdef INTEL_EGS
	int ret;
	struct gpio_dt_spec me_bt_done =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_egs), me_bt_done_in_gpios, 0);
	struct gpio_dt_spec me_authn_fail =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_egs), me_authn_fail_in_gpios, 0);

	ret = gpio_pin_configure_dt(&me_bt_done, GPIO_INPUT);
	LOG_INF("ME: gpio_pin_configure_dt[%s %d] = %d", me_bt_done.port->name, me_bt_done.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&me_bt_done, GPIO_INT_EDGE_RISING);
	LOG_INF("ME: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&me_bt_done_cb_data, me_boot_done_handler, BIT(me_bt_done.pin));
	ret = gpio_add_callback(me_bt_done.port, &me_bt_done_cb_data);
	LOG_INF("ME: gpio_add_callback = %d", ret);

	ret = gpio_pin_configure_dt(&me_authn_fail, GPIO_INPUT);
	LOG_INF("ME: gpio_pin_configure_dt[%s %d] = %d", me_authn_fail.port->name, me_authn_fail.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&me_authn_fail, GPIO_INT_EDGE_RISING);
	LOG_INF("ME: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&me_authn_fail_cb_data, me_auth_fail_handler, BIT(me_authn_fail.pin));
	ret = gpio_add_callback(me_authn_fail.port, &me_authn_fail_cb_data);
	LOG_INF("ME: gpio_add_callback = %d", ret);
#endif
}

static void me_boot_monitor_remove(void)
{
#ifdef INTEL_EGS
	struct gpio_dt_spec me_bt_done =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_egs), me_bt_done_in_gpios, 0);
	struct gpio_dt_spec me_authn_fail =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_egs), me_authn_fail_in_gpios, 0);

	gpio_pin_interrupt_configure_dt(&me_bt_done, GPIO_INT_DISABLE);
	gpio_remove_callback(me_bt_done.port, &me_bt_done_cb_data);
	gpio_pin_interrupt_configure_dt(&me_authn_fail, GPIO_INT_DISABLE);
	gpio_remove_callback(me_authn_fail.port, &me_authn_fail_cb_data);
#endif
}
#endif

void platform_monitor_init(void)
{
#ifdef SUPPORT_PLTRST
	platform_reset_monitor_init();
#endif
#ifdef SUPPORT_ME
	me_boot_monitor_init();
#endif
}

void platform_monitor_remove(void)
{
#ifdef SUPPORT_PLTRST
	platform_reset_monitor_remove();
#endif
#ifdef SUPPORT_ME
	me_boot_monitor_remove();
#endif
}

#if defined(CONFIG_INIT_POWER_SEQUENCE)
static struct gpio_callback rst_bmc_srst_cb_data;
static struct gpio_callback rst_rsmrst_cb_data;
void power_sequence_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	static int count = 2;

	gpio_pin_interrupt_configure(dev, gpio_pin, GPIO_INT_DISABLE);
	gpio_remove_callback(dev, cb);

	int ret = gpio_pin_get(dev, gpio_pin);
	LOG_INF("[CPLD->PFR] Interrupt [%s %d]=%d", dev->name, gpio_pin, ret);

	if (--count == 0) {
		LOG_INF("Power sequence passes");
		GenerateStateMachineEvent(INIT_DONE, NULL);
		SetPlatformState(CPLD_NIOS_II_PROCESSOR_STARTED);
	}
}

void power_sequence(void)
{
	struct gpio_dt_spec rst_bmc_srst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common), rst_srst_bmc_in_gpios, 0);
	struct gpio_dt_spec rst_rsmrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common), rst_rsmrst_in_gpios, 0);

	gpio_pin_configure_dt(&rst_bmc_srst, GPIO_INPUT);
	gpio_init_callback(&rst_bmc_srst_cb_data, power_sequence_handler, BIT(rst_bmc_srst.pin));
	gpio_add_callback(rst_bmc_srst.port, &rst_bmc_srst_cb_data);
	/* RESET INACTIVE means CPLD releases the RESET PIN */
	gpio_pin_interrupt_configure_dt(&rst_bmc_srst, GPIO_INT_LEVEL_INACTIVE);

	gpio_pin_configure_dt(&rst_rsmrst, GPIO_INPUT);
	gpio_init_callback(&rst_rsmrst_cb_data, power_sequence_handler, BIT(rst_rsmrst.pin));
	gpio_add_callback(rst_rsmrst.port, &rst_rsmrst_cb_data);
	/* RESET INACTIVE means CPLD releases the RESET PIN */
	gpio_pin_interrupt_configure_dt(&rst_rsmrst, GPIO_INT_LEVEL_INACTIVE);
}
#endif

struct k_work pwr_btn_work;
static struct gpio_callback fp_pwr_btn_cb_data;

static void power_btn_passthrough_update()
{
#ifdef INTEL_BHS
	struct gpio_dt_spec power_btn_in =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), fp_pwr_btn_in_gpios, 0);
	struct gpio_dt_spec power_btn_out =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), bmc_pwr_btn_out_gpios, 0);
	int ret = gpio_pin_get(power_btn_in.port, power_btn_in.pin);

	LOG_INF("[FP->PFR] PWR_BTN[%s %d] = %d", power_btn_in.port->name, power_btn_in.pin, ret);
	gpio_pin_set(power_btn_out.port, power_btn_out.pin, ret);
	gpio_pin_configure_dt(&power_btn_out, GPIO_OUTPUT);
	LOG_INF("[PFR->BMC] PWR_BTN[%s %d] = %d", power_btn_out.port->name, power_btn_out.pin, ret);
#endif
}

static void power_btn_work_handler(struct k_work *item)
{
#ifdef INTEL_BHS
	power_btn_passthrough_update();
#endif
}

void power_btn_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
#ifdef INTEL_BHS
	LOG_INF("[FP->PFR] PWN_BTN Interrupt");
	k_work_submit(&pwr_btn_work);
#endif
}

void power_btn(bool enable)
{
#ifdef INTEL_BHS
	static bool init_done = false;
	struct gpio_dt_spec power_btn_in =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), fp_pwr_btn_in_gpios, 0);
	struct gpio_dt_spec power_btn_out =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), bmc_pwr_btn_out_gpios, 0);

	if (!init_done) {
		k_work_init(&pwr_btn_work, power_btn_work_handler);
		gpio_init_callback(&fp_pwr_btn_cb_data, power_btn_handler, BIT(power_btn_in.pin));
		init_done = true;
	}

	LOG_INF("[FP->PFR] Monitor PWN_BTN[%s %d] %s",
			power_btn_in.port->name, power_btn_in.pin, enable ? "registered" : "removed");
	if (enable) {
		/* Register input */
		gpio_pin_configure_dt(&power_btn_in, GPIO_INPUT);
		gpio_add_callback(power_btn_in.port, &fp_pwr_btn_cb_data);
		gpio_pin_interrupt_configure_dt(&power_btn_in, GPIO_INT_EDGE_BOTH);

		/* Update PIN state at T0 */
		power_btn_passthrough_update();
	} else {
		/* Remove the callback */
		gpio_pin_interrupt_configure_dt(&power_btn_in, GPIO_INT_DISABLE);
		gpio_remove_callback(power_btn_in.port, &fp_pwr_btn_cb_data);

		/* Force to high at T-1 */
		LOG_INF("[PFR->BMC] T-1 PWR_BTN[%s %d] force to 1",
	  		power_btn_out.port->name, power_btn_out.pin);
		gpio_pin_set(power_btn_out.port, power_btn_out.pin, 1);
	}
#endif
}

