/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/crc.h>
#include <zephyr/kernel.h>
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "include/SmbusMailBoxCom.h"
#include "intel_pfr_cpld_utils.h"
#include "gpio/gpio_aspeed.h"
#include "pfr/pfr_util.h"
#include "i2c/hal_i2c.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#define RSU_CTRL_REG_WRITE_LEN     7
#define RSU_CTRL_REG_REQ_LEN       2
#define RSU_CTRL_REG_RES_LEN       3

#define CHK(_X)     if(_X & RSU_ERROR) {goto error;}
#define CHK_HS(_X)  if(_X) {goto error;}


uint8_t rsu_data_buf[512] __aligned(16);

extern const struct device *dev_i2c[I2C_BUS_MAX_NUM];

int get_rsu_dev(uint8_t rsu_type, const struct device **dev, uint8_t *slave_addr)
{

	switch (rsu_type) {
	case CPU_CPLD:
		if (CONFIG_INTEL_CPU_RSU_BUS >= I2C_BUS_MAX_NUM)
			goto error;
		*dev = dev_i2c[CONFIG_INTEL_CPU_RSU_BUS];
		*slave_addr = CONFIG_INTEL_CPU_RSU_DEV_ADDR;
		break;
	case SCM_CPLD:
		if (CONFIG_INTEL_SCM_RSU_BUS >= I2C_BUS_MAX_NUM)
			goto error;
		*dev = dev_i2c[CONFIG_INTEL_SCM_RSU_BUS];
		*slave_addr = CONFIG_INTEL_SCM_RSU_DEV_ADDR;
		break;
	case DEBUG_CPLD:
		if (CONFIG_INTEL_DEBUG_RSU_BUS >= I2C_BUS_MAX_NUM)
			goto error;
		*dev = dev_i2c[CONFIG_INTEL_DEBUG_RSU_BUS];
		*slave_addr = CONFIG_INTEL_DEBUG_RSU_DEV_ADDR;
		break;
	default:
		LOG_ERR("Unknown RSU type");
		return -1;
	}

	return Success;
error:
	return -1;
}

uint8_t bit_rev(uint8_t byte) {
	uint8_t reverse = 0;

	for (int i = 0; i < 8; i++) {
		if ((byte & (1 << i))) {
			reverse |= 1 << (7 - i);
		}
	}

	return reverse;
}

int intel_rsu_read_ctrl_reg(uint8_t rsu_type, uint8_t reg, uint16_t *val)
{
	const struct device *dev;
	struct i2c_msg msg[2];
	RSU_CTRL_REG_READ rsu_msg;
	uint8_t reg_addr[RSU_CTRL_REG_REQ_LEN];
	uint8_t response[RSU_CTRL_REG_RES_LEN];
	uint8_t slave_addr;
	uint8_t crc_res;
	uint8_t *res = (uint8_t *)val;

	if (get_rsu_dev(rsu_type, &dev, &slave_addr))
		return -1;

	reg_addr[0] = RSU_CTRL_REG;
	reg_addr[1] = reg;

	msg[0].buf = reg_addr;
	msg[0].len = sizeof(reg_addr);
	msg[0].flags = I2C_MSG_WRITE;
	msg[1].buf = response;
	msg[1].len = sizeof(response);
	msg[1].flags = I2C_MSG_RESTART | I2C_MSG_READ | I2C_MSG_STOP;

	if (i2c_transfer(dev, msg, 2, slave_addr))
		return -1;

	// Verify CRC
	rsu_msg.write_addr = slave_addr << 1;
	rsu_msg.reg_type = msg[0].buf[0];
	rsu_msg.reg_addr = msg[0].buf[1];
	rsu_msg.read_addr = rsu_msg.write_addr | 1;
	rsu_msg.read_data[0] = msg[1].buf[0];
	rsu_msg.read_data[1] = msg[1].buf[1];
	crc_res = crc8((uint8_t *)&rsu_msg, sizeof(rsu_msg), 7, 0, false);
	// The last byte of response is crc.
	if (response[RSU_CTRL_REG_RES_LEN - 1] != crc_res) {
		LOG_ERR("CRC mismatch (0x%02x vs. 0x%02x)", response[RSU_CTRL_REG_RES_LEN - 1],
				crc_res);
		return -1;
	}

	res[0] = response[1];
	res[1] = response[0];

	return 0;
}

int intel_rsu_write_ctrl_reg(uint8_t rsu_type, uint8_t reg, uint8_t wdata_h, uint8_t wdata_l)
{
	const struct device *dev;
	struct i2c_msg msg[2];
	uint8_t slave_addr;
	RSU_CTRL_REG_WRITE rsu_msg;

	if (get_rsu_dev(rsu_type, &dev, &slave_addr))
		return -1;

	rsu_msg.write_addr = slave_addr << 1;
	rsu_msg.reg_type = RSU_CTRL_REG;
	rsu_msg.reg_addr = reg;
	rsu_msg.zero = 0;
	rsu_msg.one = 1;
	rsu_msg.write_data[0] = wdata_h;
	rsu_msg.write_data[1] = wdata_l;
	rsu_msg.crc = crc8((uint8_t *)&rsu_msg, sizeof(rsu_msg) - 1, 7, 0, false);

	// exclude write_addr
	msg[0].buf = &rsu_msg.reg_type;
	msg[0].len = RSU_CTRL_REG_WRITE_LEN;
	msg[0].flags = I2C_MSG_WRITE | I2C_MSG_STOP;

	return i2c_transfer(dev, msg, 1, slave_addr);
}

int intel_rsu_write_data_reg(uint8_t rsu_type, uint8_t *buf, uint8_t buf_len)
{
	const struct device *dev;
	struct i2c_msg msg[2];
	uint8_t slave_addr;
	RSU_DATA_REG_WRITE rsu_msg;
	uint32_t cnt = 0;
	uint8_t crc_res;

	if (buf_len > 200) {
		LOG_ERR("buffer length exceeds maximum length");
		return -1;
	}

	if (get_rsu_dev(rsu_type, &dev, &slave_addr)) {
		LOG_ERR("Failed to find rsu devices");
		return -1;
	}

	rsu_msg.write_addr = slave_addr << 1;
	rsu_msg.reg_type = RSU_DATA_REG;
	rsu_msg.ram_addr = 0;
	rsu_msg.zero = 0;
	rsu_msg.word_len = buf_len / 2;

	memset(rsu_data_buf, 0, sizeof(rsu_data_buf));
	memcpy(rsu_data_buf, &rsu_msg, sizeof(rsu_msg));
	cnt += sizeof(rsu_msg);
	for (int i = 0; i < buf_len; i++)
		buf[i] = bit_rev(buf[i]);
	memcpy(rsu_data_buf + cnt, buf, buf_len);
	cnt += buf_len;
	crc_res = crc8((uint8_t *)rsu_data_buf, cnt, 7, 0, false);
	memcpy(rsu_data_buf + cnt, &crc_res, 1);

	msg[0].buf = &rsu_data_buf[1];
	msg[0].len = cnt;
	msg[0].flags = I2C_MSG_WRITE | I2C_MSG_STOP;

	return i2c_transfer(dev, msg, 1, slave_addr);
}

bool is_cpld_device_id_valid(uint8_t rsu_type)
{
	uint16_t devid;
	uint16_t val;

	switch (rsu_type) {
	case CPU_CPLD:
		devid = CONFIG_INTEL_CPU_RSU_DEV_ID;
		break;
	case SCM_CPLD:
		devid = CONFIG_INTEL_SCM_RSU_DEV_ID;
		break;
	case DEBUG_CPLD:
		devid = CONFIG_INTEL_DEBUG_RSU_DEV_ID;
		break;
	default:
		LOG_ERR("Unknown RSU type");
		return false;
	}

	if (intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_DEV_TYPE, &val)) {
		LOG_ERR("Failed to read RSU device type");
		return false;
	}

	if (val != devid) {
		LOG_ERR("Unknown device");
		return false;
	}

	return true;
}

int intel_rsu_dump_cpld_flash(uint8_t rsu_type, uint32_t addr, uint32_t dw_len)
{
	uint8_t addr_h_h, addr_h_l, addr_l_h, addr_l_l;
	uint32_t read_addr = addr;
	uint16_t val;
	uint8_t *res = (uint8_t *)&val;

	if (dw_len > sizeof(rsu_data_buf) / 4) {
		LOG_ERR("Word length should not exceed 128 dword(512 bytes)");
		return -1;
	}

	memset(rsu_data_buf, 0, sizeof(rsu_data_buf));

	// dw
	uint32_t byte_id;
	for (int i = 0; i < dw_len; i++) {
		read_addr = addr + i;
		addr_h_h = (read_addr >> 24) & 0xff;
		addr_h_l = (read_addr >> 16) & 0xff;
		addr_l_h = (read_addr >> 8) & 0xff;
		addr_l_l = read_addr & 0xff;
		CHK(intel_rsu_write_ctrl_reg(rsu_type, INTEL_RSU_REG_FLASH_ADDR_H,
					addr_h_h, addr_h_l));
		CHK(intel_rsu_write_ctrl_reg(rsu_type, INTEL_RSU_REG_FLASH_ADDR_L,
					addr_l_h, addr_l_l));
		CHK(intel_rsu_write_ctrl_reg(rsu_type, INTEL_RSU_REG_CMD, 0, RSU_FLASH_READ));
		byte_id = i * 4;
		CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_FLASH_RD_MEM_L, &val));
		rsu_data_buf[byte_id] = bit_rev(res[1]);
		rsu_data_buf[byte_id + 1] = bit_rev(res[0]);
		CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_FLASH_RD_MEM_H, &val));
		rsu_data_buf[byte_id + 2] = bit_rev(res[1]);
		rsu_data_buf[byte_id + 3] = bit_rev(res[0]);
	}

	LOG_INF("flash addr : %X", addr);
	LOG_HEXDUMP_INF(rsu_data_buf, sizeof(rsu_data_buf), "data:");

	return 0;
error:
	LOG_ERR("Failed to dump flash data");
	return -1;
}

int intel_rsu_hide_rsu(void)
{
	struct gpio_dt_spec hide_rsu_dt_spec =
			GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs),
					scm_rsu_hide_out_gpios, 0);
	gpio_pin_set(hide_rsu_dt_spec.port, hide_rsu_dt_spec.pin, 1);
	LOG_DBG("Hide RSU IP");
	return 0;
}

int intel_rsu_unhide_rsu(void)
{
	struct gpio_dt_spec hide_rsu_dt_spec =
			GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs),
					scm_rsu_hide_out_gpios, 0);
	gpio_pin_set(hide_rsu_dt_spec.port, hide_rsu_dt_spec.pin, 0);
	LOG_DBG("Unhide RSU IP");
	return 0;
}

int intel_rsu_get_support_mode(uint8_t rsu_type, uint16_t mode)
{
	uint16_t val;

	CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_SUPPORT_MODE, &val));
	if (val == mode)
		return 0;
	LOG_ERR("Support mode error, expected: 0x%x, actual: 0x%x", mode, val);
error:
	return -1;
}

int intel_rsu_get_lock_reg(uint8_t rsu_type)
{
	uint16_t val;

	CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_LOCK, &val));

	return val;
error:
	return -1;
}

int intel_rsu_handshake(uint8_t rsu_type)
{
	if (intel_rsu_get_lock_reg(rsu_type))
		return -1;
	if (intel_rsu_get_support_mode(rsu_type, RSU_SUPPORT_MODE_DEFAULT))
		return -1;

	return 0;
}

int intel_rsu_load_fw(uint8_t rsu_type, uint8_t image_load_bit)
{
	uint16_t val;
	CHK(intel_rsu_write_ctrl_reg(rsu_type, INTEL_RSU_REG_CMD, 0, image_load_bit));
	CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_ERR_STS, &val));
	if (val & RSU_ERROR) {
		// Load CFM firmware failed, fallback to CFM0.
		LOG_ERR("Load CFM firmware failed");
		LogErrorCodes(INTEL_CPLD_UPDATE_FAIL, INTEL_CPLD_IMAGE_LOAD_IMAGE);
		CHK(intel_rsu_write_ctrl_reg(rsu_type, INTEL_RSU_REG_CMD, 0, RSU_LOAD_CFM0));
		CHK(val);
		goto error;
	}
	return 0;
error:
	return -1;
}

int intel_rsu_check_fw_loaded(uint8_t rsu_type, uint16_t image_loaded_bit)
{
	uint16_t val;

	CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_CFG_STS, &val));
	if (!(val & image_loaded_bit)) {
		LOG_ERR("CPLD firmware is not loaded");
		LogErrorCodes(INTEL_CPLD_AUTH_FAIL, INTEL_CPLD_IMAGE_LOAD_IMAGE);
		goto error;
	}

	return 0;
error:
	return -1;
}

int intel_rsu_get_scm_board_id(void)
{
	uint8_t id;
	const struct gpio_dt_spec board_id[] = {
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), scm_board_id0_in_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), scm_board_id1_in_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), scm_board_id2_in_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), scm_board_id3_in_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), scm_board_id4_in_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), scm_board_id5_in_gpios, 0),
	};
	for (uint8_t bit = 0; bit < 6; ++bit) {
		gpio_pin_configure_dt(&board_id[bit], GPIO_INPUT);
		id = gpio_pin_get(board_id[bit].port, board_id[bit].pin) << bit;
	}

	return id;
}

#define CPLD_UPDATE_BUF_LEN          200
static uint8_t cpld_fw_buf[CPLD_UPDATE_BUF_LEN] __aligned(16);

int intel_rsu_perform_update(struct pfr_manifest *manifest, uint8_t rsu_type, uint32_t up_addr)
{
	uint32_t image_type = manifest->image_type;
	uint32_t flash_rd_addr = manifest->intel_cpld_addr[rsu_type];
	uint32_t remaining = manifest->intel_cpld_img_size[rsu_type];
	uint32_t flash_wr_dw_addr = up_addr;
	uint32_t update_size;
	uint16_t val;
	uint8_t addr_h_h, addr_h_l, addr_l_h, addr_l_l;

	uint32_t time_start;
	uint32_t time_end;

	time_start = k_uptime_get_32();
	// Validate device type
	CHK((!is_cpld_device_id_valid(rsu_type)));

	// Clear lock bit
	CHK(intel_rsu_write_ctrl_reg(rsu_type, INTEL_RSU_REG_LOCK, 0, 0));
	CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_ERR_STS, &val));
	CHK(val);

	// Set erase bit
	CHK(intel_rsu_write_ctrl_reg(rsu_type, INTEL_RSU_REG_CMD, 0, RSU_FLASH_ERASE));
	do {
		CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_ERR_STS, &val));
	} while(val & RSU_ERR_FLASH_BUSY);
	CHK(val);

	while(remaining)
	{
		update_size = (remaining >= CPLD_UPDATE_BUF_LEN) ? CPLD_UPDATE_BUF_LEN : remaining;
		addr_h_h = (flash_wr_dw_addr >> 24) & 0xff;
		addr_h_l = (flash_wr_dw_addr >> 16) & 0xff;
		addr_l_h = (flash_wr_dw_addr >> 8) & 0xff;
		addr_l_l = flash_wr_dw_addr & 0xff;
		// Set programming address (dw addr high)
		CHK(intel_rsu_write_ctrl_reg(rsu_type, INTEL_RSU_REG_FLASH_ADDR_H,
					addr_h_h, addr_h_l));
		CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_ERR_STS, &val));
		CHK(val);

		// Set programming address (dw addr low)
		CHK(intel_rsu_write_ctrl_reg(rsu_type, INTEL_RSU_REG_FLASH_ADDR_L,
					addr_l_h, addr_l_l));
		CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_ERR_STS, &val));
		CHK(val);

		// Set programming length(DW)
		CHK(intel_rsu_write_ctrl_reg(rsu_type, INTEL_RSU_REG_FLASH_OP_LEN, 0,
					update_size / 4));
		CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_ERR_STS, &val));
		CHK(val);
		// Put firmware data in data register
		pfr_spi_read(image_type, flash_rd_addr, update_size, cpld_fw_buf);
		CHK(intel_rsu_write_data_reg(rsu_type, cpld_fw_buf, update_size));
		CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_ERR_STS, &val));
		CHK(val);

		// Set program bit
		CHK(intel_rsu_write_ctrl_reg(rsu_type, INTEL_RSU_REG_CMD, 0, RSU_FLASH_WRITE));
		do {
			CHK(intel_rsu_read_ctrl_reg(rsu_type, INTEL_RSU_REG_ERR_STS, &val));
		} while(val & RSU_ERR_FLASH_BUSY);
		CHK(val);

		flash_rd_addr += CPLD_UPDATE_BUF_LEN;
		flash_wr_dw_addr += CPLD_UPDATE_BUF_LEN / 4;
		remaining -= update_size;
	}

	time_end = k_uptime_get_32();
	LOG_INF("CPLD update elapsed time = %u milliseconds", (time_end - time_start));

	k_msleep(1000);

	// Load updated firmware
	if (intel_rsu_load_fw(rsu_type, RSU_LOAD_CFM1))
		goto error;

	// Wait 1s and check result
	k_msleep(1000);

	if(intel_rsu_check_fw_loaded(rsu_type, RSU_CFG_STS_CFM1_LOADED))
		goto error;

	return 0;

error:
	LOG_ERR("CPLD firmware update failed");
	return -1;
}

int intel_cpld_read_hs_reg(uint8_t reg, uint16_t *val)
{
	const struct device *dev;
	struct i2c_msg msg[2];
	RSU_CTRL_REG_READ rsu_msg;
	uint8_t reg_addr[RSU_CTRL_REG_REQ_LEN];
	uint8_t response[RSU_CTRL_REG_RES_LEN];
	uint8_t slave_addr;
	uint8_t crc_res;
	uint8_t *res = (uint8_t *)val;

	if (get_rsu_dev(SCM_CPLD, &dev, &slave_addr))
		return -1;

	reg_addr[0] = CPLD_HS_REG;
	reg_addr[1] = reg;

	msg[0].buf = reg_addr;
	msg[0].len = sizeof(reg_addr);
	msg[0].flags = I2C_MSG_WRITE;
	msg[1].buf = response;
	msg[1].len = sizeof(response);
	msg[1].flags = I2C_MSG_RESTART | I2C_MSG_READ | I2C_MSG_STOP;

	if (i2c_transfer(dev, msg, 2, slave_addr))
		return -1;

	// Verify CRC
	rsu_msg.write_addr = slave_addr << 1;
	rsu_msg.reg_type = msg[0].buf[0];
	rsu_msg.reg_addr = msg[0].buf[1];
	rsu_msg.read_addr = rsu_msg.write_addr | 1;
	rsu_msg.read_data[0] = msg[1].buf[0];
	rsu_msg.read_data[1] = msg[1].buf[1];
	crc_res = crc8((uint8_t *)&rsu_msg, sizeof(rsu_msg), 7, 0, false);
	// The last byte of response is crc.
	if (response[RSU_CTRL_REG_RES_LEN - 1] != crc_res) {
		LOG_ERR("CRC mismatch (0x%02x vs. 0x%02x)", response[RSU_CTRL_REG_RES_LEN - 1],
				crc_res);
		return -1;
	}

	res[0] = response[1];
	res[1] = response[0];

	return 0;
}

int intel_cpld_write_hs_reg(uint8_t reg, uint8_t wdata_h, uint8_t wdata_l)
{
	const struct device *dev;
	struct i2c_msg msg[2];
	uint8_t slave_addr;
	RSU_CTRL_REG_WRITE rsu_msg;

	if (get_rsu_dev(SCM_CPLD, &dev, &slave_addr))
		return -1;

	rsu_msg.write_addr = slave_addr << 1;
	rsu_msg.reg_type = CPLD_HS_REG;
	rsu_msg.reg_addr = reg;
	rsu_msg.zero = 0;
	rsu_msg.one = 1;
	rsu_msg.write_data[0] = wdata_h;
	rsu_msg.write_data[1] = wdata_l;
	rsu_msg.crc = crc8((uint8_t *)&rsu_msg, sizeof(rsu_msg) - 1, 7, 0, false);

	// exclude write_addr
	msg[0].buf = &rsu_msg.reg_type;
	msg[0].len = RSU_CTRL_REG_WRITE_LEN;
	msg[0].flags = I2C_MSG_WRITE | I2C_MSG_STOP;

	return i2c_transfer(dev, msg, 1, slave_addr);
}

int prot_sts_match(uint8_t sts, uint8_t *match)
{
	uint16_t reg_val;
	CHK_HS(intel_cpld_read_hs_reg(INTEL_HS_REG_HS_STS, &reg_val));
	reg_val >>=4;
	*match = ((reg_val & sts) == sts) ? 1 : 0;

	return 0;
error:
	return -1;
}

int update_prot_sts(uint8_t sts)
{
	uint16_t reg_val;

	CHK_HS(intel_cpld_read_hs_reg(INTEL_HS_REG_HS_STS, &reg_val));
	reg_val |= (sts << 4);
	CHK_HS(intel_cpld_write_hs_reg(INTEL_HS_REG_HS_STS, 0, reg_val));

	return 0;
error:
	return -1;
}

#define CPLD_DEBUG_FW
uint8_t intel_hs_get_mb_board_id(void)
{
#ifdef CPLD_DEBUG_FW
	return 0x01;
#else
	uint8_t id;
	const struct gpio_dt_spec board_id[] = {
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), mb_board_id0_in_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), mb_board_id1_in_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), mb_board_id2_in_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), mb_board_id3_in_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), mb_board_id4_in_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), mb_board_id5_in_gpios, 0),
	};
	for (uint8_t bit = 0; bit < 6; ++bit) {
		gpio_pin_configure_dt(&board_id[bit], GPIO_INPUT);
		id = gpio_pin_get(board_id[bit].port, board_id[bit].pin) << bit;
	}

	return id;
#endif
}

uint8_t intel_hs_get_mb_revid(void)
{
#ifdef CPLD_DEBUG_FW
	return 0x02;
#else
	uint8_t id;
	const struct gpio_dt_spec board_id[] = {
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), mb_board_revid0_in_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), mb_board_revid1_in_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), mb_board_revid2_in_gpios, 0),
	};
	for (uint8_t bit = 0; bit < 3; ++bit) {
		gpio_pin_configure_dt(&board_id[bit], GPIO_INPUT);
		id = gpio_pin_get(board_id[bit].port, board_id[bit].pin) << bit;
	}

	return id;
#endif
}
uint16_t intel_hs_get_mb_id(void)
{
	return (intel_hs_get_mb_revid() << 8) | intel_hs_get_mb_board_id();
}

int intel_plat_cpld_handshake(void)
{
	uint16_t reg_val;
	uint8_t match = 0, cnt = 0;

	// Check handshake status
	CHK_HS(prot_sts_match(PROT_HS_STS_HANDSHAKE_DONE, &match))
	if (match)
		return 0;

	// Read MB ID and REVID
	CHK_HS(intel_cpld_read_hs_reg(INTEL_HS_REG_MB_ID, &reg_val));
	if (reg_val != intel_hs_get_mb_id()) {
		// Write unknown id to PROT STS
		CHK_HS(update_prot_sts(PROT_HS_STS_UNKNOWN_ID));
		goto error;
	}

	// Read MB CAPID
	CHK_HS(intel_cpld_read_hs_reg(INTEL_HS_REG_MB_CAPID0, &reg_val));
	if (reg_val != HS_MB_CAP_L) {
		goto error;
	}

	// Write PROT ID and PROT_REVID
	CHK_HS(intel_cpld_write_hs_reg(INTEL_HS_REG_PROT_ID, HS_PROT_REV_ID, HS_PROT_ID));
	CHK_HS(intel_cpld_write_hs_reg(INTEL_HS_REG_CFG0_PROT, HS_MB_CAP_H, HS_MB_CAP_L));
	do {
		// Wait for CPLD Ack
		if (cnt > 3) {
			// Write ACK timeout to PROT STS
			CHK_HS(update_prot_sts(PROT_HS_STS_MB_ACK_TIMEOUT));
			goto error;
		}
		cnt++;
		k_msleep(1000);
		CHK_HS(intel_cpld_read_hs_reg(INTEL_HS_REG_CFG0_MB, &reg_val));
	} while(reg_val != 0xffff);

	// Write handshake done to PROT STS
	CHK_HS(update_prot_sts(PROT_HS_STS_HANDSHAKE_DONE));
	// Check MB STS
	CHK_HS(intel_cpld_read_hs_reg(INTEL_HS_REG_HS_STS, &reg_val));
	if ((reg_val & MB_HS_STS_READY_TO_PROCEED_PROT) == MB_HS_STS_READY_TO_PROCEED_PROT)
		return 0;

error:
	LOG_ERR("Failed to handshake with Platform CPLD");
	GenerateStateMachineEvent(HANDSHAKE_FAILED, NULL);
	return -1;
}

