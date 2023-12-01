/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <zephyr/device.h>
#include <zephyr/drivers/i2c.h>
#include "pfr/pfr_common.h"

#define SCM_BOARD_ID_DEFAULT             0x29

/* Intel RSU control registers */
#define INTEL_RSU_REG_DEV_TYPE           0x00
#define INTEL_RSU_REG_SYS_RESET          0x02
// Support Mode
#define INTEL_RSU_REG_SUPPORT_MODE       0x04
#define RSU_SUPPORT_MODE_BYTE            BIT(0)
#define RSU_SUPPORT_MODE_WORD            BIT(1)
#define RSU_SUPPORT_MODE_CRC             BIT(2)
#define RSU_SUPPORT_MODE_DEFAULT         (RSU_SUPPORT_MODE_WORD | RSU_SUPPORT_MODE_CRC)

#define INTEL_RSU_REG_DEV_ADDR           0x06
#define INTEL_RSU_REG_IMG_CRC            0x08

// Status of CPLD
#define INTEL_RSU_REG_CFG_STS            0x32
#define RSU_CFG_STS_FALLBACK_EVENT       BIT(0)
#define RSU_CFG_STS_CFM0_LOADED          BIT(1)
#define RSU_CFG_STS_CFM1_LOADED          BIT(2)

#define INTEL_RSU_REG_FLASH_STS          0x34

// Status Register
#define INTEL_RSU_REG_STATUS             0x36
#define RSU_STATUS_APP_ERROR             BIT(0)
#define RSU_STATUS_RESERVED              BIT(1)
#define RSU_STATUS_FLASH_ERROR           BIT(2)
#define RSU_STATUS_FLASH_BUSY            BIT(3)
#define RSU_STATUS_LOCK_PIN              BIT(4)
#define RSU_STATUS_LOCK_REG              BIT(5)

#define INTEL_RSU_REG_LOCK               0x38
#define INTEL_RSU_REG_FLASH_ADDR_H       0x7a
#define INTEL_RSU_REG_FLASH_ADDR_L       0x7c
#define INTEL_RSU_REG_FLASH_OP_LEN       0x7e

// Intel RSU Register Command
#define INTEL_RSU_REG_CMD                0x80
#define RSU_LOAD_CFM0                    BIT(0)
#define RSU_LOAD_CFM1                    BIT(1)
#define RSU_FLASH_ERASE                  BIT(2)
#define RSU_FLASH_WRITE                  BIT(3)
// For Debug purpose
#define RSU_FLASH_READ                   BIT(4)


#define INTEL_RSU_REG_IP_REV             0x82
#define INTEL_RSU_REG_FW_REV             0x84

// Primary Error Status
#define INTEL_RSU_REG_ERR_STS            0x86
#define RSU_ERR_APP_ERROR                BIT(0)
#define RSU_ERR_CRC_ERROR                BIT(1)
#define RSU_ERR_FLASH_ERROR              BIT(2)
#define RSU_ERR_FLASH_BUSY               BIT(3)
#define RSU_ERROR                        (RSU_ERR_APP_ERROR | RSU_ERR_CRC_ERROR)

// For Debug purpose
#define INTEL_RSU_REG_FLASH_RD_MEM_H     0x8a
#define INTEL_RSU_REG_FLASH_RD_MEM_L     0x88

// PROT Handshake Flow definitions
#define HS_MB_ID                                 0x0201
#define HS_MB_CAP_H                              0x00
#define HS_MB_CAP_L                              0x85
#define HS_PROT_ID                               0x03
#define HS_PROT_REV_ID                           0x04
// Platform CPLD Handshake registers
#define INTEL_HS_REG_MB_ID                    0x0
#define INTEL_HS_REG_MB_REVID                 0x1
#define INTEL_HS_REG_MB_CAPID0                0x2
#define   MB_CAP0_SGPIO_SUPPORT               BIT(0)
#define   MB_CAP0_BMC_FLASH_QTY               BIT(1)
#define   MB_CAP0_BIOS_FLASH_QTY              BIT(2)
#define   MB_CAP0_BMC_AUTH_DONE               BIT(3)
#define   MB_CAP0_BIOS_AUTH_DONE              BIT(4)
#define   MB_CAP0_I3C_BMC_VOLTAGE             BIT(5)
#define   MB_CAP0_I3C_CPU_VOLTAGE             BIT(6)
#define   MB_CAP0_SUPPORT_MB_CAP1             BIT(7)

#define INTEL_HS_REG_MB_CAPID1                0x3
#define   MB_CAP1_BMC_SPI_RST                 BIT(0)
#define   MB_CAP1_BIOS_SPI_RST                BIT(1)
#define   MB_CAP1_PROT_IRQ                    BIT(2)
#define   MB_CAP1_BMC_CLK_MUX                 BIT(3)
#define   MB_CAP1_BIOS_CLD_MUX                BIT(4)
#define   MB_CAP1_ODM_DEF1                    BIT(5)
#define   MB_CAP1_ODM_DEF2                    BIT(6)
#define   MB_CAP1_SUPPORT_MB_CAP2             BIT(7)

#define INTEL_HS_REG_PROT_ID                  0x4
#define INTEL_HS_REG_PROT_REVID               0x5
#define INTEL_HS_REG_CFG0_PROT                0x6
#define   CFG0_PROT_SGPIO_SUPPORT             BIT(0)
#define   CFG0_PROT_BMC_FLASH_QTY             BIT(1)
#define   CFG0_PROT_BIOS_FLASH_QTY            BIT(2)
#define   CFG0_PROT_BMC_AUTH_DONE             BIT(3)
#define   CFG0_PROT_BIOS_AUTH_DONE            BIT(4)
#define   CFG0_PROT_I3C_BMC_VOLTAGE           BIT(5)
#define   CFG0_PROT_I3C_CPU_VOLTAGE           BIT(6)
#define   CFG0_PROT_SUPPORT_CFG1              BIT(7)

#define INTEL_HS_REG_CFG1_PROT                0x7
#define   CFG1_PROT_BMC_SPI_RST               BIT(0)
#define   CFG1_PROT_BIOS_SPI_RST              BIT(1)
#define   CFG1_PROT_PROT_IRQ                  BIT(2)
#define   CFG1_PROT_BMC_CLK_MUX               BIT(3)
#define   CFG1_PROT_BIOS_CLD_MUX              BIT(4)
#define   CFG1_PROT_ODM_DEF1                  BIT(5)
#define   CFG1_PROT_ODM_DEF2                  BIT(6)
#define   CFG1_PROT_SUPPORT_CFG2              BIT(7)

#define INTEL_HS_REG_CFG0_MB                  0x8
#define   CFG0_MB_SGPIO_SUPPORT               BIT(0)
#define   CFG0_MB_BMC_FLASH_QTY               BIT(1)
#define   CFG0_MB_BIOS_FLASH_QTY              BIT(2)
#define   CFG0_MB_BMC_AUTH_DONE               BIT(3)
#define   CFG0_MB_BIOS_AUTH_DONE              BIT(4)
#define   CFG0_MB_I3C_BMC_VOLTAGE             BIT(5)
#define   CFG0_MB_I3C_CPU_VOLTAGE             BIT(6)
#define   CFG0_MB_ACK_VAL                     BIT(7)

#define INTEL_HS_REG_CFG1_MB                  0x9
#define   CFG1_MB_BMC_SPI_RST                 BIT(0)
#define   CFG1_MB_BIOS_SPI_RST                BIT(1)
#define   CFG1_MB_PROT_IRQ                    BIT(2)
#define   CFG1_MB_BMC_CLK_MUX                 BIT(3)
#define   CFG1_MB_BIOS_CLD_MUX                BIT(4)
#define   CFG1_MB_ODM_DEF1                    BIT(5)
#define   CFG1_MB_ODM_DEF2                    BIT(6)
#define   CFG1_MB_ACK_VAL                     BIT(7)

#define INTEL_HS_REG_HS_STS                   0xa
#define   MB_HS_STS_WAIT_FOR_HANDSHAKE        0
#define   MB_HS_STS_WAIT_FOR_PROPOSAL         1
#define   MB_HS_STS_WAIT_FOR_HS_DONE          2
#define   MB_HS_STS_UNKNOWN_ID                5
#define   MB_HS_STS_READY_TO_PROCEED_TPM      6
#define   MB_HS_STS_READY_TO_PROCEED_PROT     7

#define   PROT_HS_STS_WAIT_FOR_MB_INFO        0
#define   PROT_HS_STS_WAIT_FOR_MB_ACK         1
#define   PROT_HS_STS_WAIT_FOR_HS_DONE        2
#define   PROT_HS_STS_MB_ACK_TIMEOUT          4
#define   PROT_HS_STS_UNKNOWN_ID              5
#define   PROT_HS_STS_NACK_UNSUPPORT          6
#define   PROT_HS_STS_HANDSHAKE_DONE          7

enum RSU_TYPE {
	CPU_CPLD = 0,
	SCM_CPLD,
	DEBUG_CPLD,
	MAX_RSU_TYPE,
};

enum CPLD_REG_TYPE {
	RSU_CTRL_REG = 0,
	RSU_DATA_REG,
	CPLD_HS_REG = 0x21,
};

enum RSU_MSG_TYPE {
	RSU_CTRL_WRITE_MSG = 0,
	RSU_CTRL_READ_MSG,
	RSU_DATA_WRITE_MSG,
};

#pragma pack(1)
typedef struct {
	uint8_t write_addr;
	uint8_t reg_type;
	uint8_t reg_addr;
	uint8_t zero;
	uint8_t one;
	uint8_t write_data[2];
	uint8_t crc;
} RSU_CTRL_REG_WRITE;

typedef struct {
	uint8_t write_addr;
	uint8_t reg_type;
	uint8_t reg_addr;
	uint8_t read_addr;
	uint8_t read_data[2];
} RSU_CTRL_REG_READ;

typedef struct {
	uint8_t write_addr;
	uint8_t reg_type;
	uint8_t ram_addr;
	uint8_t zero;
	uint8_t word_len;
} RSU_DATA_REG_WRITE;
#pragma pack()

int intel_rsu_read_ctrl_reg(uint8_t rsu_type, uint8_t reg, uint16_t *val);
int intel_rsu_write_ctrl_reg(uint8_t rsu_type, uint8_t reg, uint8_t wdata_h, uint8_t wdata_l);
int intel_rsu_write_data_reg(uint8_t rsu_type, uint8_t *buf, uint8_t buf_len);
int intel_rsu_dump_cpld_flash(uint8_t rsu_type, uint32_t addr, uint32_t dw_len);
int intel_rsu_hide_rsu(void);
int intel_rsu_unhide_rsu(void);
int intel_rsu_get_support_mode(uint8_t rsu_type, uint16_t mode);
int intel_rsu_get_lock_reg(uint8_t rsu_type);
int intel_rsu_handshake(uint8_t rsu_type);
int intel_rsu_load_fw(uint8_t rsu_type, uint8_t image_load_bit);
int intel_rsu_check_fw_loaded(uint8_t rsu_type, uint16_t image_loaded_bit);
int intel_rsu_get_scm_board_id(void);
int intel_rsu_perform_update(struct pfr_manifest *manifest, uint8_t rsu_type, uint32_t up_addr);
int intel_cpld_read_hs_reg(uint8_t reg, uint16_t *val);
int intel_cpld_write_hs_reg(uint8_t reg, uint8_t wdata_h, uint8_t wdata_l);
int intel_plat_cpld_handshake(void);
