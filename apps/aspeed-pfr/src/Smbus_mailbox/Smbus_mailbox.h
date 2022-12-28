/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "include/SmbusMailBoxCom.h"
#include "AspeedStateMachine/common_smc.h"

#pragma pack(1)

typedef char byte;

typedef enum _SMBUS_MAILBOX_RF_ADDRESS_READONLY {
	CpldIdentifier = 0x00,
	CpldReleaseVersion = 0x01,
	CpldRotSvn = 0x02,
	PlatformState = 0x03,
	RecoveryCount = 0x04,
	LastRecoveryReason = 0x05,
	PanicEventCount = 0x06,
	LastPanicReason = 0x07,
	MajorErrorCode = 0x08,
	MinorErrorCode = 0x09,
	UfmStatusValue = 0x0a,
	UfmCommand = 0x0b,
	UfmCmdTriggerValue = 0x0c,
	UfmWriteFIFO = 0x0d,
	UfmReadFIFO = 0x0e,
#if defined(CONFIG_PFR_MCTP)
	MCTPWriteFIFO = 0x0f,
#else
	BmcCheckpoint = 0x0f,
#endif
	AcmCheckpoint = 0x10,
	BiosCheckpoint = 0x11,
	PchUpdateIntent = 0x12,
	BmcUpdateIntent = 0x13,
	PchPfmActiveSvn = 0x14,
	PchPfmActiveMajorVersion = 0x15,
	PchPfmActiveMinorVersion = 0x16,
	BmcPfmActiveSvn = 0x17,
	BmcPfmActiveMajorVersion = 0x18,
	BmcPfmActiveMinorVersion = 0x19,
	PchPfmRecoverSvn = 0x1a,
	PchPfmRecoverMajorVersion = 0x1b,
	PchPfmRecoverMinorVersion = 0x1c,
	BmcPfmRecoverSvn = 0x1d,
	BmcPfmRecoverMajorVersion = 0x1e,
	BmcPfmRecoverMinorVersion = 0x1f,
	CpldFPGARoTHash = 0x20, /* 0x20 - 0x5f */
#if defined(CONFIG_PFR_MCTP)
	BmcCheckpoint = 0x60,
#endif
#if defined(CONFIG_SEAMLESS_UPDATE)
	PchSeamlessUpdateIntent = 0x61,
	BmcSeamlessUpdateIntent = 0x62,
#endif
	Reserved                = 0x63,
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	AfmActiveSvn            = 0x74,
	AfmActiveMajorVersion   = 0x75,
	AfmActiveMinorVersion   = 0x76,
	AfmRecoverSvn           = 0x77,
	AfmRecoverMajorVersion  = 0x78,
	AfmRecoverMinorVersion  = 0x79,
	ProvisionStatus2        = 0x7a,
#endif
	AcmBiosScratchPad       = 0x80,
	BmcScratchPad           = 0xc0,
} SMBUS_MAILBOX_RF_ADDRESS;

typedef enum _EXECUTION_CHECKPOINT {
	ExecutionBlockStrat = 0x01,
	NextExeBlockAuthenticationPass,
	NextExeBlockAuthenticationFail,
	ExitingPlatformManufacturerAuthority,
	StartExternalExecutionBlock,
	ReturnedFromExternalExecutionBlock,
	PausingExecutionBlock,
	ResumedExecutionBlock,
	CompletingExecutionBlock,
	EnteredManagementMode,
	LeavingManagementMode,
	ReadyToBootOS = 0x80
} EXECUTION_CHECKPOINT;

typedef enum _UPDATE_INTENT {
	PchActiveUpdate                         = 0x01,
	PchRecoveryUpdate,
	PchActiveAndRecoveryUpdate,
	HROTActiveUpdate,
	BmcActiveUpdate                         = 0x08,
	BmcRecoveryUpdate                       = 0x10,
	HROTRecoveryUpdate                      = 0x20,
	DymanicUpdate                           = 0x40,
	UpdateAtReset                           = 0x80,
	PchActiveAndRecoveryUpdateAtReset       = 0x83,
	PchActiveDynamicUpdate                  = 0x41,
	PchActiveAndDynamicUpdateAtReset        = 0xc1,
	HROTActiveAndRecoveryUpdate             = 0x24,
	BmcActiveAndRecoveryUpdate              = 0x18,
	PchActiveAndBmcActiveUpdate             = 0x09,
	PchRecoveryAndBmcRecvoeryUpdate         = 0x12,
	PchFwAndBmcFwUpdate                     = 0x1B,
	PchBmcHROTActiveAndRecoveryUpdate       = 0x3f,
	BmcActiveAndDynamicUpdate               = 0x48,
	ExceptBmcActiveUpdate                   = 0x37,
	ExceptPchActiveUpdate                   = 0x3E,
} UPDATE_INTENT;

#if defined(CONFIG_SEAMLESS_UPDATE)
typedef enum _SEAMLESS_UPDATE_INTENT {
	PchFvSeamlessUpdate                     = 0x01,
	AfmActiveUpdate                         = 0x02,
	AfmRecoveryUpdate                       = 0x04,
	AfmActiveAndRecoveryUpdate              = 0x06,
} SEAMLESS_UPDATE_INTENT;
#endif

#pragma pack()

unsigned char set_provision_data_in_flash(uint32_t addr, uint8_t *DataBuffer, uint8_t DataSize);
int get_provision_data_in_flash(uint32_t addr, uint8_t *DataBuffer, uint32_t length);
unsigned char erase_provision_data_in_flash(void);

void ResetMailBox(void);
void InitializeSmbusMailbox(void);
void SetCpldIdentifier(byte Data);
byte GetCpldIdentifier(void);
void SetCpldReleaseVersion(byte Data);
byte GetCpldReleaseVersion(void);
void SetCpldRotSvn(byte Data);
byte GetCpldRotSvn(void);
byte GetPlatformState(void);
void SetPlatformState(byte PlatformStateData);
byte GetRecoveryCount(void);
void IncRecoveryCount(void);
byte GetLastRecoveryReason(void);

int getFailedUpdateAttemptsCount(void);
void LogErrorCodes(uint8_t major_err, uint8_t minor_err);
void LogUpdateFailure(uint8_t minor_err, uint32_t failed_count);
void ClearUpdateFailure(void);
void LogLastPanic(uint8_t panic);
void LogRecovery(uint8_t reason);
void LogWatchdogRecovery(uint8_t recovery_reason, uint8_t panic_reason);

// void SetLastRecoveryReason(LAST_RECOVERY_REASON_VALUE LastRecoveryReasonValue);
void SetLastRecoveryReason(byte LastRecoveryReasonValue);

byte GetPanicEventCount(void);
void IncPanicEventCount(void);
byte GetLastPanicReason(void);
// void SetLastPanicReason(LAST_PANIC_REASON_VALUE LastPanicReasonValue);
void SetLastPanicReason(byte LastPanicReasonValue);
byte GetMajorErrorCode(void);
// void SetMajorErrorCode(MAJOR_ERROR_CODE_VALUE MajorErrorCodeValue);
void SetMajorErrorCode(byte MajorErrorCodeValue);
byte GetMinorErrorCode(void);
// void SetMinorErrorCode(MINOR_ERROR_CODE_VALUE MinorErrorCodeValue);
void SetMinorErrorCode(byte MinorErrorCodeValue);
uint8_t GetUfmStatusValue(void);
void SetUfmStatusValue(uint8_t UfmStatusBitMask);
void ClearUfmStatusValue(uint8_t UfmStatusBitMask);
int CheckUfmStatus(uint32_t UfmStatus, uint32_t UfmStatusBitMask);
void SetUfmCmdTriggerValue(byte UfmCommandTriggerValue);
byte get_provision_command(void);
void set_provision_command(byte UfmCommandValue);
void set_provision_commandTrigger(byte UfmCommandTrigger);
byte GetBmcCheckPoint(void);
void SetBmcCheckPoint(byte BmcCheckpoint);
byte GetBiosCheckPoint(void);
void SetBiosCheckPoint(byte BiosCheckpoint);
byte GetPchPfmActiveSvn(void);
void SetPchPfmActiveSvn(byte ActiveSVN);
byte GetPchPfmActiveMajorVersion(void);
void SetPchPfmActiveMajorVersion(byte ActiveMajorVersion);
byte GetPchPfmActiveMinorVersion(void);
void SetPchPfmActiveMinorVersion(byte ActiveMinorVersion);
byte GetBmcPfmActiveSvn(void);
void SetBmcPfmActiveSvn(byte ActiveSVN);
byte GetBmcPfmActiveMajorVersion(void);
void SetBmcPfmActiveMajorVersion(byte ActiveMajorVersion);
byte GetBmcPfmActiveMinorVersion(void);
void SetBmcPfmActiveMinorVersion(byte ActiveMinorVersion);
byte GetPchPfmRecoverSvn(void);
void SetPchPfmRecoverSvn(byte RecoverSVN);
byte GetPchPfmRecoverMajorVersion(void);
void SetPchPfmRecoverMajorVersion(byte RecoverMajorVersion);
byte GetPchPfmRecoverMinorVersion(void);
void SetPchPfmRecoverMinorVersion(byte RecoverMinorVersion);
byte GetBmcPfmRecoverSvn(void);
void SetBmcPfmRecoverSvn(byte RecoverSVN);
byte GetBmcPfmRecoverMajorVersion(void);
void SetBmcPfmRecoverMajorVersion(byte RecoverMajorVersion);
byte GetBmcPfmRecoverMinorVersion(void);
void SetBmcPfmRecoverMinorVersion(byte RecoverMinorVersion);
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
byte GetAfmActiveSvn(void);
void SetAfmActiveSvn(byte ActiveSVN);
byte GetAfmActiveMajorVersion(void);
void SetAfmActiveMajorVersion(byte ActiveMajorVersion);
byte GetAfmActiveMinorVersion(void);
void SetAfmActiveMinorVersion(byte ActiveMinorVersion);
byte GetAfmRecoverSvn(void);
void SetAfmRecoverSvn(byte RecoverSVN);
byte GetAfmRecoverMajorVersion(void);
void SetAfmRecoverMajorVersion(byte RecoverMajorVersion);
byte GetAfmRecoverMinorVersion(void);
void SetAfmRecoverMinorVersion(byte RecoverMinorVersion);
byte GettProvisionStatus2(void);
void SetProvisionStatus2(byte ProvisionStatus2);
#endif
void process_provision_command(void);
void UpdateBiosCheckpoint(byte Data);
void UpdateBmcCheckpoint(byte Data);
void UpdateAcmCheckpoint(byte Data);
void initializeFPLEDs(void);
unsigned char erase_provision_flash(void);
void SetUfmFlashStatus(uint32_t UfmStatus, uint32_t UfmStatusBitMask);

bool IsSpdmAttestationEnabled();

#define UFM_STATUS_LOCK_BIT_MASK                      0b1
#define UFM_STATUS_PROVISIONED_ROOT_KEY_HASH_BIT_MASK 0b10
#define UFM_STATUS_PROVISIONED_PCH_OFFSETS_BIT_MASK   0b100
#define UFM_STATUS_PROVISIONED_BMC_OFFSETS_BIT_MASK   0b1000
#define UFM_STATUS_PROVISIONED_PIT_ID_BIT_MASK        0b10000
#define UFM_STATUS_PIT_L1_ENABLE_BIT_MASK             0b100000
#define UFM_STATUS_PIT_L2_ENABLE_BIT_MASK             0b1000000
#define UFM_STATUS_PIT_HASH_STORED_BIT_MASK           0b10000000
#define UFM_STATUS_PIT_L2_PASSED_BIT_MASK             0b100000000

// If root key hash, pch and bmc offsets are provisioned, we say CPLD has been provisioned
#define UFM_STATUS_PROVISIONED_BIT_MASK               0b000001110

extern uint8_t gBiosBootDone;
extern uint8_t gBmcBootDone;

