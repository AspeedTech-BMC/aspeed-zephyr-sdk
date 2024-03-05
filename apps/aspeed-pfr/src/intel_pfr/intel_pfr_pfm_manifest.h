/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include "pfr/pfr_common.h"

#define BIOS1_BIOS2 0x00
#define ME_SPS          0x01
#define Microcode1      0x02
#define Microcode2      0x03

#define SPI_REGION     0x1
#define SMBUS_RULE     0x2
#define FVM_ADDR_DEF   0x3
#define FVM_CAP        0x4
#define AFM_ADDR_DEF   0x5

#define CFM_SPI_REGION 0x03

#define SIZE_OF_PCH_SMBUS_RULE 40
#define SPI_REGION_DEF_MIN_SIZE 16

#define PCH_FVM_SPI_REGION 0x01
#define PCH_FVM_CAP        0x04

#pragma pack(1)
typedef struct PFMSPIDEFINITION {
	uint8_t PFMDefinitionType;
	struct {
		uint8_t ReadAllowed : 1;
		uint8_t WriteAllowed : 1;
		uint8_t RecoverOnFirstRecovery : 1;
		uint8_t RecoverOnSecondRecovery : 1;
		uint8_t RecoverOnThirdRecovery : 1;
		uint8_t Reserved : 3;
	} ProtectLevelMask;
	struct {
		uint16_t SHA256HashPresent : 1;
		uint16_t SHA384HashPresent : 1;
		uint16_t Reserved : 14;
	} HashAlgorithmInfo;
	uint32_t Reserved;
	uint32_t RegionStartAddress;
	uint32_t RegionEndAddress;
} PFM_SPI_DEFINITION;

typedef enum {
	manifest_success,
	manifest_failure,
	manifest_unsupported
} Manifest_Status;

typedef struct _PFM_SPI_REGION {
	uint8_t PfmDefType;
	uint8_t ProtectLevelMask;
	struct {
		uint16_t Sha256Present : 1;
		uint16_t Sha384Present : 1;
		uint16_t Reserved : 14;
	} HashAlgorithmInfo;
	uint32_t Reserved;
	uint32_t StartOffset;
	uint32_t EndOffset;
} PFM_SPI_REGION;

typedef struct _PFM_STRUCTURE {
	uint32_t PfmTag;
	uint8_t SVN;
	uint8_t BkcVersion;
	uint16_t PfmRevision;
	uint32_t Reserved;
	uint8_t OemSpecificData[16];
	uint32_t Length;
} PFM_STRUCTURE;

typedef struct _FVM_STRUCTURE {
	uint32_t FvmTag;
	uint8_t SVN;
	uint8_t Reserved;
	uint16_t FvmRevision;
	uint16_t Reserved1;
	uint16_t FvType;
	uint8_t OemSpecificData[16];
	uint32_t Length;
} FVM_STRUCTURE;

typedef struct _PFM_SMBUS_RULE {
	uint8_t PFMDefinitionType;
	uint32_t Reserved;
	uint8_t BusId;
	uint8_t RuleID;
	uint8_t DeviceAddress;
	uint8_t CmdPasslist[32];
} PFM_SMBUS_RULE;

typedef struct _PFM_FVM_ADDRESS_DEFINITION {
	uint8_t PFMDefinitionType;
	uint16_t FVType;
	uint8_t Reserved[5];
	uint32_t FVMAddress;
} PFM_FVM_ADDRESS_DEFINITION;

typedef struct _FVM_CAPABILITIES {
	uint8_t FvmDefinition;
	uint16_t Reserved1;
	uint8_t Revision;
	uint16_t Size;
	uint32_t PckgVersion;
	uint32_t LayoutId;
	struct {
		uint32_t Reboot : 1;
		uint32_t Reserved : 31;
	} UpdateAction;
	uint8_t Reserved2[26];
	uint8_t Description[20];
} FVM_CAPABLITIES;

typedef struct _AFM_STRUCTURE {
	uint32_t AfmTag; /* Should be 0x8883CE1D */
	uint8_t SVN;
	uint8_t Reserved;
	uint16_t AfmRevision; /* Major:Minor */
	uint8_t OemSpecificData[16];
	uint32_t Length;
	uint8_t AfmBody[];
	/* Padding to nearest 128B bondary with 0xFF */
} AFM_STRUCTURE;

typedef struct _AFM_ADDRESS_DEFINITION {
	uint8_t AfmDefinitionType; /* 0x03 AFM SPI region address definitions */
	uint8_t DeviceAddress; /* 7-bit SMBus address of the device to be measured */
	uint16_t UUID; /* Universal Unique ID of the device */
	uint32_t Length; /* Length of the AFM in bytes */
	uint32_t AfmAddress; /* Address of AFM must be at least 4k aligned */
} AFM_ADDRESS_DEFINITION;

typedef struct _AFM_ADDRESS_DEFINITION_v40 {
	uint8_t AfmDefinitionType; /* 0x05 AFM SPI region address definitions */
	uint8_t DeviceAddress;
	uint16_t Reserved1;
	uint8_t uuid[16];
	uint8_t Dev_ID[4];
	uint8_t Dev_Model[8];
	uint8_t Dev_Ver[2];
	uint8_t Reserved2[14];
	uint32_t length;
	uint32_t AfmAddress;
} AFM_ADDRESS_DEFINITION_v40;

/* TODO: This structure is changed after intel 60686 rev 2.3 to include measurement block index */
typedef struct _AFM_DEVICE_MEASUREMENT_VALUE {
	uint8_t PossibleMeasurements;
	uint8_t ValueType; /* Defined in DSP0274 1.0.0 spec section 4.10 */
	uint16_t ValueSize; /* Size of measurement value */
	uint8_t Values[];
} AFM_DEVICE_MEASUREMENT_VALUE;

typedef struct _AFM_DEVICE_MEASUREMENT_VALUE_v40 {
	uint8_t PossibleMeasurements;
	uint8_t Reserved[3];
	uint8_t ValueIndex;
	uint8_t ValueType; /* Defined in DSP0274 1.0.0 spec section 4.10 */
	uint16_t ValueSize; /* Size of measurement value */
	uint8_t Values[];
} AFM_DEVICE_MEASUREMENT_VALUE_v40;

typedef struct _AFM_DEVICE_STRUCTURE {
	uint16_t UUID;
	uint8_t BusID;
	uint8_t DeviceAddress; /* 7-bit SMBus address of the device to be measured */
	uint8_t BindingSpec; /* MCTP physical trasport binding (SMBus or I3C) */
	uint16_t BindingSpecVersion; /* Major:Minor */
	uint8_t Policy;
	uint8_t SVN;
	uint8_t Reserved1;
	uint16_t AfmVersion; /* Major:Minor */
	uint32_t CurveMagic; /* AFM_PUBLIC_SECP256_TAG, AFM_PUBLIC_SECP384_TAG, AFM_PUBLIC_RSA2K_TAG ... */
	uint16_t PlatformManufacturerStr;
	uint16_t PlatformManufacturerIDModel;
	uint8_t Reserved2[20];
	uint8_t PublicKeyModuleXY[512];
	uint32_t PublicKeyExponent;
	uint8_t TotalMeasurements;
	uint8_t Reserved3[3];
	AFM_DEVICE_MEASUREMENT_VALUE Measurements[];
} AFM_DEVICE_STRUCTURE;

typedef struct _AFM_DEVICE_STRUCTURE_v40_p2 {
	uint16_t PublicKeySize;
	uint8_t *PublicKeyModuleX;
	uint8_t *PublicKeyModuleY;
	uint32_t PublicKeyExponent;
	uint16_t Reserved4;
	uint16_t CertificateSize;
	uint8_t *Certificate;
} AFM_DEVICE_STRUCTURE_v40_p2;

typedef struct _AFM_DEVICE_STRUCTURE_v40_p3 {
	uint8_t TotalMeasurements;
	uint8_t Reserved5[3];
	AFM_DEVICE_MEASUREMENT_VALUE_v40 *Measurements;
} AFM_DEVICE_STRUCTURE_v40_p3;

typedef struct _AFM_DEVICE_STRUCTURE_v40_p1 {
	uint8_t UUID[16];
	uint32_t DeviceID;
	uint8_t DeviceModel[8];
	uint16_t DeviceVersion;
	uint8_t Reserved1[16];
	uint8_t BusID;
	uint8_t DeviceAddress; /* 7-bit SMBus address of the device to be measured */
	uint8_t BindingSpec; /* MCTP physical trasport binding (SMBus or I3C) */
	uint16_t BindingSpecVersion; /* Major:Minor */
	uint8_t Policy;
	uint8_t SVN;
	uint8_t Reserved2;
	uint16_t AfmVersion; /* Major:Minor */
	uint32_t CurveMagic; /* AFM_PUBLIC_SECP256_TAG, AFM_PUBLIC_SECP384_TAG, AFM_PUBLIC_RSA2K_TAG ... */
	uint16_t PlatformManufacturerStr;
	uint16_t PlatformManufacturerIDModel;
	uint8_t Reserved3[18];
} AFM_DEVICE_STRUCTURE_v40_p1;

typedef struct _AFM_DEVICE_STRUCTURE_v40 {
	AFM_DEVICE_STRUCTURE_v40_p1 *dev;
	AFM_DEVICE_STRUCTURE_v40_p2 *pubkey;
	AFM_DEVICE_STRUCTURE_v40_p3 *measurements;
} AFM_DEVICE_STRUCTURE_v40;

typedef struct {
	uint8_t Calculated : 1;
	uint8_t Count : 2;
	uint8_t RecoveredCount : 2;
	uint8_t DynamicEraseTriggered : 1;
	uint8_t Reserved : 2;
} ProtectLevelMask;

#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)

typedef struct _CPLD_PFM_STRUCTURE {
	uint32_t PfmTag;
	uint8_t SVN;
	uint8_t BkcVersion;
	uint16_t PfmRevision;
	uint16_t DevId;
	uint16_t Reserved;
	uint8_t OemSpecificData[16];
	uint32_t Length;
} CPLD_PFM_STRUCTURE;

typedef struct _CPLD_ADDR_DEF_STRUCTURE {
	uint8_t FmDef;
	uint16_t FwType;
	uint8_t Reserved;
	uint32_t Length;
	uint32_t ImageStartAddr;
} CPLD_ADDR_DEF_STRUCTURE;

typedef struct _CFM_STRUCTURE {
	uint32_t CfmTag;
	uint8_t SVN;
	uint8_t Reserved1;
	uint16_t CpldRevision;
	uint16_t Reserved2;
	uint16_t FwType;
	uint8_t OemSpecificData[16];
	uint32_t Length;
} CFM_STRUCTURE;
#endif

#pragma pack()

int get_recover_pfm_version_details(struct pfr_manifest *manifest, uint32_t address);
int get_active_pfm_version_details(struct pfr_manifest *manifest, uint32_t address);
int pfm_spi_region_verification(struct pfr_manifest *manifest);
int update_afm_body(uint32_t type, uint32_t read_address);

