/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include "pfr/pfr_common.h"

#define INTEL_PFR_BLOCK_0_TAG           0xB6EAFD19

#define KEY_CANCELLATION_CAPSULE        0x100

#define BLOCK0_PCTYPE_ADDRESS           8
#define CSK_KEY_ID_ADDRESS              160
#define CSK_KEY_ID_ADDRESS_3K           580
#define CSK_START_ADDRESS               148
#define CSK_ENTRY_PC_SIZE               128
#define KEY_SIZE                        48
#define KEY_SIZE_3K                     512
#define HROT_UPDATE_RESERVED            32
#define MAX_BIOS_BOOT_TIME              300
#define MAX_ERASE_SIZE                  0x1000

#define BLOCK0_FRIST_RESERVED_SIZE      4
#define BLOCK0_SECOND_RESERVED_SIZE     32
#define BLOCK1_CSK_ENTRY_RESERVED_SIZE  20

#pragma pack(1)

typedef struct _PFR_AUTHENTICATION_BLOCK0 {
	// Block 0
	uint32_t Block0Tag;
	uint32_t PcLength;
	uint32_t PcType;
	uint32_t Reserved1;
	uint8_t Sha256Pc[32];
	uint8_t Sha384Pc[48];
	uint8_t Reserved2[32];
} PFR_AUTHENTICATION_BLOCK0;

typedef struct _PFR_AUTHENTICATION_BLOCK0_3K {
	// Block 0
	uint32_t Block0Tag;
	uint32_t PcLength;
	uint32_t PcType;
	uint32_t Reserved1;
	uint8_t Sha256Pc[32];
	uint8_t Sha384Pc[48];
	uint8_t Sha512Pc[64];
	uint8_t Reserved2[96];
} PFR_AUTHENTICATION_BLOCK0_3K;

typedef struct _RootEntry {
	uint32_t Tag;
	uint32_t PubCurveMagic;
	uint32_t KeyPermission;
	uint32_t KeyId;
	uint8_t PubKeyX[KEY_SIZE];
	uint8_t PubKeyY[KEY_SIZE];
	uint8_t Reserved[20];
} KEY_ENTRY;

typedef struct _RootEntry_3k {
	uint32_t Tag;
	uint32_t PubCurveMagic;
	uint32_t KeyPermission;
	uint32_t KeyId;
	union {
		struct {
			uint8_t PubKeyX[KEY_SIZE];
			uint8_t PubKeyY[KEY_SIZE];
			uint8_t Reserved1[416];
		};
		uint8_t Modulus[KEY_SIZE_3K];
	};
	uint32_t PubKeyExp;
	uint8_t Reserved[20];
} KEY_ENTRY_3K;

// CSK Entry
typedef struct _CSKENTRY {
	KEY_ENTRY CskEntryInitial;
	uint32_t CskSignatureMagic;
	uint8_t CskSignatureR[KEY_SIZE];
	uint8_t CskSignatureS[KEY_SIZE];
} CSKENTRY;

// CSK Entry For 3K Block Structure
typedef struct _CSKENTRY_3K {
	KEY_ENTRY_3K CskEntryInitial;
	uint32_t CskSignatureMagic;
	union {
		struct {
			uint8_t CskSignatureR[KEY_SIZE];
			uint8_t CskSignatureS[KEY_SIZE];
			uint8_t Reserved[416];
		};
		uint8_t Modulus[KEY_SIZE_3K];
	};
} CSKENTRY_3K;

// Block 0 Entry
typedef struct _BLOCK0ENTRY {
	uint32_t TagBlock0Entry;
	uint32_t Block0SignatureMagic;
	uint8_t Block0SignatureR[KEY_SIZE];
	uint8_t Block0SignatureS[KEY_SIZE];
} BLOCK0ENTRY;

// Block 0 Entry for 3K Block Structure
typedef struct _BLOCK0ENTRY_3K {
	uint32_t TagBlock0Entry;
	uint32_t Block0SignatureMagic;
	union {
		struct {
			uint8_t Block0SignatureR[KEY_SIZE];
			uint8_t Block0SignatureS[KEY_SIZE];
			uint8_t Reserved[416];
		};
		uint8_t Modulus[KEY_SIZE_3K];
	};
} BLOCK0ENTRY_3K;

typedef struct _RootEntry_lms {
	uint32_t Tag;
	uint32_t PubCurveMagic;
	uint32_t KeyPermission;
	uint32_t KeyId;
    int32_t keylen;
    uint8_t pubkey[100];
	uint8_t Reserved[12];
} KEY_ENTRY_lms;

typedef struct _CSKENTRY_lms {
	KEY_ENTRY_lms CskEntryInitial;
	uint32_t CskSignatureMagic;
	int32_t siglen;
	uint8_t CskSignature[2048];
} CSKENTRY_lms;

typedef struct _BLOCK0ENTRY_lms {
	uint32_t TagBlock0Entry;
	uint32_t Block0SignatureMagic;
	int32_t siglen;
	uint8_t Block0Signature[2048];
} BLOCK0ENTRY_lms;

typedef struct _PFR_AUTHENTICATION_BLOCK1_lms {
	// Block 1
	uint32_t TagBlock1;
	uint8_t ReservedBlock1[12];
	// -----------Signature chain---------
	KEY_ENTRY_lms RootEntry;   // 132byte
	CSKENTRY_lms CskEntry;
	BLOCK0ENTRY_lms Block0Entry;
} PFR_AUTHENTICATION_BLOCK1_lms;

typedef struct _PFR_AUTHENTICATION_BLOCK1 {
	// Block 1
	uint32_t TagBlock1;
	uint8_t ReservedBlock1[12];
	// -----------Signature chain---------
	KEY_ENTRY RootEntry;   // 132byte
	CSKENTRY CskEntry;
	BLOCK0ENTRY Block0Entry;

} PFR_AUTHENTICATION_BLOCK1;

typedef struct _PFR_AUTHENTICATION_BLOCK1_3K {
	// Block 1
	uint32_t TagBlock1;
	uint8_t ReservedBlock1[12];
	// -----------Signature chain---------
	KEY_ENTRY_3K RootEntry;   // 132byte
	CSKENTRY_3K CskEntry;
	BLOCK0ENTRY_3K Block0Entry;

} PFR_AUTHENTICATION_BLOCK1_3K;

struct key_entry_descriptor {
	uint32_t magic;
	uint32_t curve_magic;
	uint32_t permissions;
	uint32_t key_id;
	uint8_t public_key_x[48];
	uint8_t public_key_y[48];
	uint8_t reserved[20];
};

struct csk_entry_descriptor {
	struct key_entry_descriptor csk_entry_descriptor;
	uint32_t signature_magic;
	uint8_t signature_r[48];
	uint8_t signature_s[48];
};

struct block_0_entry {
	uint32_t magic;
	uint32_t signature_magic;
	uint8_t signature_r[48];
	uint8_t signature_s[48];
};

enum {
	PFR_CPLD_UPDATE_CAPSULE = 0x00,
	PFR_PCH_PFM,
	PFR_PCH_UPDATE_CAPSULE,
	PFR_BMC_PFM,
	PFR_BMC_UPDATE_CAPSULE,
	PFR_PCH_SEAMLESS_UPDATE_CAPSULE,
	PFR_AFM,
	PFR_INTEL_CPLD_UPDATE_CAPSULE,
	PFR_AFM_PER_DEV,
	PFR_AFM_ADD_TO_UPDATE = 0x0A,
	PFR_CPLD_UPDATE_CAPSULE_DECOMMISSON = 0x200
};

enum rsa_Curve {
	rsa2k = 3,
	rsa3k,
	rsa4k,
	rsa4k384,
	rsa4k512,
};

// Key Cancellation Enum
enum {
	CPLD_CAPSULE_CANCELLATION = 0x100,
	PCH_PFM_CANCELLATION,
	PCH_CAPSULE_CANCELLATION,
	BMC_PFM_CANCELLATION,
	BMC_CAPSULE_CANCELLATION,
	SEAMLESS_CAPSULE_CANCELLATION,
	AFM_CANCELLATION,
};

struct pfr_authentication {
	int (*validate_pctye)(struct pfr_manifest *manifest);
	int (*validate_kc)(struct pfr_manifest *manifest);
	int (*block1_block0_entry_verify)(struct pfr_manifest *manifest);
	int (*block1_csk_block0_entry_verify)(struct pfr_manifest *manifest);
	int (*block1_verify)(struct pfr_manifest *manifest);
	int (*block0_verify)(struct pfr_manifest *manifest);
#if defined(CONFIG_SEAMLESS_UPDATE)
	int (*fvm_verify)(struct pfr_manifest *manifest);
	int (*fvms_verify)(struct pfr_manifest *manifest);
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	int (*cfms_verify)(struct pfr_manifest *manifest);
	int (*online_update_cap_verify)(struct pfr_manifest *manifest);
#endif
};

#pragma pack()

int intel_pfr_manifest_verify(struct manifest *manifest, struct hash_engine *hash,
			      struct signature_verification *verification, uint8_t *hash_out, uint32_t hash_length);

void init_pfr_authentication(struct pfr_authentication *pfr_authentication);

int manifest_verify(struct manifest *manifest, struct hash_engine *hash,
		    struct signature_verification *verification, uint8_t *hash_out,
		    size_t hash_length);
#if defined(CONFIG_PIT_PROTECTION)
int intel_pfr_pit_level1_verify(void);
int intel_pfr_pit_level2_verify(void);
#endif
#if defined(CONFIG_SEAMLESS_UPDATE)
int intel_fvms_verify(struct pfr_manifest *manifest);
int intel_fvm_verify(struct pfr_manifest *manifest);
#endif

