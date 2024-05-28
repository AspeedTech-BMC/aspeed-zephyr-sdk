# Introduction
This documentation briefly introduce users how to use Intel Platform Firmware Resilience(Intel PFR) tools create Platform Firmware Manifest(PFM) and BIOS update capsule from the active BIOS image, sign the PFM and BIOS update capsule using the `intel-pfr-signing-utility`. Add the signed PFM and signed BIOS update capsule to the BIOS full ROM image compatible Intel PFR.

# Required Tools
- [intel-pfr-signing-utility](https://github.com/Intel-BMC/intel-pfr-signing-utility)  
  Please see [tools/README.md](../../README.md) for detail.
- [pfr_image.py](https://github.com/AspeedTech-BMC/openbmc/blob/aspeed-master/meta-aspeed-sdk/meta-aspeed-pfr/recipes-intel/pfr/files/pfr_image.py)  
  This is the python script for Platform Firmware Manifest(PFM) and update capsule creation. ASPEED copy this python script, [pfr_image.py](https://github.com/Intel-BMC/openbmc/blob/1-release/meta-openbmc-mods/meta-common/recipes-intel/intel-pfr/files/pfr_image.py)  from [Intel-BMC/openbmc](https://github.com/Intel-BMC/openbmc) to [AspeedTech-BMC/openbmc](https://github.com/AspeedTech-BMC/openbmc). Execute this scripts with Python 3.6 or later.

# Flash layout
In this example, the size of BIOS active image is 16MB and the BIOS full ROM image size is 64MB, the partition layout is below:
|Contents                    |Start Address|End Address(-1)   |Size(KB)| Type    |
|:---------------------------|:------------|:-----------------|:-------|:--------|
|Reserved-1                  |0x0000_0000  |0x0002_0000       |128     |Static   |
|Embedded Firmware Signature |0x0002_0000  |0x0002_4000       |16      |Static   |
|NVRAM                       |0x0002_4000  |0x0004_4000       |128     |Dynamic  |
|NVRAM Backup                |0x0004_4000  |0x0006_4000       |128     |Dynamic  |
|PSP Data                    |0x0006_4000  |0x007D_4000       |7616    |Static   |
|OEM NCB                     |0x007D_4000  |0x007E_4000       |64      |Dyanmic  |
|GPNV                        |0x007E_4000  |0x007F_4000       |64      |Dynamic  |
|WHEA                        |0x007F_4000  |0x0080_4000       |64      |Dynamic  |
|FV_MAIN                     |0x0080_4000  |0x00CA_0000       |4720    |Static   |
|FV_BB                       |0x00CA_0000  |0x0100_0000       |3456    |Static   |
|Reserved-2                  |0x0100_0000  |0x017F_0000       |8128    |Static   |
|Staging                     |0x017F_0000  |0x02BF_0000       |20480   |Dynamic  |
|Recovery                    |0x02BF_0000  |0x03FF_0000       |20480   |Static   |
|PFM                         |0x03FF_0000  |0x0400_0000       |64      |Static   |

# Create BIOS full ROM image
- Input:
  - BIOS active image whose size is **16MB**
  - Key pair generated with OpenSSL. Please see [tools/README.md](../../README.md) for detail.
  - A JSON file defines the firmware manifestation including SPI image layout.
  - XML files for the PFM and update capsule file signing with the `intel-pfr-signing-utility`
- Output:
  - BISO full ROM image whose size is **64MB**. It includes BIOS active image, signed PFM and signed BIOS update capsule.

## Generate the unsigned PFM from the BIOS active image
- input
  - BIOS active image whose size is 16MB.
  - JSON file: plta_bios_pfm.json
- output
  - the unsigned PFM: plta-pfm.bin
  - the pbc: plta-pbc.bin
  - the compressed binary: plta-bios_compressed.bin
  - the BIOS full ROM image: image-bios-pfr. It includes BIOS active image at offset 0 in this step.

  Both plta-pbc.bin and plta-bios_compressed.bin are used for unsigned BIOS update capsule generation.

- Script:
  - Generate a temporary full `64MB` image and places BIOS active imagae at the offest `0`.
  - It set BKC version `1`. So far, PFR firmware only supports this version.
  - It set SVN `1`, major version `1`, minor version `0` and build number `787788` by default.
  - Execute `pfr_image.py` to generate the unsigned PFM, pbc and compressed binary.

```
PFR_SHA="$2"
if test "x${PFR_SHA}" = "x1"; then
    echo "SHA256..."
    PFM_CONFIG_XML="${PLATFORM_NAME}_bios_pfm_config_secp256r1.xml"
    BIOS_CONFIG_XML="${PLATFORM_NAME}_bios_config_secp256r1.xml"
elif test "x${PFR_SHA}" = "x2"; then
    echo "SHA384..."
    PFM_CONFIG_XML="${PLATFORM_NAME}_bios_pfm_config_secp384r1.xml"
    BIOS_CONFIG_XML="${PLATFORM_NAME}_bios_config_secp384r1.xml"
else
    echo "Invalid hash algorithm:${PFR_SHA}"
    echo "Only support 1:sha256 and 2:sha384"
    exit 1
fi

PFR_SVN="1"
PFR_BKC_VER="1"
PFR_BUILD_VER_MAJ="1"
PFR_BUILD_VER_MIN="0"
PFR_BUILD_NUM="787788"
PFM_JSON_FILE="plta_bios_pfm.json"

# Image setting
BIOS_IMAGE_TEMP="image-bios-temp"
BIOS_PFR_IMAGE="image-bios-pfr"
# Size unit KB
PFR_IMAGE_SIZE="65536"

mk_empty_image ${BIOS_IMAGE_TEMP} ${PFR_IMAGE_SIZE}
dd bs=1k conv=notrunc seek=0 \
    if=${BIOS_ACTIVE_IMAGE}\
    of=${BIOS_IMAGE_TEMP}

python3 pfr_image.py \
    -m ${PFM_JSON_FILE} \
    -p ${PLATFORM_NAME} \
    -i ${BIOS_IMAGE_TEMP} \
    -j ${PFR_BUILD_VER_MAJ} \
    -n ${PFR_BUILD_VER_MIN} \
    -b ${PFR_BUILD_NUM} \
    -v ${PFR_BKC_VER} \
    -s ${PFR_SVN} \
    -a ${PFR_SHA} \
    -o ${BIOS_PFR_IMAGE}
```

## Sign the PFM
- input
  - the unsigned PFM: plta-pfm.bin
  - algorithm: ecdsa 384
    - the XML config: plta_bios_pfm_config_secp384r1.xml.
    - root keys: rk384_prv.pem and rk384_pub.pem
    - csk keys: csk384_prv.pem and csk384_pub.pem
  - algotithm: ecdsa 256
    - the XML config: plta_bios_pfm_config_secp256r1.xml.
    - root keys: rk_prv.pem and rk_pub.pem
    - csk keys: csk_prv.pem and csk_pub.pem
- output
  - the signed PFM: plta-pfm.bin.signed
- script
  - Sign the PFM using intel-pfr-signing-utility

```
# PFM setting
PFM_UNSIGNED_BIN="${PLATFORM_NAME}-pfm.bin"
PFM_SIGNED_BIN="${PFM_UNSIGNED_BIN}.signed"

# Sign the PFM
./intel-pfr-signing-utility -c ${PFM_CONFIG_XML} -o ${PFM_SIGNED_BIN} ${PFM_UNSIGNED_BIN} -v
```

## Add the signed PFM to the full ROM image at the PFM offset 0x03FF_0000
- input
  - the signed PFM: plta-pfm.bin.signed
- output
  - the BIOS full ROM image: image-bios-pfr. It includes signed PFM at offset 0x03FF_0000 in this step.
- script:
  - The 0x03FF_0000 is equal 65472kb
```
PFR_PFM_OFFSET="65472"

dd bs=1k conv=notrunc seek=${PFR_PFM_OFFSET} \
  if=${PFM_SIGNED_BIN} \
  of=${BIOS_PFR_IMAGE}
```

## Create the unsigned BIOS image update capsule
- input
  - the signed PFM: plta-pfm.bin.signed
  - the pbc: plta-pbc.bin
  - the compressed binary: plta-bios_compressed.bin
- output
  - the unsigned BIOS update capsule: plta-bios_cap.bin
- script
  - append with 1. signed PFM, 2. pbc, 3. BIOS compressed

```
# Update capsule setting
BIOS_UPDATE_CAPSULE="${PLATFORM_NAME}-bios_cap.bin"
BIOS_PBC_BIN="${PLATFORM_NAME}-pbc.bin"
BIOS_COMPRESSED_BIN="${PLATFORM_NAME}-bios_compressed.bin"

dd if=${PFM_SIGNED_BIN} bs=1k >> ${BIOS_UPDATE_CAPSULE}
dd if=${BIOS_PBC_BIN} bs=1k >> ${BIOS_UPDATE_CAPSULE}
dd if=${BIOS_COMPRESSED_BIN} bs=1k >> ${BIOS_UPDATE_CAPSULE}
```

## Sign the BIOS update capsule
- input
  - the unsigned BIOS update capsule: plta-bios_cap.bin
  - algorithm ecdsa 384
    - the XML config: plta_bios_config_secp384r1.xml.
    - root keys: rk384_prv.pem and rk384_pub.pem
    - csk keys: csk384_prv.pem and csk384_pub.pem
  - algotithm ecdsa 256
    - the XML config: plta_bios_config_secp256r1.xml.
    - root keys: rk_prv.pem and rk_pub.pem
    - csk keys: csk_prv.pem and csk_pub.pem
- output
  - the signed BIOS update capsule: `plta-bios_cap.bin.signed` and `bios_signed_cap.bin` which is a softlink.
- script
  - Sign the BIOS update capsule using intel-pfr-signing-utility

```
# Update capsule setting
BIOS_UPDATE_CAPSULE="${PLATFORM_NAME}-bios_cap.bin"
BIOS_SIGNED_UPDATE_CAPSULE="${BIOS_UPDATE_CAPSULE}.signed"

# Sign the BIOS update capsule
echo "Sign the BIOS update capsule..."
./intel-pfr-signing-utility -c ${BIOS_CONFIG_XML} -o ${BIOS_SIGNED_UPDATE_CAPSULE} ${BIOS_UPDATE_CAPSULE} -v
```

## Add the signed BIOS update capsule to the full ROM image at the Recovery offset 0x02BF_0000
- input
  - the signed BIOS update capsule: plta-bios_cap.bin.signed
- output
  - the BIOS full ROM image: image-bios-pfr. It includes signed BIOS update capsule at offset 0x02BF_0000 in this step.
- script:
  - The 0x02BF_0000 is equal 44992kb
```
PFR_RECOVERY_OFFSET="44992"

dd bs=1k conv=notrunc seek=${PFR_PFM_OFFSET} \
  if=${PFM_SIGNED_BIN} \
  of=${BIOS_PFR_IMAGE}
```

# Run create_bios_pfr_image.sh to generate BIOS PFR image
According to the design of Intel PFR spec, if users want to create a signature with `ECDSA 384` algorithm, it is required to use `sha384` hash algorithm. If users want to create a signature with `ECDSA 256`, it is required to use `sha256` hash algorithm.

The name of users BIOS active image: `bios_active_image`  
ASPEED PFR Keys: copy keys from `apps/aspeed-pfr/tools/intel/` to this directory.

- sha384 with ecdsa384
```
./create_bios_pfr_image.sh bios_active_image 2
```

- sha256 with ecdsa256
```
./create_bios_pfr_image.sh bios_active_image 1
```

# Notice
- Please ensuer provisioning the correct offsets of BIOS active, recovery and staging regions.
  |Region    |offset      |
  |:---------|:-----------|
  |Active    |0x03FF_0000 |
  |Recovery  |0x02BF_0000 |
  |Staging   |0x017F_0000 |

- The size of BIOS staging region is `20MB`. Please ensure to set the correct size in users configs.

```
CONFIG_PCH_STAGING_SIZE=0x1400000
```
