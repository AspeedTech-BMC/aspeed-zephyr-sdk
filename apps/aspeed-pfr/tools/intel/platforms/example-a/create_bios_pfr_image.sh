#!/bin/bash

# Input setting
PLATFORM_NAME="plta"
BIOS_ACTIVE_IMAGE="$1"
if ! test -f "${BIOS_ACTIVE_IMAGE}"; then
    echo "Invalid BIOS active image: $1"
    exit 1
fi

# 1 = SHA256
# 2 = SHA384
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

# PFM setting
PFR_SVN="1"
PFR_BKC_VER="1"
PFR_BUILD_VER_MAJ="1"
PFR_BUILD_VER_MIN="0"
PFR_BUILD_NUM="787788"
PFM_JSON_FILE="${PLATFORM_NAME}_bios_pfm.json"
PFM_UNSIGNED_BIN="${PLATFORM_NAME}-pfm.bin"
PFM_SIGNED_BIN="${PFM_UNSIGNED_BIN}.signed"

# Image setting
BIOS_IMAGE_TEMP="image-bios-temp"
BIOS_PFR_IMAGE="image-bios-pfr"
# Size unit kb
PFR_IMAGE_SIZE="65536"
PFR_RECOVERY_OFFSET="44992"
PFR_PFM_OFFSET="65472"

# Update capsule setting
BIOS_UPDATE_CAPSULE="${PLATFORM_NAME}-bios_cap.bin"
BIOS_PBC_BIN="${PLATFORM_NAME}-pbc.bin"
BIOS_COMPRESSED_BIN="${PLATFORM_NAME}-bios_compressed.bin"
BIOS_SIGNED_UPDATE_CAPSULE="${BIOS_UPDATE_CAPSULE}.signed"
BIOS_SIGNED_UPDATE_CAPSULE_LINK="bios_signed_cap.bin"

mk_empty_image() {
    image_dst="$1"
    image_size_kb=$2
    dd if=/dev/zero bs=1k count=$image_size_kb \
        | tr '\000' '\377' > $image_dst
}

rm -rf ${BIOS_IMAGE_TEMP}
rm -rf ${BIOS_PFR_IMAGE}
rm -rf *.bin
rm -rf *.bin*

# Generate the unsigned PFM from the BIOS active image
echo "Generate the unsigned PFM from the ${BIOS_ACTIVE_IMAGE} image..."

# Assemble the flash image
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

if [ $? -ne 0 ]; then
    echo "!!!Generate the unsigned PFM failed.!!!"
    exit 1
fi

mv ${PLATFORM_NAME}-bmc_compressed.bin ${PLATFORM_NAME}-bios_compressed.bin

# Sign the PFM
echo "Sign the PFM..."
./intel-pfr-signing-utility -c ${PFM_CONFIG_XML} -o ${PFM_SIGNED_BIN} ${PFM_UNSIGNED_BIN} -v
if [ $? -ne 0 ]; then
    echo "!!!Sign the PFM failed.!!!"
    exit 1
fi

# Verify the PFM
echo "Verify the PFM.."
./intel-pfr-signing-utility -p ${PFM_SIGNED_BIN} -c ${PFM_CONFIG_XML}
if [ $(./intel-pfr-signing-utility -p ${PFM_SIGNED_BIN} -c ${PFM_CONFIG_XML} 2>&1 | grep "ERR" | wc -c) -gt 0 ]; then
    echo  "!!!Verify the PFM failed.!!!"
    exit 1
fi

# Add the signed PFM to the BIOS full ROM image at the PFM offset
echo "Add the signed PFM to the BIOS full ROM image at the offset: ${PFR_PFM_OFFSET}kb"
dd bs=1k conv=notrunc seek=${PFR_PFM_OFFSET} \
  if=${PFM_SIGNED_BIN} \
  of=${BIOS_PFR_IMAGE}

# Create the unsigned BIOS image update capsule
# append with 1. pfm_signed, 2. pbc, 3. bios compressed
echo "Create the unsigned BIOS image update capsule..."
echo "append with 1:${PFM_SIGNED_BIN}, 2:${BIOS_PBC_BIN}, 3:${BIOS_COMPRESSED_BIN}"
dd if=${PFM_SIGNED_BIN} bs=1k >> ${BIOS_UPDATE_CAPSULE}
dd if=${BIOS_PBC_BIN} bs=1k >> ${BIOS_UPDATE_CAPSULE}
dd if=${BIOS_COMPRESSED_BIN} bs=1k >> ${BIOS_UPDATE_CAPSULE}

# Sign the BIOS update capsule
echo "Sign the BIOS update capsule..."
./intel-pfr-signing-utility -c ${BIOS_CONFIG_XML} -o ${BIOS_SIGNED_UPDATE_CAPSULE} ${BIOS_UPDATE_CAPSULE} -v
if [ $? -ne 0 ]; then
    echo "!!!Sign the BIOS update capsule failed.!!!"
    exit 1
fi

# Verify the update capsule
echo "Verify the update capsule.."
./intel-pfr-signing-utility -p ${BIOS_SIGNED_UPDATE_CAPSULE} -c ${BIOS_CONFIG_XML}
if [ $(./intel-pfr-signing-utility -p ${BIOS_SIGNED_UPDATE_CAPSULE} -c ${BIOS_CONFIG_XML} 2>&1 | grep "ERR" | wc -c) -gt 0 ]; then
    echo  "!!!Verify the update capsule failed.!!!"
    exit 1
fi

ln -sf ${BIOS_SIGNED_UPDATE_CAPSULE} ${BIOS_SIGNED_UPDATE_CAPSULE_LINK}

# Add the signed BIOS update capsule to the BIOS full ROM image at the Recovery offset
echo "Add the signed BIOS update capsule to the BIOS full ROM image at the Recovery offset: ${PFR_RECOVERY_OFFSET}kb"
dd bs=1k conv=notrunc seek=${PFR_RECOVERY_OFFSET} \
  if=${BIOS_SIGNED_UPDATE_CAPSULE} \
  of=${BIOS_PFR_IMAGE}

echo "Successfully create a BIOS PFR image: ${BIOS_PFR_IMAGE}"

