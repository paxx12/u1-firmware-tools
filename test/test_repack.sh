#!/bin/bash
set -e

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <firmware.img>"
    echo "Test unpacking and repacking firmware.img for byte-to-byte compatibility"
    exit 1
fi

FIRMWARE_IMG="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR/.."
set -eo pipefail

rm -rf tmp/step1-upfile/ tmp/step2-rkfw/ tmp/step3-rkafp/
mkdir -p tmp/step1-upfile/ tmp/step2-rkfw/ tmp/step3-rkafp/
REPACKED_IMG="$PWD/tmp/repacked.bin"
UPDATE_IMG="$PWD/tmp/step1-upfile/update.img"
RK_ROM_IMG="$PWD/tmp/step2-rkfw/rom.img"
RK_ROM_REPACKED="$PWD/tmp/rk-rom-repacked.img"
UPDATE_REPACKED="$PWD/tmp/update-repacked.img"

echo "Testing upfile repack for: $FIRMWARE_IMG"
echo "Work directory: $PWD"
echo

echo "Step 1: Display firmware info..."
apps/firmware-packing/sm_upfile.py info "$FIRMWARE_IMG"
echo

echo "Step 2: Unpack firmware..."
apps/firmware-packing/sm_upfile.py unpack "$FIRMWARE_IMG" tmp/step1-upfile/
echo

echo "Step 3: List unpacked files..."
ls -lh tmp/step1-upfile/
echo

echo "Step 4: Repack firmware..."
apps/firmware-packing/sm_upfile.py pack tmp/step1-upfile/ "$REPACKED_IMG"
echo

echo "Step 5: Compare original and repacked..."
if cmp -s "$FIRMWARE_IMG" "$REPACKED_IMG"; then
    echo "Success: The repacked firmware is identical to the original."
else
    echo "Failure: The repacked firmware differs from the original."
    exit 1
fi

echo
echo "Step 6: Split update.img into loader/rom/meta..."
apps/firmware-packing/rk_update_image.py unpack "$UPDATE_IMG" tmp/step2-rkfw/
echo

echo "Step 7: Unpack RKAFP image..."
apps/firmware-packing/rk_afptool.py unpack tmp/step2-rkfw/rom.img tmp/step3-rkafp/
echo

echo "Step 8: Repack RKAFP image..."
apps/firmware-packing/rk_afptool.py pack tmp/step3-rkafp/ "$RK_ROM_REPACKED"
echo

echo "Step 9: Compare original and repacked RKAFP image..."
if cmp -s "$RK_ROM_IMG" "$RK_ROM_REPACKED"; then
    echo "Success: RKAFP repack is identical."
else
    echo "Failure: RKAFP repack differs from original."
    exit 1
fi

echo
echo "Step 10: Rebuild update image..."
apps/firmware-packing/rk_update_image.py pack tmp/step2-rkfw/ "$UPDATE_REPACKED"
echo

echo "Step 11: Compare original and rebuilt update image..."
if cmp -s "$UPDATE_IMG" "$UPDATE_REPACKED"; then
    echo "Success: Update image repack is identical."
else
    echo "Failure: Update image repack differs from original."
    exit 1
fi
