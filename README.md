# Snapmaker U1 Firmware Tools

Python tools for unpacking and repacking Snapmaker U1 firmware images based on Rockchip platform.

## Requirements

```bash
apt install -y python3-crcmod

# or
pip install crcmod
```

## Firmware Structure

```
firmware.bin (UPFILE)
├── update.img (RKFW)
│   ├── loader
│   └── rom.img (RKAF)
│       ├── parameter
│       ├── boot.img
│       ├── kernel.img
│       ├── rootfs.img
│       ├── resource.img (RSCE)
│       │   ├── rk-kernel.dtb
│       │   └── ...
│       └── ...
├── at32f403a.bin (MCU1)
├── at32f415.bin (MCU2)
└── MCU_DESC
```

## Tools

### sm_upfile.py

Snapmaker UPFILE container format. Contains SOC firmware and MCU binaries.

```bash
apps/firmware-packing/sm_upfile.py info <firmware.bin>
apps/firmware-packing/sm_upfile.py unpack <firmware.bin> <outdir>
apps/firmware-packing/sm_upfile.py pack <indir> <firmware.bin>
```

### rk_update_image.py

Rockchip RKFW update image. Contains bootloader and RKAF ROM image.

```bash
apps/firmware-packing/rk_update_image.py unpack <update.img> <outdir>
apps/firmware-packing/rk_update_image.py pack <indir> <update.img>
```

### rk_afptool.py

Rockchip RKAF partition image. Contains firmware partitions (kernel, rootfs, etc).

```bash
apps/firmware-packing/rk_afptool.py unpack <rom.img> <outdir>
apps/firmware-packing/rk_afptool.py pack <indir> <rom.img>
```

### rk_resource_image.py

Rockchip resource partition image. Contains device tree blobs and other resources.

```bash
apps/firmware-packing/rk_resource_image.py unpack <resource.img> <outdir>
apps/firmware-packing/rk_resource_image.py pack <indir> <resource.img>
```

## Example: Full Unpack/Repack Workflow

```bash
# 1. Unpack UPFILE
apps/firmware-packing/sm_upfile.py unpack firmware.bin upfile/

# 2. Unpack RKFW (update.img)
apps/firmware-packing/rk_update_image.py unpack upfile/update.img rkfw/

# 3. Unpack RKAF (rom.img)
apps/firmware-packing/rk_afptool.py unpack rkfw/rom.img rkaf/

# 4. (Optional) Unpack resource.img
apps/firmware-packing/rk_resource_image.py unpack rkaf/Image/resource.img resources/

# --- Make modifications ---

# 5. (Optional) Repack resource.img
apps/firmware-packing/rk_resource_image.py pack resources/ rkaf/Image/resource.img

# 6. Repack RKAF
apps/firmware-packing/rk_afptool.py pack rkaf/ rkfw/rom.img

# 7. Repack RKFW
apps/firmware-packing/rk_update_image.py pack rkfw/ upfile/update.img

# 8. Repack UPFILE
apps/firmware-packing/sm_upfile.py pack upfile/ firmware-new.bin
```

## Testing

Verify byte-to-byte compatibility after repack:

```bash
test/test_repack.sh <firmware.bin>
```
