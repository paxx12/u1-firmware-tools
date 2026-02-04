# Snapmaker U1 Firmware Tools

Python tools for unpacking and repacking Snapmaker U1 firmware images based on Rockchip platform.

## Installation

```bash
pip install .

# For development:
pip install -e .
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

### sm-upfile

Snapmaker UPFILE container format. Contains SOC firmware and MCU binaries.

```bash
sm-upfile info <firmware.bin>
sm-upfile unpack <firmware.bin> <outdir>
sm-upfile pack <indir> <firmware.bin>
```

### rk-update-image

Rockchip RKFW update image. Contains bootloader and RKAF ROM image.

```bash
rk-update-image unpack <update.img> <outdir>
rk-update-image pack <indir> <update.img>
```

### rk-afptool

Rockchip RKAF partition image. Contains firmware partitions (kernel, rootfs, etc).

```bash
rk-afptool unpack <rom.img> <outdir>
rk-afptool pack <indir> <rom.img>
```

### rk-resource-image

Rockchip resource partition image. Contains device tree blobs and other resources.

```bash
rk-resource-image unpack <resource.img> <outdir>
rk-resource-image pack <indir> <resource.img>
```

## Example: Full Unpack/Repack Workflow

```bash
# 1. Unpack UPFILE
sm-upfile unpack firmware.bin upfile/

# 2. Unpack RKFW (update.img)
rk-update-image unpack upfile/update.img rkfw/

# 3. Unpack RKAF (rom.img)
rk-afptool unpack rkfw/rom.img rkaf/

# 4. (Optional) Unpack resource.img
rk-resource-image unpack rkaf/Image/resource.img resources/

# --- Make modifications ---

# 5. (Optional) Repack resource.img
rk-resource-image pack resources/ rkaf/Image/resource.img

# 6. Repack RKAF
rk-afptool pack rkaf/ rkfw/rom.img

# 7. Repack RKFW
rk-update-image pack rkfw/ upfile/update.img

# 8. Repack UPFILE
sm-upfile pack upfile/ firmware-new.bin
```

## Testing

Verify byte-to-byte compatibility after repack:

```bash
test/test_repack.sh <firmware.bin>
```
