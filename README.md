# Snapmaker U1 Firmware Tools

Python tools for unpacking and repacking Snapmaker U1 firmware images based on Rockchip platform.

## Requirements

```bash
apt install -y python3-crcmod u-boot-tools

# or
pip install crcmod
```

## Firmware Structure

```
firmware.bin (SNMK)
├── update.img (RKFW)
│   ├── loader
│   └── rom.img (RKAF)
│       ├── parameter
│       ├── boot.img (FIT)
│       │   ├── fdt.dtb
│       │   ├── kernel.img
│       │   └── resource.img (RSCE)
│       │       ├── rk-kernel.dtb
│       │       └── ...
│       ├── rootfs.img
│       ├── oem.img
│       ├── userdata.img
│       └── ...
├── at32f403a.bin (MCU1)
├── at32f415.bin (MCU2)
└── MCU_DESC
```

## Tools

### sm_snmk_tool.py

Snapmaker UPFILE container format. Contains SOC firmware and MCU binaries.

```bash
apps/sm_snmk_tool.py info <firmware.bin>
apps/sm_snmk_tool.py unpack <firmware.bin> <outdir>
apps/sm_snmk_tool.py pack <indir> <firmware.bin>
```

### rk_rkfw_tool.py

Rockchip RKFW update image. Contains bootloader and RKAF ROM image.

```bash
apps/rk_rkfw_tool.py unpack <update.img> <outdir>
apps/rk_rkfw_tool.py pack <indir> <update.img>
```

### rk_afp_tool.py

Rockchip RKAF partition image. Contains firmware partitions (kernel, rootfs, etc).

```bash
apps/rk_afp_tool.py unpack <rom.img> <outdir>
apps/rk_afp_tool.py pack <indir> <rom.img>
```

### rk_rkboot_tool.sh

Rockchip FIT boot image. Contains device tree, kernel, and resource image.

Requires `u-boot-tools` package (`dumpimage` and `mkimage`).

```bash
apps/rk_rkboot_tool.sh unpack <boot.img> <outdir>
apps/rk_rkboot_tool.sh pack <indir> <boot.img>
```

Note: FIT images contain timestamps and signatures. Repacked images will have different
timestamps and lose signatures, so byte-for-byte compatibility is not possible.

### rk_rsce_tool.py

Rockchip resource partition image. Contains device tree blobs and other resources.

```bash
apps/rk_rsce_tool.py unpack <resource.img> <outdir>
apps/rk_rsce_tool.py pack <indir> <resource.img>
```

## Example: Full Unpack/Repack Workflow

```bash
# 1. Unpack SNMK (firmware container)
apps/sm_snmk_tool.py unpack firmware.bin snmk/

# 2. Unpack RKFW (update.img)
apps/rk_rkfw_tool.py unpack snmk/update.img rkfw/

# 3. Unpack RKAF (rom.img)
apps/rk_afp_tool.py unpack rkfw/rom.img rkaf/

# 4. (Optional) Unpack FIT boot image
apps/rk_rkboot_tool.sh unpack rkaf/boot.img rkboot/

# 5. (Optional) Unpack resource.img from boot image
apps/rk_rsce_tool.py unpack rkboot/resource.img rsce/

# --- Make modifications ---

# 6. (Optional) Repack resource.img
apps/rk_rsce_tool.py pack rsce/ rkboot/resource.img

# 7. (Optional) Repack FIT boot image
apps/rk_rkboot_tool.sh pack rkboot/ rkaf/boot.img

# 8. Repack RKAF
apps/rk_afp_tool.py pack rkaf/ rkfw/rom.img

# 9. Repack RKFW
apps/rk_rkfw_tool.py pack rkfw/ snmk/update.img

# 10. Repack SNMK
apps/sm_snmk_tool.py pack snmk/ firmware-new.bin
```

## Testing

Verify byte-to-byte compatibility after repack:

```bash
test/test_repack.sh <firmware.bin>
```
