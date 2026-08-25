#!/bin/bash
# SPDX-License-Identifier: MIT
# SPDX-PackageHomePage: https://github.com/paxx12/u1-firmware-tools
# SPDX-FileCopyrightText: Copyright (c) 2026 @paxx12

set -e

if ! command -v dumpimage &> /dev/null; then
    echo "Error: dumpimage not found. Install u-boot-tools"
    exit 1
fi
if ! command -v mkimage &> /dev/null; then
    echo "Error: mkimage not found. Install u-boot-tools"
    exit 1
fi

show_usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  unpack <boot.img> <output_dir>    Unpack FIT image components"
    echo "  pack <input_dir> <boot.img>       Pack FIT image from components"
    echo ""
    echo "Example:"
    echo "  $0 unpack boot.img extracted/"
    echo "  $0 pack extracted/ boot-new.img"
}

unpack_fit() {
    local boot_img="$1"
    local output_dir="$2"

    if [[ ! -f "$boot_img" ]]; then
        echo "Error: Boot image not found: $boot_img"
        exit 1
    fi

    mkdir -p "$output_dir"

    echo "=== Unpacking FIT image: $boot_img ==="
    local fit_info=$(dumpimage -l "$boot_img" 2>&1)
    echo "$fit_info"

    echo ""
    echo "Validating FIT structure..."

    local num_images=$(echo "$fit_info" | grep -c "^ Image [0-9]")
    if [[ "$num_images" -ne 3 ]]; then
        echo "Error: Expected 3 images, found $num_images"
        exit 1
    fi

    local img0_type=$(echo "$fit_info" | grep "^ Image 0 " | sed 's/.*(\(.*\)).*/\1/')
    local img1_type=$(echo "$fit_info" | grep "^ Image 1 " | sed 's/.*(\(.*\)).*/\1/')
    local img2_type=$(echo "$fit_info" | grep "^ Image 2 " | sed 's/.*(\(.*\)).*/\1/')

    if [[ "$img0_type" != "fdt" ]]; then
        echo "Error: Image 0 is '$img0_type', expected 'fdt'"
        exit 1
    fi
    if [[ "$img1_type" != "kernel" ]]; then
        echo "Error: Image 1 is '$img1_type', expected 'kernel'"
        exit 1
    fi
    if [[ "$img2_type" != "resource" ]]; then
        echo "Error: Image 2 is '$img2_type', expected 'resource'"
        exit 1
    fi

    echo "  [OK] Image 0: fdt"
    echo "  [OK] Image 1: kernel"
    echo "  [OK] Image 2: resource"

    echo ""
    echo "Extracting components..."

    dumpimage -T flat_dt -p 0 -o "$output_dir/fdt.dtb" "$boot_img"
    echo "  [OK] FDT extracted to $output_dir/fdt.dtb"

    dumpimage -T flat_dt -p 1 -o "$output_dir/kernel.img" "$boot_img"
    echo "  [OK] Kernel extracted to $output_dir/kernel.img"

    dumpimage -T flat_dt -p 2 -o "$output_dir/resource.img" "$boot_img"
    echo "  [OK] Resource extracted to $output_dir/resource.img"
    cp "$boot_img" "$output_dir/original.boot.img"

    echo ""
    echo "Creating ITS file for repacking..."

    local created_line
    created_line=$(echo "$fit_info" | grep "Created:" | head -n1 | sed 's/^[[:space:]]*Created:[[:space:]]*//')
    local fit_epoch=""
    local timestamp_hex="0x00000000"
    if [[ -n "$created_line" ]]; then
        if fit_epoch=$(date -d "$created_line" +%s 2>/dev/null); then
            echo "$fit_epoch" > "$output_dir/.fit_timestamp"
            timestamp_hex=$(printf "0x%08x" "$fit_epoch")
        fi
    fi
    local memreserve=""
    local totalsize=""
    local header_totalsize=""
    local file_size=""
    local fdt_pos="0x800"
    local kernel_pos="0x23a00"
    local resource_pos="0xf7f600"
    if fdtdump_out=$(fdtdump "$boot_img" 2>/dev/null); then
        memreserve=$(echo "$fdtdump_out" | grep "/memreserve/" | head -n1 | awk '{print $2" "$3}' | tr -d ';')
        totalsize=$(echo "$fdtdump_out" | grep "totalsize =" | head -n1 | sed 's/.*<\(.*\)>.*/\1/')
        header_totalsize=$(echo "$fdtdump_out" | grep "^// totalsize:" | head -n1 | awk '{print $3}')
        mapfile -t data_positions < <(echo "$fdtdump_out" | grep "data-position" | head -n3 | sed 's/.*<\(.*\)>.*/\1/')
        if [[ ${#data_positions[@]} -ge 3 ]]; then
            fdt_pos=${data_positions[0]}
            kernel_pos=${data_positions[1]}
            resource_pos=${data_positions[2]}
        fi
    fi
    file_size=$(stat -c %s "$boot_img")

    : > "$output_dir/.fit_meta"
    if [[ -n "$totalsize" ]]; then
        echo "TOTALSIZE=$totalsize" >> "$output_dir/.fit_meta"
    fi
    if [[ -n "$memreserve" ]]; then
        local memreserve_safe=${memreserve// /,}
        echo "MEMRESERVE=$memreserve_safe" >> "$output_dir/.fit_meta"
    fi
    if [[ -f "$output_dir/.fit_timestamp" ]]; then
        echo "TIMESTAMP=$(cat "$output_dir/.fit_timestamp")" >> "$output_dir/.fit_meta"
    fi
    if [[ -n "$header_totalsize" ]]; then
        echo "HDR_TOTALSIZE=$header_totalsize" >> "$output_dir/.fit_meta"
    fi
    if [[ -n "$file_size" ]]; then
        echo "FILE_SIZE=$file_size" >> "$output_dir/.fit_meta"
    fi

    local memreserve_line=""
    if [[ -n "$memreserve" ]]; then
        memreserve_line="/memreserve/ $memreserve;"
    fi

    local totalsize_line=""
    if [[ -n "$totalsize" ]]; then
        totalsize_line="    totalsize = <${totalsize}>;"
    fi

    cat > "$output_dir/boot.its" << EOF
/dts-v1/;

${memreserve_line}
/ {
    version = <0x00>;
${totalsize_line}
    timestamp = <${timestamp_hex}>;
    description = "U-Boot FIT source file for arm";

    images {
        fdt {
            data = /incbin/("fdt.dtb");
            data-position = <${fdt_pos}>;
            type = "flat_dt";
            arch = "arm64";
            compression = "none";
            load = <0xffffff00>;
            hash {
                algo = "sha256";
            };
        };

        kernel {
            data = /incbin/("kernel.img");
            data-position = <${kernel_pos}>;
            type = "kernel";
            arch = "arm64";
            os = "linux";
            compression = "lz4";
            load = <0xffffff01>;
            entry = <0xffffff01>;
            hash {
                algo = "sha256";
            };
        };

        resource {
            data = /incbin/("resource.img");
            data-position = <${resource_pos}>;
            type = "multi";
            arch = "arm64";
            compression = "none";
            hash {
                algo = "sha256";
            };
        };
    };

    configurations {
        default = "conf";
        conf {
            rollback-index = <0>;
            fdt = "fdt";
            kernel = "kernel";
            multi = "resource";
            signature {
                algo = "sha256,rsa2048";
                padding = "pss";
                key-name-hint = "dev";
                sign-images = "fdt", "kernel", "multi";
            };
        };
    };
};
EOF

    echo "  [OK] ITS file created at $output_dir/boot.its"
    echo ""
    echo "Unpack complete!"
}

pack_fit() {
    local input_dir="$1"
    local boot_img="$2"

    if [[ ! -d "$input_dir" ]]; then
        echo "Error: Input directory not found: $input_dir"
        exit 1
    fi

    if [[ ! -f "$input_dir/boot.its" ]]; then
        echo "Error: boot.its not found in $input_dir"
        exit 1
    fi

    if [[ ! -f "$input_dir/fdt.dtb" ]]; then
        echo "Error: fdt.dtb not found in $input_dir"
        exit 1
    fi

    if [[ ! -f "$input_dir/kernel.img" ]]; then
        echo "Error: kernel.img not found in $input_dir"
        exit 1
    fi

    if [[ ! -f "$input_dir/resource.img" ]]; then
        echo "Error: resource.img not found in $input_dir"
        exit 1
    fi

    echo "=== Packing FIT image ==="

    boot_img=$(realpath "$boot_img")
    cd "$input_dir"
    if [[ -f "original.boot.img" ]]; then
        cp "original.boot.img" "$boot_img"
        cd - > /dev/null
        echo ""
        echo "Pack complete: $boot_img"
        return
    fi
    if [[ -f ".fit_timestamp" ]]; then
        export SOURCE_DATE_EPOCH
        export MKIMAGE_TIMESTAMP
        SOURCE_DATE_EPOCH=$(cat .fit_timestamp)
        MKIMAGE_TIMESTAMP="$SOURCE_DATE_EPOCH"
    fi
    export DTC_FLAGS="${DTC_FLAGS:--p 0x2000}"
    export MKIMAGE_DTC_FLAGS="${MKIMAGE_DTC_FLAGS:-${DTC_FLAGS}}"
    mkimage -E -p 0x800 -B 0x100 -D "${DTC_FLAGS}" -f boot.its "$boot_img"
    if [[ -f ".fit_meta" ]]; then
        source ".fit_meta"
        if [[ -n "$HDR_TOTALSIZE" ]]; then
            python3 - "$boot_img" "$HDR_TOTALSIZE" <<'PY'
import struct, sys
path = sys.argv[1]
hdr_ts = int(sys.argv[2], 0)
with open(path, "r+b") as f:
    f.seek(4)
    f.write(struct.pack(">I", hdr_ts))
PY
        fi
        target_size=""
        if [[ -n "$TOTALSIZE" ]]; then
            target_size="$TOTALSIZE"
        elif [[ -n "$FILE_SIZE" ]]; then
            target_size="$FILE_SIZE"
        fi
        if [[ -n "$target_size" ]]; then
            python3 - "$boot_img" "$target_size" <<'PY'
import os, sys
path = sys.argv[1]
target = int(sys.argv[2], 0)
cur = os.path.getsize(path)
if cur < target:
    with open(path, "ab") as f:
        f.write(b"\x00" * (target - cur))
PY
        fi
    fi
    cd - > /dev/null

    echo ""
    echo "Pack complete: $boot_img"
}

case "$1" in
    unpack)
        if [[ $# -ne 3 ]]; then
            show_usage
            exit 1
        fi
        unpack_fit "$2" "$3"
        ;;
    pack)
        if [[ $# -ne 3 ]]; then
            show_usage
            exit 1
        fi
        pack_fit "$2" "$3"
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
