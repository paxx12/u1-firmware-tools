#!/bin/bash

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

    echo ""
    echo "Creating ITS file for repacking..."
    cat > "$output_dir/boot.its" << 'EOF'
/dts-v1/;

/ {
    version = <0x00>;
    description = "U-Boot FIT source file for arm";

    images {
        fdt {
            data = /incbin/("fdt.dtb");
            type = "flat_dt";
            arch = "arm64";
            compression = "none";
            load = <0xffffff00>;
            data-position = <0x800>;
            hash {
                algo = "sha256";
            };
        };

        kernel {
            data = /incbin/("kernel.img");
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
    mkimage -E -p 0x800 -B 0x100 -f boot.its "$boot_img"
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
