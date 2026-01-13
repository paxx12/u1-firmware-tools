#!/usr/bin/env python3
import sys
import os
import struct
import hashlib
from pathlib import Path

BLOCK_SIZE = 512
RESOURCE_PTN_HDR_MAGIC = b'RSCE'
INDEX_TBL_ENTR_TAG = b'ENTR'
RESOURCE_PTN_VERSION = 0
INDEX_TBL_VERSION = 0
RESOURCE_PTN_HDR_SIZE = 1
INDEX_TBL_ENTR_SIZE = 1
MAX_INDEX_ENTRY_PATH_LEN = 220
MAX_HASH_LEN = 32
FDT_PATH = "rk-kernel.dtb"
DTD_SUFFIX = ".dtb"
DEFAULT_IMAGE_PATH = "resource.img"
DEFAULT_UNPACK_DIR = "out"

g_debug = False
root_path = ""

def LOGE(msg):
    print(f"Error: {msg}", file=sys.stderr)

def LOGD(msg):
    if g_debug:
        print(f"Debug: {msg}", file=sys.stderr)

def fix_blocks(size):
    return (size + BLOCK_SIZE - 1) // BLOCK_SIZE

def fix_path(path):
    if path.startswith('./'):
        return path[2:]
    return path

def switch_int(x):
    return struct.unpack('<I', struct.pack('>I', x))[0]

def switch_short(x):
    return struct.unpack('<H', struct.pack('>H', x))[0]

class ResourcePtnHeader:
    def __init__(self):
        self.magic = RESOURCE_PTN_HDR_MAGIC
        self.resource_ptn_version = RESOURCE_PTN_VERSION
        self.index_tbl_version = INDEX_TBL_VERSION
        self.header_size = RESOURCE_PTN_HDR_SIZE
        self.tbl_offset = RESOURCE_PTN_HDR_SIZE
        self.tbl_entry_size = INDEX_TBL_ENTR_SIZE
        self.tbl_entry_num = 0

    def pack(self):
        data = bytearray(BLOCK_SIZE)
        struct.pack_into('<4sHHBBBI', data, 0,
            self.magic,
            switch_short(self.resource_ptn_version),
            switch_short(self.index_tbl_version),
            self.header_size,
            self.tbl_offset,
            self.tbl_entry_size,
            switch_int(self.tbl_entry_num)
        )
        return bytes(data)

    @staticmethod
    def unpack(data):
        hdr = ResourcePtnHeader()
        vals = struct.unpack('<4sHHBBBI', data[:16])
        hdr.magic = vals[0]
        hdr.resource_ptn_version = switch_short(vals[1])
        hdr.index_tbl_version = switch_short(vals[2])
        hdr.header_size = vals[3]
        hdr.tbl_offset = vals[4]
        hdr.tbl_entry_size = vals[5]
        hdr.tbl_entry_num = switch_int(vals[6])
        return hdr

class IndexTblEntry:
    def __init__(self):
        self.tag = INDEX_TBL_ENTR_TAG
        self.path = ""
        self.hash = b'\x00' * MAX_HASH_LEN
        self.hash_size = 20
        self.content_offset = 0
        self.content_size = 0

    def pack(self):
        data = bytearray(BLOCK_SIZE)
        path_bytes = self.path.encode('utf-8')[:MAX_INDEX_ENTRY_PATH_LEN]
        struct.pack_into('<4s220s32sIII', data, 0,
            self.tag,
            path_bytes,
            self.hash,
            self.hash_size,
            switch_int(self.content_offset),
            switch_int(self.content_size)
        )
        return bytes(data)

    @staticmethod
    def unpack(data):
        entry = IndexTblEntry()
        vals = struct.unpack('<4s220s32sIII', data[:272])
        entry.tag = vals[0]
        entry.path = vals[1].rstrip(b'\x00').decode('utf-8', errors='ignore')
        entry.hash = vals[2]
        entry.hash_size = vals[3]
        entry.content_offset = switch_int(vals[4])
        entry.content_size = switch_int(vals[5])
        return entry

def mkdirs(path):
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        return True
    except:
        return False

def unpack_image(image_path, unpack_dir):
    try:
        with open(image_path, 'rb') as fp:
            header_data = fp.read(BLOCK_SIZE)
            if len(header_data) < BLOCK_SIZE:
                LOGE("Failed to read header!")
                return -1

            header = ResourcePtnHeader.unpack(header_data)

            if header.magic != RESOURCE_PTN_HDR_MAGIC:
                LOGE(f"Not a resource image({image_path})!")
                return -1

            if (header.resource_ptn_version != RESOURCE_PTN_VERSION or
                header.header_size != RESOURCE_PTN_HDR_SIZE or
                header.index_tbl_version != INDEX_TBL_VERSION or
                header.tbl_entry_size != INDEX_TBL_ENTR_SIZE):
                LOGE("Not supported in this version!")
                return -1

            print("Dump header:")
            print(f"partition version:{header.resource_ptn_version}.{header.index_tbl_version}")
            print(f"header size:{header.header_size}")
            print(f"index tbl:\n\toffset:{header.tbl_offset}\tentry size:{header.tbl_entry_size}\tentry num:{header.tbl_entry_num}")

            print("Dump Index table:")
            for i in range(header.tbl_entry_num):
                entry_data = fp.read(BLOCK_SIZE)
                if len(entry_data) < BLOCK_SIZE:
                    LOGE(f"Failed to read index entry:{i}!")
                    return -1

                entry = IndexTblEntry.unpack(entry_data)

                if entry.tag != INDEX_TBL_ENTR_TAG:
                    LOGE(f"Something wrong with index entry:{i}!")
                    return -1

                print(f"entry({i}):\n\tpath:{entry.path}\n\toffset:{entry.content_offset}\tsize:{entry.content_size}")

                out_path = os.path.join(unpack_dir, entry.path)
                mkdirs(out_path)

                offset = entry.content_offset * BLOCK_SIZE
                fp.seek(offset)
                content = fp.read(entry.content_size)

                try:
                    with open(out_path, 'wb') as ofp:
                        ofp.write(content)
                except Exception as e:
                    LOGE(f"Failed to write:{entry.path}")
                    return -1

            print(f"Unpack {image_path} to {unpack_dir} succeeded!")
            return 0

    except Exception as e:
        LOGE(f"Failed to open:{image_path}: {e}")
        return -1

def write_data(fp, offset_block, data):
    try:
        offset = offset_block * BLOCK_SIZE
        fp.seek(offset)
        fp.write(data)
        return True
    except:
        return False

def write_file(fp, offset_block, src_path, hash_size=20):
    LOGD(f"try to write file({src_path}) to offset:{offset_block}...")
    try:
        with open(src_path, 'rb') as src_fp:
            content = src_fp.read()

        if hash_size == 20:
            hash_val = hashlib.sha1(content).digest()
        elif hash_size == 32:
            hash_val = hashlib.sha256(content).digest()
        else:
            return -1, None

        blocks = fix_blocks(len(content))
        padded_data = content.ljust(blocks * BLOCK_SIZE, b'\x00')

        if not write_data(fp, offset_block, padded_data):
            return -1, None

        return len(content), hash_val

    except Exception as e:
        LOGE(f"Failed to open:{src_path}: {e}")
        return -1, None

def pack_image(image_path, file_list):
    files = list(file_list)

    dtb_files = []
    other_files = []
    for f in files:
        if f != image_path:
            if f.endswith(DTD_SUFFIX):
                dtb_files.append(f)
            else:
                other_files.append(f)

    files = dtb_files + other_files
    file_num = len(files)

    if file_num == 0:
        LOGE("No file to pack!")
        return -1

    try:
        with open(image_path, 'wb') as fp:
            header = ResourcePtnHeader()
            header.tbl_entry_num = file_num

            fp.write(header.pack())

            offset = header.header_size + header.tbl_entry_size * header.tbl_entry_num
            entries = []

            for i, file_path in enumerate(files):
                if not os.path.exists(file_path):
                    LOGE(f"File not found: {file_path}")
                    return -1

                file_size = os.path.getsize(file_path)
                content_size, hash_val = write_file(fp, offset, file_path, 20)

                if content_size < 0:
                    LOGE(f"Failed to write file: {file_path}")
                    return -1

                entry = IndexTblEntry()
                entry.content_offset = offset
                entry.content_size = content_size
                entry.hash = hash_val.ljust(MAX_HASH_LEN, b'\x00')
                entry.hash_size = len(hash_val)

                path = file_path
                if root_path and path.startswith(root_path):
                    path = path[len(root_path):]
                    if path.startswith('/'):
                        path = path[1:]

                path = fix_path(path)

                is_first_dtb = (i < len(dtb_files) and i == 0)
                if is_first_dtb:
                    LOGD(f"mod fdt path:{file_path} -> {FDT_PATH}...")
                    path = FDT_PATH

                entry.path = path
                entries.append(entry)

                offset += fix_blocks(content_size)

            for i, entry in enumerate(entries):
                entry_offset = header.header_size + i * header.tbl_entry_size
                if not write_data(fp, entry_offset, entry.pack()):
                    LOGE("Failed to write index table!")
                    return -1

        print(f"Pack to {image_path} succeeded!")
        return 0

    except Exception as e:
        LOGE(f"Failed to create:{image_path}: {e}")
        return -1

def usage(prog):
    print(f"Usage: {prog} unpack <image> <outdir>")
    print(f"       {prog} pack <indir> <image>")
    print(f"       {prog} [options] [FILES]")
    print("Options:")
    print("\t--pack\t\t\tPack image from given files.")
    print("\t--unpack\t\tUnpack given image to current dir.")
    print("\t--image=path\t\tSpecify input/output image path.")
    print("\t--root=path\t\tSpecify resources' root dir.")
    print("\t--verbose\t\tDisplay more runtime informations.")
    print("\t--help\t\t\tDisplay this information.")

def main():
    global g_debug, root_path

    prog = os.path.basename(sys.argv[0])

    if len(sys.argv) == 4 and sys.argv[1] == "unpack":
        return unpack_image(sys.argv[2], sys.argv[3])
    if len(sys.argv) == 4 and sys.argv[1] == "pack":
        indir = sys.argv[2]
        image_path = sys.argv[3]
        root_path = indir
        files = []
        for dirpath, _, filenames in os.walk(indir):
            for f in filenames:
                files.append(os.path.join(dirpath, f))
        if not files:
            LOGE("No files to pack!")
            return -1
        return pack_image(image_path, files)

    action = "pack"
    image_path = DEFAULT_IMAGE_PATH

    args = sys.argv[1:]
    files = []

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '--verbose':
            g_debug = True
        elif arg == '--help':
            usage(prog)
            return 0
        elif arg == '--pack':
            action = "pack"
        elif arg == '--unpack':
            action = "unpack"
        elif arg.startswith('--image='):
            image_path = arg[8:]
        elif arg.startswith('--root='):
            root_path = arg[7:]
        elif arg.startswith('--'):
            LOGE(f"Unknown opt:{arg}")
            usage(prog)
            return -1
        else:
            files.append(arg)
        i += 1

    if action == "pack":
        if not files:
            LOGE("No file to pack!")
            return -1
        LOGD(f"try to pack {len(files)} files.")
        return pack_image(image_path, files)
    elif action == "unpack":
        unpack_dir = files[0] if files else DEFAULT_UNPACK_DIR
        return unpack_image(image_path, unpack_dir)

    return -1

if __name__ == "__main__":
    sys.exit(main() or 0)
