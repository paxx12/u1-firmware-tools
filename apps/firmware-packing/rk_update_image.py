#!/usr/bin/env python3
import sys
import os
import struct
import hashlib
from pathlib import Path
from datetime import datetime

DEFAULT_CHIP_TYPE = 0x50

class RKFWHeader:
    FORMAT = '<4sHIIHBBBBBIIIIIIIII45s'
    SIZE = 102

    def __init__(self):
        self.head_code = b'RKFW'
        self.head_len = 0x66
        self.version = 0
        self.code = 0x01030000
        self.year = 0
        self.month = 0
        self.day = 0
        self.hour = 0
        self.minute = 0
        self.second = 0
        self.chip = DEFAULT_CHIP_TYPE
        self.loader_offset = 0x66
        self.loader_length = 0
        self.image_offset = 0
        self.image_length = 0
        self.unknown1 = 0
        self.unknown2 = 1
        self.system_fstype = 0
        self.backup_endpos = 0
        self.reserved = b'\x00' * 45

    def pack(self):
        return struct.pack(self.FORMAT,
            self.head_code,
            self.head_len,
            self.version,
            self.code,
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.chip,
            self.loader_offset,
            self.loader_length,
            self.image_offset,
            self.image_length,
            self.unknown1,
            self.unknown2,
            self.system_fstype,
            self.backup_endpos,
            self.reserved
        )

class UpdateHeader:
    PART_FORMAT = '<32s60sIIIII'
    PART_SIZE = struct.calcsize(PART_FORMAT)
    HEADER_FORMAT = '<4sI34s30s56sIII'
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, data):
        header_base = struct.unpack(self.HEADER_FORMAT, data[:self.HEADER_SIZE])
        self.magic = header_base[0]
        self.length = header_base[1]
        self.model = header_base[2]
        self.id = header_base[3]
        self.manufacturer = header_base[4]
        self.unknown1 = header_base[5]
        self.version = header_base[6]
        self.num_parts = header_base[7]

        self.parts = []
        offset = self.HEADER_SIZE
        for i in range(min(self.num_parts, 16)):
            part_data = struct.unpack(self.PART_FORMAT, data[offset:offset + self.PART_SIZE])
            self.parts.append({
                'name': part_data[0].rstrip(b'\x00').decode('utf-8', errors='ignore'),
                'filename': part_data[1].rstrip(b'\x00').decode('utf-8', errors='ignore'),
                'nand_size': part_data[2],
                'pos': part_data[3],
                'nand_addr': part_data[4],
                'padded_size': part_data[5],
                'size': part_data[6]
            })
            offset += self.PART_SIZE

def read_metadata(metafile):
    metadata = {}
    try:
        with open(metafile, 'r') as fp:
            for line in fp:
                line = line.strip()
                if line.startswith('chip=0x'):
                    metadata['chip'] = int(line.split('=')[1], 16)
                elif line.startswith('code=0x'):
                    metadata['code'] = int(line.split('=')[1], 16)
                elif line.startswith('build_time='):
                    time_str = line.split('=')[1]
                    dt = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                    metadata['year'] = dt.year
                    metadata['month'] = dt.month
                    metadata['day'] = dt.day
                    metadata['hour'] = dt.hour
                    metadata['minute'] = dt.minute
                    metadata['second'] = dt.second

        if 'chip' not in metadata or 'year' not in metadata:
            print(f"Invalid metadata file {metafile}: missing required fields", file=sys.stderr)
            return None

        return metadata
    except Exception as e:
        print(f"Can't open metadata file {metafile}: {e}", file=sys.stderr)
        return None

def import_data(infile, fp):
    try:
        with open(infile, 'rb') as in_fp:
            data = in_fp.read()
            fp.write(data)
            return data, len(data)
    except Exception as e:
        print(f"Error reading {infile}: {e}", file=sys.stderr)
        return None, 0

def append_md5sum(fp):
    md5_ctx = hashlib.md5()
    fp.seek(0)

    while True:
        chunk = fp.read(1024)
        if not chunk:
            break
        md5_ctx.update(chunk)

    digest = md5_ctx.hexdigest()
    fp.write(digest.encode('ascii'))

def ensure_parent(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)

def unpack_rom(update_filename, loader_out, rom_out, meta_out):
    try:
        with open(update_filename, 'rb') as fp:
            header_data = fp.read(RKFWHeader.SIZE)
            if len(header_data) != RKFWHeader.SIZE:
                print(f"invalid header length in {update_filename}", file=sys.stderr)
                return -1

            header = struct.unpack(RKFWHeader.FORMAT, header_data)
            head_code = header[0]
            if head_code != b'RKFW':
                print(f"invalid head code: {head_code}", file=sys.stderr)
                return -1

            _, head_len, version, code, year, month, day, hour, minute, second, chip, loader_offset, loader_length, image_offset, image_length, unknown1, unknown2, system_fstype, backup_endpos, _ = header

            fp.seek(0, os.SEEK_END)
            total_size = fp.tell()

            if loader_offset + loader_length > total_size or image_offset + image_length > total_size:
                print("invalid offsets/lengths in header", file=sys.stderr)
                return -1

            fp.seek(loader_offset)
            loader_data = fp.read(loader_length)

            fp.seek(image_offset)
            rom_data = fp.read(image_length)

            ensure_parent(loader_out)
            ensure_parent(rom_out)
            with open(loader_out, 'wb') as out_fp:
                out_fp.write(loader_data)
            with open(rom_out, 'wb') as out_fp:
                out_fp.write(rom_data)

            ensure_parent(meta_out)
            with open(meta_out, 'w') as meta_fp:
                meta_fp.write(f"chip=0x{chip:08x}\n")
                meta_fp.write(f"code=0x{code:x}\n")
                meta_fp.write(f"build_time={year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}\n")

            print(f"rom version: {version >> 24}.{(version >> 16) & 0xFF}.{version & 0xFFFF}")
            print(f"build time: {year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}")
            print(f"chip: {chip}")
            print(f"loader offset/len: {loader_offset}/{loader_length}")
            print(f"image offset/len: {image_offset}/{image_length}")
            return 0

    except Exception as e:
        print(f"Can't unpack {update_filename}: {e}", file=sys.stderr)
        return -1

def pack_rom(loader_filename, image_filename, outfile, metafile=None):
    rom_header = RKFWHeader()

    now = datetime.now()
    rom_header.year = now.year
    rom_header.month = now.month
    rom_header.day = now.day
    rom_header.hour = now.hour
    rom_header.minute = now.minute
    rom_header.second = now.second

    if metafile:
        metadata = read_metadata(metafile)
        if metadata is None:
            return -1

        if 'chip' in metadata:
            rom_header.chip = metadata['chip']
        if 'code' in metadata:
            rom_header.code = metadata['code']
        if 'year' in metadata:
            rom_header.year = metadata['year']
            rom_header.month = metadata['month']
            rom_header.day = metadata['day']
            rom_header.hour = metadata['hour']
            rom_header.minute = metadata['minute']
            rom_header.second = metadata['second']

        print(f"using metadata from: {metafile}", file=sys.stderr)

    try:
        with open(outfile, 'wb+') as fp:
            fp.write(b'\x00' * 0x66)

            fp.seek(rom_header.loader_offset)
            print("generate image...", file=sys.stderr)

            loader_data, loader_length = import_data(loader_filename, fp)
            if loader_data is None or loader_length < 16:
                print(f"invalid loader: \"{loader_filename}\"", file=sys.stderr)
                return -1

            rom_header.loader_length = loader_length

            rom_header.image_offset = rom_header.loader_offset + rom_header.loader_length
            image_data, image_length = import_data(image_filename, fp)
            if image_data is None or image_length < 136:
                print(f"invalid rom: \"{image_filename}\"", file=sys.stderr)
                return -1

            rom_header.image_length = image_length

            try:
                rkaf_header = UpdateHeader(image_data[:2048])
                rom_header.version = rkaf_header.version

                backup_part_idx = None
                for i, part in enumerate(rkaf_header.parts):
                    if part['name'] == 'backup':
                        backup_part_idx = i
                        break

                if backup_part_idx is not None:
                    part = rkaf_header.parts[backup_part_idx]
                    rom_header.backup_endpos = (part['nand_addr'] + part['nand_size']) // 0x800
                else:
                    rom_header.backup_endpos = 0
            except Exception as e:
                print(f"Warning: Could not parse RKAF header: {e}", file=sys.stderr)

            fp.seek(0)
            fp.write(rom_header.pack())

            print("append md5sum...", file=sys.stderr)
            append_md5sum(fp)

        print("success!", file=sys.stderr)
        return 0

    except Exception as e:
        print(f"Can't open file {outfile}: {e}", file=sys.stderr)
        return -1

def main():
    if len(sys.argv) >= 4 and sys.argv[1] in ("unpack", "-unpack"):
        infile = sys.argv[2]
        outdir = sys.argv[3]
        loader_out = os.path.join(outdir, "loader.img")
        rom_out = os.path.join(outdir, "rom.img")
        meta_out = os.path.join(outdir, "rkfw.meta")
        os.makedirs(outdir, exist_ok=True)
        return unpack_rom(infile, loader_out, rom_out, meta_out)
    if len(sys.argv) >= 4 and sys.argv[1] in ("pack", "-pack"):
        indir = sys.argv[2]
        outfile = sys.argv[3]
        loader = os.path.join(indir, "loader.img")
        rom = os.path.join(indir, "rom.img")
        meta = os.path.join(indir, "rkfw.meta")
        if not os.path.exists(meta):
            meta = None
        return pack_rom(loader, rom, outfile, meta)

    print(f"Usage: {sys.argv[0]} unpack <image> <outdir>", file=sys.stderr)
    print(f"       {sys.argv[0]} pack <indir> <image>", file=sys.stderr)
    return 1

if __name__ == "__main__":
    sys.exit(main())
