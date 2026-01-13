#!/usr/bin/env python3
import sys
import os
import struct
import hashlib

UPFILE_MAGIC = b'SNMK'
UPFILE_FILE_COUNT = 4
HEADER_FORMAT = '>4sHH24s14sH16s'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
ENTRY_SIZE = 32

FILE_TYPE_STRINGS = ["SOC_FW", "MCU1_FW", "MCU2_FW", "MCU_DESC"]
FILE_NAMES = ["update.img", "at32f403a.bin", "at32f415.bin", "MCU_DESC"]

DATA_MAP = bytes([
    0x00, 0xa2, 0xe9, 0x0e, 0xde, 0x64, 0xee, 0x12,
    0x46, 0x3b, 0xe7, 0x79, 0xa5, 0x80, 0x55, 0x33,
    0x32, 0x3c, 0x0b, 0x7e, 0xce, 0xcc, 0x59, 0x37,
    0x01, 0x9b, 0x4e, 0xc1, 0xab, 0x18, 0x72, 0x11,
    0x9c, 0x5b, 0xe5, 0x8d, 0xe8, 0x0d, 0x69, 0x97,
    0x29, 0xd9, 0xc5, 0xaf, 0x4a, 0x61, 0x7a, 0x63,
    0x39, 0xc6, 0xbc, 0xd0, 0x92, 0xae, 0x7f, 0xdd,
    0x6c, 0x07, 0x3a, 0xb9, 0x91, 0xf7, 0xc7, 0x45,
    0x34, 0x40, 0xb5, 0x28, 0x44, 0xe6, 0xcb, 0x4d,
    0x3d, 0x9e, 0x94, 0x2b, 0x60, 0xd2, 0x2f, 0x3e,
    0x67, 0xd6, 0x52, 0xd3, 0xa8, 0xd4, 0xf8, 0x1a,
    0xda, 0xec, 0x70, 0x7c, 0xa0, 0x1d, 0x06, 0x4f,
    0x6e, 0x2d, 0xb8, 0x36, 0xf0, 0x43, 0x22, 0xbd,
    0xb4, 0x82, 0x9d, 0xeb, 0xa4, 0x56, 0x76, 0xe4,
    0x25, 0x15, 0x98, 0x71, 0xc3, 0x50, 0x49, 0x77,
    0x08, 0xfb, 0x47, 0x23, 0xaa, 0x8a, 0x20, 0xfc,
    0xf6, 0x8c, 0x85, 0x30, 0x1e, 0xc9, 0x62, 0xba,
    0x53, 0x0f, 0xf2, 0x57, 0x51, 0x7b, 0x13, 0x1f,
    0x96, 0xc0, 0x35, 0x73, 0x87, 0xdb, 0xb7, 0xa3,
    0xed, 0x90, 0x5f, 0x9a, 0xdc, 0xe3, 0xe1, 0x0a,
    0x1b, 0x17, 0xea, 0x41, 0xfe, 0x58, 0x26, 0xcd,
    0x05, 0xc2, 0x02, 0x88, 0x6a, 0x9f, 0x93, 0x74,
    0xe2, 0x2a, 0x09, 0xac, 0x81, 0x5c, 0x1c, 0xf3,
    0x8b, 0xfa, 0x84, 0xa1, 0xd7, 0x5d, 0xbe, 0x75,
    0x38, 0xe0, 0xa6, 0x2c, 0x2e, 0x66, 0x86, 0xef,
    0x54, 0x68, 0xb6, 0xa9, 0xf5, 0x0c, 0xf9, 0xb3,
    0xbf, 0x14, 0xb2, 0xfd, 0xbb, 0xd5, 0x04, 0xf4,
    0xa7, 0x48, 0xf1, 0x6d, 0x6b, 0x99, 0x7d, 0x4b,
    0xb0, 0xad, 0x21, 0x95, 0xd1, 0xcf, 0xc4, 0x24,
    0xca, 0x8e, 0xb1, 0x83, 0x16, 0xdf, 0x19, 0x10,
    0x27, 0x4c, 0x6f, 0x31, 0x3f, 0x5a, 0x65, 0x78,
    0xc8, 0xd8, 0x03, 0x89, 0x5e, 0x8f, 0x42, 0xff
])

DECODE_MAP = bytes([DATA_MAP.index(i) for i in range(256)])

def decode_data(data):
    return bytes(DATA_MAP[b] for b in data)

def encode_data(data):
    return bytes(DECODE_MAP[b] for b in data)

def calculate_checksum(data):
    return sum(data) & 0xFFFF

def validate_checksum(data, checksum_offset, expected):
    data_list = bytearray(data)
    data_list[checksum_offset:checksum_offset+2] = b'\x00\x00'
    calculated = calculate_checksum(data_list)
    if calculated != expected:
        print(f"Checksum mismatch: calculated 0x{calculated:04x}, expected 0x{expected:04x}", file=sys.stderr)
        return False
    return True

def calculate_md5(data):
    return hashlib.md5(data).digest()

def validate_md5(data, expected):
    return calculate_md5(data) == expected

def trim_right(s):
    return s.rstrip(b'\x00\n\r \t').decode('utf-8', errors='ignore')

def read_encoded_data(fp, size):
    data = fp.read(size)
    if len(data) != size:
        return None
    return decode_data(data)

def write_encoded_data(fp, data):
    fp.write(encode_data(data))

def info_command(infile, outdir=None, file_callback=None):
    try:
        with open(infile, 'rb') as fp:
            if outdir:
                os.makedirs(outdir, exist_ok=True)
                os.chdir(outdir)

            header_data = read_encoded_data(fp, HEADER_SIZE)
            if not header_data:
                print("Failed to read header", file=sys.stderr)
                return -1

            magic, magic_ver, checksum, version, build_date, files, reserved = struct.unpack(
                HEADER_FORMAT, header_data
            )

            if magic != UPFILE_MAGIC:
                print(f"Invalid magic: {magic}", file=sys.stderr)
                return -1

            if not validate_checksum(header_data[:HEADER_SIZE], 6, checksum):
                print("Header checksum validation failed", file=sys.stderr)
                return -1

            print("UPFILE Header:")
            print(f"  Magic:\t{magic.decode('ascii', errors='ignore')}")
            print(f"  Magic Ver:\t0x{magic_ver:04x}")
            print(f"  Version:\t{trim_right(version)}")
            print(f"  Build Date:\t{trim_right(build_date)}")
            print(f"  Checksum:\t0x{checksum:04x}")
            print(f"  Files:\t{files}")

            if file_callback:
                file_callback("UPFILE_VERSION", version.rstrip(b'\x00'))
                file_callback("UPFILE_BUILD_DATE", build_date.rstrip(b'\x00'))

            if files > UPFILE_FILE_COUNT:
                print(f"Too many files found: {files}", file=sys.stderr)
                return -1

            for i in range(files):
                fp.seek(HEADER_SIZE + i * ENTRY_SIZE)
                entry_data = read_encoded_data(fp, ENTRY_SIZE)
                if not entry_data:
                    print(f"Failed to read file entry {i}", file=sys.stderr)
                    return -1

                file_type, entry_checksum, offset, size, md5 = struct.unpack('>HHQI16s', entry_data)

                if not validate_checksum(entry_data, 2, entry_checksum):
                    print(f"File entry {i} checksum validation failed", file=sys.stderr)
                    return -1

                print(f"File Entry {i}:")
                print(f"  Type:\t\t{file_type}")
                print(f"  Offset:\t0x{offset:016x}")
                print(f"  Size:\t\t{size}")
                print(f"  Checksum:\t0x{entry_checksum:04x}")
                print(f"  MD5:\t\t{md5.hex()}")

                fp.seek(offset)
                file_data = fp.read(size)
                if len(file_data) != size:
                    print(f"Failed to read data for file entry {i}", file=sys.stderr)
                    return -1

                if not validate_md5(file_data, md5):
                    print(f"File entry {i} MD5 validation failed", file=sys.stderr)
                    return -1

                if file_callback:
                    file_callback(FILE_NAMES[i], file_data)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return -1

    return 0

def unpack_file(filename, data):
    try:
        with open(filename, 'wb') as fp:
            fp.write(data)
        print(f"Extracted {filename} ({len(data)} bytes)")
    except Exception as e:
        print(f"Failed to write to {filename}: {e}", file=sys.stderr)

def unpack_command(infile, outdir=None):
    return info_command(infile, outdir, unpack_file)

def pack_file(outfp, index, file_type, filename, data_offset):
    print(f"Packing file {filename} as type {file_type}")
    try:
        with open(filename, 'rb') as infp:
            file_data = infp.read()

        file_size = len(file_data)
        md5 = calculate_md5(file_data)

        entry_data = bytearray(32)
        struct.pack_into('>HHQI16s', entry_data, 0, file_type, 0, data_offset, file_size, md5)

        entry_checksum = calculate_checksum(entry_data)
        struct.pack_into('>H', entry_data, 2, entry_checksum)

        outfp.seek(HEADER_SIZE + index * ENTRY_SIZE)
        write_encoded_data(outfp, bytes(entry_data))

        outfp.seek(data_offset)
        outfp.write(file_data)

        return data_offset + file_size

    except Exception as e:
        print(f"Error packing {filename}: {e}", file=sys.stderr)
        return -1

def read_string_from_file(filename, max_size):
    try:
        with open(filename, 'r') as fp:
            content = fp.read(max_size).encode('utf-8')
            return content.rstrip(b'\n\r \t')
    except:
        return None

def pack_command(outfile, indir=None):
    try:
        if indir:
            os.chdir(indir)

        version = read_string_from_file("UPFILE_VERSION", 24)
        if version is None:
            print("Error: UPFILE_VERSION not found", file=sys.stderr)
            return -1

        build_date = read_string_from_file("UPFILE_BUILD_DATE", 14)
        if build_date is None:
            print("Error: UPFILE_BUILD_DATE not found", file=sys.stderr)
            return -1

        header = bytearray(HEADER_SIZE)
        struct.pack_into(HEADER_FORMAT, header, 0,
                         UPFILE_MAGIC, 1, 0,
                         version.ljust(24, b'\x00'),
                         build_date.ljust(14, b'\x00'),
                         UPFILE_FILE_COUNT,
                         b'\x00' * 16)

        header_checksum = calculate_checksum(header[:HEADER_SIZE])
        struct.pack_into('>H', header, 6, header_checksum)

        with open(outfile, 'wb') as outfp:
            write_encoded_data(outfp, bytes(header))

            print(f"Packing UPFILE with {UPFILE_FILE_COUNT} files")

            data_offset = HEADER_SIZE + UPFILE_FILE_COUNT * ENTRY_SIZE

            for i in range(UPFILE_FILE_COUNT):
                result = pack_file(outfp, i, i, FILE_NAMES[i], data_offset)
                if result == -1:
                    return -1
                data_offset = result

            print(f"Packed UPFILE to {outfile}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return -1

    return 0

def main():
    if len(sys.argv) == 3 and sys.argv[1] == "info":
        return info_command(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "unpack":
        return unpack_command(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "pack":
        return pack_command(sys.argv[3], sys.argv[2])

    print(f"Usage: {sys.argv[0]} info <upfile>", file=sys.stderr)
    print(f"       {sys.argv[0]} unpack <upfile> <outdir>", file=sys.stderr)
    print(f"       {sys.argv[0]} pack <indir> <outfile>", file=sys.stderr)
    return -1

if __name__ == "__main__":
    sys.exit(main())
