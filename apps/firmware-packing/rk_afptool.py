#!/usr/bin/env python3
import sys
import os
import struct
import re
from pathlib import Path
import crcmod

RKAFP_MAGIC = b'RKAF'
PARM_MAGIC = b'PARM'

_rkcrc_func = crcmod.mkCrcFun(0x104C10DB7, initCrc=0, rev=False, xorOut=0)

def rkcrc(data, crc=0):
    return _rkcrc_func(data, crc)

def filestream_crc(fp, length):
    crc = 0
    remaining = length
    while remaining > 0:
        chunk_size = min(remaining, 65536)
        chunk = fp.read(chunk_size)
        if not chunk:
            break
        crc = _rkcrc_func(chunk, crc)
        remaining -= len(chunk)
    return crc

def create_dir(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)

def extract_file(fp, offset, length, path):
    try:
        create_dir(path)
        with open(path, 'wb') as ofp:
            fp.seek(offset)
            remaining = length
            while remaining > 0:
                chunk_size = min(remaining, 1024)
                chunk = fp.read(chunk_size)
                if not chunk:
                    break
                ofp.write(chunk)
                remaining -= len(chunk)
        return 0
    except Exception as e:
        print(f"Can't open/create file: {path}: {e}")
        return -1

HEADER_BASE_SIZE = 136
PART_FORMAT = '<32s60sIIIII'
PART_SIZE = struct.calcsize(PART_FORMAT)
HEADER_RESERVED_SIZE = 0x74
HEADER_SIZE = 2048

def unpack_update(srcfile, dstdir):
    try:
        Path(dstdir).mkdir(parents=True, exist_ok=True)

        with open(srcfile, 'rb') as fp:
            header_data = fp.read(HEADER_SIZE)
            if len(header_data) < HEADER_BASE_SIZE:
                print("Can't read image header", file=sys.stderr)
                return -1

            magic = header_data[0:4]
            if magic != RKAFP_MAGIC:
                print("Invalid header magic", file=sys.stderr)
                return -1

            length, = struct.unpack('<I', header_data[4:8])

            fp.seek(length)
            crc_data = fp.read(4)
            if len(crc_data) != 4:
                print("Can't read crc checksum", file=sys.stderr)
                return -1
            expected_crc, = struct.unpack('<I', crc_data)

            print("Check file...", end='', flush=True)
            fp.seek(0)
            calculated_crc = filestream_crc(fp, length)
            if calculated_crc != expected_crc:
                print("Fail")
                return -1
            print("OK")

            model = header_data[8:42].rstrip(b'\x00').decode('utf-8', errors='ignore')
            id_str = header_data[42:72].rstrip(b'\x00').decode('utf-8', errors='ignore')
            manufacturer = header_data[72:128].rstrip(b'\x00').decode('utf-8', errors='ignore')
            unknown1, version, num_parts = struct.unpack('<III', header_data[128:140])

            meta_path = os.path.join(dstdir, "rkaf_header.meta")
            try:
                with open(meta_path, 'w') as meta_fp:
                    meta_fp.write(f"model={model}\n")
                    meta_fp.write(f"id={id_str}\n")
                    meta_fp.write(f"manufacturer={manufacturer}\n")
                    meta_fp.write(f"version={version}\n")
                    meta_fp.write(f"unknown1={unknown1}\n")
            except Exception as e:
                print(f"Warning: Failed to write header metadata: {e}", file=sys.stderr)

            print("------- UNPACK -------")
            if num_parts > 0:
                for i in range(min(num_parts, 16)):
                    offset = 140 + i * PART_SIZE
                    part_data = header_data[offset:offset + PART_SIZE]

                    name = part_data[0:32].rstrip(b'\x00').decode('utf-8', errors='ignore')
                    filename = part_data[32:92].rstrip(b'\x00').decode('utf-8', errors='ignore')
                    nand_size, pos, nand_addr, padded_size, size = struct.unpack('<IIIII', part_data[92:112])

                    print(f"Unpacking: name={name} filename={filename}\tnand_addr={nand_addr}/{nand_size}\tpos={pos}/{size}/{padded_size}")

                    if filename == "SELF":
                        print("Skip SELF file.")
                        continue

                    if name.startswith("parameter"):
                        pos += 8
                        size -= 12

                    dest_path = os.path.join(dstdir, filename)

                    if pos + size > length:
                        print(f"Invalid part: {name}", file=sys.stderr)
                        continue

                    extract_file(fp, pos, size, dest_path)

        return 0

    except Exception as e:
        print(f"can't open file \"{srcfile}\": {e}", file=sys.stderr)
        return -1

def parse_partitions(parts_str):
    partitions = []
    for part in parts_str.split(','):
        match = re.match(r'([0-9a-fA-Fx-]+)@([0-9a-fA-Fx]+)\(([^)]+)\)', part)
        if match:
            size_str, start_str, name = match.groups()
            if size_str == '-':
                size = 0xFFFFFFFF
            else:
                size = int(size_str, 16)
            start = int(start_str, 16)
            name = name.split(':')[0]
            partitions.append({'name': name, 'start': start, 'size': size})
    return partitions

def parse_parameter(fname):
    image = {
        'version': 0,
        'machine_model': '',
        'machine_id': '',
        'manufacturer': '',
        'partitions': []
    }

    try:
        with open(fname, 'r') as fp:
            for line in fp:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if ':' not in line:
                    continue

                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()

                if key == 'FIRMWARE_VER':
                    match = re.match(r'(\d+)\.(\d+)(?:\.(\d+))?', value)
                    if match:
                        a, b, c = match.groups()
                        a = int(a)
                        b = int(b)
                        c = int(c) if c is not None else 0
                        image['version'] = (a << 24) + (b << 16) + c
                elif key == 'MACHINE_MODEL':
                    image['machine_model'] = value[:0x22]
                elif key == 'MACHINE_ID':
                    image['machine_id'] = value[:0x1e]
                elif key == 'MANUFACTURER':
                    image['manufacturer'] = value[:0x38]
                elif key == 'CMDLINE':
                    for param in value.split():
                        if '=' in param:
                            param_key, param_value = param.split('=', 1)
                            if param_key == 'mtdparts':
                                parts = param_value.split(':', 1)
                                if len(parts) == 2:
                                    image['partitions'] = parse_partitions(parts[1])

        return image

    except Exception as e:
        print(f"Can't open file: {fname}: {e}")
        return None

def get_packages(fname):
    packages = []
    try:
        with open(fname, 'r') as fp:
            for line in fp:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split(None, 1)
                if len(parts) == 2:
                    name, path = parts
                    packages.append({'name': name, 'path': path})

        return packages

    except Exception as e:
        print(f"Can't open file: {fname}: {e}")
        return None

def find_partition_byname(partitions, name):
    if name == 'parameter':
        return {'name': 'parameter', 'start': 0, 'size': 0x4000}

    for part in reversed(partitions):
        if part['name'] == name:
            return part

    return None

def import_package(ofp, part, path):
    part['pos'] = ofp.tell()
    part['size'] = 0
    part['padded_size'] = 0

    try:
        with open(path, 'rb') as ifp:
            if part['name'] == 'parameter':
                content = ifp.read(2048 - 12)
                crc = rkcrc(content)

                buf = bytearray(2048)
                buf[0:4] = PARM_MAGIC
                struct.pack_into('<I', buf, 4, len(content))
                buf[8:8+len(content)] = content
                struct.pack_into('<I', buf, 8 + len(content), crc)

                ofp.write(buf)
                part['size'] = 8 + len(content) + 4
                part['padded_size'] = 2048
            else:
                while True:
                    chunk = ifp.read(2048)
                    if not chunk:
                        break

                    if len(chunk) < 2048:
                        chunk = chunk.ljust(2048, b'\x00')

                    ofp.write(chunk)
                    part['size'] += len(chunk) if len(chunk) <= len(ifp.read(0)) + len(chunk) else len(chunk)
                    part['padded_size'] += 2048

                ifp.seek(0, 2)
                actual_size = ifp.tell()
                part['size'] = actual_size

        return 0

    except Exception as e:
        print(f"Error importing {path}: {e}")
        return -1

def append_crc(fp):
    fp.seek(0, 2)
    file_len = fp.tell()

    print("Add CRC...")
    fp.seek(0)
    crc = filestream_crc(fp, file_len)

    fp.seek(0, 2)
    fp.write(struct.pack('<I', crc))

def load_header_metadata(srcdir):
    meta_path = os.path.join(srcdir, "rkaf_header.meta")
    if not os.path.exists(meta_path):
        return None
    metadata = {}
    try:
        with open(meta_path, 'r') as fp:
            for line in fp:
                line = line.strip()
                if not line or '=' not in line:
                    continue
                key, val = line.split('=', 1)
                metadata[key] = val
    except Exception as e:
        print(f"Warning: Failed to read header metadata: {e}", file=sys.stderr)
        return None
    return metadata

def pack_update(srcdir, dstfile):
    print("------ PACKAGE ------")

    param_file = os.path.join(srcdir, "parameter.txt")
    image = parse_parameter(param_file)
    if image is None:
        return -1

    package_file = os.path.join(srcdir, "package-file")
    packages = get_packages(package_file)
    if packages is None:
        return -1

    metadata = load_header_metadata(srcdir)

    for pkg in packages:
        partition = find_partition_byname(image['partitions'], pkg['name'])
        if partition:
            pkg['nand_addr'] = partition['start']
            pkg['nand_size'] = partition['size']
        else:
            pkg['nand_addr'] = 0xFFFFFFFF
            pkg['nand_size'] = 0

    try:
        with open(dstfile, 'wb+') as fp:
            header = bytearray(HEADER_SIZE)
            fp.write(header)

            parts = []
            for i, pkg in enumerate(packages):
                part = {
                    'name': pkg['name'],
                    'filename': pkg['path'],
                    'nand_addr': pkg['nand_addr'],
                    'nand_size': pkg['nand_size'],
                    'pos': 0,
                    'size': 0,
                    'padded_size': 0
                }

                if pkg['path'] == 'SELF':
                    parts.append(part)
                    continue

                reused = False
                for j, prev_part in enumerate(parts):
                    if prev_part['filename'] == part['filename']:
                        part['pos'] = prev_part['pos']
                        part['size'] = prev_part['size']
                        part['padded_size'] = prev_part['padded_size']
                        print(f"Re-using: name={part['name']} from={prev_part['name']} filename={part['filename']} nand_addr={part['nand_addr']}/{part['nand_size']} pos={part['pos']}/{part['size']}/{part['padded_size']}")
                        reused = True
                        break

                if not reused:
                    src_path = os.path.join(srcdir, pkg['path'])
                    import_package(fp, part, src_path)
                    part['padded_size'] = (part['size'] + 2047) // 2048
                    print(f"Added: name={part['name']} path={src_path} nand_addr={part['nand_addr']}/{part['nand_size']} pos={part['pos']}/{part['size']}/{part['padded_size']}")

                parts.append(part)

            length = fp.tell()

            for part in reversed(parts):
                if part['filename'] == 'SELF':
                    part['size'] = length + 4
                    part['padded_size'] = (part['size'] + 511) // 512 * 512

            model = metadata.get('model') if metadata and 'model' in metadata else image['machine_model']
            machine_id = metadata.get('id') if metadata and 'id' in metadata else image['machine_id']
            manufacturer = metadata.get('manufacturer') if metadata and 'manufacturer' in metadata else image['manufacturer']
            version = int(metadata.get('version')) if metadata and 'version' in metadata else image['version']
            unknown1 = int(metadata.get('unknown1')) if metadata and 'unknown1' in metadata else 0

            struct.pack_into('<4sI', header, 0, RKAFP_MAGIC, length)
            struct.pack_into('<34s', header, 8, model.encode('utf-8'))
            struct.pack_into('<30s', header, 42, machine_id.encode('utf-8'))
            struct.pack_into('<56s', header, 72, manufacturer.encode('utf-8'))
            struct.pack_into('<III', header, 128, unknown1, version, len(parts))

            for i, part in enumerate(parts):
                offset = 140 + i * PART_SIZE
                struct.pack_into('<32s', header, offset, part['name'].encode('utf-8'))
                struct.pack_into('<60s', header, offset + 32, part['filename'].encode('utf-8'))
                struct.pack_into('<IIIII', header, offset + 92,
                    part['nand_size'], part['pos'], part['nand_addr'],
                    part['padded_size'], part['size'])

            fp.seek(0)
            fp.write(header)

            append_crc(fp)

        print("------ OK ------")
        return 0

    except Exception as e:
        print(f"Can't open file \"{dstfile}\": {e}")
        return -1

def usage(appname):
    name = os.path.basename(appname)
    print(f"Usage: {name} <pack|unpack> <input> <output>")
    print(f"       {name} unpack <image> <outdir>")
    print(f"       {name} pack <indir> <image>")

def main():
    if len(sys.argv) != 4:
        usage(sys.argv[0])
        return 1

    if sys.argv[1] in ('pack', '-pack'):
        if pack_update(sys.argv[2], sys.argv[3]) == 0:
            print("Pack OK!")
        else:
            print("Pack failed")
            return 1
    elif sys.argv[1] in ('unpack', '-unpack'):
        if unpack_update(sys.argv[2], sys.argv[3]) == 0:
            print("UnPack OK!")
        else:
            print("UnPack failed")
            return 1
    else:
        usage(sys.argv[0])
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
