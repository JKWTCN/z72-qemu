# SPDX-License-Identifier: GPL-2.0-or-later
"""Survey boot-chain and card-update structure in the stock Z7 II master.

Static byte decoding only: no emulation, no device access, no payload export.
The tool records offsets, decoded tables, pinned code-window digests and
negative keyword scans. It does not authenticate packages, recover boot
material or prove any execution path on a camera.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, MASTER_SHA, require, validate_master
from analyze.firmware_structure import scatter_records

# Card-update filename templates (8.3 with ? wildcards) and the directory
# prefix observed next to them in every audited version.
TEMPLATES = (
    'EG1840??.BIN', 'VR1840??.BIN', 'EX1840??.BIN', '_D_UT1??.BIN',
    '_UT1????.BIN', '_WT4????.BIN', 'SB??????.BIN', 'NKLD????.BIN',
    'WR1_????.BIN', '_D_WT???.BIN', '_TPFW???.BIN', 'Z7_2_???.BIN',
    '????_???.BIN', 'WRR10_??.BIN', '_WT?_???.BIN', '_TPJ01??.BIN',
    'WR??????.BIN', 'LF??????.BIN', 'ML??????.BIN', 'MA??????.BIN',
    'TC??????.BIN', 'RG??????.BIN',
)
FIRMWARE_DIR = 'firmware\\'
RECORD_STRIDE = 12

# C 1.70 pinned sites (member offsets). The two TBB dispatch tables and the
# two adjacent close-file handler windows distinguish the accepted-no-check
# category-5 path from the category-7 close-and-report-3 path.
SCAN_TBB = 0x37C3DC
SCAN_HANDLER_WINDOW = (0x37C426, 0x37C47A)
CAT5_WINDOW = (0x37C426, 0x37C42E)
CAT7_WINDOW = (0x37C466, 0x37C46E)
CAT7_REJECT_HALFWORD = 0x2503  # movs r5, #3

REGION_RUNTIME = 0xB185E5C4
REGION_COUNT = 33
REGION_STRIDE = 44
OBJECT_RUNTIME = 0xB185EB70
OBJECT_COUNT = 81
OBJECT_STRIDE = 28

# External-boot markers that must stay absent from every audited member.
NEGATIVE_KEYWORDS = (
    b'BOOTDISK', b'bootdisk', b'AUTOEXEC', b'autoexec', b'LOADER', b'loader',
    b'NKLD', b'UPDATE', b'update', b'BOOT', b'Boot', b'boot',
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def template_offsets(image):
    found = {}
    for name in TEMPLATES:
        found[name] = image.find(name.encode('ascii'))
    found[FIRMWARE_DIR] = image.find(FIRMWARE_DIR.encode('ascii'))
    return found


def update_records(image, templates):
    """Recover [category][template pointer][condition] records by template."""
    records = {}
    for name, offset in templates.items():
        if offset < 0 or not name.endswith('.BIN'):
            continue
        pattern = struct.pack('<I', BASE + offset)
        pos, hits = 0, []
        while True:
            pos = image.find(pattern, pos)
            if pos < 0:
                break
            start = pos - 4
            if start >= 0:
                category = image[start]
                record = image[start:start + RECORD_STRIDE]
                condition = struct.unpack_from('<I', record, 8)[0]
                code_pointer = BASE <= condition < BASE + len(image)
                if (1 <= category <= 0x20 and record[1:4] == b'\0\0\0'
                        and (condition == 0 or code_pointer)):
                    hits.append(dict(
                        offset=start, category=category,
                        template=name, condition=condition))
            pos += 1
        records[name] = hits
    return records


def tbb_targets(image, site, count):
    """Decode a TBB dispatch table (byte offsets are halfword units)."""
    table = image[site + 4:site + 4 + count]
    return [site + 4 + byte * 2 for byte in table]


def scan_table(image):
    scan = dict(
        site=SCAN_TBB,
        categories=dict(zip(range(0xD), tbb_targets(image, SCAN_TBB, 0xD))),
        handler_window=dict(
            offset=SCAN_HANDLER_WINDOW[0], length=SCAN_HANDLER_WINDOW[1] - SCAN_HANDLER_WINDOW[0],
            sha256=sha256(image[SCAN_HANDLER_WINDOW[0]:SCAN_HANDLER_WINDOW[1]])),
        category5_close_only=dict(
            offset=CAT5_WINDOW[0], length=CAT5_WINDOW[1] - CAT5_WINDOW[0],
            sha256=sha256(image[CAT5_WINDOW[0]:CAT5_WINDOW[1]])),
        category7_close_report3=dict(
            offset=CAT7_WINDOW[0], length=CAT7_WINDOW[1] - CAT7_WINDOW[0],
            sha256=sha256(image[CAT7_WINDOW[0]:CAT7_WINDOW[1]]),
            reject_halfword=struct.unpack_from('<H', image, CAT7_WINDOW[1] - 2)[0]))
    require(scan['category7_close_report3']['reject_halfword'] == CAT7_REJECT_HALFWORD,
            'Category-7 reject halfword mismatch')
    return scan


def nor_tables(image):
    """Decode the region and object descriptors from the boot-copied data."""
    def file_offset(runtime):
        for record in scatter_records(image):
            if record['kind'] != 'copy':
                continue
            if record['destination'] <= runtime < record['destination'] + record['size']:
                return runtime - record['destination'] + record['source'] - BASE
        return None
    region_offset = file_offset(REGION_RUNTIME)
    object_offset = file_offset(OBJECT_RUNTIME)
    require(region_offset is not None and object_offset is not None,
            'Boot-copy mapping for descriptor tables not found')
    regions = []
    for index in range(REGION_COUNT):
        words = struct.unpack_from('<11I', image, region_offset + index * REGION_STRIDE)
        if words[0] == 0:
            continue
        regions.append(dict(index=index, preferred=words[0], alternate=words[1] or None,
                            span=words[3] if words[3] else words[2], flags=words[4:10]))
    objects = []
    for number in range(OBJECT_COUNT):
        words = struct.unpack_from('<7I', image, object_offset + number * OBJECT_STRIDE)
        if words[0] != number:
            continue
        objects.append(dict(number=number, offset=words[1], length=words[3],
                            region=words[5], parent=words[6] or None))
    return dict(region_table=dict(runtime=REGION_RUNTIME, file_offset=region_offset,
                                  count=len(regions), regions=regions),
                object_table=dict(runtime=OBJECT_RUNTIME, file_offset=object_offset,
                                  count=len(objects), objects=objects))


def negative_scan(name, data):
    hits = {}
    for keyword in NEGATIVE_KEYWORDS:
        count = data.count(keyword)
        if count:
            positions, pos = [], data.find(keyword)
            while pos >= 0 and len(positions) < 8:
                positions.append(pos)
                pos = data.find(keyword, pos + 1)
            hits[keyword.decode('ascii')] = dict(count=count, first=positions)
    return dict(member=str(name), length=len(data), sha256=sha256(data), keyword_hits=hits)


def nkld_header(path):
    """Parse the public NKLD lens-data container header; keep payload out."""
    data = path.read_bytes()
    header = dict(length=len(data),
                  data_offset=int.from_bytes(data[0:2], 'big'),
                  total_length=int.from_bytes(data[2:4], 'big'),
                  major_version=data[4], minor_version=data[5],
                  entry_count=int.from_bytes(data[6:8], 'big'),
                  magic=int.from_bytes(data[8:12], 'big'),
                  data_length=int.from_bytes(data[12:14], 'big'))
    header['magic_known'] = header['magic'] == 0x87C7CAAC
    header['bounds_sane'] = (header['data_offset'] + header['data_length']
                             <= header['total_length'] <= len(data))
    return header


def read_xor_tables(source):
    text = source.read_text(encoding='utf-8-sig')
    tables = []
    for name in ('Xor_Ord1', 'Xor_Ord2', 'Xor_Ord3'):
        match = re.search(rf'static (?:byte|int)\[\] {name} = \{{(.*?)\}};', text, re.S)
        require(match is not None, f'Missing table: {name}')
        tables.append(bytes(int(value, 16) & 255
                            for value in re.findall(r'0x([0-9A-Fa-f]+)', match.group(1))))
    return tables


def decode_package(raw, tables):
    body = bytearray(len(raw) - 0x20)
    first, second, third = tables
    for index in range(len(body)):
        body[index] = (raw[index + 0x20] ^ first[index & 0xFF]
                       ^ second[(index >> 8) & 0xFF] ^ third[(index >> 16) & 0xFF])
    count = struct.unpack_from('>I', body, 0x20)[0]
    require(0 < count <= 64, 'Invalid package member count')
    members = []
    for index in range(count):
        entry = body[0x30 + index * 32:0x30 + (index + 1) * 32]
        name = entry[:16].split(b'\0')[0].decode('ascii')
        start, length = struct.unpack('>II', entry[16:24])
        members.append((name, start, length))
    return body, members


def history_scan(packages, tables):
    rows = []
    for path in sorted(packages.glob('Z7_2_*.bin')):
        stream, members = decode_package(path.read_bytes(), tables)
        master = [m for m in members if 'mas' in m[0] or
                  ('eg1840' in m[0] and 'sla' not in m[0])]
        require(len(master) == 1, f'Ambiguous master member in {path.name}')
        name, start, length = master[0]
        image = stream[start:start + length]
        templates = template_offsets(image)
        records = update_records(image, templates)
        nkld = templates.get('NKLD????.BIN', -1)
        z72 = templates.get('Z7_2_???.BIN', -1)
        row = dict(package=path.name, member=name, length=length,
                   version=image[0x20:0x2C].decode('ascii').strip('\0'),
                   nkld_template=nkld, z72_template=z72,
                   missing_templates=[k for k, v in templates.items() if v < 0],
                   category7_records=records.get('NKLD????.BIN', []),
                   category4_records=records.get('Z7_2_???.BIN', []))
        rows.append(row)
    return rows


def run(args):
    master = args.master.read_bytes()
    validate_master(master)
    report = dict(
        format=1,
        firmware_included=False,
        scope='Boot-chain card-update structure survey; static byte decoding only',
        master_sha256=sha256(master),
        templates=template_offsets(master),
        update_records=update_records(master, template_offsets(master)),
        scan_dispatch=scan_table(master),
        nor_layout=nor_tables(master),
        members=[negative_scan('eg1840_mas_01700', master)] +
                [negative_scan(path.name, path.read_bytes()) for path in args.members],
    )
    if args.nkld:
        report['nkld_header'] = nkld_header(args.nkld)
    if args.packages:
        require(args.tables and args.tables.exists(), 'XOR table source required for history scan')
        report['history'] = history_scan(args.packages, read_xor_tables(args.tables))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=1), encoding='ascii')
    print(f'wrote {args.report}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--nkld', type=Path, help='optional local NKLD-format file')
    parser.add_argument('--packages', type=Path, help='optional history package directory')
    parser.add_argument('--tables', type=Path, help='Firmware.cs XOR table source')
    parser.add_argument('--members', nargs='*', default=[], type=Path,
                        help='additional member images for the negative keyword scan')
    args = parser.parse_args()
    run(args)


if __name__ == '__main__':
    main()
