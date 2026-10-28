# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify the original initialization extent and buffer address conversions."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require, validate_master
from analyze.firmware_structure import scatter_records
from tools.boot_region_probe import RegionProbe


class AllocatorProbe(RegionProbe):
    def boundary(self, u, address, size, unused):
        # Supply one free descriptor and uncontended locks. The constructor,
        # bitmap search, size rounding and descriptor stores remain native.
        if address in (0x1034fa90, 0x1034fbae, 0x1034fcd8, 0x10360f18, 0x10360f12):
            u.reg_write(UC_ARM_REG_R0, self.DATA + 0x1000 if address == 0x1034fcd8 else 0)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(u, address, size, unused)


def processing_pool(image):
    engine = AllocatorProbe(image)
    cases = []
    for requested, occupied, expected_base, expected_size in (
            (0x268250, 0, 0xb0100000, 0x280000),
            (0x7fffff, 0, 0xb0100000, 0x800000),
            (0, 15, 0xb0880000, 0x80000)):
        engine.call(0x3834c0)
        base = engine.word(0xb1808ca8)
        require(base == 0xb0100000, 'Processing pool constructor differs')
        engine.u.mem_write(0xb1d41a28, struct.pack('<16I', *([1] * occupied + [0] * (16 - occupied))))
        pointer = engine.call(0x38354e, requested, 1)
        require(pointer == engine.DATA + 0x1000, 'Allocator descriptor differs')
        address, length, first, count = struct.unpack('<4I', engine.u.mem_read(pointer, 16))
        require((address, length, first, count) ==
                (expected_base, expected_size, occupied, expected_size // 0x80000),
                'Native processing allocation differs')
        require(engine.word(pointer + 16) & 255 == 1, 'Allocation kind differs')
        cases.append(dict(requested=hex(requested), occupied_blocks=occupied,
                          address=hex(address), allocated_size=hex(length),
                          first_block=first, blocks=count))
    return dict(constructor='0x103a34c0', allocator='0x103a354e',
                base='0xb0100000', block_bytes='0x80000', block_count=16,
                end='0xb0900000', cases=cases,
                fixture='Free descriptor and uncontended locks; no pixel buffers supplied.')


def probe(image):
    validate_master(image)
    address = 0x5d170000
    records = [row for row in scatter_records(image) if row['kind'] == 'zero' and
               row['destination'] <= address < row['destination'] + row['size']]
    require(len(records) == 1, 'Expected one initialization record for the grid buffer')
    record = records[0]
    require((record['destination'], record['size']) == (0x54900000, 0xafd2400),
            'Unexpected uncached initialization span')
    engine = RegionProbe(image)
    engine.call(0x3a585c)  # Original runtime address-table constructor.
    cases = []
    for source, expected in ((0x54900000, 0x54900000), (0x54f00000, 0x54f00000),
                             (address, address), (0x5f8d23fc, 0x5f8d23fc),
                             (0x50560000, 0x30260000), (0x62059800, 0x36d59800)):
        row = engine.call(0x3a5ad8, source)
        require(0xb2b4145c <= row < 0xb2b415c4, 'Address-table lookup escaped its entries')
        start, kind, peer, end = struct.unpack('<4I', engine.u.mem_read(row, 16))
        converted = engine.call(0x3a5a7a, source)
        require(converted == expected, 'Native buffer conversion differs')
        cases.append(dict(address=hex(source), row=hex(row), start=hex(start),
                          end=hex(end), kind=hex(kind), peer=hex(peer),
                          converted=hex(converted)))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                initialization=record,
                initialized_end=hex(record['destination'] + record['size']),
                model_existing_backing_end='0x54f00000',
                model_added_base='0x54f00000', model_added_size='0xa9d2400',
                address_table_constructor='0x103c585c', lookup='0x103c5ad8',
                cache_to_bus='0x103c5a7a', cases=cases,
                processing_pool=processing_pool(image),
                limitations=['The address classifier alone does not establish physical RAM.',
                             'Original initialization and live translation provide separate evidence.',
                             'No sensor statistics, pixels or photograph are generated.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(initialized_end=report['initialized_end'], cases=len(report['cases']))))


if __name__ == '__main__':
    main()
