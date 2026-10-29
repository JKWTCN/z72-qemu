# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the original managed pool behind the observed primary RAW buffer."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class PoolProbe(RegionProbe):
    def boundary(self, u, address, size, unused):
        if address == 0x1034fe30:
            require(u.reg_read(UC_ARM_REG_R0) == 0x37bc,
                    'Unexpected pool metadata allocation size')
            u.reg_write(UC_ARM_REG_R0, self.DATA + 0x10000)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(u, address, size, unused)


def probe(image):
    native = PoolProbe(image)
    profile_address = 0x11983578
    header, capacity, unit, limit, base, kind, alignment = struct.unpack_from(
        '<5I2B', image, profile_address - BASE)
    require((header, capacity, unit, limit, base, kind, alignment) ==
            (0x68, 0x3b586000, 0xaea000, 87, 0x83900000, 1, 7),
            'Observed primary pool profile differs')
    argument = native.DATA + 0x8000
    # Same six words observed at the native constructor; byte +0xd is set
    # by the original wrapper, independently of the alignment byte +0xc.
    words = (base, capacity, unit, alignment | 0x100, limit, header)
    native.u.mem_write(argument, struct.pack('<6I', *words))
    require(native.call(0x102e5e6c - BASE, native.DATA, argument) == 1,
            'Original managed pool constructor failed')
    for index in range(limit):
        descriptor = native.DATA + 0x10000 + index * 0x3c
        require(native.word(descriptor) == base + index * unit and
                native.word(descriptor + 0x10) == index,
                'Original slot source or index differs')
    requested = 0x417c000
    result = native.call(0x102e5fe4 - BASE, native.DATA, requested)
    require(result == native.DATA + 0x10000 + 81 * 0x3c,
            'Original request selected another descriptor')
    source, length, view, view_bytes, index, units = struct.unpack(
        '<6I', native.u.mem_read(result, 24))
    require((source, length, view_bytes, index, units) ==
            (0xbad0a000, requested, header, 81, 6),
            'Original primary allocation differs')
    require(not native.copies and not native.programs and not native.erases,
            'Pool construction crossed an unexpected host boundary')
    overlap = min(source + length, 0xbb300000) - max(source, 0xbaa00000)
    require(overlap == 0x5f6000, 'Code-cache intersection differs')
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        profile=hex(profile_address), constructor='0x102e5e6c', allocator='0x102e5fe4',
        constructor_arguments=[hex(value) for value in words],
        slot_count=limit, slot_stride=hex(unit), metadata_bytes='0x37bc',
        allocation=dict(requested_bytes=requested, source=hex(source), bytes=length,
            view_bytes=view_bytes, first_slot=index, units=units, end=hex(source + length)),
        code_cache_intersection=dict(start=hex(source), end='0xbb300000', bytes=overlap),
        native_slot_construction_and_allocation=True,
        host_boundaries=['One bounded allocation of synthetic descriptor/view storage.'],
        limitations=['Pool metadata uses synthetic RAM; no pixel storage is allocated or written.',
                    'The allocation reproduces the observed numeric overlap, not DMA address-space ownership.',
                    'No firmware wait, capture completion, JPEG or file is supplied.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS original primary pool construction and six-unit allocation')


if __name__ == '__main__':
    main()
