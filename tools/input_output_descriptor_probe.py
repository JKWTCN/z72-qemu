# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute C 1.70 output register setters against synthetic descriptors."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from tools.boot_region_probe import RegionProbe
from unicorn.arm_const import UC_ARM_REG_R3


def probe(image):
    native = RegionProbe(image)
    native.u.mem_map(0x20068000, 0x4000)
    descriptor = native.DATA
    configuration = descriptor + 0x1000
    target, extent = 0x54000000, 0x12000
    native.u.mem_write(descriptor, struct.pack('<4I', target, 0, extent, 3))
    native.u.reg_write(UC_ARM_REG_R3, configuration)
    native.call(0x21a63c, descriptor, 2, 7)
    require(native.word(configuration + 0x1c) == extent and
            native.word(configuration + 0x14) == 1 and
            bytes(native.u.mem_read(configuration + 0x18, 1)) == b'\x07' and
            bytes(native.u.mem_read(configuration + 0xc, 1)) == b'\x01',
            'Original output configuration builder differs')
    require(struct.unpack('<8I', native.u.mem_read(configuration + 0x24, 32)) == (target,) * 8,
            'Original builder address groups differ')
    native.call(0x1eb16a, 0, 1, configuration + 0x10)
    require(native.word(0x2006a580) == extent,
            'Original buffer extent does not reach output register')
    native.call(0x1eb142, 0, 1, configuration + 4)
    require(native.word(0x2006a514) == 3 and native.word(0x2006a548) == 1 and
            native.word(0x2006a524) == 0,
            'Original output count and control forwarding differs')
    cases = []
    for channel in (0, 1, 9):
        base = 0x2006a400 + channel * 0x100
        require(native.word(0xb18069d4 + channel * 4) == base + 0x14,
                'Original output register table does not match channel')
        native.u.mem_write(base + 0x3c, struct.pack('<I', 0xa5a50001))
        native.u.mem_write(descriptor, struct.pack('<4I', 2, 0x1357, 3, 0x2468))
        native.call(0x1eb16a, 0, channel, descriptor)
        registers = {hex(offset): native.word(base + offset)
                     for offset in (0x3c, 0x40, 0x44, 0x80)}
        require(registers == {'0x3c': 0xa5a50005, '0x40': 0x1357,
                              '0x44': 3, '0x80': 0x2468},
                'Original descriptor field forwarding differs: ' + repr(registers))
        for bank in (0, 1):
            native.call(0x1eb232, 0, channel, bank)
            require(native.word(base + 0x3c) == 0xa5a50004 | bank,
                    'Original bank selection changed unrelated bits')
        targets = [0x54000000 + index * 0x1000 for index in range(4)]
        native.u.mem_write(descriptor, struct.pack('<4I', *targets))
        planes = channel == 9
        for bank in (0, 1):
            native.u.reg_write(UC_ARM_REG_R3, descriptor)
            native.call(0x1eb1da, 0, channel, bank)
            offsets = [0x50 + bank * 0x10 + index * 4 for index in range(4 if planes else 1)]
            require([native.word(base + offset) for offset in offsets] == targets[:len(offsets)],
                    'Original output address bank forwarding differs')
        cases.append(dict(channel=channel, base=hex(base),
                          field_registers={key: hex(value) for key, value in registers.items()},
                          address_banks=['0x50', '0x60'], addresses_per_bank=4 if planes else 1,
                          bank_selection_preserves_other_bits=True))
    return dict(firmware_included=False, master_sha256=hashlib.sha256(image).hexdigest(),
                execution='original Thumb setters with synthetic descriptors and MMIO storage',
                builder=dict(entry='0x1023a63c', supplied_count=2, stored_count_minus_one=1,
                             count_register='0x2006a548',
                             buffer_extent=extent, extent_register='0x2006a580',
                             addresses_per_bank=4, banks=2),
                setters=['0x1020b142', '0x1020b16a', '0x1020b232', '0x1020b1da'], cases=cases,
                host_function_boundaries_used=False, pixel_transfer_verified=False,
                limitation='Field forwarding and bank selection do not establish pixel format, transfer size or completion timing.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS original output descriptor fields, bank selection and address forwarding')
