# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover the processing DMA register contract by executing its original setter."""
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
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2


class DescriptorProbe(RegionProbe):
    def boundary(self, cpu, address, size, unused):
        # The setter waits eight counter ticks after submitting its channel.
        # Only the two counter reads are supplied by the test environment.
        if address == 0x103bdba4:
            cpu.reg_write(UC_ARM_REG_R0, 100)
            cpu.reg_write(UC_ARM_REG_R1, 0)
            cpu.reg_write(UC_ARM_REG_PC, (address + 4) | 1)
        elif address == 0x103bdba8:
            cpu.reg_write(UC_ARM_REG_R1, 109)
            cpu.reg_write(UC_ARM_REG_R2, 0)
            cpu.reg_write(UC_ARM_REG_PC, (address + 4) | 1)
        else:
            super().boundary(cpu, address, size, unused)


def probe(image):
    native = DescriptorProbe(image)
    native.u.mem_map(0x20100000, 0x10000)
    node, parameters = native.DATA, native.DATA + 0x1000
    targets = [0x54900000, 0x56b0d000, 0x58d1a000, 0x5af27000]
    data = bytearray(64)
    struct.pack_into('<4I', data, 0, 2080, 2080, 0, 0)
    struct.pack_into('<4I', data, 0x10, *targets)
    struct.pack_into('<4H', data, 0x2a, 1380, 918, 0, 0)
    struct.pack_into('<2H', data, 0x32, 1380, 918)
    native.u.mem_write(parameters, bytes(data))
    cases = []
    for channel in (0, 15):
        base = 0x20100400 + channel * 0x40
        native.u.mem_write(node, bytes([0, channel]) + bytes(10) + struct.pack('<I', parameters))
        native.call(0x39da1e, node)
        words = list(struct.unpack('<13I', native.u.mem_read(base, 52)))
        expected = [1, 0, 918 << 16 | 1380, 0, 2080, 2080, 0, 0,
                    918 << 16 | 1380, *targets]
        require(words == expected, 'Original processing DMA descriptor packing differs: ' + repr(words))
        require(native.word(0x2010002c) == channel, 'Original channel submission differs')
        cases.append(dict(channel=channel, base=hex(base),
                          registers={hex(index * 4): hex(value) for index, value in enumerate(words)},
                          submitted_channel=native.word(0x2010002c)))
    return dict(firmware_included=False, master_sha256=hashlib.sha256(image).hexdigest(),
                entry='0x103bda1e', register_table='0x10789cc0',
                host_boundaries=['two counter reads, advanced by nine ticks'],
                synthetic_parameters=dict(first_words=[2080, 2080, 0, 0],
                    address_fields=['0x10', '0x14', '0x18', '0x1c'],
                    rectangle_fields=['0x2a', '0x2c', '0x2e', '0x30'],
                    size_fields=['0x32', '0x34'], other_flags=0),
                cases=cases, pixel_transfer_verified=False,
                limitation='Packing and submission are verified; channel direction, pixel formats and completion remain unverified.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS original processing DMA register packing and channel submission')
