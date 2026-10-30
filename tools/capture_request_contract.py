# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify original single-capture request format and storage fields."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe
from tools.native_capture_caller import capture_request_words


class RequestProbe(RegionProbe):
    def boundary(self, cpu, address, size, unused):
        if address == 0x104c7bfc:
            cpu.reg_write(UC_ARM_REG_R0, 0)  # single-capture branch
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(cpu, address, size, unused)


def check(image):
    native = RequestProbe(image)
    packet, output = native.DATA, native.DATA + 0x100
    cases = []
    for storage, storage_byte in ((0, 0), (0x10001, 3), (0x20001, 4)):
        for format_code, format_byte in ((0, 0), (0x3800, 1), (0x3801, 2)):
            data = bytearray(20)
            struct.pack_into('<H', data, 6, 0x100e)
            struct.pack_into('<2I', data, 12, storage, format_code)
            native.u.mem_write(packet, bytes(data))
            native.u.mem_write(output, bytes(20))
            native.call(0x10490872 - 0x10020000, packet, output)
            words = list(struct.unpack('<5I', native.u.mem_read(output, 20)))
            expected = [format_byte << 8 | storage_byte << 16, 1, 0, 0, 1]
            require(words == expected, 'Original capture format/storage request differs')
            if format_code in (0, 0x3801):
                require(capture_request_words(format_code == 0x3801, storage >> 16) == words,
                        'Diagnostic caller request differs from the original builder')
            cases.append(dict(storage=hex(storage), format=hex(format_code), words=words))
    # The original scalar getter resolves property 0x161a through its ROM
    # descriptor. Validate the address used by read-only native observations.
    group = 0x11906924 + (0x161a >> 8) * 28
    index = struct.unpack('<H', native.u.mem_read(group + 12, 2))[0] + (0x161a & 255)
    descriptor = 0x118fb024 + index * 16
    kind, size, address, unused = struct.unpack('<4I', native.u.mem_read(descriptor, 16))
    require((kind, size, address) == (7, 4, 0xb25517d0), 'Format scalar descriptor differs')
    native.u.mem_write(address, struct.pack('<I', 3))
    require(native.call(0x101017d8 - 0x10020000, 0x161a, output) == 1 and
            native.word(output) == 3, 'Original format getter differs from its descriptor')
    return dict(format=1, result='passed', firmware_included=False,
        master_sha256=MASTER_SHA, builder='0x10490872', operation='0x100e', cases=cases,
        diagnostic_caller_comparisons=6,
        format_property=dict(id='0x161a', descriptor=hex(descriptor), address=hex(address),
            getter='0x101017d8', synthetic_value=3, readback=3),
        host_boundaries=['Supply synthetic packet/output and a single-capture mode getter',
                         'Seed a synthetic scalar to check the original property getter'],
        limitations=['Request construction only; no admission, image encoding or file writing'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original single-capture format and storage request construction')
