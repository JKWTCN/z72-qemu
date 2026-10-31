# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify native single-capture request fields and internal format selection."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R5, UC_ARM_REG_R6,
                              UC_ARM_REG_LR, UC_ARM_REG_PC)

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
            require(capture_request_words(format_code == 0x3801, storage >> 16,
                                          format_code == 0x3800) == words,
                    'Diagnostic caller request differs from the original builder')
            # Start after the original scalar getter, supplying its baseline
            # return value. Execute the native request-byte selection itself.
            native.u.reg_write(UC_ARM_REG_R0, 3)
            native.u.reg_write(UC_ARM_REG_R5, output)
            native.u.reg_write(UC_ARM_REG_R6, 0xffffffff)
            native.u.emu_start(0x103ba935, 0x103ba94a, count=30)
            selected = native.u.reg_read(UC_ARM_REG_R6)
            require(native.u.reg_read(UC_ARM_REG_PC) == 0x103ba94a and
                    selected == (1 if format_code == 0x3800 else 3),
                    'Native capture format selection differs')
            cases.append(dict(storage=hex(storage), format=hex(format_code), words=words,
                              selected_internal_format=selected))
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
    mode_properties = []
    for property_id, expected_address in ((0x1b0c, 0xb255213c), (0x2400, 0xb2552694)):
        group = 0x11906924 + (property_id >> 8) * 28
        index = struct.unpack('<H', native.u.mem_read(group + 12, 2))[0] + (property_id & 255)
        record = 0x118fb024 + index * 16
        property_kind, property_size, pointer, _ = struct.unpack('<4I', native.u.mem_read(record, 16))
        require((property_kind, property_size, pointer) == (7, 4, expected_address),
                'Control property scalar descriptor differs')
        native.u.mem_write(pointer, struct.pack('<I', 1))
        require(native.call(0x101017d8 - 0x10020000, property_id, output) == 1 and
                native.word(output) == 1, 'Original control getter differs from its descriptor')
        mode_properties.append(dict(id=hex(property_id), descriptor=hex(record), address=hex(pointer),
                                    getter='0x101017d8', synthetic_value=1, readback=1))
    program_mapping = []
    for external, internal in ((1, 3), (2, 0), (3, 2), (4, 1)):
        require(native.call(0x105032b2 - 0x10020000, 0x119e9004, 11, external) == internal and
                native.call(0x105032d0 - 0x10020000, 0x119e9004, 11, internal) == external,
                'Original exposure-program mapping differs')
        program_mapping.append(dict(external=external, internal=internal))
    return dict(format=1, result='passed', firmware_included=False,
        master_sha256=MASTER_SHA, builder='0x10490872', operation='0x100e', cases=cases,
        diagnostic_caller_comparisons=9,
        format_selection=dict(entry='0x103ba934', stop='0x103ba94a',
                              supplied_current_format=3),
        control_properties=mode_properties,
        exposure_program_mapping=dict(table='0x119e9004', count=11,
            to_internal='0x105032b2', to_external='0x105032d0', cases=program_mapping),
        format_property=dict(id='0x161a', descriptor=hex(descriptor), address=hex(address),
            getter='0x101017d8', synthetic_value=3, readback=3),
        host_boundaries=['Supply synthetic packet/output and a single-capture mode getter',
                         'Supply the scalar getter return before native format-byte selection',
                         'Seed a synthetic scalar to check the original property getter'],
        limitations=['Request construction and bounded format selection only; no admission, encoding or file writing'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original capture request construction and internal format selection')
