# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original auxiliary image configuration, controls and interrupts."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class AuxProbe(RegionProbe):
    BASE = 0x20201000
    RECORDER = RegionProbe.DATA + 0x1000

    def __init__(self, image):
        super().__init__(image)
        self.writes, self.events = [], []
        self.u.mem_map(self.BASE, 0x1000)
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.mmio_write,
                        begin=self.BASE, end=self.BASE + 0xfff)

    def mmio_write(self, u, access, address, size, value, unused):
        self.writes.append(dict(address=hex(address), bytes=size, value=hex(value)))

    def boundary(self, u, address, size, unused):
        if address == self.RECORDER:
            context = u.reg_read(UC_ARM_REG_R1)
            self.events.append(dict(notification=hex(u.reg_read(UC_ARM_REG_R0)),
                context=hex(context), cause=hex(self.word(context + 0x64)),
                result=hex(self.word(context + 0x60))))
            u.reg_write(UC_ARM_REG_R0, 0)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(u, address, size, unused)


def builder_contract(native):
    request, source_handle, target_handle, source, target, output = [
        native.DATA + offset for offset in (0x2000, 0x2200, 0x2400, 0x2600, 0x2800, 0x2a00)]
    native.u.mem_write(source_handle + 4, struct.pack('<I', source))
    native.u.mem_write(target_handle + 4, struct.pack('<I', target))
    native.u.mem_write(source, struct.pack('<I', 0x58000000))
    native.u.mem_write(target, struct.pack('<I', 0x5a000000))
    cases = []
    for mode, width, height, accepted in (
            (0, 320, 224, 1), (0, 319, 224, 0), (0, 320, 223, 0),
            (0, 1536, 256, 1), (0, 1537, 224, 0),
            (0, 320, 1024, 1), (0, 320, 1025, 0),
            (0, 960, 416, 1), (0, 992, 416, 0), (0, 641, 431, 1),
            (1, 640, 432, 1), (2, 640, 432, 1), (2, 640, 432, 1),
            (3, 640, 432, 1), (3, 640, 432, 1)):
        native.u.mem_write(request, struct.pack('<3I', mode, source_handle, target_handle))
        native.u.mem_write(source_handle + 0x22, struct.pack('<hh', width, height))
        native.u.mem_write(output, bytes(0xe0))
        result = native.call(0x215ff6, request, output)
        require(result == accepted, 'Auxiliary image descriptor admission differs')
        row = dict(mode=mode, width=width, height=height, accepted=bool(result))
        if result:
            require(native.word(output + 0x70) == width // 32 and
                    native.word(output + 0x74) == height // 32,
                    'Auxiliary image grid derivation differs')
            require(all(native.word(output + offset + index * 4) == address
                        for offset, address in ((0x2c, 0x58000000), (0x3c, 0x58000000),
                                                (0x4c, 0x5a000000), (0x5c, 0x5a000000))
                        for index in range(4)), 'Auxiliary image address forwarding differs')
            scratch = 0xb25f2960 if mode in (0, 2) else 0xb2652960
            require(native.word(output + 0x78) == scratch,
                    'Auxiliary image scratch selection differs')
            row.update(grid=[native.word(output + 0x70), native.word(output + 0x74)],
                       source=hex(native.word(output + 0x2c)),
                       target=hex(native.word(output + 0x4c)), scratch=hex(scratch),
                       field_7c=native.word(output + 0x7c))
        cases.append(row)
    return dict(entry='0x10235ff6', source_geometry_offsets=['0x22', '0x24'],
                cases=cases, host_function_boundaries_used=False)


def probe(image):
    native = AuxProbe(image)
    controls = []
    for entry, argument, expected in (
            (0x1029469a, 0, [(4, 1)]),
            (0x102946a4, 0, [(4, 0)]),
            (0x102946ae, 0, [(0x44, 3), (0x48, 7), (0x14, 1)]),
            (0x102946c0, 0, [(0x44, 2), (0x48, 0)]),
            (0x102946c0, 1, [(0x44, 3), (0x48, 7)]),
            (0x102946c0, 2, [(0x44, 1), (0x48, 1)])):
        native.writes.clear()
        native.call(entry - 0x10020000, argument)
        require(native.writes == [dict(address=hex(native.BASE + offset), bytes=4,
                                       value=hex(value)) for offset, value in expected],
                'Auxiliary image run control differs')
        controls.append(dict(entry=hex(entry), argument=argument, writes=list(native.writes)))
    configurations = []
    context, descriptor, shadow = native.DATA + 0x200, native.DATA + 0x800, native.DATA + 0x500
    native.u.mem_write(context + 4, struct.pack('<I', shadow))
    fields = ((0, 0x4c), (4, 0x50), (8, 0x54), (0xc, 0x5c), (0x10, 0x60),
              (0x14, 0xa0), (0x18, 0xa4), (0x1c, 0xa8), (0x20, 0xac),
              (0x24, 0xb0), (0x28, 0xb4), (0x2c, 0xb8), (0x30, 0xbc),
              (0x34, 0xc0), (0x38, 0xc4), (0x3c, 0xc8), (0x40, 0xcc),
              (0x4c, 0x108), (0x50, 0x10c), (0x54, 0x110),
              (0x58, 0x124), (0x5c, 0x16c), (0x68, 0x20))
    for pattern in (False, True):
        data = struct.pack('<28I', *[0x80000800 + index * 0x10001 if pattern else 0
                                    for index in range(28)])
        native.u.mem_write(descriptor, data)
        native.writes.clear()
        native.call(0x2744a6, context, descriptor)
        expected = [(0, 1), (0, 0)]
        for offset, register in fields:
            value = struct.unpack_from('<I', data, offset)[0]
            if offset in (0, 0x38):
                value = int(bool(value))
            elif offset == 0x10:
                value &= 0xff
            elif offset in (0x2c, 0x30, 0x34):
                value &= 0x7ff
            expected.append((register, value))
        # +0x44 contributes two bits, while +0x48 supplies an independent enable.
        combined = (data[0x44] & 3) << 2 | int(bool(struct.unpack_from('<I', data, 0x48)[0]))
        expected.insert(19, (0x100, combined))
        require(native.writes == [dict(address=hex(native.BASE + offset), bytes=4,
                                       value=hex(value)) for offset, value in expected],
                'Auxiliary image configuration forwarding differs')
        require(bytes(native.u.mem_read(shadow, 0x70)) == data,
                'Native configuration shadow copy differs')
        configurations.append(dict(pattern=pattern, writes=list(native.writes), shadow_copy_bytes=0x70))
    context = native.DATA + 0x200
    native.u.mem_write(0xb1801ef8, struct.pack('<I', context))
    native.u.mem_write(context + 0x68, struct.pack('<2I', 0xc7, native.RECORDER | 1))
    interrupts = []
    for cause in (0, 1, 2, 0x40, 0x80, 0xc7):
        native.u.mem_write(context + 0x60, struct.pack('<2I', 0xabcdef01, 0))
        native.u.mem_write(native.BASE + 0x2c, struct.pack('<I', cause))
        native.u.mem_write(native.BASE + 0x1a0, struct.pack('<I', 0x13572468))
        native.writes.clear()
        native.events.clear()
        native.call(0x274364)
        expected = [(0x2c, cause)]
        if cause & 0x40:
            expected += [(0x44, 2), (0x48, 0), (0, 1), (0, 0), (0x20, 0xc7)]
        if cause & 2:
            expected += [(0, 1), (0, 0)]
        require(native.writes == [dict(address=hex(native.BASE + offset), bytes=4,
                                       value=hex(value)) for offset, value in expected],
                'Auxiliary image interrupt writes differ')
        require(native.events == [dict(notification='0x41051c01', context=hex(context),
                cause=hex(cause), result=hex(0x13572468 if cause & 1 else 0xabcdef01))],
                'Auxiliary image interrupt callback differs')
        interrupts.append(dict(cause=hex(cause), writes=list(native.writes),
                               events=list(native.events)))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        base=hex(native.BASE), controls=controls, configuration_entry='0x102944a6',
        configuration_fields=[dict(source=hex(offset), register=hex(native.BASE + register))
                              for offset, register in fields],
        combined_control=dict(register='0x20201100', source='byte +0x44 low two bits -> bits 2..3; nonzero word +0x48 -> bit 0'),
        configurations=configurations, builder=builder_contract(native), interrupt_entry='0x10294364',
        interrupts=interrupts, host_boundaries=['record interrupt callback'],
        limitations=['Synthetic register storage and result value; no pixels or hardware completion.',
                     'Records the status acknowledgement write; does not emulate its hardware semantics.',
                     'Native callback delivery for a supplied cause does not prove an actual runtime request.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS 6 auxiliary image run controls, 2 configurations, 15 descriptors and 6 interrupt causes')
