# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original auxiliary image run controls and interrupt delivery."""
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
        base=hex(native.BASE), controls=controls, interrupt_entry='0x10294364',
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
    print('PASS 6 auxiliary image run controls and 6 interrupt causes')
