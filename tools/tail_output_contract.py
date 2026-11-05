# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify capture tail output notifications and their delegate condition."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.sampling_output_contract import OutputProbe


class TailProbe(OutputProbe):
    CALLBACK = OutputProbe.DATA + 0x2f000

    def __init__(self, image):
        super().__init__(image)
        self.observed = []

    def boundary(self, u, address, size, unused):
        a, b = u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)
        if address == 0x102eab0e:
            require((a, b) == (2, 0), 'Unexpected sampling command')
            u.reg_write(UC_ARM_REG_R0, 0)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        elif address in (self.CALLBACK, 0x1026f714):
            self.observed.append(dict(boundary=hex(address), r0=hex(a), r1=hex(b)))
            u.reg_write(UC_ARM_REG_PC, self.STOP)
            u.emu_stop()
        else:
            return super().boundary(u, address, size, unused)


def check(image):
    probe = TailProbe(image)
    cases = []
    for state, mode, count, expected in ((1, 0, 0, 0x04200301),
            (1, 1, 0, 0x04200301), (1, 2, 0, 0x04200303),
            (1, 2, 1, 0x04200301), (2, 0, 0, 0x04200301),
            (3, 0, 0, 0x04200303), (4, 0, 0, 0x04200304)):
        header = bytearray(0x20)
        header[:2] = bytes((state, mode))
        struct.pack_into('<I', header, 8, probe.CALLBACK | 1)
        struct.pack_into('<I', header, 0x18, count)
        probe.u.mem_write(0xb1868988, bytes(header))
        probe.observed.clear()
        probe.call(0x2a9ca6)
        require(probe.observed[0]['r0'] == hex(expected), 'Tail notification differs')
        cases.append(dict(state=state, mode=mode, count=count, observed=list(probe.observed)))
    consumers = []
    for state in (16, 17, 18):
        probe.u.mem_write(0xb1868510, bytes(0x30))
        probe.u.mem_write(0xb1868510, bytes([state]))
        probe.observed.clear()
        probe.call(0x24d0ec, 0x04200301)
        expected = [dict(boundary='0x1026f714', r0='0x6', r1='0x0')] if state == 17 else []
        require(probe.observed == expected, 'Delegate condition registration differs')
        consumers.append(dict(state=state, observed=list(probe.observed)))
    deadlines = []
    for mask, base in ((0x40, 0x20063190), (0x80, 0x200631d0)):
        for start, width in ((0, 1000), (100, 1), (1000, 500)):
            parameters = probe.DATA + 0x100
            probe.u.mem_write(parameters, bytes(44))
            probe.u.reg_write(UC_ARM_REG_R3, parameters)
            require(probe.call(0x2a9e0a, start, 0, width) == 0,
                    'Tail deadline encoder rejected input')
            probe.writes.clear()
            probe.call(0x27642a, 0, mask, parameters)
            values = [probe.word(base + offset) for offset in range(0, 0x1c, 4)]
            first, second = start * 72, (start * 10 + width) * 72 // 10
            expected = [0xffffffff, 0xffffff, 0xffff,
                        (first & 0xffff) | ((second & 0xffff) << 16),
                        first >> 16 & 0xffffff, second >> 16 & 0xffffff,
                        (first >> 40) | ((second >> 40) << 16)]
            require(values == expected, 'Tail deadline register layout differs')
            deadlines.append(dict(mask=hex(mask), start=start, width=width,
                                  registers=[hex(x) for x in values]))
    return dict(result='passed', master_sha256=MASTER_SHA, notifications=cases,
        consumers=consumers, deadlines=deadlines, limitations=[
            'Synthetic callback registration and state; stop before delegate setter.',
            'Sampling command (2, 0) returns zero at an explicit boundary.',
            'Does not generate hardware events or establish whole-machine capture completion.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('PASS tail output notification and delegate state conditions')
