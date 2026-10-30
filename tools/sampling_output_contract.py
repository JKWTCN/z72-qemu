# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify original sampling output control and the two capture task routes."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class OutputProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.u.mem_map(0x20060000, 0x4000)
        self.writes, self.tasks = [], []
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write, begin=0x20060000, end=0x20063fff)

    def write(self, u, access, address, size, value, unused):
        self.writes.append(dict(address=hex(address), size=size, value=hex(value)))

    def boundary(self, u, address, size, unused):
        a, b = u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)
        if address == 0x103a30f0:
            u.mem_write(a, struct.pack('<2I', 0x12345678, 0))
        elif address == 0x103606e4:
            self.tasks.append([hex(a), hex(b)])
        elif address in (0x10360f18, 0x10360f12, 0x103a047c):
            u.reg_write(UC_ARM_REG_R0, 0)
        else:
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def check(image):
    native = OutputProbe(image)
    callbacks = [0] * 11
    callbacks[3:5] = [0x102e9b09, 0x102e9af7]
    native.u.mem_write(native.DATA, struct.pack('<11I', *callbacks))
    native.u.reg_write(UC_ARM_REG_R3, 0)
    native.call(0x2bcc20, 0xb1806d64, native.DATA, 0)
    require(native.word(0x20060034) == 0x18 and
            native.word(0xb1806d78) == callbacks[3] and
            native.word(0xb1806d7c) == callbacks[4], 'Original callback registration differs')
    routes = []
    for state in (6, 7):
        for status in (8, 16, 24):
            native.u.mem_write(0xb1868628, bytes(0x100))
            native.u.mem_write(0xb1868628, bytes([state]))
            native.u.mem_write(0x20060038, struct.pack('<I', status))
            native.writes.clear()
            native.tasks.clear()
            native.call(0x2bc5ea)
            expected = [[hex(0xb23ed8d8), hex(task)] for bit, task in ((8, 0x40), (16, 0x400))
                        if status & bit and state == 7]
            require(native.tasks == expected, 'Original sampling output task route differs')
            require([int(row['value'], 16) for row in native.writes] ==
                    [bit for bit in (8, 16) if status & bit], 'IRQ acknowledgement differs')
            routes.append(dict(state=state, status=hex(status), tasks=list(native.tasks),
                               writes=list(native.writes)))
    controls = []
    for mask in (8, 16, 24):
        for entry, mode in ((0x102962ea, 0), (0x10296324, 1)):
            native.writes.clear()
            native.call(entry - 0x10020000, 0, mask)
            expected = (([0x200630f0] if mask & 8 else []) +
                        ([0x20063130] if mask & 16 else [])) if not mode else []
            expected += [0x20060014 if mode else 0x20060010,
                         0x2006001c if mode else 0x20060018,
                         0x20060024 if mode else 0x20060020]
            require([int(row['address'], 16) for row in native.writes] == expected and
                    [int(row['value'], 16) for row in native.writes] ==
                    ([1] * (len(expected) - 3) + [0, 0, mask]), 'Original output control writes differ')
            controls.append(dict(entry=hex(entry), mask=hex(mask), mode=mode,
                                 writes=list(native.writes)))
    gates = []
    for mode in (0, 1):
        native.writes.clear()
        native.call(0x2bc808, 0, 0x30, mode)
        require(native.writes == [dict(address=hex(0x20060000 + mode * 4), size=4, value='0x0'),
                                 dict(address=hex(0x20060008 + mode * 4), size=4, value='0x30')],
                'Original output gate writes differ')
        gates.append(dict(mask='0x30', mode=mode, writes=list(native.writes)))
    deadlines = []
    for channel_mask, base in ((8, 0x200630d0), (16, 0x20063110)):
        for start, width in ((0, -1), (10, -1), (10, 5), (1000000, 1000)):
            parameters = native.DATA + 0x100
            native.u.mem_write(parameters, bytes(44))
            native.u.reg_write(UC_ARM_REG_R3, parameters)
            result = native.call(0x2c8262, start, 0, width & 0xffffffff)
            require(result == 0, 'Original output deadline encoder rejected bounded input')
            native.writes.clear()
            native.call(0x27642a, 0, channel_mask, parameters)
            values = [native.word(base + offset) for offset in range(0, 0x1c, 4)]
            first = start * 72
            second = (start + width) * 72 if width >= 0 else (1 << 56) - 1
            expected = [0xffffffff, 0xffffff, 0xffff,
                        (first & 0xffff) | (second & 0xffff) << 16,
                        first >> 16 & 0xffffff, second >> 16 & 0xffffff,
                        (first >> 40) | (second >> 40) << 16]
            require(values == expected, 'Original 56-bit deadline register layout differs')
            deadlines.append(dict(mask=hex(channel_mask), start=start, width=width,
                                  registers=[hex(x) for x in values]))
    return dict(format=1, result='passed', firmware_included=False, master_sha256=MASTER_SHA,
        register_callbacks='0x102dcc20', interrupt='0x102dc5ea', callbacks=[hex(x) for x in callbacks[3:5]],
        routes=routes, controls=controls, gates=gates,
        deadline_encoder='0x102e8262', deadline_writer='0x1029642a', deadlines=deadlines,
        host_boundaries=['synthetic callback descriptors, sampling state and MMIO storage',
                         'synthetic timestamp; record task posts and hardware writes',
                         'replace resource lookup and lock/unlock with inert return values'],
        limitations=['Does not prove physical output timing, event generation or photo completion',
                     'Synthetic status storage records acknowledgement but does not implement W1C'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original sampling outputs: control writes, callback registration and capture task routing')
