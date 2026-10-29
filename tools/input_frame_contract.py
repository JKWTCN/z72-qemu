# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify original input cause routing and task-event translations."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class FrameProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.events = []
        self.notifications = []

    def boundary(self, u, address, size, unused):
        if address == self.DATA + 0x28000:
            self.notifications.append((u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)))
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        elif address in (0x10360f18, 0x10360f12, 0x1034fe7e):
            u.reg_write(UC_ARM_REG_R0, 1)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        elif address in (0x103606e4, 0x103610cc):
            self.events.append((u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)))
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(u, address, size, unused)


def probe(image):
    engine = FrameProbe(image)
    cases = []
    for bank, bits, logical, callback, group, events in (
            (0, 1, 0x10000000, 0x102391b2, 0, [(0xb26b3888, 1)]),
            (0, 0x40, 0x10000000, 0x102391b2, 0, [(0xb26b3888, 4)]),
            (0, 0x41, 0x10000000, 0x102391b2, 0, [(0xb26b3888, 1), (0xb26b3888, 4)]),
            (0, 8, 0x10000000, 0x102391b2, 0, [(0xb188814c, 0x100000)]),
            (0, 0x10, 0x10000000, 0x102391b2, 0, [(0xb188814c, 0x200000)]),
            (0, 0x80, 0x10000000, 0x102391b2, 0, [(0xb26b3888, 0x10)]),
            (3, 1, 0x20, 0x10239436, 2, [(0xb188814c, 0x1000000)]),
            (3, 0x20, 0x10, 0x10239480, 2, [(0xb188814c, 0x800000)]),
            (3, 0x40000000, 0x400, 0x1023938c, 2, [(0xb188814c, 0x2000000)]),
            (4, 0x80, 0x200, 0x1023931c, 2, [(0xb188814c, 0x4000000)]),
            (4, 0x100, 0x200, 0x1023931c, 2, [(0xb26b3888, 0x4000)])):
        status = [0] * 8
        status[bank] = bits
        engine.u.mem_write(engine.DATA, struct.pack('<8I', *status))
        result = engine.call(0x1ead46, engine.DATA)
        require(result == logical, 'Original logical cause routing differs')
        engine.events.clear()
        engine.call(callback - 0x10020000, 0x41072800 + group, engine.DATA)
        require(engine.events == events, 'Original input callback events differ')
        cases.append(dict(bank=bank, bits=hex(bits), logical=hex(result),
                          callback=hex(callback), group=group,
                          events=[dict(object=hex(target), bits=hex(value))
                                  for target, value in engine.events]))
    finite_cases = []
    node, context = engine.DATA + 0x400, engine.DATA + 0x1000
    for finite, queued, inhibited, callback in ((1, 1, 0, 1), (1, 0, 0, 1),
                                               (0, 1, 0, 1), (0, 1, 1, 1), (1, 1, 0, 0)):
        engine.u.mem_write(0xb26b38cc, struct.pack('<2I', finite, inhibited))
        engine.u.mem_write(0xb1888168, struct.pack('<I', engine.DATA + 0x28001 if callback else 0))
        engine.u.mem_write(0xb26b3984, struct.pack('<5I',
            node if queued else 0, node if queued else 0, queued, 0, 0))
        engine.u.mem_write(node, struct.pack('<3I', node, node, context))
        engine.notifications.clear()
        engine.call(0x218d4a, 0x10)
        expected = ([(0x041a0001, context if queued else 0)] if finite else
                    [(0x041a0004, 0)] if not inhibited else []) if callback else []
        require(engine.notifications == expected, 'Original task-0x10 notifications differ')
        remaining = engine.word(0xb26b398c)
        require(remaining == (0 if finite else queued), 'Original finite queue consumption differs')
        finite_cases.append(dict(finite_flag=bool(finite), queued=queued,
            alternate_inhibited=bool(inhibited), callback=bool(callback), remaining=remaining,
            notifications=[dict(code=hex(code), context=hex(pointer))
                           for code, pointer in engine.notifications]))
    input_events = []
    for code, task_bits in ((0x041a0001, 0x10000), (0x041a0004, 0x10)):
        for pointer in (0, context):
            engine.events.clear()
            engine.call(0x20e2e0, code, pointer)
            require(engine.events == [(0xb25eeb78, task_bits)],
                    'Original finite notification to input-task translation differs')
            input_events.append(dict(code=hex(code), context=hex(pointer),
                                     task='0xb25eeb78', bits=hex(task_bits)))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                cause_decoder='0x1020ad46', cases=cases,
                finite_task=dict(dispatcher='0x10238d4a', event='0x10',
                    consumer='0x1023c6ec', queue='0xb26b3984', cases=finite_cases,
                    upper_callback='0x1022e2e0', input_events=input_events,
                    host_boundaries=['lock/unlock success and queue-node release']),
                limitations=['Synthetic event storage and host task/event API boundaries.',
                             'Task delivery does not prove frame-buffer ownership or pixel processing.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(routes=len(result['cases']))))


if __name__ == '__main__':
    main()
