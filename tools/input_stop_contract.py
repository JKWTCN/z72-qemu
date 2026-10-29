# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover input stop requests and their original interrupt translations."""
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


class StopProbe(RegionProbe):
    RECORDER = RegionProbe.DATA + 0x28000

    def __init__(self, image):
        super().__init__(image)
        self.u.mem_map(0x20068000, 0x1000)
        self.writes, self.events, self.task_events, self.notifications = [], [], [], []
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write, begin=0x20068000, end=0x20068fff)

    def write(self, u, access, address, size, value, unused):
        require(size == 4, 'Unexpected input access width')
        self.writes.append((address, value))

    def boundary(self, u, address, size, unused):
        if address == 0x10361034:
            target, length = u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)
            require(length == 32, 'Unexpected temporary clear size')
            u.mem_write(target, bytes(length))
        elif address == 0x103610cc:
            self.events.append(u.reg_read(UC_ARM_REG_R1))
        elif address == 0x103606e4:
            self.task_events.append((u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)))
        elif address == self.RECORDER:
            self.notifications.append((u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)))
        elif address in (0x10360f18, 0x10360f12):
            pass  # Uncontended lock boundaries; native mask and callback code still runs.
        else:
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def probe(image):
    engine = StopProbe(image)
    cases = []
    for entry, command, logical, status, events in (
            (0x10209020, 3, 0x600, [0, 0x110, 0, 0, 0, 0, 0, 0], [4, 4]),
            (0x1020ae7c, 4, 0x10, [0, 1, 0, 0, 0, 0, 0, 0], [2]),
            (0x10208c84, 8, 0x20, [0x10000000, 0, 0, 0, 0, 0, 0, 0], [1]),
            (0x1020a05c, 0x10, 0x800, [0, 0x1000, 0, 0, 0, 0, 0, 0], [8]),
            (0x1020a17e, 0x60, 2, [0, 0, 0, 0, 0, 0, 0, 0x30], [0x10])):
        engine.u.mem_write(0x20068000, bytes(0x1000))
        engine.writes.clear()
        engine.call(entry - 0x10020000)
        require(engine.writes[-1] == (0x20068060, command), 'Input request differs')
        require((0x2006800c, logical) in engine.writes, 'Input channel disable differs')
        masks = [engine.word(0x20068200 + index * 32) for index in range(8)]
        require(masks == status, 'Stop interrupt enables differ')
        engine.u.mem_write(engine.DATA, struct.pack('<8I', *status))
        engine.u.mem_write(0xb180681c, struct.pack('<8I', *status))
        result = engine.call(0x1ea71a, 0, engine.DATA)
        require(result == logical, 'Physical-to-logical stop translation differs')
        engine.events.clear()
        engine.call(0x1ec0a8, 0, result)
        require(engine.events == events, 'Stop callback waiter events differ')
        cases.append(dict(entry=hex(entry), command=hex(command), logical=hex(logical),
                          status=[hex(value) for value in status],
                          waiter_events=[hex(value) for value in engine.events]))
    run_controls = []
    for selector, mask in ((0, 0x400), (1, 0x200), (2, 0x600)):
        writes = []
        for entry, register in ((0x10208f72, 0x20068008), (0x10208ff6, 0x2006800c)):
            engine.writes.clear()
            engine.call(entry - 0x10020000, 0, selector)
            require(engine.writes == [(register, mask)], 'Input run control differs')
            writes.append(dict(entry=hex(entry), register=hex(register), mask=hex(mask)))
        run_controls.append(dict(selector=selector, start=writes[0], disable=writes[1]))
    # Supply a synthetic registered cause group and two native DMA handle fields.
    # The original disable orchestrator, mask writer, decoder and callbacks execute.
    saved_group = bytes(engine.u.mem_read(0xb1806840, 36))
    synthetic_group = struct.pack('<9I', 0x10000000, *([0xffffffff] * 8))
    for address, value in ((0xb18096cc, engine.DATA + 0x1000),
                           (0xb18096d0, engine.DATA + 0x2000),
                           (engine.DATA + 0x1008, 0x20), (engine.DATA + 0x2008, 0x40)):
        engine.u.mem_write(address, struct.pack('<I', value))
    disable_cases = []
    for pending, physical, bank, bits, logical, callback in (
            (1, [1], 0, 0x200, 1, 0x10239524),
            (2, [4, 8], 0, 0xa000, 0xc, 0x10239298),
            (4, [0x800], 1, 0x800, 0x800, 0x102392be),
            (8, [0x10], 0, 0x80000000, 0x10, 0x10239480),
            (0x10, [0x20], 0, 0x20000, 0x40, 0x10239410),
            (0x20, [0x40], 0, 0x80000, 0x80, 0x102393ea),
            (0x40, [0x20], 0, 0x8000000, 0x20, 0x10239436),
            (0x100, [0x400], 1, 8, 0x400, 0x1023938c),
            (0x200, [0x200], 1, 0x80, 0x200, 0x1023931c)):
        engine.u.mem_write(0x20068000, bytes(0x1000))
        engine.u.mem_write(0xb26b38cc, struct.pack('<2I', 2, 1))
        engine.u.mem_write(0xb1806840, synthetic_group)
        engine.writes.clear()
        engine.call(0x1023c796 - 0x10020000, pending)
        engine.u.mem_write(0xb1806840, saved_group)
        disables = [value for address, value in engine.writes if address == 0x2006800c]
        require(disables == physical, 'Native soft disable operands differ')
        require(engine.word(0x20068200 + bank * 32) & bits == bits,
                'Native soft disable did not enable its completion causes')
        status = [0] * 8
        status[bank] = bits
        engine.u.mem_write(engine.DATA, struct.pack('<8I', *status))
        decoded = engine.call(0x1ead46, engine.DATA)
        require(decoded == logical, f'Disable cause routing differs: {pending:#x}, {decoded:#x}')
        engine.u.mem_write(0xb26b38c8, struct.pack('<I', pending))
        engine.task_events.clear()
        engine.call(callback - 0x10020000, 0x41072800, engine.DATA)
        require(engine.word(0xb26b38c8) == 0, 'Disable callback retained its pending bit')
        require(engine.task_events == [(0xb26b3888, 0x1000)], 'Disable completion task event differs')
        # Another outstanding channel must prevent aggregate completion.
        engine.u.mem_write(0xb26b38c8, struct.pack('<I', pending | 0x10000))
        engine.task_events.clear()
        engine.call(callback - 0x10020000, 0x41072800, engine.DATA)
        require(engine.word(0xb26b38c8) == 0x10000 and not engine.task_events,
                'Disable callback completed with another channel outstanding')
        disable_cases.append(dict(pending=hex(pending), physical=[hex(v) for v in physical],
            bank=bank, bits=hex(bits), logical=hex(logical), callback=hex(callback),
            task_event='0x1000', waits_for_other_channels=True))
    engine.u.mem_write(0xb1888168, struct.pack('<I', engine.RECORDER | 1))
    engine.notifications.clear()
    engine.call(0x10238d4a - 0x10020000, 0x1000)
    require(engine.notifications == [(0x041a0004, 0)], 'Disable task notification differs')
    # Logical input 0x80 has an independent end event, outside the aggregate
    # pending word above. The configured stream already enables bank 7 bit 3.
    engine.writes.clear()
    engine.call(0x1023c796 - 0x10020000, 0x80)
    require(engine.writes == [(0x2006800c, 2)], 'Independent disable operand differs')
    status = [0] * 8
    status[7] = 8
    engine.u.mem_write(engine.DATA, struct.pack('<8I', *status))
    require(engine.call(0x1ead46, engine.DATA) == 2, 'Independent disable routing differs')
    engine.task_events.clear()
    engine.call(0x102394dc - 0x10020000, 0x41072804, engine.DATA)
    require(engine.task_events == [(0xb26b3888, 0x20)], 'Independent disable event differs')
    engine.notifications.clear()
    engine.call(0x10238d4a - 0x10020000, 0x20)
    require(engine.notifications == [(0x041a0006, 0)], 'Independent disable notification differs')
    engine.task_events.clear()
    engine.call(0x1022e2e0 - 0x10020000, 0x041a0006, 0)
    require(engine.task_events == [(0xb25eeb78, 0x20)], 'Independent input task event differs')
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                decoder='0x1020a71a', callback='0x1020c0a8', cases=cases,
                run_controls=run_controls,
                disable_cases=disable_cases, disable_task_notification='0x041a0004',
                independent_disable=dict(pending='0x80', physical='0x2', bank=7, bits='0x8',
                    logical='0x2', callback='0x102394dc', interrupt_group=4,
                    low_task_event='0x20', notification='0x041a0006', input_task_event='0x20',
                    drain_handler='0x10235944', enable_mask_supplied_by_existing_configuration=True),
                limitations=['Synthetic memory and event API boundaries only.',
                             'Registered mask group and two DMA handle fields are synthetic.',
                             'No physical response latency or pixel transfer is established.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(stop_commands=len(report['cases']))))


if __name__ == '__main__':
    main()
