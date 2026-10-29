# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original context consumer masks, pending queues and derived flags."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class ContextProbe(RegionProbe):
    def boundary(self, u, address, size, unused):
        if address in (0x10360f2e, 0x10360f12, 0x10350d86, 0x1034ffbe):
            # Uncontended lock, inactive query flags and zero setting value.
            u.reg_write(UC_ARM_REG_R0, int(address == 0x10360f2e))
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(u, address, size, unused)


class PendingProbe(ContextProbe):
    RECORDER = RegionProbe.DATA + 0x1000

    def __init__(self, image):
        super().__init__(image)
        self.events = []

    def boundary(self, u, address, size, unused):
        if address == self.RECORDER:
            payload = u.reg_read(UC_ARM_REG_R1)
            self.events.append(dict(notification=hex(u.reg_read(UC_ARM_REG_R0)),
                status=bytes(u.mem_read(payload, 1))[0], context=hex(self.word(payload + 8))))
            u.reg_write(UC_ARM_REG_R0, 0)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(u, address, size, unused)


def pending_contract(image):
    engine = PendingProbe(image)
    queues = (0xb25eeba4, 0xb25eebc4, 0xb25eebe4, 0xb25eec04)
    contexts = [engine.DATA + 0x200 + index * 0x200 for index in range(2)]
    nodes = [engine.DATA + 0x4000 + index * 12 for index in range(2)]
    engine.u.mem_write(0xb1887e80, struct.pack('<I', engine.RECORDER | 1))
    cases = []
    for queue in queues:
        for mask in (0x40000, 1, 0x40001):
            for address in queues:
                engine.call(0x32fa90, address)
            for index, context in enumerate(contexts):
                engine.u.mem_write(context, bytes(0x150))
                engine.u.mem_write(context + 0xc, b'\x01')
                engine.u.mem_write(context + 0x14c, struct.pack('<I', 0x40001))
                engine.u.mem_write(nodes[index], struct.pack('<3I',
                    nodes[1 - index], nodes[1 - index], context))
            engine.u.mem_write(queue, struct.pack('<5I', nodes[0], nodes[1], 2, 2, nodes[0]))
            engine.events.clear()
            engine.call(0x2100b0, mask)
            pending = [engine.word(context + 0x14c) for context in contexts]
            completed = queue == 0xb25eec04 and mask == 0x40001
            expected = [dict(notification='0x41a0008', status=0, context=hex(context))
                        for context in reversed(contexts)] if completed else []
            require(pending == [0x40001 & ~mask] * 2 and engine.events == expected,
                    'Original pending-mask clear or completion differs')
            require(engine.word(queue + 8) == (0 if completed else 2),
                    'Original pending queue removal differs')
            cases.append(dict(queue=hex(queue), clear_mask=hex(mask), initial_pending='0x40001',
                pending=[hex(value) for value in pending], remaining=engine.word(queue + 8),
                events=list(engine.events)))
    return dict(entry='0x102300b0', cases=cases, native_list_operations=True,
                host_boundaries=['uncontended lock/unlock', 'record completion callback'],
                limitation='Synthetic queues and context masks; no DMA or hardware completion is supplied.')


def probe(image):
    engine = ContextProbe(image)
    context = engine.DATA
    engine.u.mem_write(context + 12, b'\x03')
    releases = []
    for mask, expected in ((1, 2), (2, 0), (2, 0)):
        result = engine.call(0x30a792, context, mask)
        value = bytes(engine.u.mem_read(context + 12, 1))[0]
        require(result == expected and value == expected, 'Consumer mask release differs')
        releases.append(dict(mask=hex(mask), remaining=hex(value)))
    root = 0xb1868af0
    engine.u.mem_write(root + 6, b'\x01')
    engine.u.mem_write(root + 0xa4, struct.pack('<2I', 0, 2))
    flags = []
    for expected_flag, expected_count, expected_state in ((1, 1, 1), (1, 2, 1), (0, 2, 2)):
        engine.call(0x304f04, context + 8)
        flag = engine.word(context + 0x40)
        count = engine.word(root + 0xa4)
        state = bytes(engine.u.mem_read(root + 6, 1))[0]
        require((flag, count, state) == (expected_flag, expected_count, expected_state),
                'Counter-derived context flag differs')
        flags.append(dict(field_40=flag, counter=count, state_6=state))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                release_entry='0x1032a792', consumer_offset='0xc', releases=releases,
                header_entry='0x10324f04', caller_argument='context + 8', flags=flags,
                pending_clear=pending_contract(image),
                limitations=['Synthetic context, driver counters, query results and uncontended locks.',
                             'These fields alone do not identify a display request or pixel-processing job.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(releases=len(report['releases']), flags=len(report['flags']),
                          pending_cases=len(report['pending_clear']['cases']))))


if __name__ == '__main__':
    main()
