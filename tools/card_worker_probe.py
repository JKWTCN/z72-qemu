# SPDX-License-Identifier: GPL-2.0-or-later
"""Run original card slot worker code on a captured machine RAM snapshot.

The card slot driver table registers at runtime (see card_slot_probe.py),
so the worker chain below the slot operations cannot be studied from the
image alone. This probe loads a machine RAM snapshot (the two memsave
regions), forces the slot enable byte and runs the original slot worker
entry points with instruction hooks. Every access outside the mapped
snapshot is recorded: the SD host controller register window shows up as
a cluster of unmapped peripheral accesses. The probe reads state and
never writes firmware files.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require

CODE_BASE = 0x10000000
CODE_BYTES = 0x4000000
RAM_BASE = 0xB1800000
RAM_BYTES = 0x4800000
SCRATCH = 0x50000000
STACK = 0x500F0000
STOP = 0x50000000
ENABLE_BYTE = 0xB1808B50
PERIPHERAL = range(0x20000000, 0x30000000)


class CardWorker:
    def __init__(self, code_dump, ram_dump):
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
        from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_R0,
                                       UC_ARM_REG_R1, UC_ARM_REG_R2,
                                       UC_ARM_REG_R3, UC_ARM_REG_SP,
                                       UC_ARM_REG_LR, UC_ARM_REG_PC)
        self.regs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
        self.sp, self.lr, self.pc = UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
        self.u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        for address, size in ((CODE_BASE, CODE_BYTES), (RAM_BASE, RAM_BYTES),
                              (0x04000000, 0x1000), (SCRATCH, 0x100000),
                              # Timer family and platform configuration
                              # spans read as RAM so the worker chain passes
                              # through them; only genuinely new windows
                              # surface in the unmapped log.
                              (0x2B000000, 0x4000), (0x20010000, 0x1000000),
                              (0x04200000, 0x100000),
                              (0x28000000, 0x1000), (0x2C000000, 0x200000),
                              (0xB6000000, 0x6000000)):
            self.u.mem_map(address, size)
        self.u.mem_write(CODE_BASE, code_dump)
        self.u.mem_write(RAM_BASE, ram_dump)
        self.u.hook_add(UC_HOOK_CODE, lambda u, *a: u.emu_stop(),
                        begin=STOP, end=STOP)
        self.executed = []
        self.peripheral_access = []
        self.unmapped = []
        from unicorn import (UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_READ,
                             UC_HOOK_MEM_WRITE)
        def memory(u, access, address, size, value, unused):
            kind = {16: 'read', 17: 'write', 18: 'fetch',
                    19: 'read', 20: 'write', 21: 'fetch'}.get(access)
            entry = dict(kind=kind, address=hex(address), size=size,
                         value=None if kind == 'read' or value is None
                         else hex(value))
            if address in PERIPHERAL:
                self.peripheral_access.append(entry)
            else:
                self.unmapped.append(entry)
            # Every unmapped read returns zero and writes are absorbed, so
            # the original chain keeps running past missing devices.
            return True
        self.u.hook_add(UC_HOOK_MEM_UNMAPPED, memory)
        self.rtos = set()

    def hook(self, offset, callback):
        from unicorn import UC_HOOK_CODE
        def wrapper(u, address, size, unused):
            callback(*(u.reg_read(r) for r in self.regs))
            u.reg_write(self.pc, u.reg_read(self.lr))
        self.u.hook_add(UC_HOOK_CODE, wrapper, begin=BASE + offset,
                        end=BASE + offset)

    def full_trace(self, limit=0x800000):
        from unicorn import UC_HOOK_CODE
        self.path = []
        self.u.hook_add(UC_HOOK_CODE,
                        lambda u, address, size, unused:
                            self.path.append(address - BASE),
                        begin=BASE, end=BASE + limit)

    def trace(self, offset):
        from unicorn import UC_HOOK_CODE
        self.u.hook_add(UC_HOOK_CODE,
                        lambda u, address, size, unused:
                            self.executed.append(hex(address - BASE)),
                        begin=BASE + offset, end=BASE + offset)

    def result(self, value):
        self.u.reg_write(self.regs[0], value)

    def noop(self, *args):
        pass

    def copy(self, target, source, size, unused):
        if size:
            self.u.mem_write(target,
                             bytes(self.u.mem_read(source, size)))
        self.result(target)

    def zero(self, target, size, *args):
        if size:
            self.u.mem_write(target, bytes(size))
        self.result(target)

    def upper(self, value, *args):
        self.result(value - 32 if 97 <= value <= 122 else value)

    def ctype(self, *args):
        self.result(SCRATCH + 0x1000)

    def call(self, offset, *args, budget=2000000):
        for register, value in zip(self.regs, args):
            self.u.reg_write(register, value)
        self.u.reg_write(self.sp, STACK)
        self.u.reg_write(self.lr, STOP | 1)
        try:
            self.u.emu_start((BASE + offset) | 1, STOP, count=budget)
        except Exception as error:
            return dict(fault=str(error),
                        pc=hex(self.u.reg_read(self.pc) - BASE))
        reached = self.u.reg_read(self.pc)
        return dict(returned=None if reached == STOP else 'stopped',
                    pc=hex(reached - BASE) if reached != STOP else None,
                    value=None if reached != STOP
                    else self.u.reg_read(self.regs[0]))


def run(args):
    code_dump = Path(f'{args.ram_dump}.10000000').read_bytes()
    ram_dump = Path(f'{args.ram_dump}.B1800000').read_bytes()
    require(len(code_dump) == CODE_BYTES and len(ram_dump) == RAM_BYTES,
            'Unexpected RAM snapshot sizes')
    probe = CardWorker(code_dump, ram_dump)
    # Card worker entries from the captured slot table and the query path.
    probe.trace(0x4626A4)   # configured predicate (slot 0)
    probe.trace(0x4622CC)
    probe.trace(0x4626DC)
    probe.trace(0x462240)
    probe.trace(0x4620EC)
    probe.trace(0x4620FA)
    probe.trace(0x462A0E)
    probe.trace(0x4628FC)
    probe.trace(0x463222)
    probe.trace(0x4631F2)
    probe.trace(0x463212)
    probe.trace(0x461BEA)
    probe.trace(0x462676)
    probe.trace(0x481594)
    # Unlock/release entries are RTOS boundaries; the lock-and-fetch
    # entry 0x481594 must run natively because it also returns the slot
    # object pointer. The runtime memory/lock/string primitives use the
    # same boundary set as the bounded update probe.
    probe.hook(0x4815FC, lambda *a: None)
    probe.hook(0x48174A, lambda *a: None)
    for offset, callback in (
            (0x340F44, probe.copy), (0x340FAC, probe.copy),
            (0x341034, probe.zero), (0x32FA28, probe.noop),
            (0x32F9EC, probe.noop), (0x3802DA, probe.upper),
            (0x3D7144, probe.ctype), (0x340F18, probe.noop),
            (0x340F12, probe.noop), (0x4C09FE, probe.noop)):
        probe.hook(offset, callback)
    flags = bytes(0x20 if 48 <= c <= 57 else 16 if 65 <= c <= 90
                  else 128 if 97 <= c <= 122 else 0 for c in range(256))
    probe.u.mem_write(SCRATCH + 0x1000, bytes(4) + flags)
    report = dict(format=1, passed=False,
                  snapshot=str(args.ram_dump),
                  enable_byte_before=probe.u.mem_read(ENABLE_BYTE, 1)[0])
    probe.u.mem_write(ENABLE_BYTE, bytes((1,)))
    import struct as _s
    if args.capability_all:
        # Present every platform capability bit so the driver chain does
        # not exit early; the real machine registers these as device words.
        probe.u.mem_write(0x04200000, bytes([0xFF]) * 0x100000)
    descriptors = []
    for index in range(3):
        entry = 0xB1808AC4 + index * 0x18
        words = _s.unpack('<6I', probe.u.mem_read(entry, 0x18))
        if words[0]:
            descriptors.append(words)
    registry_entries = []
    struct_base = SCRATCH + 0x2000
    for index, words in enumerate(descriptors):
        module = struct_base + index * 0x40
        obj = 0xB1D28018 + index * 0x20
        name = SCRATCH + 0x4000 + index * 8
        probe.u.mem_write(name, b'MOD' + bytes((48 + index,)) + bytes(4))
        record = _s.pack('<HHIIIIIIII', index, index, name, 0, 0,
                         words[1], words[2], words[3], words[4], words[5])
        probe.u.mem_write(module, record)
        probe.u.mem_write(obj, record)
        probe.u.mem_write(0xB1D28008 + index * 4,
                          _s.pack('<I', module))
        registry_entries.append(dict(module=index,
                                     struct=hex(module), object=hex(obj)))
    probe.u.mem_write(0xB1D28078, _s.pack('<H', len(descriptors)))
    report['synthesized_registry'] = registry_entries
    experiments = []
    probe.full_trace()
    for label, offset, arguments in (
            ('configured_slot0', 0x4626A4, (0,)),
            ('query_local_slot0', 0x462A0E, (0, SCRATCH + 0x8000)),
            ('configured_slot1', 0x4626A4, (1,)),
            ('query_local_slot1', 0x462A0E, (1, SCRATCH + 0x8000)),
            ('sd_module_op0', 0x481C70, (SCRATCH + 0x5000, SCRATCH + 0x5100,
                                          0, 0)),
            ('sd_module_op1', 0x481E30, (SCRATCH + 0x5000, SCRATCH + 0x5100,
                                          0, 0)),
            ('sd_module_op2', 0x481F06, (SCRATCH + 0x5000, SCRATCH + 0x5100,
                                          0, 0)),
            ('sd_module_op3', 0x482016, (SCRATCH + 0x5000, SCRATCH + 0x5100,
                                          0, 0))):
        before_io = len(probe.peripheral_access)
        result = probe.call(offset, *arguments)
        import struct as _struct
        registry = list(_struct.unpack('<3I', probe.u.mem_read(0xB1D28008, 12)))
        count = _struct.unpack('<H', probe.u.mem_read(0xB1D28078, 2))[0]
        entry = dict(module_registry=[hex(word) for word in registry],
                     module_count=count)
        path = getattr(probe, 'path', [])
        experiments.append(dict(
            experiment=label, entry=hex(offset), result=result,
            registry=entry,
            executed=probe.executed,
            path_length=len(path),
            path_tail=[hex(pc) for pc in path[-60:]],
            peripheral_access=probe.peripheral_access[before_io:],
            unmapped_count=len(probe.unmapped)))
        if result.get('fault'):
            break
    report['experiments'] = experiments
    report['peripheral_access_total'] = probe.peripheral_access
    report['unmapped_total'] = probe.unmapped[:200]
    report['passed'] = bool(probe.peripheral_access) or all(
        e['result'].get('returned') == 'stopped' or e['result'].get('value') is not None
        for e in experiments)
    args.destination.mkdir(parents=True, exist_ok=True)
    (args.destination / 'report.json').write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str) + '\n',
        encoding='utf-8')
    print(('PASS ' if report['passed'] else 'FAIL ') +
          f"card worker execution, peripheral accesses: "
          f"{len(probe.peripheral_access)}", flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ram-dump', required=True, type=Path,
                        help='memsave snapshot prefix from card_slot_probe')
    parser.add_argument('--capability-all', action='store_true',
                        help='Set all platform capability bits to present')
    parser.add_argument('--destination', required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments)


if __name__ == '__main__':
    main()
