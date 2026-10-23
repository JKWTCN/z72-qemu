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
from collections import deque
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, digest, require

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
    def __init__(self, code_dump, ram_dump, aux_dump):
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
        from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_R0,
                                       UC_ARM_REG_R1, UC_ARM_REG_R2,
                                       UC_ARM_REG_R3, UC_ARM_REG_SP,
                                       UC_ARM_REG_LR, UC_ARM_REG_PC)
        self.regs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
        self.sp, self.lr, self.pc = UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
        self.u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.call_hooks = {}
        self.u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        for address, size in ((CODE_BASE, CODE_BYTES), (RAM_BASE, RAM_BYTES),
                              (0x04000000, 0x1000), (SCRATCH, 0x100000),
                              # Timer family and platform configuration
                              # spans read as RAM so the worker chain passes
                              # through them; only genuinely new windows
                              # surface in the unmapped log.
                              (0x2B000000, 0x4000), (0x2B200000, 0x1000),
                              (0x2A900000, 0x1000),
                              (0x20010000, 0x1000000),
                              (0x04200000, 0x100000),
                              (0x28000000, 0x1000), (0x2C000000, 0x200000),
                              (0xB6000000, 0x6000000)):
            self.u.mem_map(address, size)
        self.u.mem_write(CODE_BASE, code_dump)
        self.u.mem_write(RAM_BASE, ram_dump)
        if aux_dump:
            require(len(aux_dump) == 0x100000, 'Unexpected low-memory snapshot size')
            self.u.mem_map(0, 0x100000)
            self.u.mem_write(0, aux_dump)
        self.u.hook_add(UC_HOOK_CODE, lambda u, *a: u.emu_stop(),
                        begin=STOP, end=STOP)
        self.executed = []
        self.peripheral_access = []
        self.peripheral_tail = deque(maxlen=64)
        self.peripheral_access_count = 0
        self.unmapped = []
        from unicorn import (UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_READ,
                             UC_HOOK_MEM_WRITE)
        def entry(u, access, address, size, value):
            kind = {16: 'read', 17: 'write', 18: 'fetch',
                    19: 'read', 20: 'write', 21: 'fetch'}.get(access)
            return dict(kind=kind, address=hex(address), size=size,
                         pc=hex(u.reg_read(self.pc)),
                         value=None if kind == 'read' or value is None
                         else hex(value))
        def peripheral(u, access, address, size, value, unused):
            self.peripheral_access_count += 1
            record = entry(u, access, address, size, value)
            self.peripheral_tail.append(record)
            if len(self.peripheral_access) < 512:
                self.peripheral_access.append(record)
        def memory(u, access, address, size, value, unused):
            record = entry(u, access, address, size, value)
            if address in PERIPHERAL:
                peripheral(u, access, address, size, value, unused)
            self.unmapped.append(record)
            # Stop at missing memory; returning true without mapping it does
            # not supply a zero-valued device and obscures the original fault.
            return False
        self.u.hook_add(UC_HOOK_MEM_UNMAPPED, memory)
        self.u.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, peripheral,
                        begin=PERIPHERAL.start, end=PERIPHERAL.stop - 1)
        self.rtos = set()
        self.bus_guard_states = []
        def bus_guard(u, address, size, unused):
            context = u.reg_read(self.regs[0])
            # Do not read an absent window from the host hook: let the
            # original instruction produce the unmapped-access diagnostic.
            enabled = None if context == 0 and not aux_dump else struct.unpack(
                '<I', u.mem_read(context + 0x14, 4))[0]
            state = dict(context=hex(context), enabled=enabled)
            if state not in self.bus_guard_states:
                self.bus_guard_states.append(state)
        self.u.hook_add(UC_HOOK_CODE, bus_guard,
                        begin=BASE + 0x4F87F4, end=BASE + 0x4F87F4)

    def hook(self, offset, callback):
        from unicorn import UC_HOOK_CODE
        previous = self.call_hooks.pop(offset, None)
        if previous is not None:
            self.u.hook_del(previous)
        def wrapper(u, address, size, unused):
            callback(*(u.reg_read(r) for r in self.regs))
            u.reg_write(self.pc, u.reg_read(self.lr))
        self.call_hooks[offset] = self.u.hook_add(
            UC_HOOK_CODE, wrapper, begin=BASE + offset, end=BASE + offset)

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

    def install_svc_trap(self, response=None):
        # The RTOS API layer calls svc #6 with ip holding a packed service
        # id (Thumb wrappers jump into ARM thunks at 0xE4xxxx). Emulate the
        # trap: record the service, answer success and skip the call.
        from unicorn import UC_HOOK_INTR
        from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_IP
        self.services = []
        def trap(u, intno, unused):
            if intno not in (2, 6):
                raise RuntimeError('Unexpected trap ' + str(intno))
            pc = u.reg_read(UC_ARM_REG_PC)
            service = u.reg_read(UC_ARM_REG_IP)
            self.services.append(dict(pc=hex(pc), service=hex(service)))
            if response is not None:
                value = response(service, tuple(u.reg_read(r) for r in self.regs))
                if value is not None:
                    self.services[-1]['device_response'] = hex(value)
                    u.reg_write(UC_ARM_REG_R0, value)
                    return
            # Success by default; pointer-shaped answers come from a
            # per-service scratch slot so pointer-expecting callers do not
            # dereference zero.
            slot = SCRATCH + 0x50000 + (len(self.services) & 0xFF) * 0x40
            u.mem_write(slot, bytes(0x40))
            u.reg_write(UC_ARM_REG_R0, slot)
            # The trap exposes the instruction after SVC. Advancing again
            # skips the wrapper's LR restore and corrupts its return stack.
        self.u.hook_add(UC_HOOK_INTR, trap)

    def install_allocators(self):
        # Bump allocator over the top scratch half, mirroring the bounded
        # update probe's host heap; frees are validated against it.
        self.heap = SCRATCH + 0x80000
        self.heap_next = self.heap
        self.heap_end = SCRATCH + 0x100000
        self.heap_live = set()
        def allocate(size, *args):
            size = (size + 7) & ~7
            if self.heap_next + size > self.heap_end:
                self.result(0)
                return
            address = self.heap_next
            self.heap_next += size
            self.heap_live.add(address)
            self.u.mem_write(address, bytes(size))
            self.result(address)
        def release(address, *args):
            self.heap_live.discard(address)
        self.hook(0x32FE30, allocate)
        self.hook(0x32FE7E, release)

    def call(self, offset, *args, budget=2000000, stack=STACK):
        for register, value in zip(self.regs, args):
            self.u.reg_write(register, value)
        self.u.reg_write(self.sp, stack)
        if len(args) > 4:
            self.u.mem_write(stack, struct.pack('<' + 'I' * (len(args) - 4), *args[4:]))
        self.u.reg_write(self.lr, STOP | 1)
        return self.execute((BASE + offset) | 1, budget)

    def execute(self, start, budget):
        try:
            self.u.emu_start(start, STOP, count=budget)
        except Exception as error:
            reached = self.u.reg_read(self.pc)
            return dict(fault=str(error),
                        runtime_pc=hex(reached),
                        pc=hex(reached - BASE)
                        if BASE <= reached < CODE_BASE + CODE_BYTES else None)
        reached = self.u.reg_read(self.pc)
        return dict(returned=None if reached == STOP else 'stopped',
                    pc=hex(reached - BASE) if reached != STOP else None,
                    value=None if reached != STOP
                    else self.u.reg_read(self.regs[0]))


def run(args, worker_class=CardWorker, quiet=False):
    code_dump = Path(f'{args.ram_dump}.10000000').read_bytes()
    ram_dump = Path(f'{args.ram_dump}.B1800000').read_bytes()
    require(len(code_dump) == CODE_BYTES and len(ram_dump) == RAM_BYTES,
            'Unexpected RAM snapshot sizes')
    aux_dump = Path(f'{args.ram_dump}.0')
    if aux_dump.exists():
        aux = aux_dump.read_bytes()
    else:
        aux = b''
    probe = worker_class(code_dump, ram_dump, aux)
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
    probe.trace(0x4F811E)  # bus enable and readiness polling
    probe.trace(0x4F7212)  # readiness status read
    probe.trace(0x47FDB2)  # SD protocol initializer
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
            (0x340F12, probe.noop), (0x4C09FE, probe.noop),
            (0x3410CC, lambda *a: probe.result(0)),
            (0x3410D2, lambda *a: probe.result(0)),
            (0x3BC538, probe.noop), (0x39099C, probe.noop),
            (0x37FB8A, probe.noop), (0x3B3E3E, lambda *a: probe.result(0)),
            (0x3BC514, lambda *a: probe.result(0)),
            (0x3B58FA, lambda *a: probe.result(0))):
        probe.hook(offset, callback)
    probe.install_allocators()
    probe.install_svc_trap()
    flags = bytes(0x20 if 48 <= c <= 57 else 16 if 65 <= c <= 90
                  else 128 if 97 <= c <= 122 else 0 for c in range(256))
    probe.u.mem_write(SCRATCH + 0x1000, bytes(4) + flags)
    report = dict(format=2, passed=False,
                  snapshot=dict(code_sha256=digest(code_dump), ram_sha256=digest(ram_dump),
                                auxiliary_bytes=len(aux), auxiliary_sha256=digest(aux)),
                  enable_byte_address=hex(ENABLE_BYTE + 1),
                  enable_byte_before=probe.u.mem_read(ENABLE_BYTE + 1, 1)[0],
                  enable_byte_forced=1,
                  platform_configuration_overridden=args.capability_all)
    probe.u.mem_write(ENABLE_BYTE + 1, bytes((1,)))
    if args.sd_host:
        # Match the optional QEMU SD-host link prerequisites. This fixture
        # supplies no endpoint or card data and cannot establish readiness.
        probe.u.mem_write(0x2B200058, struct.pack('<I', 0x110000))
        probe.u.mem_write(0x2B000010, struct.pack('<I', 1 << 10))
        probe.u.mem_write(0x2A900098, struct.pack('<I', 2))
    report['sd_host_link_prerequisites_synthetic'] = args.sd_host
    import struct as _s
    if args.capability_all:
        # All-one configuration is a synthetic diagnostic fixture. Active-low
        # presence tests can interpret it as absence rather than readiness.
        probe.u.mem_write(0x04200000, bytes([0xFF]) * 0x100000)
    descriptors = []
    for index in range(3):
        entry = 0xB1808AC4 + index * 0x18
        words = _s.unpack('<6I', probe.u.mem_read(entry, 0x18))
        if words[0]:
            descriptors.append(words)
    # The table at 0xB1D28008 is a private handle table: uint16 count,
    # three pointers and three 32-byte objects. Descriptor records do not
    # belong there; the original open operation creates these objects.
    report['private_handle_count_before'] = _s.unpack(
        '<H', probe.u.mem_read(0xB1D28008, 2))[0]
    report['sd_context_before'] = dict(
        presence_slots=[hex(word) for word in _s.unpack(
            '<2I', probe.u.mem_read(0xB18019F4, 8))],
        bus_handle=hex(_s.unpack('<I', probe.u.mem_read(0xB18019A0, 4))[0]),
        low_memory_snapshot_mapped=bool(aux))
    require(len(descriptors) == 3, 'Requires the CF/SD/XQD module descriptor table')
    sd = descriptors[1]
    require(bytes(probe.u.mem_read(sd[0], 3)) == b'SD\0', 'Unexpected SD descriptor')
    sd_targets = [(word & ~1) - BASE for word in (sd[1], sd[2], sd[4], sd[5])]
    for offset in sd_targets:
        probe.trace(offset)
    report['sd_entries'] = [dict(runtime=hex(BASE + offset), member_offset=hex(offset),
                                 code_sha256=digest(bytes(probe.u.mem_read(BASE + offset, 32))))
                            for offset in sd_targets]
    experiments = []
    probe.full_trace()
    # Logical slot 1 selects SD, but its module-local controller index is
    # recovered by the original slot mapping helper rather than assumed.
    sd_index = probe.call(0x463212, 1)
    require(sd_index.get('value') is not None, 'Cannot resolve SD controller index')
    sd_index = sd_index['value']
    report['sd_logical_slot'] = 1
    report['sd_controller_index'] = sd_index
    entries = (
            ('sd_board_context_init', 0x47D8E4, ()),
            ('sd_bus_service_init', 0x4F7AE4, ()),
            ('sd_bus_power_on', 0x47E21C, ()),
            ('card_service_init', 0x4630B0, ()),
            ('configured_slot0', 0x4626A4, (0,)),
            ('query_local_slot0', 0x462A0E, (0, SCRATCH + 0x8000)),
            ('configured_slot1', 0x4626A4, (1,)),
            ('query_local_slot1', 0x462A0E, (1, SCRATCH + 0x8000)),
            ('sd_module_op0', sd_targets[0], (1,)),
            ('sd_module_op1', sd_targets[1], (1, sd_index, SCRATCH + 0x5100)),
            ('sd_module_op2', sd_targets[2], (1, SCRATCH + 0x5100)),
            ('sd_module_op3', sd_targets[3], (1, SCRATCH + 0x5100)),
            ('sd_protocol_init', 0x47FDB2, (sd_index, SCRATCH + 0x10000, 0x8000,
                                          SCRATCH + 0x20000, 0x1000, SCRATCH + 0x25000)))
    selected = set(args.experiment or [e[0] for e in entries])
    require(selected <= {e[0] for e in entries}, 'Unknown worker experiment')
    for label, offset, arguments in entries:
        if label not in selected:
            continue
        before_io = len(probe.peripheral_access)
        before_io_count = probe.peripheral_access_count
        before_path, before_services, before_entries = len(probe.path), len(probe.services), len(probe.executed)
        result = probe.call(offset, *arguments)
        import struct as _struct
        registry = list(_struct.unpack('<3I', probe.u.mem_read(0xB1D2800C, 12)))
        count = _struct.unpack('<H', probe.u.mem_read(0xB1D28008, 2))[0]
        entry = dict(handle_pointers=[hex(word) for word in registry], handle_count=count)
        path = probe.path[before_path:]
        io_count = probe.peripheral_access_count - before_io_count
        experiments.append(dict(
            experiment=label, entry=hex(offset), result=result,
            arguments=[hex(value) for value in arguments],
            sd_context=dict(presence_slots=[hex(word) for word in _s.unpack(
                '<2I', probe.u.mem_read(0xB18019F4, 8))],
                bus_handle=hex(_s.unpack('<I', probe.u.mem_read(0xB18019A0, 4))[0])),
            private_handles=entry,
            services=list(probe.services[before_services:]),
            executed=list(probe.executed[before_entries:]),
            path_length=len(path),
            path_tail=[hex(pc) for pc in path[-60:]],
            peripheral_access=probe.peripheral_access[before_io:],
            peripheral_access_count=io_count,
            peripheral_access_tail=list(probe.peripheral_tail)[-min(io_count, 64):]
                if io_count else [],
            unmapped_count=len(probe.unmapped)))
        if label.startswith('query_local_slot'):
            experiments[-1]['query_status'] = _s.unpack(
                '<I', probe.u.mem_read(SCRATCH + 0x8000, 4))[0]
        if result.get('fault'):
            break
    report['experiments'] = experiments
    report['peripheral_access_total'] = probe.peripheral_access
    report['unmapped_total'] = probe.unmapped[:200]
    report['peripheral_access_count'] = probe.peripheral_access_count
    report['peripheral_log_limit'] = 512
    report['passed'] = all(e['result'].get('value') == 0 for e in experiments)
    report['pass_condition'] = 'All selected entries returned zero; this does not establish card operation'
    report['rtos_responses_are_synthetic'] = True
    report['mapped_device_words_are_synthetic'] = True
    report['bus_guard_states'] = probe.bus_guard_states
    report['experiments_share_state'] = True
    args.destination.mkdir(parents=True, exist_ok=True)
    (args.destination / 'report.json').write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str) + '\n',
        encoding='utf-8')
    if not quiet:
        print(('PASS ' if report['passed'] else 'FAIL ') +
              f"card worker execution, peripheral accesses: "
              f"{len(probe.peripheral_access)}", flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ram-dump', required=True, type=Path,
                        help='memsave snapshot prefix from card_slot_probe')
    parser.add_argument('--capability-all', action='store_true',
                        help='Set platform configuration words to all ones (synthetic)')
    parser.add_argument('--sd-host', action='store_true',
                        help='Supply synthetic link prerequisites of the QEMU SD-host profile')
    parser.add_argument('--experiment', action='append',
                        help='Run a named worker entry; repeat to select multiple entries')
    parser.add_argument('--destination', required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments)


if __name__ == '__main__':
    main()
