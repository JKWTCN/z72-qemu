# SPDX-License-Identifier: GPL-2.0-or-later
"""Run bounded original update directory/member checks on local input files.

File I/O, cache maintenance, runtime memory/string primitives, ASCII flags,
locks and diagnostic logging are provided by the host. Member checks stop
before version-list formatting. GetProprietyCheck runs with a synthetic
snapshot. This probe does not activate menu dispatch, verify the whole-package
digest, or program storage. Firmware bytes stay local.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, digest, require, validate_master


class NativeUpdateProbe:
    PARSER_CONTEXT = 0xB25EBFA0
    UPDATE_STATE = 0xB1887C80
    MEMBER_STATE = 0xB25EC3A0
    SCRATCH = 0x51000000
    STACK = 0x500FF000
    STOP = 0x50000000

    def __init__(self, master, data, image_capacity=0x4000000):
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
        from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_R0,
                                       UC_ARM_REG_R1, UC_ARM_REG_R2,
                                       UC_ARM_REG_R3, UC_ARM_REG_SP,
                                       UC_ARM_REG_LR, UC_ARM_REG_PC)
        self.regs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
        self.sp, self.lr, self.pc = UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
        self.u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        for address, size in ((BASE, (len(master) + 4095) & ~4095),
                              (0xB1800000, 0x100000), (0xB25E0000, 0x20000),
                              (0xB23BC000, 0x2000),
                              (0x50000000, 0x100000), (self.SCRATCH, 0x100000)):
            self.u.mem_map(address, size)
        self.u.mem_write(BASE, master)
        self.u.hook_add(UC_HOOK_CODE, lambda u, *args: u.emu_stop(),
                        begin=self.STOP, end=self.STOP)
        self.executed = []
        for offset in (0x747048, 0x3D645A, 0x37AA82, 0x37AAA6,
                       0x3D9A2A, 0x3D8AE4):
            self.u.hook_add(UC_HOOK_CODE,
                            lambda u, address, size, unused: self.executed.append(hex(address - BASE)),
                            begin=BASE + offset, end=BASE + offset)
        self.data, self.position, self.io = data, 0, []
        self.put_word(self.UPDATE_STATE + 0x40, self.SCRATCH)
        # Explicit synthetic running-image descriptor, not a captured body state.
        self.put_word(0xB25EC0DC + 4, BASE)
        self.put_word(0xB25EC0DC + 0x10, image_capacity)
        # Provide the ASCII flags consumed by the original runtime callers.
        # Locale initialization is outside this bounded execution environment.
        self.put_word(self.SCRATCH + 0x1000, self.SCRATCH + 0x1100)
        flags = bytes(8 if 48 <= c <= 57 else 16 if 65 <= c <= 90
                      else 128 if 97 <= c <= 122 else 0 for c in range(256))
        self.u.mem_write(self.SCRATCH + 0x1100, flags)
        self.hooks = {
            0x4B3D90: self.seek, 0x4B3D82: self.read,
            0x340F44: self.copy, 0x340FAC: self.copy,
            0x341034: self.zero, 0x32FA28: self.noop,
            0x32F9EC: self.noop, 0x3802DA: self.upper,
            0x3D7144: self.ctype,
            # Single-thread snapshot reads need no host lock operation.
            0x340F18: self.noop, 0x340F12: self.noop,
            0x4C09FE: self.noop,
        }
        for offset, callback in self.hooks.items():
            def hook(u, address, size, unused, callback=callback):
                callback(*(u.reg_read(r) for r in self.regs))
                u.reg_write(self.pc, u.reg_read(self.lr))
            self.u.hook_add(UC_HOOK_CODE, hook, begin=BASE + offset, end=BASE + offset)

    def put_word(self, address, value):
        self.u.mem_write(address, struct.pack('<I', value))

    def word(self, address):
        return struct.unpack('<I', self.u.mem_read(address, 4))[0]

    def result(self, value):
        self.u.reg_write(self.regs[0], value)

    def noop(self, *args):
        pass

    def copy(self, target, source, size, unused):
        require(size <= 0x100000, 'Unexpected copy length')
        if size:
            self.u.mem_write(target, bytes(self.u.mem_read(source, size)))
        self.result(target)

    def zero(self, target, size, *args):
        require(size <= 0x100000, 'Unexpected zero length')
        if size:
            self.u.mem_write(target, bytes(size))
        self.result(target)

    def upper(self, value, *args):
        self.result(value - 32 if 97 <= value <= 122 else value)

    def ctype(self, *args):
        self.result(self.SCRATCH + 0x1000)

    def seek(self, handle, offset, whence, tell):
        offset = offset if offset < 0x80000000 else offset - 0x100000000
        require(whence in (0, 1, 2), 'Unexpected seek mode')
        position = (0, self.position, len(self.data))[whence] + offset
        self.io.append(dict(operation='seek', position=position))
        if position < 0:
            self.result(0)
            return
        self.position = position
        self.put_word(tell, position)
        self.result(1)

    def read(self, handle, request, count, actual):
        target, capacity = struct.unpack('<II', self.u.mem_read(request + 4, 8))
        require(count <= capacity and count <= 0x100000, 'Unexpected read length')
        block = self.data[self.position:self.position + count]
        self.io.append(dict(operation='read', position=self.position,
                            requested=count, actual=len(block)))
        if block:
            self.u.mem_write(target, block)
        self.position += len(block)
        self.put_word(actual, len(block))
        self.result(0x043A0080)

    def call(self, offset, *args, stop_offset=None):
        for register, value in zip(self.regs, args):
            self.u.reg_write(register, value)
        self.u.reg_write(self.sp, self.STACK)
        self.u.reg_write(self.lr, self.STOP | 1)
        stop = BASE + stop_offset if stop_offset is not None else self.STOP
        self.u.emu_start((BASE + offset) | 1, stop,
                         count=2000000, timeout=10000000)
        reached = self.u.reg_read(self.pc)
        require(reached in (stop, self.STOP),
                'Native execution did not return within its budget')
        if reached != self.STOP:
            return None
        require(self.u.reg_read(self.sp) == self.STACK, 'Native stack mismatch')
        return self.u.reg_read(self.regs[0])

    def parser(self):
        returned = self.call(0x38D340, 1, 0x20)
        return dict(returned=returned,
                    encoded_package_flag=self.u.mem_read(self.PARSER_CONTEXT + 8, 1)[0],
                    member_count=struct.unpack('<H', self.u.mem_read(
                        self.PARSER_CONTEXT + 0x2E, 2))[0], io=self.io)

    def member_checks(self):
        returned = self.call(0x37BC0E, 0, 1, stop_offset=0x37C100)
        return dict(returned=returned,
                    reached_version_list_formatting=returned is None,
                    encoded_package_flag=self.u.mem_read(self.PARSER_CONTEXT + 8, 1)[0],
                    member_mask=self.word(self.MEMBER_STATE + 0x78),
                    io=self.io)

    def propriety(self, snapshot):
        require(len(snapshot) == 0x50, 'Expected 80-byte runtime snapshot')
        # Original snapshot getter reads this global while holding its lock.
        self.u.mem_write(0xB23BCCF0 + 0xAC, snapshot)
        output = self.SCRATCH + 0x2000
        returned = self.call(0x747048, 0, 0, output)
        return dict(service_return=returned, reason=self.word(output),
                    executed_entries=self.executed)


def propriety_suite(master):
    baseline = bytearray(0x50)
    struct.pack_into('<I', baseline, 0, 1)
    baseline[4] = 1
    cases = [('baseline', {}, 1, 0), ('snapshot_absent', {0: 0}, 3, 1),
             ('source_zero', {4: 0}, 3, 1), ('source_five', {4: 5}, 3, 1),
             ('level_one', {0xB: 1}, 1, 0), ('level_two', {0xB: 2}, 3, 1),
             ('second_level_two', {7: 1, 0x23: 2}, 3, 1),
             ('third_level_two', {7: 2, 0x3B: 2}, 3, 1)]
    cases.extend((f'flag_{offset:x}', {offset: 1}, 3, 1)
                 for offset in (8, 0x20, 0x38))
    results = []
    for label, edits, returned, reason in cases:
        snapshot = bytearray(baseline)
        for offset, value in edits.items():
            snapshot[offset] = value
        result = NativeUpdateProbe(master, b'').propriety(bytes(snapshot))
        require(result['service_return'] == returned and result['reason'] == reason and
                result['executed_entries'][:3] == ['0x747048', '0x3d645a', '0x37aa82'] and
                '0x3d9a2a' in result['executed_entries'],
                'Unexpected propriety result: ' + label)
        results.append(dict(case=label, snapshot_edits={hex(k): v for k, v in edits.items()},
                            **result))
    return dict(scope='Original GetProprietyCheck and snapshot predicates; synthetic runtime snapshot',
                baseline=dict(valid_word=1, source_byte=1, other_bytes=0),
                snapshot_getter_executed=True, locks_and_diagnostic_logger_skipped=True,
                cases=results)


def run_suite(master, package, candidate=None):
    validate_master(master)
    require(digest(package) ==
            'fc0e94f57500a1f0e287c6b9a036c81a5ffceccb8432a377d645b3fa35a19b6a',
            'Requires stock Z7 II C 1.70 update package')

    def flipped(offset):
        changed = bytearray(package)
        changed[offset] ^= 1
        return bytes(changed)

    cases = [
        ('stock_package', package, 0x4000000, 1, None, 31),
        ('bare_master', master, 0x4000000, 0, 12, 0),
        ('truncated_before_directory', package[:64], 0x4000000, 0, 12, 0),
        ('changed_outer_digest', flipped(0), 0x4000000, 1, None, 31),
        ('changed_last_member_crc', flipped(len(package) - 17), 0x4000000, 1, None, 31),
        ('capacity_equal_master_length', package, len(master), 1, 11, 29),
        # First member length is big-endian at body +0x44, file +0x64.
        ('invalid_ex_member_length', flipped(0x67), 0x4000000, 1, 11, 12),
    ]
    if candidate is not None:
        cases.append(('local_candidate', candidate, 0x4000000, 1, None, 31))
    results = []
    for label, data, capacity, expected_parser, expected_return, expected_mask in cases:
        parser = NativeUpdateProbe(master, data, capacity).parser()
        checks = NativeUpdateProbe(master, data, capacity).member_checks()
        require(parser['returned'] == expected_parser and
                checks['returned'] == expected_return and
                checks['member_mask'] == expected_mask,
                f'Unexpected native result: {label}: parser={parser["returned"]}, '
                f'member_return={checks["returned"]}, mask={checks["member_mask"]}')
        results.append(dict(case=label, input_sha256=digest(data), length=len(data),
                            image_capacity=capacity, parser=parser,
                            member_checks=checks))
    return dict(master_sha256=digest(master), cases=results,
                propriety=propriety_suite(master),
                environment=dict(running_image='supplied stock master; zero platform tag',
                                 character_classification='host ASCII flags',
                                 other_runtime_ram='zero initialized'),
                scope='Original directory parser and member checks, stopping before version-list formatting',
                whole_package_digest_verified=False, menu_dispatch_executed=False,
                native_service_methods_executed=['GetProprietyCheck'],
                storage_programmed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--stock-package', type=Path, required=True)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    require(not args.report.exists(), 'Report already exists')
    master, package = args.master.read_bytes(), args.stock_package.read_bytes()
    candidate = args.candidate.read_bytes() if args.candidate else None
    report = run_suite(master, package, candidate)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    for case in report['cases']:
        print(case['case'], 'parser=', case['parser']['returned'],
              'member_return=', case['member_checks']['returned'],
              'member_mask=', case['member_checks']['member_mask'])


if __name__ == '__main__':
    main()
