# SPDX-License-Identifier: GPL-2.0-or-later
"""Trace original persistent configuration copying and the still-compute gate."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R4, UC_ARM_REG_SP,
                              UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg


def machine(image):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(BASE, (len(image) + 4095) & ~4095)
    cpu.mem_write(BASE, image)
    cpu.mem_map(0x50000000, 0x10000)
    return cpu


def check(master, slave):
    master_info = analyze_eg(master, 'master')
    slave_info = analyze_eg(slave, 'slave')
    source = machine(master)
    source.mem_map(0xb20d2000, 0x21000)
    source.mem_map(0xb20cf000, 0x1000)
    target = machine(slave)
    # The taken path stops at the real calculation entry, before execution.
    def stop_at_request(cpu, address, size, unused):
        if address == 0x1011ef16:
            cpu.emu_stop()
    target.hook_add(UC_HOOK_CODE, stop_at_request)
    ids = [0x41b, 0x41c, None, 0x2a0, 0x2a1, 0x351, 0x350,
           0x415, 0x428, 0x429, 0x412, 0x425, 0x41e, 0x111]
    cache, copied = 0xb20d2894, 0x50001000
    capture, nested = 0x50002000, 0x50003000
    target.mem_map(0xc16be000, 0x1000)
    locks = []

    def lock_boundary(cpu, address, size, unused):
        if address in (0x10360f18, 0x10360f12):
            locks.append(dict(entry=hex(address), object=hex(cpu.reg_read(UC_ARM_REG_R0))))
            cpu.reg_write(UC_ARM_REG_R0, 1)
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))

    source.hook_add(UC_HOOK_CODE, lock_boundary)
    default_address, default_size = 0x118b02ac, 0x1fffc
    defaults = master[default_address - BASE:default_address - BASE + default_size]
    source.mem_write(cache - 1, b'\xa5' * (default_size + 2))
    source.reg_write(UC_ARM_REG_SP, 0x5000e000)
    source.reg_write(UC_ARM_REG_LR, 0x5000f001)
    # Run the original initializer, memory copy and derived-cache refresh.
    # Only its two mutex calls are supplied by this isolated environment.
    source.emu_start(0x103c0a65, 0x5000f000, count=500000)
    require(source.reg_read(UC_ARM_REG_PC) == 0x5000f000 and
            source.reg_read(UC_ARM_REG_R0) == 1, 'Default initialization did not return')
    require(bytes(source.mem_read(cache, default_size)) == defaults,
            'Native object-8 defaults differ from the original ROM table')
    require(source.mem_read(cache - 1, 1) == b'\xa5' and
            source.mem_read(cache + default_size, 1) == b'\xa5',
            'Default initialization crossed cache guards')
    require([row['entry'] for row in locks] == ['0x10360f18', '0x10360f12'],
            'Unexpected default-refresh lock boundaries')
    require(defaults[0x2a1] == 0, 'Original compute default changed')
    default_report = dict(initializer='0x103c0a64', source=hex(default_address),
        bytes=default_size, sha256=hashlib.sha256(defaults).hexdigest(),
        copy_and_refresh_executed=True, returned=1, cache_guards_preserved=True,
        mutex_boundaries=locks, cache_2a1=defaults[0x2a1])
    cases = []
    for fixture, value in [('firmware_defaults', defaults[0x2a1]),
                           *[('synthetic', value) for value in (0, 1, 2, 3, 255)]]:
        if fixture == 'synthetic':
            for index in ids:
                if index is not None:
                    source.mem_write(cache + index, bytes([index & 255]))
            source.mem_write(cache + 0x2a1, bytes([value]))
        source.mem_write(copied - 1, bytes([0xa5]) * 16)
        source.reg_write(UC_ARM_REG_R0, copied)
        source.reg_write(UC_ARM_REG_SP, 0x5000e000)
        source.reg_write(UC_ARM_REG_LR, 0x5000f001)
        source.emu_start(0x103603d9, 0x5000f000, count=1000)
        require(source.reg_read(UC_ARM_REG_PC) == 0x5000f000 and
                source.reg_read(UC_ARM_REG_R0) == 1, 'Native configuration copy did not return')
        data = bytes(source.mem_read(copied, 14))
        expected = [0 if index is None else defaults[index] for index in ids]
        if fixture == 'synthetic':
            expected = [0 if index is None else value if index == 0x2a1 else index & 255
                        for index in ids]
        require(list(data) == expected, 'Native configuration offsets differ')
        require(source.mem_read(copied - 1, 1) == b'\xa5' and
                source.mem_read(copied + 14, 1) == b'\xa5', 'Configuration copy crossed guards')
        target.mem_write(capture + 0x4f4, struct.pack('<I', nested))
        target.mem_write(nested + 0x2b78, data)
        target.mem_write(nested + 0x1e08, b'\xa5' * 6)
        target.reg_write(UC_ARM_REG_R4, capture)
        target.reg_write(UC_ARM_REG_SP, 0x5000e000)
        target.emu_start(0x1012c649, 0x1012c6d2, count=1000)
        pc = target.reg_read(UC_ARM_REG_PC)
        requested = pc == 0x1011ef16
        require(requested == (value != 2), 'Native compute gate condition differs')
        output = bytes(target.mem_read(nested + 0x1e08, 6))
        require(output == (b'\xa5' * 6 if requested else bytes(6)),
                'Native skipped-path result clearing differs')
        cases.append(dict(fixture=fixture, cache_2a1=value, copied_bytes=list(data),
                          nested_2b7c=data[4], calculation_requested=requested,
                          stopped_pc=hex(pc), result_halfwords=list(struct.unpack('<3H', output))))
    return dict(format=1, result='passed', firmware_included=False,
        master_sha256=master_info['sha256'], slave_sha256=slave_info['sha256'],
        copy_entry='0x103603d8', reader_entry='0x103c09e8', cache_base=hex(cache),
        destination_offset='0x2b78', copied_indices=ids, default_initialization=default_report,
        cases=cases,
        host_boundaries=['Default-refresh mutex wrappers return success',
                         'Synthetic object-8 cache bytes for non-default cases and capture context',
                         'Enter gate at 0x1012c648 after earlier stage preconditions',
                         'Stop requested calculation at 0x1011ef16 before it executes'],
        limitations=['No persistent configuration is changed in the whole machine',
                     'ROM defaults do not establish the contents of a particular camera',
                     'Value 2 is a native branch condition, not a verified supported user setting',
                     'No compute result algorithm, encoding or photograph is executed'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.master.read_bytes(), args.slave.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original persistent configuration copy and exact still-compute gate')
