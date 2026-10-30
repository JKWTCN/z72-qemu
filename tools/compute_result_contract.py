# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original compute-result filtering and downstream parameter selection."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP,
                              UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg


def check(image):
    structure = analyze_eg(image, 'slave')
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(BASE, (len(image) + 4095) & ~4095)
    cpu.mem_write(BASE, image)
    cpu.mem_map(0x50000000, 0x10000)
    context, parameters, output = 0x50001000, 0x50002000, 0x50003000
    capture, nested = 0x50004000, 0x50005000
    selector, metadata, selected = 0x50006000, 0x50007000, 0x50008000
    stop = 0x5000f000
    configuration = [0] * 9
    config_calls = []

    def put(address, *values):
        cpu.mem_write(address, struct.pack('<' + 'I' * len(values), *values))

    def words(address, count):
        return list(struct.unpack('<' + 'I' * count, cpu.mem_read(address, count * 4)))

    def boundary(uc, address, size, unused):
        if address == 0x10161e5a:
            config_calls.append(address)
            put(uc.reg_read(UC_ARM_REG_R1), *configuration)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, boundary)

    def call(address, first, second=0):
        cpu.reg_write(UC_ARM_REG_R0, first)
        cpu.reg_write(UC_ARM_REG_R1, second)
        cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
        cpu.reg_write(UC_ARM_REG_LR, stop | 1)
        cpu.emu_start(address | 1, stop, count=10000)
        require(cpu.reg_read(UC_ARM_REG_PC) == stop, 'Original result routine did not return')

    put(context + 0xc, capture, output)
    put(capture + 0x4f4, nested)
    put(nested + 0x134, 0, 0)
    put(selector + 0xc, metadata, output, 0, selected)
    thresholds = list(struct.unpack('<2H', cpu.mem_read(0x101eec34, 4)))
    require(thresholds == [5, 5], 'Result thresholds changed')
    # Every native metadata mode uses the result-driven selection branch here.
    overrides = bytes(cpu.mem_read(0x10238400, 52))
    require(not any(overrides), 'Metadata selection overrides changed')
    cases = []
    fixtures = [
        ('all-below', [5, 5, 5], [0, 0, 0], [0] * 9, [5, 5, 5], 0),
        ('first', [6, 5, 5], [0, 0, 0], [0] * 9, [6, 5, 5], 1),
        ('second', [9, 6, 5], [0, 0, 0], [0] * 9, [9, 6, 5], 2),
        ('third', [9, 6, 6], [0, 0, 0], [0] * 9, [9, 6, 6], 3),
        ('third-alone', [0, 0, 6], [0, 0, 0], [0] * 9, [0, 0, 6], 3),
        ('third-rule-filters-both', [9, 10, 10], [10, 10, 10],
         [1, 1000, 1024, 2, 0, 0, 0, 0, 0], [9, 0, 0], 1),
        ('filter-second', [9, 10, 5], [10, 10, 5],
         [0, 0, 0, 0, 1, 1000, 1024, 2, 2], [9, 0, 5], 1),
        ('filter-both', [9, 10, 10], [10, 10, 10],
         [1, 1000, 1024, 2, 1, 1000, 1024, 2, 2], [9, 0, 0], 1),
    ]
    for name, first, second, configuration, expected, category in fixtures:
        put(parameters + 0x594, *first, *second)
        put(output, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)
        call(0x1011e75a, context, parameters)
        actual = words(output, 3)
        require(actual == expected, 'Original result filtering differs: ' + name + repr(actual))
        # The caller stores these bounded values as halfwords before selection.
        cpu.mem_write(output, struct.pack('<3H', *actual))
        categories = []
        for mode in range(26):
            cpu.mem_write(metadata, bytes([mode]))
            cpu.mem_write(selector + 0x15, b'\xff')
            call(0x10148ff2, selector)
            value = cpu.mem_read(selector + 0x15, 1)[0]
            require(value == category, 'Original downstream category differs: ' + name)
            categories.append(value)
        cases.append(dict(name=name, first_pass=first, second_pass=second,
                          supplied_configuration=configuration, filtered=actual,
                          categories_by_metadata_mode=categories))
    require(len(config_calls) == len(fixtures), 'Configuration boundary count differs')
    return dict(format=1, result='passed', firmware_included=False,
        slave_sha256=structure['sha256'], thresholds=thresholds, cases=cases,
        entries=dict(filter='0x1011e75a', selector='0x10148ff2'),
        host_boundaries=['Synthetic contexts, result triples and nine configuration words',
                         'Configuration lookup 0x10161e5a returns supplied words'],
        limitations=['No compute program or RAW input algorithm is executed',
                     'Synthetic result triples do not establish physical units or their producer',
                     'No whole-machine reply, encoding or photograph is produced'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.slave.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original two-pass result filtering and downstream category selection')
