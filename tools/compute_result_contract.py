# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original compute-result filtering and downstream parameter selection."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP,
                              UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg, scatter_records


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
    preparation_queries, translations, maintenance = [], [], []

    def put(address, *values):
        cpu.mem_write(address, struct.pack('<' + 'I' * len(values), *values))

    def words(address, count):
        return list(struct.unpack('<' + 'I' * count, cpu.mem_read(address, count * 4)))

    def boundary(uc, address, size, unused):
        if address == 0x10161e5a:
            config_calls.append(address)
            put(uc.reg_read(UC_ARM_REG_R1), *configuration)
        elif address in (0x10164b82, 0x10161e56):
            # No temperature reading is available; auxiliary words are supplied
            # separately in the original destination table.
            preparation_queries.append(hex(address))
            uc.reg_write(UC_ARM_REG_R0, 0)
        elif address == 0x10065a7a:
            translations.append(uc.reg_read(UC_ARM_REG_R0))
        elif address == 0x10069ca4:
            maintenance.append([uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)])
        else:
            return
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, boundary)

    def call(address, first, second=0, count=10000):
        cpu.reg_write(UC_ARM_REG_R0, first)
        cpu.reg_write(UC_ARM_REG_R1, second)
        cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
        cpu.reg_write(UC_ARM_REG_LR, stop | 1)
        cpu.emu_start(address | 1, stop, count=count)
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
    # Execute request preparation through the native table copy, before the
    # geometry/configuration helpers. The native row selector runs unhooked.
    descriptor = 0x50009000
    put(context, descriptor)
    cpu.mem_write(descriptor + 0x24, b'\x02')
    cpu.mem_write(descriptor + 0x26, struct.pack('<H', 12432))
    cpu.mem_write(descriptor + 0x28, struct.pack('<H', 8288))
    cpu.mem_write(descriptor + 0x2a, struct.pack('<H', 5520))
    put(descriptor + 0x34, 0xbad0a000)
    preparations = []
    for alternate in (0, 1):
        cpu.mem_write(nested + 0x2b79, bytes([alternate]))
        for pass_index in (0, 1):
            cpu.mem_write(parameters, bytes(0x600))
            cpu.reg_write(UC_ARM_REG_R0, context)
            cpu.reg_write(UC_ARM_REG_R1, pass_index)
            cpu.reg_write(UC_ARM_REG_R2, parameters)
            cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
            cpu.emu_start(0x1011ecd7, 0x1011edb8, count=1000)
            require(cpu.reg_read(UC_ARM_REG_PC) == 0x1011edb8,
                    'Original parameter preparation did not reach geometry boundary')
            fields = {hex(offset): words(parameters + offset, 1)[0]
                      for offset in range(0x484, 0x4d4, 4)}
            require([fields[hex(offset)] for offset in (0x494, 0x498, 0x49c, 0x4a4)] ==
                    [12432, 2, 0xbad0a000, 5520], 'RAW descriptor changed between passes')
            expected = ([33, 24, 24, 24, 33792, 24576] if pass_index else
                        [181, 12, 12, 12, 185344, 12288] if alternate else
                        [29, 12, 12, 12, 29696, 12288])
            require([fields[hex(offset)] for offset in
                     (0x484, 0x488, 0x48c, 0x490, 0x4ac, 0x4b0)] == expected,
                    'Original per-pass parameter table differs')
            preparations.append(dict(alternate=alternate, pass_index=pass_index, fields=fields))
    # Continue through the native geometry and coefficient preparation. Pixels
    # remain unmapped; these routines prepare a request rather than calculate it.
    cpu.mem_map(0xc1000000, 0xa00000)
    cpu.mem_map(0x60000000, 0x200000)
    for record in scatter_records(image):
        if (record['kind'] == 'copy' and 0xc1000000 <= record['destination'] and
                record['destination'] + record['size'] <= 0xc1a00000):
            offset = record['source'] - BASE
            cpu.mem_write(record['destination'], image[offset:offset + record['size']])
    cpu.mem_write(nested, bytes(0x4000))
    put(context, descriptor, 1, 0, capture, output)
    put(nested + 300, 0xffff, 0xffffffff)
    cpu.mem_write(nested + 218, b'\x01')
    put(0xc1012f28, 0x60000000)
    auxiliary = list(range(100, 112))
    put(0xc16a2180, *auxiliary)
    packed = bytearray(1808)
    expected_coefficients = bytearray(b'\xa5' * (6 * 896))
    for row in range(21):
        for bank in range(6):
            for column in range(10):
                if row < 12:
                    value = row * 11 - bank * 5 - column
                    struct.pack_into('<b', packed, row * 60 + bank * 10 + column, value)
                else:
                    value = -row * 503 + bank * 31 + column
                    struct.pack_into('<h', packed,
                                     720 + ((row - 12) * 60 + bank * 10 + column) * 2, value)
                struct.pack_into('<i', expected_coefficients,
                                 bank * 896 + row * 40 + column * 4, value)
    cpu.mem_write(0x600db7d0, bytes(packed))
    full_preparations = []
    for name, x, y, expected_geometry in (
            ('center', 0, 0, [4144, 2760]),
            ('offset', 2560, -5120, [4154, 2740]),
            ('fractional', -2561, 255, [4133, 2760]),
            ('negative', -1061377, -707073, [-2, -2])):
        put(nested + 0x33c4, x & 0xffffffff, y & 0xffffffff)
        for pass_index in (0, 1):
            cpu.mem_write(parameters - 8, b'HEADMARK' + bytes(1512) + b'TAILMARK')
            untouched_results = b'\xde\xad\xbe\xef' * 6
            cpu.mem_write(parameters + 0x594, untouched_results)
            cpu.mem_write(0xc1691080, b'\xa5' * len(expected_coefficients))
            preparation_queries.clear()
            translations.clear()
            maintenance.clear()
            cpu.reg_write(UC_ARM_REG_R2, parameters)
            call(0x1011ecd6, context, pass_index, count=100000)
            geometry = list(struct.unpack('<2i', cpu.mem_read(parameters + 0x4d4, 8)))
            require(geometry == expected_geometry, 'Native packed geometry differs: ' + name)
            require(words(parameters, 2) ==
                    [0xc192530c if pass_index else 0xc1921d6c, parameters + 0x484],
                    'Native request row or argument pointer differs')
            require(words(parameters + 0x4dc, 12) == auxiliary and
                    words(parameters + 0x50c, 21) ==
                    [0xc1691080 + row * 40 for row in range(21)] and
                    words(parameters + 0x560, 1) == [output], 'Native request pointers differ')
            require(words(parameters + 0x4a0, 1) == [8280] and
                    words(parameters + 0x4a4, 1) == [5520], 'Native request dimensions differ')
            actual_coefficients = bytes(cpu.mem_read(0xc1691080, len(expected_coefficients)))
            require(actual_coefficients == expected_coefficients,
                    'Full preparation did not use native signed coefficient expansion')
            require(preparation_queries == ['0x10164b82', '0x10161e56'] and
                    translations == [0x600db7d0] and maintenance == [[0x600db7d0, 1808]],
                    'Native preparation boundaries differ')
            require(cpu.mem_read(parameters + 0x594, 24) == untouched_results and
                    cpu.mem_read(parameters - 8, 8) == b'HEADMARK' and
                    cpu.mem_read(parameters + 1512, 8) == b'TAILMARK',
                    'Request preparation wrote results or crossed its storage')
            full_preparations.append(dict(name=name, pass_index=pass_index,
                supplied_offsets=[x, y], geometry=geometry,
                selected_row=hex(words(parameters, 1)[0]),
                metadata_hex=bytes(cpu.mem_read(parameters + 0x564, 36)).hex(),
                coefficients_sha256=hashlib.sha256(actual_coefficients).hexdigest(),
                results_untouched=True, guards_preserved=True))
    return dict(format=1, result='passed', firmware_included=False,
        slave_sha256=structure['sha256'], thresholds=thresholds, cases=cases,
        request_preparations=preparations,
        full_request_preparations=full_preparations, supplied_auxiliary_words=auxiliary,
        entries=dict(filter='0x1011e75a', selector='0x10148ff2'),
        host_boundaries=['Synthetic contexts, RAW descriptor, result triples and nine configuration words',
                         'Configuration lookup 0x10161e5a returns supplied words',
                         'Full preparation supplies absent temperature and twelve auxiliary words',
                         'Signed calibration fixture; identity source translation; recorded cache maintenance'],
        limitations=['No compute program or RAW input algorithm is executed',
                     'Early preparation cases stop at 0x1011edb8; full cases execute 0x1011ecd6 to return',
                     'Full preparation covers one RAW descriptor and the default coefficient source, without preview or interpolation',
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
    print('PASS original full request preparation, signed geometry, filtering and category selection')
