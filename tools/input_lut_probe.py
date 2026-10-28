# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original input table and analysis setters with synthetic data."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require, validate_master


def probe(image):
    validate_master(image)
    engine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    engine.mem_map(0x10208000, 0x4000)
    engine.mem_write(0x10208000, image[0x1e8000:0x1ec000])
    engine.mem_map(0xb1806000, 0x1000)
    engine.mem_write(0xb1806000, image[0x237ff94:0x2380f94])
    engine.mem_map(0x1078a000, 0x1000)
    engine.mem_write(0x1078a000, image[0x76a000:0x76b000])
    engine.mem_map(0x50000000, 0x3000)
    engine.mem_map(0x2006a000, 0x2000)
    values = [(17 * index + 3) & 0xffff for index in range(129)]
    engine.mem_write(0x50000000, struct.pack('<129H', *values))
    writes = []
    engine.hook_add(UC_HOOK_MEM_WRITE,
        lambda u, access, address, size, value, unused: writes.append((address, size, value)),
        begin=0x2006a000, end=0x2006bfff)
    engine.reg_write(UC_ARM_REG_R1, 0x50000000)
    engine.reg_write(UC_ARM_REG_LR, 0x50002001)
    engine.emu_start(0x1020b131, 0x50002000, count=2000)
    require(engine.reg_read(UC_ARM_REG_PC) == 0x50002000, 'Table writer did not return')
    require(writes == [(0x2006b000 + index * 4, 4, value)
                       for index, value in enumerate(values)], 'Table write contract differs')
    require(bytes(engine.mem_read(0x2006b204, 4)) == bytes(4), 'Table writer overran its range')
    table_writes = list(writes)
    engine.mem_write(0x50000400, bytes((index * 7 + 1) & 255 for index in range(512)))
    engine.mem_write(0x50000454, b'\0')  # Select the explicit A260/A264 parameter path.
    parameters, covered = [], set()
    engine.reg_write(UC_ARM_REG_SP, 0x50001800)
    for entry in (0x1020aea8, 0x1020aed6, 0x1020af14, 0x1020afb4,
                  0x1020b056, 0x1020b094):
        writes.clear()
        engine.reg_write(UC_ARM_REG_R1, 0x50000400)
        engine.reg_write(UC_ARM_REG_LR, 0x50002001)
        engine.emu_start(entry | 1, 0x50002000, count=2000)
        require(engine.reg_read(UC_ARM_REG_PC) == 0x50002000, 'Analysis setter did not return')
        require(writes and all(0x2006a200 <= address <= 0x2006a370 and size == 4
                               for address, size, _ in writes), 'Analysis setter escaped its range')
        covered.update(address for address, _, _ in writes)
        parameters.append(dict(entry=hex(entry), writes=len(writes),
                               addresses=[hex(address) for address, _, _ in writes]))
    require(covered == set(range(0x2006a200, 0x2006a374, 4)),
            'Analysis register coverage differs: ' + repr(
                [hex(address) for address in sorted(set(range(0x2006a200, 0x2006a374, 4)) - covered)]))
    contexts = []
    for descriptor, address in ((0xb18067b4, 0x2006a000), (0xb18067c4, 0x2006be00)):
        writes.clear()
        engine.reg_write(UC_ARM_REG_R0, descriptor)
        engine.reg_write(UC_ARM_REG_R1, 0x50000400)
        engine.reg_write(UC_ARM_REG_LR, 0x50002001)
        engine.emu_start(0x10209ef7, 0x50002000, count=2000)
        require(engine.reg_read(UC_ARM_REG_PC) == 0x50002000, 'Context setter did not return')
        require([(a, size) for a, size, _ in writes] ==
                [(address + index * 4, 4) for index in range(10)], 'Context registers differ')
        contexts.append(dict(descriptor=hex(descriptor), entry='0x10209ef6',
                             addresses=[hex(a) for a, _, _ in writes]))
        writes.clear()
        engine.reg_write(UC_ARM_REG_R0, descriptor)
        engine.reg_write(UC_ARM_REG_R1, 7)
        engine.reg_write(UC_ARM_REG_R2, 3)
        engine.reg_write(UC_ARM_REG_LR, 0x50002001)
        engine.emu_start(0x10209feb, 0x50002000, count=2000)
        require(engine.reg_read(UC_ARM_REG_PC) == 0x50002000 and
                writes == [(address + 0x40, 4, 0x37)], 'Context control packing differs')
        contexts[-1]['control'] = dict(entry='0x10209fea', address=hex(address + 0x40),
                                      packed_value='0x37')
    secondary, secondary_words = [], set()
    for entry, arguments in (
            (0x10208e96, (0x50000400, 0, 0)),
            (0x10208cb0, (0x50000400, 0, 0)),
            (0x10208db6, (0x50000400, 0, 0)),
            (0x10208cf4, (0x50000400, 0, 0)),
            (0x10208ed0, (3, 0x50000400, 0)),
            (0x10208f12, (1, 2, 3)), (0x10208f1e, (7, 0, 0)),
            (0x10208e7e, (1, 2, 3))):
        writes.clear()
        for register, value in zip((UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), arguments):
            engine.reg_write(register, value)
        engine.reg_write(UC_ARM_REG_LR, 0x50002001)
        engine.emu_start(entry | 1, 0x50002000, count=2000)
        require(engine.reg_read(UC_ARM_REG_PC) == 0x50002000, 'Secondary setter did not return')
        require(writes and all(size == 4 for _, size, _ in writes), 'Secondary write width differs')
        secondary_words.update(address for address, _, _ in writes)
        secondary.append(dict(entry=hex(entry), writes=len(writes),
                              addresses=[hex(address) for address, _, _ in writes]))
    require(secondary_words == set(range(0x2006b800, 0x2006b988, 4)) |
            set(range(0x2006ba00, 0x2006babc, 4)), 'Secondary configuration coverage differs')
    reads, getters = [], []
    engine.hook_add(UC_HOOK_MEM_READ,
        lambda u, access, address, size, value, unused: reads.append((address, size)),
        begin=0x2006a000, end=0x2006bfff)
    cases = [
        (0x10209f4a, descriptor, 0x50000800, list(range(address + 0x100, address + 0x130, 4)))
        for descriptor, address in ((0xb18067b4, 0x2006a000), (0xb18067c4, 0x2006be00))]
    cases += [(0x10209ffa, descriptor, 0, [address + 0x44])
              for descriptor, address in ((0xb18067b4, 0x2006a000), (0xb18067c4, 0x2006be00))]
    cases += [(0x10208e0a, 0, 0x50000800,
               [0x2006bb70, 0x2006bb74, 0x2006bb78, 0x2006bc78, 0x2006bd78,
                0x2006bb7c, 0x2006bc7c, 0x2006bd7c]),
              (0x10208e8e, 0, 0, [0x2006b988])]
    cases += [(0x1020af08, 0, index, [0x2006a3e0 + index * 4]) for index in range(4)]
    for entry, a, b, expected in cases:
        reads.clear()
        engine.reg_write(UC_ARM_REG_R0, a)
        engine.reg_write(UC_ARM_REG_R1, b)
        engine.reg_write(UC_ARM_REG_LR, 0x50002001)
        engine.emu_start(entry | 1, 0x50002000, count=2000)
        require(engine.reg_read(UC_ARM_REG_PC) == 0x50002000 and
                reads == [(address, 4) for address in expected],
                f'Result getter accesses differ at {entry:#x}: {reads!r}')
        getters.append(dict(entry=hex(entry), r0=hex(a), r1=hex(b),
                            addresses=[hex(address) for address, _ in reads]))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                entry='0x1020b130', code_window_sha256=hashlib.sha256(
                    image[0x1eb130:0x1eb142]).hexdigest(), synthetic_source=True,
                input_element_bytes=2, output_access_bytes=4, writes=len(table_writes),
                first_address=hex(table_writes[0][0]), last_address=hex(table_writes[-1][0]),
                all_values_match=True, next_word_untouched=True,
                analysis_setters=parameters, analysis_distinct_words=len(covered),
                context_setters=contexts,
                secondary_setters=secondary, secondary_distinct_words=len(secondary_words),
                synthetic_row_count=3,
                result_getters=getters, result_reset_value_is_experimental=True,
                native_firmware_completion_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(table_words=report['writes'],
                          analysis_words=report['analysis_distinct_words'],
                          context_groups=len(report['context_setters']),
                          secondary_words=report['secondary_distinct_words'],
                          output=str(args.out))))


if __name__ == '__main__':
    main()
