# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the observed native quality-selection measurement/write transition."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_MEM_READ
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg, scatter_records


def check(image, capture):
    identity = analyze_eg(image, 'slave')
    submits = [row for row in capture['trace']['records'] if row['entry'] == 'capture-slave-codec-request-submit']
    argument = submits[1]['codec_argument']
    values = [int(value, 16) for value in argument['words']]
    settings = values[0x34 // 4] - int(argument['address'], 16)
    require(settings == 0xa0 and values[0] >> 16 == 1620 and values[1] == 1080,
            'Unexpected captured quality-selection request')
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for start, size in ((BASE, (len(image) + 4095) & ~4095),
                        (0xc1000000, 0xa00000), (0x50000000, 0x10000)):
        cpu.mem_map(start, size)
    cpu.mem_write(BASE, image)
    for row in scatter_records(image):
        if row['kind'] == 'copy' and 0xc1000000 <= row['destination'] and row['destination'] + row['size'] <= 0xc1a00000:
            begin = row['source'] - BASE
            cpu.mem_write(row['destination'], image[begin:begin + row['size']])
    request, quality, table0, table1 = 0x50001000, 0x50002000, 0x50003000, 0x50003040
    source = struct.pack('<' + 'I' * len(values), *values)[settings:]
    require(source[0] == 2 and len(source) == 24, 'Unexpected captured quality settings')
    cpu.mem_write(quality, source + bytes(8))
    unknown_reads = []

    def read(uc, access, address, size, value, unused):
        if address < quality + 32 and address + size > quality + len(source):
            unknown_reads.append(dict(address=hex(address), bytes=size))

    cpu.hook_add(UC_HOOK_MEM_READ, read, begin=quality, end=quality + 31)
    data = bytearray(0x38)
    struct.pack_into('<I', data, 0, values[0])
    struct.pack_into('<H', data, 4, values[1])
    struct.pack_into('<4I', data, 8, values[0x28 // 4], values[0x2c // 4], values[0x30 // 4], quality)
    struct.pack_into('<2I', data, 0x30, table0, table1)
    cpu.mem_write(request, bytes(data))

    def run():
        cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
        cpu.reg_write(UC_ARM_REG_LR, 0x5000f001)
        cpu.reg_write(UC_ARM_REG_R0, request)
        cpu.emu_start(0x1012f543, 0x5000f000, count=10000)
        require(cpu.reg_read(UC_ARM_REG_PC) == 0x5000f000, 'Native quality callback did not return')
        words = struct.unpack('<14I', cpu.mem_read(request, 0x38))
        return dict(return_value=cpu.reg_read(UC_ARM_REG_R0),
            pass_count=words[6], measured_result=words[7], measurement_mode=words[9],
            scale=words[10] & 255, quantizer_scale=words[11],
            tables=[bytes(cpu.mem_read(pointer, 64)).hex() for pointer in (table0, table1)])

    initial = run()
    require(initial['return_value'] == 0 and initial['measurement_mode'] == 1 and initial['scale'] == 2,
            'Native quality callback did not request the observed quarter-size measurement')
    cpu.mem_write(request + 0x18, struct.pack('<3I', 1, 0x8000, initial['quantizer_scale']))
    after = run()
    require(after['return_value'] == 0 and after['measurement_mode'] == 0,
            'Native quality callback did not switch to normal output after the measured size')
    require(not unknown_reads, f'Native callback consumed uncaptured settings: {unknown_reads}')
    return dict(format=1, result='passed', firmware_included=False, slave_sha256=identity['sha256'],
        callback='0x1012f542', initial=initial, after_measurement=after,
        host_boundaries=['Use captured request geometry, size targets and 24-byte quality settings',
                         'Rebase pointers to synthetic RAM; reject access to uncaptured trailing settings',
                         'Supply a synthetic measured result of 0x8000 for the second callback'],
        limitations=['No hardware scaling, JPEG output, interrupt or saved file is exercised',
                     'A measurement-to-write transition does not prove final convergence for all inputs'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--capture-report', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.slave.read_bytes(), json.loads(args.capture_report.read_text(encoding='utf-8')))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native quarter-size measurement and normal-output quality transition')
