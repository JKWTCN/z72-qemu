# SPDX-License-Identifier: GPL-2.0-or-later
"""Replay native JPEG copy splitting and the nonzero-result early return."""
import argparse
import json
from pathlib import Path
import re
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg


def check(image, capture):
    identity = analyze_eg(image, 'slave')
    records = capture['trace']['records']
    outputs = {}
    for record in records:
        if 'codec_output' in record:
            address = int(record['codec']['output_prefix']['address'], 16)
            outputs[address] = record['codec_output']['bytes']
    rows = capture['trace']['memory_transfer_trace']['events']
    cases = []
    for source, length in outputs.items():
        copy_bytes = (length - 2 + 7) & ~7
        matches = [row for row in rows if f'source={source + 2:#x} ' in row]
        if not matches:
            continue
        destination = int(re.search(r'destination=(0x[0-9a-f]+)', matches[0])[1], 16)
        for supplied_result in (0, 1):
            cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            cpu.mem_map(BASE, (len(image) + 4095) & ~4095)
            cpu.mem_write(BASE, image)
            cpu.mem_map(0x50000000, 0x10000)
            calls = []

            def hook(uc, address, size, unused):
                if address != 0x1006993e:
                    return
                pointer = uc.reg_read(UC_ARM_REG_R0)
                packet = bytes(uc.mem_read(pointer, 0x28))
                width, source_pitch, destination_pitch, count = struct.unpack_from('<4H', packet, 2)
                first, second = struct.unpack_from('<2I', packet, 12)
                calls.append(dict(source=hex(first), destination=hex(second), width=width,
                    rows=count, source_pitch=source_pitch, destination_pitch=destination_pitch,
                    timeout=uc.reg_read(UC_ARM_REG_R1)))
                uc.reg_write(UC_ARM_REG_R0, supplied_result)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

            cpu.hook_add(UC_HOOK_CODE, hook, begin=0x1006993e, end=0x1006993e)
            cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
            cpu.reg_write(UC_ARM_REG_LR, 0x5000f001)
            cpu.reg_write(UC_ARM_REG_R0, destination)
            cpu.reg_write(UC_ARM_REG_R1, source + 2)
            cpu.reg_write(UC_ARM_REG_R2, copy_bytes)
            cpu.emu_start(0x10061629, 0x5000f000, count=10000)
            require(cpu.reg_read(UC_ARM_REG_PC) == 0x5000f000, 'Native copy splitter did not return')
            result = cpu.reg_read(UC_ARM_REG_R0)
            require(calls[0]['source'] == hex(source + 2), 'Native source differs')
            if supplied_result == 0:
                require(result == 0 and len(calls) == 2, 'Native splitter did not issue its remainder')
                require(sum(c['width'] * c['rows'] for c in calls) == copy_bytes,
                        'Native split did not cover the complete input')
                bulk = calls[0]['width'] * calls[0]['rows']
                require(calls[1]['source'] == hex(source + 2 + bulk) and
                        calls[1]['destination'] == hex(destination + bulk), 'Native remainder addresses differ')
            else:
                require(result == 0xffffffff and len(calls) == 1,
                        'Nonzero bulk result did not prevent the remainder')
            cases.append(dict(source=hex(source), jpeg_bytes=length, copy_bytes=copy_bytes,
                supplied_service_result=supplied_result, native_return=hex(result), calls=calls))
    require(len(cases) == 6, 'Requires all three captured JPEG copy streams')
    return dict(format=1, result='passed', firmware_included=False, slave_sha256=identity['sha256'],
        native_splitter='0x10061628', cases=cases,
        host_boundaries=['Use geometry and addresses from the actual completed DMA trace',
                         'Round the JPEG body to eight bytes, as observed in the native copy return trace',
                         'Intercept 0x1006993e to record each descriptor and supply status 0 or 1'],
        limitations=['No DMA, callbacks, scheduling or actual memory copies are executed',
                     'The forced nonzero case does not prove the status observed in the full machine'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--capture-report', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.slave.read_bytes(), json.loads(args.capture_report.read_text(encoding='utf-8')))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native JPEG copy split and nonzero-result early return')
