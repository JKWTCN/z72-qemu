# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe the original delay repetition constructor and register writes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require, validate_master
from analyze.firmware_structure import scatter_records


def check(image):
    validate_master(image)
    data = next(row for row in scatter_records(image)
                if row['kind'] == 'copy' and row['destination'] == 0xb1800000)
    copied = image[data['source'] - 0x10020000: data['source'] - 0x10020000 + data['size']]

    def words(address, count):
        return struct.unpack_from('<' + 'I' * count, copied, address - 0xb1800000)

    descriptors = []
    for channel in range(12):
        address = 0xb18063ac + channel * 20
        registers = words(address, 5)[2]
        pointers = words(registers + 0x50, 3)
        require(bool(pointers[0]) == (channel < 5), 'Unexpected limit capability')
        descriptors.append(dict(channel=channel, descriptor=hex(address),
            registers=[hex(value) for value in pointers]))
    machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    machine.mem_map(0x1036e000, 0x4000)
    machine.mem_write(0x1036e000, image[0x34e000:0x352000])
    machine.mem_map(0xb1800000, (len(copied) + 4095) & ~4095)
    machine.mem_write(0xb1800000, copied)
    machine.mem_map(0x50000000, 0x3000)
    machine.mem_map(0x2c010000, 0x2000)

    def run(address, r0):
        for register, value in ((UC_ARM_REG_R0, r0), (UC_ARM_REG_R1, 0x50000000),
                               (UC_ARM_REG_SP, 0x50001000), (UC_ARM_REG_LR, 0x50002001)):
            machine.reg_write(register, value)
        machine.emu_start(address | 1, 0x50002000, count=128)
        require(machine.reg_read(UC_ARM_REG_PC) == 0x50002000, 'Original function escaped its bound')
        return machine.reg_read(UC_ARM_REG_R0)

    cases = []
    for channel, requested in ((4, 0), (4, 1), (4, 2), (7, 1)):
        machine.mem_write(0x2c010000, bytes(0x2000))
        machine.mem_write(0x2c010100 + channel * 0x100, struct.pack('<I', 1))
        run(0x10371a96, requested)
        configuration = list(struct.unpack('<2I', machine.mem_read(0x50000000, 8)))
        result = run(0x1036e996, 0xb18063ac + channel * 20)
        base = 0x2c011100 + channel * 0x100
        registers = list(struct.unpack('<3I', machine.mem_read(base + 0x38, 12)))
        events = struct.unpack('<I', machine.mem_read(base - 0x1000, 4))[0]
        require(configuration == ([1, requested] if requested else [0, 1]), 'Constructor changed')
        require((result, registers[:2], events) == (
            (2, [0, 0], 1) if channel >= 5 else
            (0, [1, requested], 9) if requested else (0, [0, 0], 1)), 'Register contract changed')
        cases.append(dict(channel=channel, requested=requested, configuration=configuration,
                          result=result, limit_registers=registers, events=hex(events)))
    window = image[0x34e996:0x34e9d6]
    return dict(observation='original-delay-limit-register-contract', result='passed',
        constructor='0x10371a96', configure='0x1036e996', descriptors=descriptors, cases=cases,
        code_window_sha256=hashlib.sha256(window).hexdigest(),
        synthetic_mmio=True, physical_expiration_executed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original delay limit: constructor, supported channels and register writes')
