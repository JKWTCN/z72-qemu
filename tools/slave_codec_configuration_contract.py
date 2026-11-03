# SPDX-License-Identifier: GPL-2.0-or-later
"""Replay the observed native slave codec configuration and start routines."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP,
                              UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg, scatter_records


def check(image, capture, request_index=0):
    identity = analyze_eg(image, 'slave')
    records = capture['trace']['records']
    configurations = [row['codec'] for row in records if row['entry'] == 'capture-slave-codec-device-configure']
    starts = [row['codec'] for row in records if row['entry'] == 'capture-slave-codec-device-start']
    require(0 <= request_index < min(len(configurations), len(starts)), 'Captured codec request index is out of range')
    before, ready = configurations[request_index], starts[request_index]
    descriptor = int(ready['configuration']['address'], 16)
    handle = int(ready['device']['address'], 16)
    values = [int(word, 16) for word in ready['configuration']['words']]
    registers = [int(word, 16) for word in ready['registers']]
    output = registers[0x440 // 4]
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for start, size in ((BASE, (len(image) + 4095) & ~4095),
                        (0xc1000000, 0xa00000), (0x24072000, 0x1000),
                        (0x50000000, 0x10000), (output & ~4095, 0x2000)):
        cpu.mem_map(start, size)
    if not 0xc1000000 <= descriptor < 0xc1a00000:
        cpu.mem_map(descriptor & ~4095, 0x2000)
    cpu.mem_write(BASE, image)
    for row in scatter_records(image):
        if row['kind'] == 'copy' and 0xc1000000 <= row['destination'] and row['destination'] + row['size'] <= 0xc1a00000:
            begin = row['source'] - BASE
            cpu.mem_write(row['destination'], image[begin:begin + row['size']])
    cpu.mem_write(handle, struct.pack('<4I', 0x113, 0, 0, 0))
    cpu.mem_write(descriptor, struct.pack('<' + 'I' * len(values), *values))
    tables = []
    for index, offset in enumerate((0x20, 0x28)):
        pointer = values[offset // 4]
        packed = struct.pack('>16I', *registers[0x100 // 4 + index * 16:0x100 // 4 + (index + 1) * 16])
        observed = next((table for table in ready['tables'] if table['field'] == hex(offset)), None)
        require(index == 1 or observed is not None, 'Captured first quantizer source is missing')
        if observed is not None:
            require(packed.hex() == observed['bytes'], 'Observed quantizer packing differs')
        cpu.mem_write(pointer, packed)
        tables.append(dict(field=hex(offset), bytes=packed.hex(),
            source='Observed source bytes' if observed is not None else 'Reconstructed from packed MMIO words'))
    cpu.mem_write(0x24072000, struct.pack('<' + 'I' * len(before['registers']),
                                       *(int(word, 16) for word in before['registers'])))
    cpu.mem_write(output, b'\xcc' * 128)
    writes, output_writes = [], []

    def write(uc, access, address, size, value, unused):
        if 0x24072000 <= address < 0x24072600:
            writes.append(dict(address=hex(address), bytes=size, value=hex(value)))
        if output <= address < output + values[0x68 // 4]:
            output_writes.append(dict(address=hex(address), bytes=size))

    def run(address, first, second=0):
        cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
        cpu.reg_write(UC_ARM_REG_LR, 0x5000f001)
        cpu.reg_write(UC_ARM_REG_R0, first)
        cpu.reg_write(UC_ARM_REG_R1, second)
        cpu.emu_start(address | 1, 0x5000f000, count=10000)
        require(cpu.reg_read(UC_ARM_REG_PC) == 0x5000f000, 'Native codec configuration fragment did not return')

    cpu.hook_add(UC_HOOK_MEM_WRITE, write)
    run(0x10095e58, handle, descriptor)
    require(list(struct.unpack('<384I', cpu.mem_read(0x24072000, 0x600))) == registers,
            'Native codec configuration differs from the observed register file')
    require(struct.unpack('<I', cpu.mem_read(handle + 4, 4))[0] == descriptor,
            'Native codec configuration did not bind its descriptor')
    configure_writes = list(writes)
    cpu.mem_write(descriptor + 0x90, struct.pack('<3I', 99, 0, 0xffffffff))
    cpu.mem_write(0xc1001410, struct.pack('<I', 0xffffffff))
    writes.clear()
    run(0x100960b8, handle)
    require(struct.unpack('<3I', cpu.mem_read(descriptor + 0x90, 12)) == (0, 0, 0),
            'Native codec start retained stale result words')
    require(cpu.mem_read(0xc1001410, 4) == bytes(4), 'Native codec start retained accumulated flags')
    final = struct.unpack('<384I', cpu.mem_read(0x24072000, 0x600))
    require(final[1] == registers[1] | 1 and final[0x400 // 4] & 0xc000 == 0x4000 and
            final[0x404 // 4] & 0xc000 == 0x4000, 'Native codec start controls differ')
    require(cpu.mem_read(output, 128) == b'\xcc' * 128, 'Native configuration/start modified the synthetic output prefix')
    require(not output_writes, 'Native configuration/start wrote compressed output')
    fields = (0x18, 0x1c, 0x28, 0x410, 0x414, 0x418, 0x41c, 0x430, 0x434,
              0x440, 0x458, 0x484, 0x490, 0x494)
    measuring = values[0x10 // 4] != 0
    require(registers[0x458 // 4] == (0 if measuring else values[0x68 // 4] // 512),
            'Observed capacity conversion differs')
    scale = (values[0x54 // 4] >> 16) & 255
    require(registers[0x1c // 4] == ((values[0x18 // 4] >> 16) >> scale) and
            registers[0x18 // 4] == ((values[0x1c // 4] & 0xffff) >> scale),
            'Native codec header scaling differs')
    return dict(format=1, result='passed', firmware_included=False, slave_sha256=identity['sha256'],
        request_index=request_index, measuring=measuring, scale=scale,
        configure='0x10095e58', start='0x100960b8', descriptor=hex(descriptor), tables=tables,
        registers={hex(0x24072000 + offset): hex(registers[offset // 4]) for offset in fields},
        output_capacity_bytes=values[0x68 // 4], configuration_writes=configure_writes,
        start_writes=list(writes),
        host_boundaries=['Use the captured descriptor and pre-configuration register state',
                         'Reconstruct the second quantizer from observed packed register words',
                         'Synthetic RAM and MMIO; no pixel input or hardware side effects'],
        limitations=['Second quantizer replay is not an independent packing check',
                     'No compressed output, device IRQ or saved photograph is produced'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--capture-report', type=Path, required=True)
    parser.add_argument('--request-index', type=int, default=0)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.slave.read_bytes(), json.loads(args.capture_report.read_text(encoding='utf-8')), args.request_index)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native slave codec configuration, quantizers, capacity and start writes')
