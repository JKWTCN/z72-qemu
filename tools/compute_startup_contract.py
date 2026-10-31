# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original compute initialization and record its MMIO and event contract."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                     UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE)
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                              UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                              UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg, scatter_records


def check(image):
    structure = analyze_eg(image, 'slave')
    cases = []
    for copy_result in (0, 1):
        cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        cpu.mem_map(BASE, (len(image) + 4095) & ~4095)
        cpu.mem_write(BASE, image)
        for address, size in ((0xc1000000, 0xa00000), (0x04280000, 0x2000),
                              (0x24060000, 0x2000), (0x80300000, 0x28000),
                              (0x50000000, 0x10000)):
            cpu.mem_map(address, size)
        for record in scatter_records(image):
            if (record['kind'] == 'copy' and 0xc1000000 <= record['destination'] and
                    record['destination'] + record['size'] <= 0xc1a00000):
                offset = record['source'] - BASE
                cpu.mem_write(record['destination'], image[offset:offset + record['size']])
        # Nonzero initial control words expose the original read/modify/write
        # operations; these are fixtures, not a measured power-on state.
        cpu.mem_write(0x04280084, struct.pack('<I', 0xffffffff))
        cpu.mem_write(0x04281058, struct.pack('<I', 0xffffffff))
        cpu.mem_write(0xc100716c, struct.pack('<I', 0x50001000))
        accesses, events, resources, copies = [], [], [], []

        def boundary(uc, address, size, unused):
            if address not in (0x10066b2c, 0x10066b3c, 0x100f9714, 0x100f970e,
                               0x1006671a, 0x1006568e, 0x100f9786):
                return
            arguments = [uc.reg_read(register) for register in
                         (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
            result = 0
            if address == 0x1006671a:
                resources.append(arguments[0])
            elif address == 0x1006568e:
                unused_handle, destination, source, length = arguments
                require((destination, source, length) == (0x80300000, 0x10834b54, 0x27800),
                        'Original compute upload recipe changed')
                data = bytes(uc.mem_read(source, length))
                if not copy_result:
                    uc.mem_write(destination, data)
                copies.append(dict(source=hex(source), destination=hex(destination),
                                   bytes=length, sha256=hashlib.sha256(data).hexdigest(),
                                   supplied_return=copy_result, data_written=not copy_result))
                result = copy_result
            elif address == 0x100f9786:
                events.append(dict(object=hex(arguments[0]), mask=hex(arguments[1])))
            uc.reg_write(UC_ARM_REG_R0, result)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

        def memory(uc, access, address, size, value, unused):
            if 0x04280000 <= address < 0x04282000 or 0x24060000 <= address < 0x24062000:
                row = dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)), address=hex(address),
                           bytes=size, write=access == UC_MEM_WRITE)
                if row['write']:
                    row['value'] = hex(value)
                accesses.append(row)

        cpu.hook_add(UC_HOOK_CODE, boundary)
        cpu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, memory)
        cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
        cpu.reg_write(UC_ARM_REG_LR, 0x5000f001)
        cpu.emu_start(0x10054a2b, 0x5000f000, count=100000)
        require(cpu.reg_read(UC_ARM_REG_PC) == 0x5000f000, 'Original initializer did not return')
        require(resources == [4] and len(copies) == 1, 'Initialization boundary calls changed')
        initialized = int.from_bytes(cpu.mem_read(0xc1007174, 4), 'little')
        require(initialized == 1 and events == [dict(object='0xc1007170', mask='0x2')],
                'Original initialization flag or notification changed')
        writes = [row for row in accesses if row['write']]
        core_writes = [(row['address'], row['value']) for row in writes
                       if 0x24060000 <= int(row['address'], 16) < 0x24062000]
        require(core_writes == [('0x24060008', '0x0'), ('0x2406000c', '0x0'),
                                ('0x24060000', '0x0'), ('0x24060014', '0x8030c000')],
                'Original compute control writes changed')
        core_reads = [row for row in accesses if not row['write'] and
                      0x24060000 <= int(row['address'], 16) < 0x24062000]
        require(not core_reads, 'Initialization now reads a compute status or reply')
        require(int.from_bytes(cpu.mem_read(0x04280084, 4), 'little') == 0xdfffffff and
                int.from_bytes(cpu.mem_read(0x04281058, 4), 'little') == 0xfaffffff,
                'Original control-bit clearing changed')
        cases.append(dict(copy_return=copy_result, uploads=copies, mmio_accesses=accesses,
                          initialized=initialized, events=events, core_reads=core_reads))
    return dict(format=1, result='passed', firmware_included=False,
        slave_sha256=structure['sha256'], initializer='0x10054a2a', cases=cases,
        host_boundaries=['Resource initialization and uncontended lock operations return zero',
                         'Upload boundary copies the actual payload for return zero; return one writes nothing',
                         'Record the original event notification without scheduling tasks',
                         'Plain MMIO fixture storage; no processor or hardware side effects'],
        limitations=['Software initialization is set even when the supplied upload return is one',
                     'This contract does not execute the uploaded program or produce a mailbox reply',
                     'Control-bit writes alone do not identify the processor architecture or prove execution'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.slave.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original compute initialization, control writes and unconditional software-ready flag')
