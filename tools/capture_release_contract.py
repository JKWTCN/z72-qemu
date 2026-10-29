# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover local capture routes, operation 59 admission and filtered resource checks."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from tools.boot_region_probe import RegionProbe
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_PC, UC_ARM_REG_LR


class ReleaseProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.requests = []

    def boundary(self, cpu, address, size, unused):
        if address in (0x10360f2e, 0x10360f12):
            cpu.reg_write(UC_ARM_REG_R0, 1)
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        elif address == 0x10228d3a:
            entry, pointer, length = [cpu.reg_read(reg) for reg in
                                      (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
            require(length == 12, 'Unexpected release request size')
            self.requests.append(dict(entry=hex(entry), length=length,
                parameters=list(struct.unpack('<3I', cpu.mem_read(pointer, length)))))
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(cpu, address, size, unused)


def resource_query_contract(native):
    """Execute the original filtered intersection query with synthetic masks."""
    primary, secondary, scratch = [native.DATA + offset for offset in (0x400, 0x500, 0x600)]
    for descriptor, pointer in ((0xb1869898, primary), (0xb18698a0, secondary),
                                (0xb18698b0, scratch)):
        native.u.mem_write(descriptor, struct.pack('<2I', 128, pointer))

    def query(first, second):
        for pointer, mask in ((primary, first), (secondary, second), (scratch, 0)):
            native.u.mem_write(pointer, mask.to_bytes(16, 'little'))
        return native.call(0x209fdc)

    excluded = []
    blocked = []
    for bit in range(128):
        result = query(1 << bit, 1 << bit)
        require(result in (0, 1), 'Unexpected original resource query result')
        (excluded if result else blocked).append(bit)
    require(len(excluded) == 40, 'Original exclusion list differs')
    require(query(0, 0) == 1 and query(1, 2) == 1, 'Empty/disjoint resource query differs')
    require(query((1 << 128) - 1, (1 << 128) - 1) == 0, 'Intersecting resource query differs')
    return dict(entry='0x10229fdc', capacity=128,
        descriptors=[hex(address) for address in (0xb1869898, 0xb18698a0, 0xb18698b0)],
        excluded_bits=excluded, blocking_bits=blocked, single_bit_cases=128,
        empty_result=1, disjoint_result=1, all_set_result=0,
        interpretation='Returns 1 when primary and filtered secondary have no common set bit; 0 otherwise.',
        host_boundaries=['successful lock acquisition and release'],
        limitation='Synthetic mask contract; does not identify the bits set by the running firmware or change native admission.')


def probe(image):
    native = ReleaseProbe(image)
    routes = []
    for opcode in (0x100e, 0x90c0, 0x9207):
        record = native.call(0x443d70, opcode)
        require(record != 0, 'Expected local command route is missing')
        words = struct.unpack('<7I', native.u.mem_read(record, 28))
        require(words[0] == opcode, 'Command route code differs')
        routes.append(dict(opcode=hex(opcode), record=hex(record),
                           callbacks=[hex(word) for word in words[4:]]))
    parameters = (0x101, 0x102, 0x103)
    native.u.mem_write(native.DATA, struct.pack('<3I', *parameters))
    callback = native.DATA + 0x2001
    slot = 0xb23f6fe4 + 59 * 4
    cases = []
    for supplied, occupied in ((True, False), (False, False), (True, True)):
        native.requests.clear()
        native.u.mem_write(slot, struct.pack('<I', callback if occupied else 0))
        result = native.call(0x3d36fa, native.DATA, callback if supplied else 0)
        accepted = supplied and not occupied
        require(result == int(not accepted), 'Original release admission result differs')
        expected = [dict(entry='0x103f19c1', length=12, parameters=list(parameters))] if accepted else []
        require(native.requests == expected, 'Original release queue request differs')
        require(native.word(slot) == (callback if accepted or occupied else 0),
                'Original release callback registration differs')
        cases.append(dict(callback_supplied=supplied, slot_occupied=occupied,
                          result=result, queued=list(native.requests)))
    return dict(firmware_included=False, master_sha256=hashlib.sha256(image).hexdigest(),
        resource_query=resource_query_contract(native),
        command_lookup='0x10463d70', routes=routes, operation=59,
        submit='0x103f36fa', callback_slot=hex(slot), cases=cases,
        host_boundaries=['record queue submission without executing the capture task'],
        limitation='Local route and synthetic submit contract only; no USB device, native shutter, exposure or file write is exercised.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS original local routes, operation 59 callback/queue and 128-bit resource query contracts')
