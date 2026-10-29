# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover processing DMA and port contracts by executing original setters."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from tools.boot_region_probe import RegionProbe
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2


class DescriptorProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.notifications = []

    def boundary(self, cpu, address, size, unused):
        # The setter waits eight counter ticks after submitting its channel.
        # Only the two counter reads are supplied by the test environment.
        if address == self.DATA + 0x2000:
            self.notifications.append([cpu.reg_read(UC_ARM_REG_R0), cpu.reg_read(UC_ARM_REG_R1)])
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        elif address == 0x103bdba4:
            cpu.reg_write(UC_ARM_REG_R0, 100)
            cpu.reg_write(UC_ARM_REG_R1, 0)
            cpu.reg_write(UC_ARM_REG_PC, (address + 4) | 1)
        elif address == 0x103bdba8:
            cpu.reg_write(UC_ARM_REG_R1, 109)
            cpu.reg_write(UC_ARM_REG_R2, 0)
            cpu.reg_write(UC_ARM_REG_PC, (address + 4) | 1)
        else:
            super().boundary(cpu, address, size, unused)


def probe(image):
    native = DescriptorProbe(image)
    native.u.mem_map(0x20100000, 0x10000)
    node, parameters = native.DATA, native.DATA + 0x1000
    targets = [0x54900000, 0x56b0d000, 0x58d1a000, 0x5af27000]
    data = bytearray(64)
    struct.pack_into('<4I', data, 0, 2080, 2080, 0, 0)
    struct.pack_into('<4I', data, 0x10, *targets)
    struct.pack_into('<4H', data, 0x2a, 1380, 918, 0, 0)
    struct.pack_into('<2H', data, 0x32, 1380, 918)
    native.u.mem_write(parameters, bytes(data))
    cases = []
    for channel in (0, 15):
        base = 0x20100400 + channel * 0x40
        addresses = targets if channel == 0 else [0, 0x12000, 0x24000, 0]
        native.u.mem_write(parameters + 0x10, struct.pack('<4I', *addresses))
        native.u.mem_write(node, bytes([0, channel]) + bytes(10) + struct.pack('<I', parameters))
        native.call(0x39da1e, node)
        words = list(struct.unpack('<13I', native.u.mem_read(base, 52)))
        expected = [1, 0, 918 << 16 | 1380, 0, 2080, 2080, 0, 0,
                    918 << 16 | 1380, *addresses]
        require(words == expected, 'Original processing DMA descriptor packing differs: ' + repr(words))
        require(native.word(0x2010002c) == channel, 'Original channel submission differs')
        cases.append(dict(channel=channel, base=hex(base),
                          supplied_address_operands=[hex(value) for value in addresses],
                          registers={hex(index * 4): hex(value) for index, value in enumerate(words)},
                          submitted_channel=native.word(0x2010002c)))
    native.u.mem_write(0xb1801d74, struct.pack('<I', (native.DATA + 0x2000) | 1))
    completion_cases = []
    for status, event in ((0, 0), (1, 1), (4, 2), (5, 3)):
        native.notifications.clear()
        native.u.mem_write(0x20100018, struct.pack('<3I', status, 0, 0))
        native.call(0x39ce38)
        expected = [[0x41051001, event]] if event else []
        require(native.notifications == expected, 'Original processing completion event mapping differs')
        completion_cases.append(dict(status_18=hex(status), notifications=[
            dict(code=hex(code), event=hex(value)) for code, value in native.notifications]))
    binding_cases = []
    binding_parameters = native.DATA + 0x3000
    for port in (0, 1):
        addresses = [0x54000000 + port * 0x1000000 + row * 0x100000 + column * 0x1000
                     for row in range(4) for column in range(16)]
        addresses[32] = 0
        enabled = [2 if column == 5 else int(column in (0, 15)) for column in range(16)]
        seed = [0x77000000 + index * 4 for index in range(128)]
        native.u.mem_write(0x20102200, struct.pack('<128I', *seed))
        native.u.mem_write(binding_parameters, struct.pack('<80I', *addresses, *enabled))
        native.call(0x39d188, 0, port, binding_parameters)
        expected = seed[:]
        for index, address in enumerate(addresses):
            if enabled[index % 16]:
                expected[port * 64 + index] = address
        actual = list(struct.unpack('<128I', native.u.mem_read(0x20102200, 512)))
        require(actual == expected, 'Original processing address-bank selection differs')
        control = 0x20102000 + port * 0x100
        native.u.mem_write(control, struct.pack('<I', 0xa5a501f0))
        native.call(0x39d08a, 0, port)
        started = native.word(control)
        require(started == 0xa5a501f1, 'Original processing port enable differs')
        native.call(0x39d0a2, 0, port)
        stopped = native.word(control)
        require(stopped == 0xa5a501f0, 'Original processing port disable differs')
        binding_cases.append(dict(bank_selector=port, control_port=port,
            bank_base=hex(0x20102200 + port * 0x100),
            supplied_addresses=[hex(value) for value in addresses], enabled=enabled,
            registers=[hex(value) for value in actual[port * 64:(port + 1) * 64]],
            inactive_bank_preserved=True, control_started=hex(started), control_stopped=hex(stopped)))
    native.u.mem_write(0xb1cf0f40, struct.pack('<8I', *([(native.DATA + 0x2000) | 1] * 8)))
    routed_event_cases = []
    for status, event in ((1, 1), (2, 2), (0x10000, 0x100), (0x20000, 0x200)):
        native.notifications.clear()
        native.u.mem_write(0x20100018, struct.pack('<3I', 0, status, 0))
        native.call(0x39ce38)
        require(native.notifications == [[0x41051002, event]],
                'Original processing subscriber status mapping differs: ' + repr((status, native.notifications)))
        routed_event_cases.append(dict(status_1c=hex(status), subscriber=(status.bit_length() - 1) % 16,
            notifications=[
            dict(code=hex(code), event=hex(value)) for code, value in native.notifications]))
    return dict(firmware_included=False, master_sha256=hashlib.sha256(image).hexdigest(),
                entry='0x103bda1e', register_table='0x10789cc0',
                host_boundaries=['two counter reads, advanced by nine ticks',
                                 'completion subscriber records original handler arguments'],
                synthetic_parameters=dict(first_words=[2080, 2080, 0, 0],
                    address_fields=['0x10', '0x14', '0x18', '0x1c'],
                    rectangle_fields=['0x2a', '0x2c', '0x2e', '0x30'],
                    size_fields=['0x32', '0x34'], other_flags=0),
                cases=cases, completion_handler='0x103bce38', completion_cases=completion_cases,
                port_bindings=dict(entry='0x103bd188', matrix_rows=4, matrix_columns=16,
                    enable_flags_offset='0x100', cases=binding_cases,
                    enable_entry='0x103bd08a', disable_entry='0x103bd0a2'),
                routed_event_cases=routed_event_cases,
                pixel_transfer_verified=False,
                limitation='Packing, submission and handler event mapping are verified; channel direction, pixel formats, data movement and hardware completion timing remain unverified.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS original processing DMA packing, submission, event mapping and port address banks')
