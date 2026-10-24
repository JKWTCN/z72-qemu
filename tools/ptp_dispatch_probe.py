# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise C 1.70 PTP routing and diagnostic gates on synthetic RAM.

Requires Unicorn and a locally supplied original master image. Transport
buffer/reply and bulk copy are host boundaries; command routing, string
matching, configuration reads and debug queue admission execute original code.
The memory dump callback runs separately on synthetic RAM with its print sink
captured. No USB device is opened and no firmware or key bytes are exported.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require, validate_master
from analyze.firmware_structure import scatter_records
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_R0,
                               UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)


class Probe:
    STOP = 0x50020000
    INPUT = 0x50000000
    ARGV = INPUT + 0x1000
    SAMPLE = INPUT + 0x2000

    def __init__(self, image):
        validate_master(image)
        self.u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        self.u.mem_map(BASE, (len(image) + 4095) & ~4095)
        self.u.mem_map(0xB1800000, 0x4800000)
        self.u.mem_map(self.INPUT, 0x30000)
        self.u.mem_write(BASE, image)
        for record in scatter_records(image):
            if record['kind'] == 'copy':
                start = record['source'] - BASE
                self.u.mem_write(record['destination'], image[start:start + record['size']])
        self.regs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
        self.responses, self.prints, self.reads = [], [], []
        self.hooks = {0x61C384: self.input_buffer, 0x61C4FC: self.reply,
                      0x340FAC: self.copy}
        self.u.hook_add(UC_HOOK_CODE, self.code)
        self.u.hook_add(UC_HOOK_MEM_READ, self.memory_read,
                        begin=self.SAMPLE, end=self.SAMPLE + 0x3FF)
        self.config = struct.unpack_from('<I', image, 0x3A0AC8)[0] + 0x4D6
        self.queue = struct.unpack_from('<I', image, 0x39C878)[0]
        self.buffer = struct.unpack_from('<I', image, 0x39C87C)[0] - 0x80
        self.enable = struct.unpack_from('<I', image, 0x39C96C)[0]

    def word(self, address):
        return struct.unpack('<I', self.u.mem_read(address, 4))[0]

    def put_word(self, address, value):
        self.u.mem_write(address, struct.pack('<I', value))

    def string(self, address):
        result = bytearray()
        for i in range(512):
            value = self.u.mem_read(address + i, 1)[0]
            if not value:
                return result.decode('ascii')
            result.append(value)
        raise ValueError('Unterminated diagnostic string')

    def code(self, u, address, size, unused):
        if address == self.STOP:
            u.emu_stop()
        elif address - BASE in self.hooks:
            args = [u.reg_read(r) for r in self.regs]
            result = self.hooks[address - BASE](*args)
            u.reg_write(UC_ARM_REG_R0, result)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))

    def memory_read(self, u, access, address, size, value, unused):
        self.reads.extend(range(address, address + size))

    def input_buffer(self, *args):
        return self.INPUT

    def reply(self, packet, response, *args):
        self.responses.append(response)
        return 0

    def copy(self, destination, source, count, unused):
        require(count <= 0x1000, 'Unexpected bulk copy')
        self.u.mem_write(destination, bytes(self.u.mem_read(source, count)))
        return destination

    def print_sink(self, *args):
        self.prints.append(self.string(args[0]))
        return 0

    def call(self, offset, *args):
        for reg, value in zip(self.regs, (*args, 0, 0, 0, 0)):
            self.u.reg_write(reg, value)
        self.u.reg_write(UC_ARM_REG_SP, self.INPUT + 0x18000)
        self.u.reg_write(UC_ARM_REG_LR, self.STOP | 1)
        self.u.emu_start(BASE + offset | 1, self.STOP, count=100000)
        require(self.u.reg_read(UC_ARM_REG_PC) == self.STOP,
                'Native function did not return: ' + hex(offset))
        return self.u.reg_read(UC_ARM_REG_R0)

    def run(self):
        tables = []
        for selector in range(10):
            table = self.call(0x458EBC, selector)
            records = []
            if table:
                for index in range(256):
                    address = table + index * 28
                    words = struct.unpack('<7I', self.u.mem_read(address, 28))
                    if words[0] == 0:
                        break
                    require(self.call(0x458EF6, table, words[0]) == address,
                            'Linear lookup mismatch')
                    routed = self.call(0x443D70, words[0])
                    require(routed in (0, address), 'Router returned a different record')
                    require(self.call(0x443D70, words[0]) == routed, 'Cache mismatch')
                    records.append(dict(opcode=hex(words[0]), address=hex(address),
                                        fields=[hex(v) for v in words[1:]],
                                        routed=bool(routed)))
                else:
                    raise ValueError('Unterminated PTP table')
            tables.append(dict(selector=selector, table=hex(table), records=records))
        negative = [0, 0x1000, 0x90FF, 0x9100, 0x92E0, 0x92F1, 0x94FC, 0xFFFF]
        for opcode in negative:
            require(self.call(0x443D70, opcode) == 0, 'Unexpected negative route')
        gate_cases = []
        initial_config = self.u.mem_read(self.config, 1)[0]
        initial_enable = self.u.mem_read(self.enable, 1)[0]
        for offset in (0x42415E, 0x4243BC):
            for value in (0, 1):
                self.u.mem_write(self.config, bytes([value]))
                self.responses.clear()
                result = self.call(offset, 0, self.INPUT)
                expected = [] if value else [0x2005]
                require(result == value and self.responses == expected, 'Gate mismatch')
                gate_cases.append(dict(callback=hex(BASE + offset), flag=value,
                                       result=result, responses=[hex(v) for v in expected]))
        names = []
        for index in range(32):
            address = 0xB188B7FC + index * 12
            callback, name, help_text = struct.unpack('<3I', self.u.mem_read(address, 12))
            if not callback:
                break
            names.append(dict(name=self.string(name), callback=hex(callback)))
        queue_cases = []
        # Harmless text command; memory callbacks are exercised separately.
        for name, command, enabled, busy, accepted in (
                ('enabled', 'debug help', 1, 0, True),
                ('disabled', 'debug help', 0, 0, False),
                ('busy', 'debug help', 1, 1, False),
                ('maximum', 'debug ' + 'x' * 127, 1, 0, True),
                ('too_long', 'debug ' + 'x' * 128, 1, 0, False),
                ('unknown', 'unknown', 1, 0, False)):
            self.u.mem_write(self.INPUT, command.encode('ascii') + b'\0')
            self.u.mem_write(self.enable, bytes([enabled]))
            self.put_word(self.queue + 8, busy)
            self.put_word(self.queue + 0x18, 0)
            self.u.mem_write(self.buffer, b'\0' * 256)
            self.responses.clear()
            require(self.call(0x42418A, 0, self.INPUT) == 1, 'Diagnostic dispatch failed')
            length = self.word(self.queue + 0x18)
            expected = command[6:].encode('ascii') + b'\n' if accepted else b''
            require(length == len(expected), 'Queue admission mismatch: ' + name)
            require(bytes(self.u.mem_read(self.buffer, max(1, length))) == (expected or b'\0'),
                    'Queue content mismatch')
            require(self.responses == [0x2001], 'Diagnostic response mismatch')
            queue_cases.append(dict(case=name, admitted=accepted, queued_length=length,
                                    response='0x2001'))
        self.hooks[0x3BA804] = self.print_sink
        self.u.mem_write(self.SAMPLE, bytes(range(256)) * 4)
        dumps = []
        for count, size, expected in ((2, 8, 16), (2, 0, 512), (1, 0, 512)):
            self.u.mem_write(self.ARGV, struct.pack('<2I', self.SAMPLE, size))
            self.prints.clear()
            self.reads.clear()
            self.call(0x39C82C, 0, self.ARGV, count)
            addresses = sorted(set(self.reads))
            require(addresses == list(range(self.SAMPLE, self.SAMPLE + expected)),
                    'Memory dump read extent mismatch')
            require(len(self.prints) == 1 + expected // 16, 'Dump print count mismatch')
            dumps.append(dict(argument_count=count, requested_size=size,
                              synthetic_bytes_read=expected, print_calls=len(self.prints)))
        # Separate execution of the RAM-resident print appender; this does not
        # establish that the diagnostic print flags select it on a camera.
        require(self.word(BASE + 0x30B770) == 0xB2BB0001 and
                self.word(0xB2BB0118) == 0xB18004F0 and
                self.word(0xB2BB011C) == 0xB1C81898, 'Print appender binding mismatch')
        self.u.mem_write(self.INPUT, b'probe\0')
        self.put_word(0xB18004F0, 0)
        self.call(0xB2BB0000 - BASE, self.INPUT)
        require(self.word(0xB18004F0) == 6 and
                bytes(self.u.mem_read(0xB1C81898, 7)) == b'probe\n\0',
                'Print appender mismatch')
        self.put_word(0xB18004F0, 0x5FFFE)
        self.call(0xB2BB0000 - BASE, self.INPUT)
        require(self.word(0xB18004F0) == 0x5FFFE, 'Print capacity gate mismatch')
        require(sum(len(t['records']) for t in tables) == 161, 'Record count mismatch')
        unrouted = [r['opcode'] for t in tables for r in t['records'] if not r['routed']]
        require(unrouted == ['0x9535'] + [r['opcode'] for r in tables[4]['records']],
                'Unexpected unrouted command set: ' + repr(unrouted))
        return dict(format=1, master_sha256=MASTER_SHA, tables=tables,
                    negative_routes=[hex(v) for v in negative], unrouted_opcodes=unrouted,
                    diagnostic_gate_address=hex(self.config),
                    debug_enable_address=hex(self.enable),
                    initial_fixture_bytes=dict(diagnostic=initial_config, debug=initial_enable),
                    gate_cases=gate_cases, text_commands=names, queue_cases=queue_cases,
                    memory_dump_cases=dumps,
                    print_appender=dict(entry='0xb2bb0000', buffer='0xb1c81898',
                                        count='0xb18004f0', capacity=0x60000,
                                        synthetic_append_verified=True,
                                        capacity_rejection_verified=True),
                    host_boundaries=['transport input buffer', 'transport response',
                                     'bulk copy', 'memory dump print sink'],
                    camera_usb_access_verified=False, real_boot_material_recovered=False,
                    k8_recovered=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = Probe(args.master.read_bytes()).run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS 161 PTP records, router/cache boundaries, diagnostic gates, queue and synthetic dump')
