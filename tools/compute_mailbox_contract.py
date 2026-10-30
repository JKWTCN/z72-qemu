# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the original slave mailbox sender and reply callbacks in isolation."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                              UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg, scatter_records


def check(image):
    structure = analyze_eg(image, 'slave')
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(BASE, (len(image) + 4095) & ~4095)
    cpu.mem_write(BASE, image)
    cpu.mem_map(0xc1000000, 0xa00000)
    cpu.mem_map(0x24061000, 0x1000)
    cpu.mem_map(0x50000000, 0x4000)
    for record in scatter_records(image):
        if (record['kind'] == 'copy' and 0xc1000000 <= record['destination'] and
                record['destination'] + record['size'] <= 0xc1a00000):
            offset = record['source'] - BASE
            cpu.mem_write(record['destination'], image[offset:offset + record['size']])
    events = []

    def word(address):
        return int.from_bytes(cpu.mem_read(address, 4), 'little')

    def put(address, value):
        cpu.mem_write(address, struct.pack('<I', value))

    def boundary(uc, address, size, unused):
        if address in (0x10066b2c, 0x10066b3c, 0x100f9786, 0x100f978c, 0x100f9794):
            arguments = [uc.reg_read(register) for register in
                         (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
            if address in (0x100f9786, 0x100f978c, 0x100f9794):
                events.append(dict(entry=hex(address), object=hex(arguments[0]),
                                   mask=hex(arguments[1])))
            if address == 0x100f9794:
                put(arguments[2], 0)
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, boundary)
    engine, channel, packet = 0xc100644c, 0x24061100, 0x50002000
    stop = 0x50001000

    def call(address, first=0, second=0):
        cpu.reg_write(UC_ARM_REG_R0, first)
        cpu.reg_write(UC_ARM_REG_R1, second)
        cpu.reg_write(UC_ARM_REG_SP, 0x50000800)
        cpu.reg_write(UC_ARM_REG_LR, stop | 1)
        cpu.emu_start(address | 1, stop, count=10000)
        require(cpu.reg_read(UC_ARM_REG_PC) == stop, 'Native mailbox call did not return')
        return cpu.reg_read(UC_ARM_REG_R0)

    template = struct.pack('<5I', 0x154, 0x01ff0001, 0, 0x10059263, 0)
    cpu.mem_write(engine, template)
    put(0xc1006408, engine)
    call(0x10060c64, engine)
    put(0x50002000, 2)
    put(0x50002004, 0)
    put(0x50002008, 0xc1690a8c)
    accepted = call(0x100594b2, 0, packet)
    require(accepted == 1 and word(channel + 4) == 3 and word(channel + 8) == 1 and
            word(channel + 0x10) == 4 and word(channel + 0x40) == 0 and
            word(channel + 0x44) == 0xc1690a8c, 'Native outgoing mailbox recipe differs')
    require(events == [dict(entry='0x100f978c', object='0xc1006418', mask='0x1'),
                       dict(entry='0x100f9794', object='0xc1006418', mask='0x1')],
            'Native sender wait object differs')
    outgoing = dict(accepted=accepted, registers={hex(offset): hex(word(channel + offset))
        for offset in (0, 4, 8, 0x10, 0x40, 0x44)}, events=events.copy())

    events.clear()
    put(channel + 0x38, 1)
    put(0x24061080, 0x100)
    call(0x10060860)
    require(word(channel + 0x34) == 1 and
            events == [dict(entry='0x100f9786', object='0xc1006418', mask='0x1')],
            'Native request acknowledgement differs')
    acknowledgement = dict(interrupt=227, queue_head='0x24061080', head_value='0x100',
                            response_mask=hex(word(channel + 0x38)),
                            clear=hex(word(channel + 0x34)), events=events.copy())

    replies = []
    for slot, result in zip((0, 1, 4, 7), (0, 1, 2, 0xffffffff)):
        events.clear()
        cpu.mem_write(0xc144dc08, template)
        put(0xc1006414, 0x10054a01)
        words = [result, *range(0x21, 0x29)]
        reply_channel = channel + slot * 0x80
        cpu.mem_write(reply_channel + 0x40, struct.pack('<9I', *words))
        put(0x24061084, 0x100 + slot * 0x80)
        call(0x1006085a)
        require(word(0xc144dc20) == result and word(0xc14758ec) == result and
                cpu.mem_read(0xc144dc1c, 1) == b'\x09' and word(reply_channel + 0x14) == 2 and
                events == [dict(entry='0x100f9786', object='0xc1007170', mask='0x1')],
                'Native nine-word result forwarding differs')
        replies.append(dict(interrupt=228, queue_head='0x24061084',
            head_value=hex(0x100 + slot * 0x80), slot=slot,
            words=[hex(value) for value in words],
            copied_words=[hex(word(0xc144dc20 + index * 4)) for index in range(9)],
            result=hex(word(0xc14758ec)), request_clear=hex(word(reply_channel + 0x14)),
            events=events.copy()))
    events.clear()
    put(0xc1006414, 0)
    call(0x1006085a)
    require(not events, 'Missing callback still signaled completion')
    return dict(format=1, result='passed', firmware_included=False,
        slave_sha256=structure['sha256'], outgoing=outgoing,
        acknowledgement=acknowledgement, replies=replies, missing_callback_events=events.copy(),
        host_boundaries=['Synthetic engine, packet, MMIO words and reply payloads',
                         'Accept uncontended locks; record event operations and return immediately from waits'],
        limitations=['No hardware interrupt is raised and no processor program is executed',
                     'Acceptance and synthetic replies do not prove calculation or an encoded photograph',
                     'Four synthetic result values are forwarded verbatim; their application meaning is not established'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.slave.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original mailbox send, request acknowledgement and separate nine-word results')
