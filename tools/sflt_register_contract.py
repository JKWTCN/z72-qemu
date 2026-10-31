# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute native SFLT register paths, request construction and command packing."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                              UC_ARM_REG_R3, UC_ARM_REG_SP,
                              UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg, scatter_records


def check(image):
    structure = analyze_eg(image, 'slave')
    storage = []
    for profile, base, capacity, unit, start, length in (
            (0x101f15d0, 0x80800000, 0x2b8f600, 0xe85200, 0x80800000, 0x304f600),
            (0x101f1540, 0xc8900000, 0xdd2200, 0x49b600, 0xc8900000, 0x1e12200)):
        values = struct.unpack_from('<5I2B', image, profile - BASE)
        require((values[1], values[2], values[4]) == (capacity, unit, base),
                'Native SFLT buffer pool profile differs')
        records = [row for row in scatter_records(image) if row['kind'] == 'zero' and
                   row['destination'] == start and row['size'] == length]
        require(len(records) == 1 and base + capacity <= start + length,
                'Native SFLT buffer pool initialization differs')
        storage.append(dict(profile=hex(profile), base=hex(base), capacity=hex(capacity),
                            unit=hex(unit), initialization=records[0]))
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(BASE, (len(image) + 4095) & ~4095)
    cpu.mem_write(BASE, image)
    for address, size in ((0xc1000000, 0xa00000), (0x20203000, 0x1000),
                          (0x50000000, 0x10000), (0xc500c000, 0x1000)):
        cpu.mem_map(address, size)
    for record in scatter_records(image):
        if (record['kind'] == 'copy' and 0xc1000000 <= record['destination'] and
                record['destination'] + record['size'] <= 0xc1a00000):
            offset = record['source'] - BASE
            cpu.mem_write(record['destination'], image[offset:offset + record['size']])
    handle, configuration, request = 0xc100156c, 0x50001000, 0x50002000
    recorder, stop = 0x50004000, 0x5000f000
    writes, registrations, resources, callbacks, events = [], [], [], [], []

    def put(address, *values):
        cpu.mem_write(address, struct.pack('<' + 'I' * len(values), *values))

    def word(address):
        return struct.unpack('<I', cpu.mem_read(address, 4))[0]

    def boundary(uc, address, size, unused):
        first, second = (uc.reg_read(register) for register in (UC_ARM_REG_R0, UC_ARM_REG_R1))
        if address == 0x1006664e:
            resources.append(dict(identifier=hex(first), object=hex(second)))
        elif address == 0x1005ea6a:
            registrations.append(dict(intid=first, handler=hex(second)))
        elif address == recorder:
            callbacks.append(dict(notification=hex(first), configuration=hex(second),
                                  status=hex(word(second + 0x10))))
        elif address == 0x1006a954:
            events.append(dict(object=hex(first), mask=hex(second)))
        else:
            return
        uc.reg_write(UC_ARM_REG_R0, 1)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def memory(uc, access, address, size, value, unused):
        writes.append(dict(address=hex(address), bytes=size, value=hex(value)))

    cpu.hook_add(UC_HOOK_CODE, boundary)
    cpu.hook_add(UC_HOOK_MEM_WRITE, memory, begin=0x20203000, end=0x20203fff)

    def call(address, *arguments):
        for index, register in enumerate((UC_ARM_REG_R0, UC_ARM_REG_R1,
                                          UC_ARM_REG_R2, UC_ARM_REG_R3)):
            cpu.reg_write(register, arguments[index] if index < len(arguments) else 0)
        cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
        cpu.reg_write(UC_ARM_REG_LR, stop | 1)
        cpu.emu_start(address | 1, stop, count=10000)
        require(cpu.reg_read(UC_ARM_REG_PC) == stop, 'Native SFLT routine did not return')

    call(0x1009a4f8)
    require(resources == [dict(identifier='0x111', object=hex(handle))] and
            registrations == [dict(intid=124, handler='0x1009a491')],
            'Native SFLT interrupt registration differs')
    require(cpu.mem_read(0x10168c56, 5) == b'SFLT\0', 'Native interrupt name changed')
    parameters = bytearray(0x34)
    struct.pack_into('<3I', parameters, 0, 1, 0, 1)
    struct.pack_into('<2I', parameters, 0x14, 0x3c8d, 0)
    struct.pack_into('<I', parameters, 0x1c, recorder | 1)
    cpu.mem_write(configuration, bytes(parameters))
    call(0x1009a61a, handle, configuration)
    require(word(handle + 4) == configuration and word(0x20203020) == 0x3c8d,
            'Native SFLT configuration pointer or interrupt mask differs')
    configuration_writes = list(writes)
    writes.clear()
    call(0x1009ac14)
    require(writes == [dict(address='0x20203004', bytes=4, value='0x1')] and
            not callbacks and not events, 'Native start generated a completion')
    start_writes = list(writes)
    cases = []
    for status in (0, 1, 0x400, 0x401, 0x80):
        put(0x2020302c, status)
        writes.clear()
        callbacks.clear()
        events.clear()
        call(0x1009a490)
        acknowledgements = [row for row in writes if row['address'] == '0x2020302c']
        pulses = [int(row['value'], 0) for row in writes if row['address'] == '0x20203000']
        require(acknowledgements == [dict(address='0x2020302c', bytes=4, value=hex(status))],
                'Native SFLT acknowledgement differs')
        require(pulses == [1, 0] * (bool(status & 0x400) + bool(status & 1)),
                'Native SFLT reset-pulse handling differs')
        require(callbacks == [dict(notification='0x41052c01', configuration=hex(configuration),
                                   status=hex(status))], 'Native SFLT callback differs')
        direct_callback = list(callbacks)
        put(configuration + 0x1c, 0x100b4b63)
        put(0xc1007a94, request)
        put(request + 0x98, 0x388d, 0)
        events.clear()
        call(0x1009a490)
        expected = [dict(object='0xc1486dac', mask=hex(bit))
                    for cause, bit in ((0x400, 2), (1, 4)) if status & cause]
        require(events == expected and word(request + 0x94) == status,
                'Native SFLT service-event routing differs')
        cases.append(dict(status=hex(status), acknowledgements=acknowledgements,
                          reset_writes=pulses, callbacks=direct_callback, service_events=list(events)))
        put(configuration + 0x1c, recorder | 1)

    # Execute the original request builder and command packer. Input images
    # and output buffers are intentionally unmapped: these routines describe
    # processing, but do not perform it on the application CPU.
    context, source, resource, block, prepared = (0x50005000, 0x50007000,
                                                0x50007200, 0x50007300, 0x50008000)
    program = 0xc500c000
    coefficients = list(range(-8, 8)) + [-9]
    programs = []
    for width, height in ((128, 32), (8288, 5520)):
        for image_format, mode in ((2, 2), (3, 0), (4, 1)):
            cpu.mem_write(context, bytes(0x180))
            cpu.mem_write(prepared, bytes(0x6f8))
            cpu.mem_write(program, b'\xa5' * 0x1000)
            cpu.mem_write(0xc10014b0, bytes(0xbc))
            stride = width * 2  # Supplied fixture stride; pixel packing is not inferred.
            cpu.mem_write(source + 0x24, struct.pack('<BB3H', image_format, 0,
                                                   stride, width, height))
            put(source + 0x34, 0x90000000)
            put(context + 8, source)
            put(context + 0x54, 0x91000000)
            put(context + 0x68, 0x92000000)
            put(context + 0x138, prepared)
            put(resource + 4, block)
            put(block, 0x93000000)
            put(context + 0x144, resource)
            call(0x1011715c, width, height, 0)
            count = cpu.reg_read(UC_ARM_REG_R0)
            require(count == (4 if width == 128 else 12), 'Native SFLT record count differs')
            cpu.mem_write(context + 0x140, bytes((count, 0)))
            for offset in (50, 84):
                cpu.mem_write(prepared + offset, struct.pack('<17h', *coefficients))
            call(0x10117074, context, request)
            length = 128 + count * 80
            require([word(request + offset) for offset in (0x28, 0x48, 0x68)] ==
                    [0x90000000, 0x91000000, 0x92000000],
                    'Native SFLT source or target ports differ')
            require([word(request + offset) for offset in (0x88, 0x8c, 0x90, 0x98)] ==
                    [prepared, program, length, 0x388d], 'Native SFLT program submission differs')
            call(0x1009a8b2, handle, prepared, program, length)
            require(word(program) == mode and word(program + 4) == stride,
                    'Native SFLT format or stride packing differs')
            require(cpu.mem_read(program + length, 16) == b'\xa5' * 16,
                    'Native SFLT packer wrote beyond its declared program')
            # Each coefficient bank contains 17 signed input halfwords. The
            # first 16 become eight pairs of 10-bit fields; the last is a
            # sign-extended word. These checks establish encoding, not math.
            for offset in (14 * 4, 23 * 4):
                actual = [word(program + offset + index * 4) for index in range(9)]
                expected = [(coefficients[index] & 0x3ff) |
                            ((coefficients[index + 1] & 0x3ff) << 16)
                            for index in range(0, 16, 2)] + [coefficients[16] & 0xffffffff]
                require(actual == expected, 'Native SFLT coefficient packing differs')
            records = []
            for index in range(count):
                geometry = struct.unpack('<2H', cpu.mem_read(prepared + 120 + index * 104, 4))
                words = struct.unpack('<20I', cpu.mem_read(program + 128 + index * 80, 80))
                require(words[0] == geometry[0] | (geometry[1] << 16),
                        'Native SFLT record geometry differs')
                require(list(words[2:9]) == list(struct.unpack('<7I',
                    cpu.mem_read(prepared + 128 + index * 104, 28))),
                    'Native SFLT record address packing differs')
                records.append(dict(index=index, dimensions=list(geometry),
                                    addresses=[hex(value) for value in words[2:9]]))
            programs.append(dict(image_format=image_format, packed_mode=mode,
                dimensions=[width, height], stride=stride, bytes=length, record_count=count,
                header_words=[hex(word(program + index * 4)) for index in range(32)],
                records=records))
    return dict(format=1, result='passed', firmware_included=False,
        slave_sha256=structure['sha256'], name='SFLT', registers='0x20203000',
        registration=registrations, resource_registration=resources,
        configuration_writes=configuration_writes, start_writes=start_writes,
        handler='0x1009a490', service_callback='0x100b4b62', cases=cases,
        program_cases=programs, storage=storage,
        host_boundaries=['Resource and interrupt registration are recorded',
                         'Synthetic register status and configuration; native callbacks execute',
                         'Native service-event publication is recorded at its kernel boundary',
                         'Synthetic context, geometry, strides, addresses and coefficients; image buffers unmapped'],
        limitations=['Plain MMIO storage records W1C writes without implementing hardware clearing',
                     'Calling the handler directly does not prove an interrupt was delivered by hardware',
                     'Command encoding checks do not establish pixel packing or arithmetic',
                     'No DMA command, source pixel, filter calculation or photograph is executed'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.slave.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native SFLT registers, interrupt callbacks, request builder and command packing')
