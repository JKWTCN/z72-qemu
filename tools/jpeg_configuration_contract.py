# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify original encoder configuration and start writes without encoding pixels."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import UC_HOOK_MEM_WRITE

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.jpeg_interrupt_contract import EncoderProbe


class ConfigurationProbe(EncoderProbe):
    def __init__(self, image):
        super().__init__(image)
        self.writes = []
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write, begin=0x24073000, end=0x24073fff)

    def write(self, u, access, address, size, value, unused):
        self.writes.append(dict(address=hex(address), bytes=size, value=hex(value)))


def source_mapping(native):
    request, image, output, job, descriptor = [native.DATA + offset for offset in
                                              (0x2000, 0x2100, 0x2200, 0x2300, 0x2400)]
    source = bytearray(0x20)
    source[0] = 1
    struct.pack_into('<2H', source, 2, 640, 320)
    struct.pack_into('<2H', source, 0xa, 640, 480)
    struct.pack_into('<2I', source, 0x14, 0x53000000, 0x53100000)
    native.u.mem_write(image, bytes(source))
    native.u.mem_write(output, struct.pack('<3I', 0, 0, 0x53200000))
    native.u.mem_write(request, struct.pack('<3I', image, output, 0x100000) + bytes(0x34))
    native.call(0x102b3d14 - 0x10020000, request, 0, job)
    native.call(0x102e431a - 0x10020000, job, descriptor)
    native.writes.clear()
    native.events.clear()
    native.call(0x103696e4 - 0x10020000, 0xb1801eb4, descriptor)
    mapping = {0x24073410: 640, 0x24073414: 320,
               0x24073418: 640, 0x2407341c: 480,
               0x24073430: 0x53000000, 0x24073434: 0x53100000,
               0x24073440: 0x53200000, 0x24073458: 0x800}
    require(all(native.word(address) == value for address, value in mapping.items()),
            'Original image/job/encoder field route differs')
    require(not native.events, 'Source configuration manufactured an encoder notification')
    return dict(image_builder='0x102b3d14', descriptor_builder='0x102e431a',
        image_fields={'0x2': 640, '0x4': 320, '0xa': 640, '0xc': 480,
                      '0x14': '0x53000000', '0x18': '0x53100000'},
        output_descriptor_field_8='0x53200000', request_field_8='0x100000',
        registers={hex(address): hex(value) for address, value in mapping.items()},
        interpretation='Image halfwords 2/4 become DMA geometry; image pointers 0x14/0x18 '
                       'and output descriptor pointer 8 use separate register groups')


def check(image):
    native = ConfigurationProbe(image)
    descriptor = native.DATA + 0x200
    tables = [bytes(range(64)), bytes(range(64, 128))]
    for index, table in enumerate(tables):
        native.u.mem_write(native.DATA + 0x1000 + index * 64, table)
    cases = []
    for scale in range(4):
        native.u.mem_write(0x24073000, bytes(0x1000))
        parameters = bytearray(0xb0)
        struct.pack_into('<2I', parameters, 0, 1, 1)
        parameters[0x14] = 3
        struct.pack_into('<2H', parameters, 0x16, 640, 480)
        struct.pack_into('<4I', parameters, 0x1c, native.DATA + 0x1000, 5,
                         native.DATA + 0x1040, 2)
        parameters[0x52] = scale
        struct.pack_into('<I', parameters, 0x58, 256)
        struct.pack_into('<Q', parameters, 0x60, 513)
        fields = {0x68: 0x53000000, 0x6c: 0x53100000, 0x70: 0x52000000,
                  0x74: 0x52080000, 0x78: 0x53200000, 0x98: 0x1000, 0x9c: 0x1234,
                  0xa8: native.RECORDER | 1}
        for offset, value in fields.items():
            struct.pack_into('<I', parameters, offset, value)
        native.u.mem_write(descriptor, bytes(parameters))
        native.writes.clear()
        native.events.clear()
        native.call(0x3496e4, 0xb1801eb4, descriptor)
        require(native.word(0xb1801eb8) == descriptor, 'Configuration did not bind the current descriptor')
        require(not native.events, 'Configuration manufactured an encoder notification')
        require(native.u.mem_read(0x24073000, 1) == bytes([0x1b]) and
                native.u.mem_read(0x24073003, 1) == bytes([4]), 'Encoder byte mode or table selection differs')
        require(bytes(native.u.mem_read(0x24073100, 64)) == tables[0] and
                bytes(native.u.mem_read(0x24073140, 64)) == tables[1], 'Quantization table copy differs')
        dimensions = bytes(native.u.mem_read(0x24073007, 4))
        expected = struct.pack('>2H', 480 >> scale, 640 >> scale)
        require(dimensions == expected, 'Header dimension byte order or scale differs')
        mapping = {0x24073410: fields[0x70], 0x24073414: fields[0x74],
                   0x24073418: 640, 0x2407341c: 480, 0x24073430: fields[0x68],
                   0x24073434: fields[0x6c], 0x24073440: fields[0x78],
                   0x24073450: 256, 0x24073458: 1,
                   0x24073484: fields[0x98], 0x240734f0: fields[0x9c]}
        require(all(native.word(address) == value for address, value in mapping.items()),
                'Encoder descriptor-to-register mapping differs')
        configuration_writes = list(native.writes)
        native.u.mem_write(0x24073001, bytes([0x40]))
        native.u.mem_write(descriptor + 0x88, struct.pack('<3I', 99, 0, 0xffffffff))
        native.u.mem_write(0xb1801eb0, struct.pack('<I', 0xffffffff))
        native.writes.clear()
        native.events.clear()
        native.call(0x34991a, 0xb1801eb4)
        require(native.word(descriptor + 0x88) == 0 and native.word(descriptor + 0x90) == 0 and
                native.word(0xb1801eb0) == 0, 'Start retained old encoder results')
        require(native.u.mem_read(0x24073001, 1) == bytes([0x41]) and
                native.word(0x24073400) & 0xc000 == 0x4000 and
                native.word(0x24073404) & 0xc000 == 0x4000, 'Encoder start control writes differ')
        require(not native.events, 'Configuration or start manufactured an encoder notification')
        cases.append(dict(scale=scale, header_dimensions=dimensions.hex(),
            registers={hex(address): hex(value) for address, value in mapping.items()},
            configuration_writes=configuration_writes, start_writes=list(native.writes)))
    source = source_mapping(native)
    return dict(format=1, result='passed', firmware_included=False, master_sha256=MASTER_SHA,
        configure='0x103696e4', start='0x1036991a', current_pointer='0xb1801eb8', cases=cases,
        source_mapping=source,
        host_boundaries=['supply synthetic descriptors, quantization tables and MMIO storage',
                         'record register writes; no hardware events are supplied'],
        limitations=['Synthetic image, output descriptor and request; pixel layout and DMA semantics remain unverified',
                     'No source pixels, encoded bitstream, photo completion or card file are produced'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original encoder configuration: descriptor mapping, tables, dimensions and start writes')
