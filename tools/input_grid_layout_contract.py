# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the original startup and preview grid view constructor."""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


def probe(image):
    native = RegionProbe(image)
    native.u.mem_map(0x20068000, 0x4000)
    output = native.DATA + 0x100
    cases = []
    for selector, variant, columns, rows, field_14 in ((15, 0, 30, 12, 5), (3, 0, 30, 20, 2)):
        template = native.call(0x102ce4f6 - 0x10020000, selector, variant)
        require(0x10020000 <= template < 0x10020000 + len(image), 'Grid template lookup failed')
        native.u.mem_write(output - 4, struct.pack('<I', 0x11223344) + b'\xa5' * 24 +
                           struct.pack('<I', 0x55667788))
        require(native.call(0x102ce622 - 0x10020000, selector, variant, output) == 1,
                'Original grid constructor failed')
        data = bytes(native.u.mem_read(output, 24))
        pitch, actual_columns, actual_rows = (struct.unpack_from('<H', data, at)[0]
                                              for at in (0, 0xa, 0xc))
        require((pitch, actual_columns, actual_rows) == (64, columns, rows),
                'Original grid dimensions or pitch differ')
        require(pitch == ((columns * 2 + 15) & ~15), 'Grid storage pitch differs')
        require(struct.unpack_from('<H', data, 0x14)[0] == field_14,
                'Original grid auxiliary field differs')
        require(data[0xf] == data[0x17] == 0xa5 and
                native.word(output - 4) == 0x11223344 and native.word(output + 24) == 0x55667788,
                'Grid constructor changed padding or adjacent storage')
        # Supply the view to the original analysis builder, which packs the
        # geometry and the auxiliary halfword into independent MMIO fields.
        header = native.DATA + 0x1000
        native.u.mem_write(header, bytes(0x14) + data + bytes(12))
        parameters = bytearray(0x38)
        parameters[0:2] = bytes([selector, variant])
        struct.pack_into('<I', parameters, 0x24, 1)
        struct.pack_into('<I', parameters, 0x30, header)
        native.u.mem_write(native.DATA, bytes(parameters))
        copies_before = len(native.copies)
        require(native.call(0x1023a07e - 0x10020000, native.DATA, 1) == 1,
                'Original grid analysis builder failed')
        registers = [native.word(0x2006a2bc + index * 4) for index in range(6)]
        halves = struct.unpack('<7H', data[:14])
        tag = struct.unpack_from('<H', data, 0x10)[0]
        require(registers == [3, field_14 << 16 | tag, halves[1], halves[2],
                              halves[3] | halves[4] << 10, columns | rows << 8],
                'Original grid analysis MMIO packing differs')
        cases.append(dict(selector=selector, variant=variant, template=hex(template),
            row_bytes=pitch, columns=actual_columns, rows=actual_rows,
            storage_bytes=pitch * rows,
            fields={hex(at): hex(struct.unpack_from('<H', data, at)[0])
                    for at in (*range(0, 0xe, 2), 0x10, 0x12, 0x14)},
            byte_e=data[0xe], byte_16=data[0x16], padding_preserved=True,
            analysis_registers={hex(0x2006a2bc + index * 4): hex(value)
                                for index, value in enumerate(registers)},
            analysis_host_memory_copies=len(native.copies) - copies_before))
    return dict(firmware_included=False, master_sha256=MASTER_SHA,
        lookup='0x102ce4f6', constructor='0x102ce622',
        destination_view_offset='0x14', analysis_builder='0x1023a07e', cases=cases,
        constructor_host_function_boundaries_used=False,
        analysis_host_boundaries=['Bounded memory copies at 0x10360fac; no MMIO or completion substitution.'],
        limitations=['Synthetic selectors; the startup template has independent runtime binding evidence.',
                     'Pitch is aligned from twice the column count; numerical sample interpretation remains unverified.',
                     'The auxiliary field 5 or 2 does not determine sample width in this constructor.',
                     'No pixel transfer, output completion or sensor timing is generated.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('PASS original startup and preview grid layout construction')
