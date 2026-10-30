# SPDX-License-Identifier: GPL-2.0-or-later
"""Check embedded compute-program tables against the native mailbox layout."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from analyze.firmware_structure import analyze_eg


def check(image):
    structure = analyze_eg(image, 'slave')
    source, destination, length = 0x10834b54, 0x80300000, 0x27800
    program = image[source - 0x10020000:source - 0x10020000 + length]
    digest = hashlib.sha256(program).hexdigest()
    require(len(program) == length and digest ==
            '3d4ec1c8d56984cc296d732cd5d9dc06b5fdcaeb74b811cd92f3c013dbfe4dac',
            'Program differs from the observed native upload')

    def words(offset, count):
        return struct.unpack_from('<' + 'I' * count, program, offset)

    pointer_runs = []
    for offset, count, expected in ((0x6d9c, 32, 0x8032420a),
                                    (0x8734, 8, 0x80324e32)):
        values = words(offset, count)
        require(set(values) == {expected}, 'Repeated program pointer table differs')
        require(destination <= expected < destination + length,
                'Program pointer outside uploaded span')
        pointer_runs.append(dict(offset=hex(offset), address=hex(destination + offset),
            count=count, target=hex(expected), target_offset=hex(expected - destination)))
    device = words(0x8754, 10)
    host = [0x24061088, *[0x24061100 + index * 0x80 for index in range(8)], 0x24061900]
    require(list(device) == [value + 0x10000000 for value in host],
            'Program address table differs from the host mailbox layout')
    table = [dict(index=index, program_address=hex(device[index]),
                  host_address=hex(host[index]), difference='0x10000000')
             for index in range(10)]
    # Scan byte positions, without assuming instruction size or boundaries.
    references = []
    for value in (0x80306d9c, 0x80308734, 0x34061080, 0x34061084,
                  0x34061088, 0x34061100, 0x34061900):
        needle = struct.pack('<I', value)
        offsets = []
        start = 0
        while (found := program.find(needle, start)) >= 0:
            offsets.append(hex(found))
            start = found + 1
        references.append(dict(value=hex(value), literal_offsets=offsets))
    return dict(format=1, result='passed', firmware_included=False,
        slave_sha256=structure['sha256'], program_sha256=digest,
        source=hex(source), destination=hex(destination), length=length,
        configured_entry='0x8030c000', repeated_program_pointers=pointer_runs,
        mailbox_address_table=dict(offset='0x8754', entries=table),
        literal_search=references,
        limitations=['Table words are data observations, not decoded instructions',
                     'Equal layout and fixed address difference do not prove hardware aliases',
                     'Repeated targets are candidates; callback or interrupt roles are unproven',
                     'No processor architecture, request dispatcher or RAW calculation is identified'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.slave.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native uploaded program tables and host mailbox layout comparison')
