# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare the master and slave compute payloads using native load metadata."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from tools.compute_program_layout import check


def compare(master, slave):
    master_info = analyze_eg(master, 'master')
    slave_layout = check(slave)
    # Literal pool used by the original master initializer 0x1024493a.
    length_word, source, destination, entry = struct.unpack_from('<4I', master, 0x10244a30 - BASE)
    require((length_word, source, destination, entry) ==
            (0x122d4740, 0x122acf40, 0x50200000, 0x5020c000), 'Native master load literals differ')
    length = struct.unpack_from('<I', master, length_word - BASE)[0]
    require(length == slave_layout['length'], 'Native upload lengths differ')
    left = master[source - BASE:source - BASE + length]
    right_start = int(slave_layout['source'], 0) - BASE
    right = slave[right_start:right_start + length]
    slave_base = int(slave_layout['destination'], 0)
    delta = slave_base - destination
    normalized = bytearray(left)
    candidates = []
    for offset in range(length - 3):
        master_word = struct.unpack_from('<I', left, offset)[0]
        slave_word = struct.unpack_from('<I', right, offset)[0]
        if slave_base <= slave_word < slave_base + length and slave_word - master_word == delta:
            candidates.append(offset)
            normalized[offset:offset + 4] = right[offset:offset + 4]
    tables = []
    for offset, count, target_offset in ((0x6d9c, 32, 0x2420a), (0x8734, 8, 0x24e32)):
        require(set(struct.unpack_from('<' + 'I' * count, left, offset)) == {destination + target_offset},
                'Master repeated internal-address table differs')
        tables.append(dict(offset=hex(offset), count=count,
            master_target=hex(destination + target_offset), slave_target=hex(slave_base + target_offset)))
    require(left[0x8754:0x877c] == right[0x8754:0x877c], 'Message address tables differ')
    require(normalized[0xc000:0xc040] == right[0xc000:0xc040],
            'Address-difference candidates do not account for the first 64 entry bytes')
    return dict(format=1, result='passed', firmware_included=False,
        master_sha256=master_info['sha256'], slave_sha256=slave_layout['slave_sha256'],
        master_load=dict(initializer='0x1024493a', copy_call='0x10244966',
            configure_call='0x1024498c', source=hex(source), destination=hex(destination),
            length_word=hex(length_word), length=length, entry=hex(entry)),
        master_program_sha256=hashlib.sha256(left).hexdigest(),
        slave_program_sha256=slave_layout['program_sha256'], address_difference=hex(delta),
        raw_equal_bytes=sum(a == b for a, b in zip(left, right)),
        candidate_word_offsets=[hex(value) for value in candidates],
        differences_after_candidate_replacement=sum(a != b for a, b in zip(normalized, right)),
        first_64_entry_bytes_equal_after_replacement=True, repeated_address_tables=tables,
        message_address_table_equal=True,
        limitations=['Static load literals and payloads are checked; no master initializer is executed',
                     'Candidate four-byte spans in code may mix opcode and immediate bits',
                     'Candidate replacement is an offline comparison, not a firmware relocation rule',
                     'Other differences remain; the complete programs are not equivalent',
                     'No instruction semantics, RAW calculation or photograph is established'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.master.read_bytes(), args.slave.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native master upload metadata, paired address tables and bounded entry comparison')
