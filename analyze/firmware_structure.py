# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate and describe C1.70 EG startup, initialization and task structures."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, crc, digest, require


@dataclass(frozen=True)
class EgProfile:
    role: str
    size: int
    sha256: str
    boot: int
    literals: int
    scatter_count: int
    tasks_start: int
    tasks_count: int
    windows: tuple


PROFILES = {
    'master': EgProfile('master', 38239098,
        '478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe',
        0xBC88, 0xBFC8, 20, 0x2425508, 293,
        ((0x100, 0x140, 0x420), (0xB18, 0xB19, 0x460), (0xB19, 0xB20, 0x461),
         (0xB20, 0xB2C, 0x480), (0xB2C, 0xB5F, 0x492), (0xB5F, 0xB60, 0x490),
         (0xB7C, 0xB7D, 0x491))),
    'slave': EgProfile('slave', 8834370,
        'e0d2589cf036bbf8ce6e4c32f5f2bab61fe35e863660bf6a0ee8082d8a64e1bb',
        0xBCD4, 0xC014, 15, 0x852084, 97,
        ((0x100, 0x140, 0x420), (0xC10, 0xC1A, 0x460), (0xC1A, 0xC50, 0x482),
         (0xC50, 0xC51, 0x480), (0xC60, 0xC61, 0x481))),
}


def u32(image, offset):
    require(0 <= offset <= len(image) - 4, 'Word outside firmware')
    return struct.unpack_from('<I', image, offset)[0]


def branch_target(image, offset):
    word = u32(image, offset)
    require(word & 0xFF000000 == 0xEA000000, 'Expected unconditional ARM branch')
    displacement = word & 0xFFFFFF
    if displacement & 0x800000:
        displacement -= 0x1000000
    return offset + 8 + displacement * 4


def literal(image, offset, register):
    word = u32(image, offset)
    require(word & 0xFF7FF000 == (0xE51F0000 | register << 12),
            'Expected ARM PC-relative literal load')
    displacement = word & 0xFFF
    address = offset + 8 + (displacement if word & 0x800000 else -displacement)
    return u32(image, address)


def scatter_records(image, offset=0x14000, max_records=64):
    """Decode copy/zero records without allocating their destination ranges.

    Zero records reuse source pointers; their sizes are not file read lengths.
    Handler offsets identify the verified Thumb copy and zero implementations.
    """
    records = []
    for index in range(max_records + 1):
        position = offset + index * 16
        require(position + 16 <= len(image) - 2, 'Truncated initialization table')
        source, destination, size, handler = struct.unpack_from('<4I', image, position)
        if not any((source, destination, size, handler)):
            return records
        require(index < max_records, 'Unterminated initialization table')
        require(handler in (BASE + 0x6C, BASE + 0x88), 'Unknown initialization handler')
        require(size > 0 and size % 4 == 0 and destination % 4 == 0,
                'Invalid initialization alignment/size')
        require(destination + size <= 1 << 32, 'Initialization destination overflow')
        kind = 'copy' if handler == BASE + 0x6C else 'zero'
        if kind == 'copy':
            require(BASE <= source and source + size <= BASE + len(image) - 2,
                    'Initialization source outside firmware payload')
        records.append(dict(table_offset=position, kind=kind, source=source,
                            destination=destination, size=size, handler=handler))
    raise ValueError('Unterminated initialization table')


def task_records(image, start, count):
    records = []
    for index in range(count):
        offset = start + index * 28
        require(offset + 28 <= len(image) - 2, 'Truncated task table')
        raw, *fields = struct.unpack_from('<12s4I', image, offset)
        name = raw.rstrip(b'\0')
        require(name and all(0x20 <= c < 0x7F for c in name), 'Invalid task name')
        records.append(dict(offset=offset, name=name.decode('ascii'), fields=fields))
    return records


def thumb_literal(image, offset, register):
    """Resolve a little-endian Thumb T1 LDR literal in member-file space."""
    require(0 <= offset <= len(image) - 2, 'Thumb instruction outside firmware')
    word = struct.unpack_from('<H', image, offset)[0]
    require(word & 0xFF00 == (0x4800 | register << 8),
            'Expected Thumb PC-relative literal load')
    return u32(image, ((offset + 4) & ~3) + (word & 0xFF) * 4)


def communication_stores(image, entry):
    """Decode the verified communication header store sequence by semantics.

    The stock sequence is a PC-relative literal load of the local window
    address (r0), a zero register (r1), literal loads of both magic words
    (r2/r3), then word stores at window offsets 0x0 (r2), 0x4/0x8 (STRD
    r1/r3) and 0x10 (r1). Single-instruction encodings are pinned where the
    documented store pattern fully determines them; the original byte
    sequence is not redistributed with this project.
    """
    require(0 <= entry and entry + 16 <= len(image) - 2,
            'Communication header outside firmware')
    words = struct.unpack_from('<8H', image, entry)
    require(all(w & 0xF800 == 0x4800 for w in (words[0], words[2], words[3])) and
            words[0] >> 8 & 7 == 0 and words[2] >> 8 & 7 == 2 and
            words[3] >> 8 & 7 == 3,
            'Expected PC-relative literal loads into r0/r2/r3')
    require(words[1] == 0x2100, 'Expected MOVS r1, #0 before the stores')
    require(words[4] & 0xF800 == 0x6000 and words[4] >> 6 & 0x1F == 0 and
            words[4] >> 3 & 7 == 0 and words[4] & 7 == 2,
            'Expected STR r2, [r0] at window offset 0')
    require(words[5] == 0xE9C0 and words[6] >> 12 == 3 and
            words[6] >> 8 & 0xF == 1 and words[6] & 0xFF == 1,
            'Expected STRD r1, r3, [r0, #4] at window offsets 4 and 8')
    require(words[7] & 0xF800 == 0x6000 and words[7] >> 6 & 0x1F == 4 and
            words[7] >> 3 & 7 == 0 and words[7] & 7 == 1,
            'Expected STR r1, [r0, #0x10] at window offset 0x10')


def communication_header(image, role, records):
    """Describe only the verified stores after the OS calls, before the POP.

    Offsets 0x0C and 0x14 are untouched by this block. Their meanings and
    the physical connection between the two local windows remain unresolved.
    """
    entry = {'master': 0x367E20, 'slave': 0x40CD8}[role]
    address = {'master': 0xB7CF0000, 'slave': 0xC60F0000}[role]
    communication_stores(image, entry)
    actual = thumb_literal(image, entry, 0)
    magic = [thumb_literal(image, entry + 4, 2), thumb_literal(image, entry + 6, 3)]
    require(actual == address and magic == [0x00C00108, 0xAA550001],
            'Communication header literals mismatch')
    zero = [r for r in records if r['kind'] == 'zero' and r['destination'] == address]
    require(len(zero) == 1 and zero[0]['size'] == 0xC618,
            'Communication header zero record mismatch')
    return dict(local_address=address, zero_size=zero[0]['size'],
                entry_offset=entry, stop_offset=entry + 16, instruction_state='Thumb',
                writes=[dict(offset=offset, value=value)
                        for offset, value in zip((0, 4, 8, 0x10), (*magic, 0, 0))],
                untouched_word_offsets=[0xC, 0x14],
                full_initializer_verified=False, inter_engine_transport_verified=False)


def section_mapping(image, address):
    """Decode a short-descriptor section; reject faults, tables and supersections."""
    require(0 <= address < 1 << 32, 'Section address outside 32-bit space')
    descriptor = u32(image, 0x10000 + (address >> 20) * 4)
    require(descriptor & 3 == 2 and not descriptor & (1 << 18),
            'Expected ordinary section descriptor')
    return dict(virtual_address=address, descriptor=descriptor,
                physical_address=(descriptor & 0xFFF00000) | (address & 0xFFFFF),
                domain=(descriptor >> 5) & 15,
                access_permissions=((descriptor >> 10) & 3) | ((descriptor >> 13) & 4),
                execute_never=bool(descriptor & 16))


def boot_prefix(image, profile):
    """Describe the uninterrupted core-zero path up to its first MMIO store."""
    delta = profile.boot - 0xBC88
    stop = 0xBDA4 + delta
    require(u32(image, stop) == 0xE5801000 and
            u32(image, stop - 4) == 0xE3A01021,
            'First boot MMIO store mismatch')
    address = literal(image, stop - 8, 0)
    require(address == 0x04264000, 'First boot MMIO address mismatch')
    checkpoints = [dict(offset=offset + delta, mode=mode, stack_top=u32(
        image, profile.literals + 16 + index * 4))
        for index, (offset, mode) in enumerate(zip(
            (0xBD44, 0xBD54, 0xBD64, 0xBD74, 0xBD84, 0xBD94),
            (0x1B, 0x17, 0x11, 0x12, 0x1F, 0x13)))]
    mappings = [section_mapping(image, address) for address in
                (BASE, BASE + profile.boot, BASE + 0x10000,
                 *(c['stack_top'] - 4 for c in checkpoints), 0x04264000)]
    require(all(m['virtual_address'] == m['physical_address'] for m in mappings),
            'Boot prefix requires native identity mappings')
    return dict(entry_offset=0, stop_offset=stop, stack_checkpoints=checkpoints,
                section_mappings=mappings,
                first_mmio=dict(instruction_offset=stop, address=address, value=0x21),
                mmio_executed=False, full_boot_verified=False)


def analyze_eg(image, role):
    profile = PROFILES[role]
    require(len(image) == profile.size and digest(image) == profile.sha256 and crc(image) == 0,
            'Requires stock Z7 II C 1.70 ' + role + ' EG')
    require(image[0x20:0x2C] == b'Ver.01.70.02', 'EG version mismatch')
    require(branch_target(image, 0) == profile.boot, 'Boot branch mismatch')
    records = scatter_records(image)
    require(len(records) == profile.scatter_count, 'Initialization record count mismatch')
    delta = profile.boot - 0xBC88
    early = []
    for start in (0xBE74, 0xBED0, 0xBF2C):
        entry = start + delta
        early.append(dict(entry_offset=entry, stop_offset=entry + 0x58,
                          source=literal(image, entry, 0),
                          destination=literal(image, entry + 4, 1),
                          size=literal(image, entry + 8, 2)))
    stacks = [u32(image, profile.literals + 16 + i * 4) for i in range(6)]
    return dict(role=role, size=len(image), sha256=digest(image), crc_verified=True,
                version='Ver.01.70.02', image_base=BASE,
                startup=dict(entry_offset=profile.boot, instruction_state='ARM',
                    ttbr=u32(image, profile.literals + 4),
                    domain_access=u32(image, profile.literals + 8),
                    vector_address=u32(image, profile.literals + 12),
                    stack_modes=['UND', 'ABT', 'FIQ', 'IRQ', 'SYS', 'SVC'],
                    core_zero_stack_tops=stacks, per_core_stack_stride=0x4000,
                    secondary_release_address=0x04008FFC, secondary_release_value=0xBABEBABE,
                    early_copies=early),
                initialization=dict(table_offset=0x14000, record_size=16,
                    copy_handler_offset=0x6C, zero_handler_offset=0x88,
                    handler_instruction_state='Thumb', records=records,
                    copy_bytes=sum(r['size'] for r in records if r['kind'] == 'copy'),
                    zero_bytes=sum(r['size'] for r in records if r['kind'] == 'zero')),
                communication=communication_header(image, role, records),
                boot_prefix=boot_prefix(image, profile),
                tasks=dict(record_size=28, fields_semantics_verified=False,
                    records=task_records(image, profile.tasks_start, profile.tasks_count)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True, help='New JSON file')
    args = parser.parse_args()
    try:
        report = dict(format=1, offset_space='decoded_member_file',
                      runtime_addresses='explicit image_base, source, destination and startup addresses',
                      images=[analyze_eg(args.master.read_bytes(), 'master'),
                              analyze_eg(args.slave.read_bytes(), 'slave')],
                      natural_boot_verified=False, dual_engine_execution_verified=False)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open('x', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
    except (OSError, ValueError) as error:
        parser.exit(1, f'Error: {error}\n')
    print('PASS master/slave firmware structures:', args.report)


if __name__ == '__main__':
    main()
