# SPDX-License-Identifier: GPL-2.0-or-later
"""Audit local Z7 II update history and bounded boot-material candidates.

No members or candidate bytes are written. Structural CRC checks and static
instruction observations do not authenticate packages or verify installation.
Candidate comparisons use only the pinned C 1.70 digest implementation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_REG, ARM_REG_R1, ARM_REG_R2, ARM_REG_SP
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, digest, require, validate_master
from analyze.firmware_structure import scatter_records, section_mapping, thumb_literal
from analyze.update_container import describe_container
from analyze.upgrade_signature import decode, key_stream, STREAM_TABLE, INDEX_TABLE

BOOT_ADDRESS = 0x10000088
PREFIX_SIZE = 0x20000
STOCK_PACKAGE_SHA = 'fc0e94f57500a1f0e287c6b9a036c81a5ffceccb8432a377d645b3fa35a19b6a'


def boot_readers(image):
    """Find T1 literal loads followed by the observed check-setup sequence.

    Inspect all halfword-aligned possible starts; returned sites are static
    candidates, not proof of executable reachability or a memory read.
    """
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    sites = []
    literal = image.find(struct.pack('<I', BOOT_ADDRESS))
    while literal >= 0:
        if literal % 4 == 0:
            for pos in range(max(0, literal - 1024), literal, 2):
                word = struct.unpack_from('<H', image, pos)[0]
                if word & 0xFF00 != 0x4800:
                    continue
                if ((pos + 4) & ~3) + (word & 255) * 4 != literal:
                    continue
                ins = list(md.disasm(image[pos:pos + 16], pos, count=5))
                if len(ins) != 5 or [i.mnemonic for i in ins] != ['ldr', 'mov', 'movw', 'bl', 'bl']:
                    continue
                move, seed = ins[1].operands, ins[2].operands
                if not (len(move) == len(seed) == 2 and
                        move[0].type == move[1].type == seed[0].type == ARM_OP_REG and
                        move[0].reg == ARM_REG_R2 and move[1].reg == ARM_REG_SP and
                        seed[0].reg == ARM_REG_R1 and seed[1].type == ARM_OP_IMM):
                    continue
                sites.append(dict(offset=pos, literal_offset=literal,
                                  address=BOOT_ADDRESS, seed=seed[1].imm,
                                  setup_target=ins[3].operands[0].imm,
                                  check_target=ins[4].operands[0].imm))
        literal = image.find(struct.pack('<I', BOOT_ADDRESS), literal + 1)
    return sites


def compare_candidate(candidate, state, expected, stream):
    """Test final K8 and raw B8 interpretations without emitting their values."""
    matches = []
    for kind, value in (('K8', candidate),
                        ('B8', bytes(a ^ b for a, b in zip(candidate, stream)))):
        current = state.copy()
        current.update(value)
        if current.digest() == expected:
            matches.append(kind)
    return matches


def execute_setup(image, reader, records):
    """Run original argument setup, copy and string routines on synthetic B8.

    This isolated call starts at the setup target, with the three arguments
    supplied by the host. It does not execute the original caller or boot.
    """
    setup = reader['setup_target']
    context = thumb_literal(image, setup + 6, 0)
    data, stop = 0x50000000, 0x50020000
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
    u.mem_map(0x10000000, PREFIX_SIZE)
    u.mem_map(BASE, (len(image) + 4095) & ~4095)
    u.mem_write(BASE, image)
    u.mem_map(0xB1800000, 0x4800000)
    u.mem_map(data, 0x30000)
    for record in records:
        if record['kind'] == 'copy':
            offset = record['source'] - BASE
            u.mem_write(record['destination'], image[offset:offset + record['size']])
    reads, writes = [], []

    def access(machine, kind, address, size, value, unused):
        if address < BOOT_ADDRESS + 8 and address + size > BOOT_ADDRESS:
            (reads if kind == UC_MEM_READ else writes).append((address, size))

    u.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, access)
    u.mem_write(data, b'Z_7_2\0')
    cases = []
    for sample in (bytes(8), bytes((17 * i + 3) & 255 for i in range(8))):
        reads.clear()
        writes.clear()
        u.mem_write(BOOT_ADDRESS, sample)
        u.mem_write(context + 12, bytes([0xCC]) * 20)
        for reg, value in ((UC_ARM_REG_R0, BOOT_ADDRESS), (UC_ARM_REG_R1, reader['seed']),
                           (UC_ARM_REG_R2, data), (UC_ARM_REG_SP, data + 0x18000),
                           (UC_ARM_REG_LR, stop | 1)):
            u.reg_write(reg, value)
        u.emu_start(BASE + setup | 1, stop, count=100000)
        require(u.reg_read(UC_ARM_REG_PC) == stop, 'Historical setup did not return')
        require(bytes(u.mem_read(context + 12, 8)) == sample,
                'Historical setup did not preserve synthetic B8')
        require(struct.unpack('<I', u.mem_read(context + 20, 4))[0] == reader['seed'] and
                bytes(u.mem_read(context + 24, 6)) == b'Z_7_2\0',
                'Historical setup seed or model mismatch')
        covered = {address + i for address, size in reads for i in range(size)}
        require(set(range(BOOT_ADDRESS, BOOT_ADDRESS + 8)) <= covered and not writes,
                'Historical setup read/write boundary mismatch')
        cases.append(dict(boot_reads=[dict(address=a, bytes=n) for a, n in reads],
                          boot_writes=0, synthetic_bytes_copied=True,
                          seed_and_model_stored=True, returned=True))
    return dict(context_address=context, synthetic_cases=cases,
                original_copy_and_string_routines=True, host_function_stubs=0,
                original_caller_executed=False, actual_boot_material_recovered=False)


def run(args):
    master = args.master.read_bytes()
    validate_master(master)
    paths = sorted(args.packages.glob('Z7_2_*.bin'))
    require(bool(paths), 'No Z7 II update packages found')
    # Establish the digest oracle using an independently pinned original file.
    reference = next((p for p in paths if digest(p.read_bytes()) == STOCK_PACKAGE_SHA), None)
    require(reference is not None, 'Requires the original C 1.70 package in the history directory')
    stock = reference.read_bytes()
    stock_body = stock[32:64] + decode(master, stock[64:], 32)
    describe_container(stock_body)
    state = hashlib.sha1(stock_body)
    expected, stream = stock[:20], key_stream(master)
    tables = master[STREAM_TABLE:STREAM_TABLE + 256] + master[INDEX_TABLE:INDEX_TABLE + 256]
    report = dict(format=1, firmware_included=False, master_sha256=digest(master),
                  reference_package_sha256=STOCK_PACKAGE_SHA, packages=[],
                  candidate_scope='Every eight-byte window in unique auxiliary members and the first 0x20000 bytes of each unique engine member',
                  candidate_target='Original C 1.70 header only; both B8 and K8 interpretations',
                  candidate_regions=[], windows_tested=0, sha1_comparisons=0, matches=[])
    seen = set()
    for path in paths:
        raw = path.read_bytes()
        body = raw[32:64] + decode(master, raw[64:], 32)
        info = describe_container(body)
        require(len(info['members']) == 5, 'Expected five Z7 II members')
        package = dict(file=path.name, bytes=len(raw), sha256=digest(raw),
                       body_sha256=info['sha256'], member_crcs_verified=True,
                       container_crc_verified=True, header_digest_verified=False,
                       members=[])
        for entry in info['members']:
            data = body[entry['offset']:entry['offset'] + entry['length']]
            item = dict(entry)
            engine = entry['name'].startswith('eg1840_')
            if engine:
                item['version'] = data[32:44].rstrip(b'\0').decode('ascii')
                item['boot_reader_candidates'] = boot_readers(data)
                item['boot_mapping'] = section_mapping(data, BOOT_ADDRESS)
                records = scatter_records(data)
                item['scatter_record_count'] = len(records)
                item['boot_prefix_overlaps'] = [r for r in records if
                    r['destination'] < 0x10020000 and
                    r['destination'] + r['size'] > 0x10000000]
                table_offset = data.find(tables)
                item['matching_transform_tables_offset'] = table_offset if table_offset >= 0 else None
                item['setup_execution'] = [execute_setup(data, reader, records)
                                           for reader in item['boot_reader_candidates']]
            package['members'].append(item)
            region = data[:PREFIX_SIZE] if engine else data
            region_sha = digest(region)
            if region_sha in seen:
                continue
            seen.add(region_sha)
            report['candidate_regions'].append(dict(file=path.name, member=entry['name'],
                offset=0, bytes=len(region), sha256=region_sha))
            for pos in range(max(0, len(region) - 7)):
                candidate = region[pos:pos + 8]
                matches = compare_candidate(candidate, state, expected, stream)
                if matches:
                    report['matches'].append(dict(file=path.name, member=entry['name'],
                        offset=pos, interpretations=matches, candidate_sha256=digest(candidate)))
            report['windows_tested'] += max(0, len(region) - 7)
        report['packages'].append(package)
        print(json.dumps(dict(file=path.name, members=len(package['members']),
                             matches=len(report['matches']))), flush=True)
    report['sha1_comparisons'] = report['windows_tested'] * 2
    report['header_digest_match_found'] = bool(report['matches'])
    report['limitations'] = [
        'Historical decode tables are borrowed from C 1.70; directory and all CRCs are checked independently.',
        'Static instruction candidates do not prove reachability, initialization or equivalent historical digest algorithms.',
        'Setup executions use synthetic boot bytes and host-supplied arguments; they do not authenticate historical packages or recover real boot contents.',
        'Only auxiliary members and packaged engine prefixes are searched for contiguous values, not entire historical engine images or arbitrary constructors.',
        'A negative result does not locate the real boot material or prove it absent from the packages.',
        'No native menu update, storage programming or reset persistence is exercised.']
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(packages=len(paths), windows=report['windows_tested'],
                         matches=len(report['matches']))))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--packages', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    run(parser.parse_args())


if __name__ == '__main__':
    main()
