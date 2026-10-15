# SPDX-License-Identifier: GPL-2.0-or-later
"""Follow stock reset through continuation stores and all three early copies."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg, section_mapping
from analyze.boot_continuation import (CONTINUATION_WORDS, PRESERVED_WORDS,
    continuation_profile, continuation_writes)
from tools.boot_probe import reset_machine
from tools.early_boot_probe import word
from tools.platform_boot_probe import trace_platform
from tools.structure_probe import verify_copy


def continue_to(remote, offset):
    address = BASE + offset
    remote.breakpoint(address)
    try:
        require(remote.command('c').startswith('T05'), 'Continuation did not stop normally')
        require(remote.get(remote.regs(), 'pc') == address,
                'Continuation failed or reached an exception vector')
    finally:
        remote.breakpoint(address, False)


def trace_continuation(remote, structure, image, scenario):
    role = structure['role']
    platform = trace_platform(remote, structure, image,
                              'shared-path' if scenario == 'shared-path' else 'stock')
    profile = continuation_profile(role)
    seeds = dict(zip(PRESERVED_WORDS, (0xA55A5AA4, 0x12345678, 0xABCDEF01))) if scenario == 'seeded-config' else {}
    for address, value in seeds.items():
        remote.write(address, struct.pack('<I', value))
    invalid = scenario == 'invalid-system-section'
    if invalid:
        descriptor = structure['startup']['ttbr'] + (0x200 << 2)
        original_descriptor = remote.read(descriptor, 4)
        remote.write(descriptor, bytes(4))
    expected = continuation_writes(role, seeds)
    stores, reads, trace = [], [], []
    clock_seen = transfer_seen = False
    stack = structure['startup']['core_zero_stack_tops'][-1]
    for _ in range(140):
        regs = remote.regs()
        offset = remote.get(regs, 'pc') - BASE
        trace.append(dict(offset=offset, sp=remote.get(regs, 'sp')))
        require(remote.get(regs, 'cpsr') & 0x3F == 0x13, 'Continuation left ARM SVC')
        if offset == profile['transfer_return']:
            break
        require(profile['entry'] <= offset < profile['transfer_return'] or
                profile['clock_entry'] <= offset < profile['clock_entry'] + 16 or
                profile['transfer_entry'] <= offset < profile['transfer_entry'] + 0x6C,
                f'Unexpected continuation PC {offset:#x}')
        if offset == profile['clock_entry']:
            clock_seen = True
            require(remote.get(regs, 'lr') == BASE + profile['clock_return'], 'Clock hook return mismatch')
        if offset == profile['transfer_entry']:
            transfer_seen = True
            require(remote.get(regs, 'sp') == stack and remote.get(regs, 'r4') == stack,
                    'Original SVC stack was not restored')
            require(remote.get(regs, 'r0') == profile['transfer_destination'] and
                    remote.get(regs, 'r1') == profile['transfer_size'] and
                    remote.get(regs, 'lr') == BASE + profile['transfer_return'],
                    'Memory initialization arguments mismatch')
        instruction = struct.unpack_from('<I', image, offset)[0]
        # Track configuration and literal accesses; the single-register PUSH
        # and POP are checked through stack/register restoration instead.
        is_store = False
        if instruction & 0xFE400000 == 0xE4000000 and (instruction >> 16) & 15 != 13:
            rn, rd = (instruction >> 16) & 15, (instruction >> 12) & 15
            base = BASE + offset + 8 if rn == 15 else remote.get(regs, f'r{rn}')
            delta = instruction & 0xFFF
            address = base + (delta if instruction & (1 << 23) else -delta)
            is_store = not instruction & (1 << 20)
            if is_store:
                value = remote.get(regs, f'r{rd}')
                require(len(stores) < len(expected) and (address, value) == expected[len(stores)],
                        f'Continuation store mismatch at {offset:#x}')
            elif address in PRESERVED_WORDS or address == profile['optional_pointer']:
                value = word(remote, address)
                require(value == seeds.get(address, 0), 'Continuation input value mismatch')
                reads.append(dict(offset=offset, address=address, value=value))
        remote.command('s')
        if invalid and is_store:
            after = remote.regs()
            require(address == 0x20016020 and remote.get(after, 'pc') ==
                    structure['startup']['vector_address'] + 0x10 and
                    remote.get(after, 'cpsr') & 0x1F == 0x17,
                    'Invalid continuation section did not cause first-store data abort')
            remote.write(descriptor, original_descriptor)
            require(word(remote, address) == 0, 'Faulting continuation store changed device')
            return dict(platform=platform, fault_offset=offset, fault_address=address,
                        data_abort_verified=True, copies_executed=False,
                        invalid_descriptor_restored=True)
        if is_store:
            require(word(remote, address) == value, 'Continuation store readback mismatch')
            stores.append(dict(offset=offset, address=address, value=value))
    else:
        raise ValueError('Continuation exceeded instruction bound')
    require(len(stores) == 24 and len(reads) == 4 and clock_seen and transfer_seen,
            'Incomplete continuation stores or calls')
    require(remote.get(regs, 'sp') == stack and remote.get(regs, 'r4') == stack,
            'Memory initializer failed to preserve stack/register')
    copies = []
    for record in structure['startup']['early_copies']:
        require(remote.get(remote.regs(), 'pc') == BASE + record['entry_offset'],
                'Early copy continuity mismatch')
        copies.append(verify_copy(remote, image, record,
            lambda r=record: continue_to(remote, r['stop_offset'])))
        after = remote.regs()
        require(remote.get(after, 'sp') == stack and remote.get(after, 'r0') ==
                record['source'] + record['size'] and remote.get(after, 'r1') ==
                record['destination'] + record['size'], 'Early copy end state mismatch')
        # The recorded loop boundary precedes MOV r0,r1; execute it to reach
        # the next original loop or the final completion-wait call.
        remote.command('s')
        require(remote.get(remote.regs(), 'r0') == record['destination'] + record['size'],
                'Early copy did not publish its final destination')
    require(remote.get(remote.regs(), 'pc') == BASE + profile['wait_call'],
            'Early copies did not reach memory completion wait call')
    remote.command('s')
    require(remote.get(remote.regs(), 'pc') == BASE + profile['wait_entry'],
            'Stock memory completion wait entry mismatch')
    require(remote.read(BASE + 0x10000, 0x4000) == image[0x10000:0x14000],
            'Continuation modified original page table')
    return dict(platform=platform, stores=stores, reads=reads, trace=trace, copies=copies,
                stop_offset=profile['wait_entry'], original_svc_stack_restored=True,
                stock_page_table_preserved=True, memory_initialization_setup=dict(
                    destination=profile['transfer_destination'], size=profile['transfer_size'],
                    blocks=(profile['transfer_size'] + 0x3FFF) >> 14, block_size=0x4000),
                memory_initialization_completion_verified=False, completion_wait_executed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    try:
        images = dict(master=args.master.read_bytes(), slave=args.slave.read_bytes())
        structures = {role: analyze_eg(image, role) for role, image in images.items()}
        for image in images.values():
            require(all(section_mapping(image, a)['physical_address'] == a and
                        section_mapping(image, a)['execute_never'] for a in CONTINUATION_WORDS),
                    'Expected native XN continuation mappings')
        args.destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, qemu_version=subprocess.check_output(
            [args.qemu, '--version'], text=True).splitlines()[0], contexts=[],
            full_boot_verified=False, menu_verified=False,
            assumptions=['Stock reset, instructions and original page table; stock EG preloaded.',
                'Platform completion remains experimental and synchronous.',
                'Memory initialization completion is checked by a separate memory boot probe.',
                'Copy destinations are poisoned and guarded in instance RAM; source EG unchanged.',
                'Seeded configuration and invalid section are separate negative controls.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], scenarios={})
            for scenario in ['stock', 'seeded-config', 'invalid-system-section'] + (
                    ['shared-path'] if role == 'slave' else []):
                with reset_machine(args.qemu, args.destination / f'{role}-{scenario}', image, role) as remote:
                    context['scenarios'][scenario] = trace_continuation(remote, structures[role], image, scenario)
                print('PASS', role, scenario, flush=True)
            context['passed'] = True
            report['contexts'].append(context)
        report['passed'] = True
        (args.destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print('Report:', args.destination / 'report.json')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
