# SPDX-License-Identifier: GPL-2.0-or-later
"""Run stock reset through the first system-configuration write batch."""
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
from analyze.system_configuration import (POLL_ARGUMENTS, SLAVE_BRANCH_WORDS,
    SYSTEM_WRITES, expected_system_writes, system_path)
from tools.boot_probe import reset_machine
from tools.early_boot_probe import trace_early, word


def trace_system(remote, structure, image, scenario):
    role = structure['role']
    shared = scenario == 'shared-path'
    seed = 0xA5A50004 if shared else (0xA5A50000 if scenario == 'poisoned-config' else 0)
    branch_seed = 0x5A5A0010 if scenario == 'poisoned-config' else 0
    trace_early(remote, structure, image, 'stock')
    require(all(word(remote, a) == 0 for a in
                (*SLAVE_BRANCH_WORDS, *dict(SYSTEM_WRITES))),
            'Unexpected system configuration reset state')
    if scenario in ('poisoned-config', 'shared-path'):
        remote.write(SLAVE_BRANCH_WORDS[0], struct.pack('<I', branch_seed))
        remote.write(SLAVE_BRANCH_WORDS[1], struct.pack('<I', seed))
    if scenario == 'poisoned-config':
        for address in dict(SYSTEM_WRITES):
            remote.write(address, struct.pack('<I', 0xDEADBEEF))
    start, stop, poll = system_path(role, shared)
    expected = expected_system_writes(role, shared)
    trace, stores = [], []

    def checkpoint(offset):
        regs = remote.regs()
        require(remote.get(regs, 'pc') == BASE + offset and
                remote.get(regs, 'cpsr') & 0x3F == 0x13,
                f'Unexpected system boot state at offset {offset:#x}')
        trace.append(dict(offset=offset, sp=remote.get(regs, 'sp'),
                          cpsr=remote.get(regs, 'cpsr')))
        return regs

    # Stock caller and slave condition select the routine; no CPU state is set.
    caller = list(range(0x394, 0x3A8, 4)) if role == 'master' else [
        *range(0x394, 0x3C4, 4), 0x3C4 if shared else 0x3E8]
    for offset in caller:
        checkpoint(offset)
        remote.command('s')
    require(word(remote, SLAVE_BRANCH_WORDS[0]) ==
            (branch_seed | 4 if role == 'slave' else branch_seed),
            'Slave branch setup did not preserve unrelated bits')
    require(word(remote, SLAVE_BRANCH_WORDS[1]) == seed,
            'Branch selector word was unexpectedly modified')

    for offset in range(start, stop, 4):
        regs = checkpoint(offset)
        instruction = struct.unpack_from('<I', image, offset)[0]
        # These analyzed paths use unconditional immediate-offset STR words.
        is_store = instruction & 0xFE500000 == 0xE4000000
        if is_store:
            index = len(stores)
            require(index < len(expected), 'Unexpected additional system store')
            address, value = expected[index]
            base = remote.get(regs, 'r' + str((instruction >> 16) & 15))
            displacement = instruction & 0xFFF
            actual_address = base + (displacement if instruction & (1 << 23) else -displacement)
            actual_value = remote.get(regs, 'r' + str((instruction >> 12) & 15))
            require((actual_address, actual_value) == (address, value),
                    f'System store arguments mismatch at {offset:#x}')
            if scenario == 'invalid-system-section':
                remote.write(structure['startup']['ttbr'] + (address >> 20) * 4, bytes(4))
                remote.command('s')
                fault = remote.regs()
                require(remote.get(fault, 'pc') == structure['startup']['vector_address'] + 0x10
                        and remote.get(fault, 'cpsr') & 0x1F == 0x17,
                        'Invalid system section failed to cause data abort')
                return dict(data_abort_verified=True, fault_offset=offset,
                            fault_pc=remote.get(fault, 'pc'), trace=trace)
        remote.command('s')
        if is_store:
            require(word(remote, address) == value, 'System store readback mismatch')
            stores.append(dict(offset=offset, address=address, value=value))

    regs = checkpoint(stop)
    require(len(stores) == 58, 'System write count mismatch')
    require(tuple(remote.get(regs, f'r{i}') for i in range(3)) == POLL_ARGUMENTS,
            'First status poll arguments mismatch')
    require(remote.get(regs, 'sp') == 0x04008ED0, 'Nested system stack mismatch')
    caller_lr = 0x3A8 if role == 'master' else (0x3C8 if shared else 0x3EC)
    require(remote.read(0x04008EF8, 8) == struct.pack('<II',
            structure['startup']['core_zero_stack_tops'][-1],
            BASE + structure['boot_prefix']['stop_offset'] + 0x20),
            'System caller did not preserve original r4/lr')
    require(word(remote, 0x04008EF4) == BASE + caller_lr,
            'System callee did not save its return address')
    for address, value in dict(expected).items():
        require(word(remote, address) == value, 'Final system register mismatch')
    require(remote.read(BASE + 0x10000, 0x4000) == image[0x10000:0x14000],
            'System startup modified the stock page table')
    return dict(trace=trace, stores=stores, stop_offset=stop, poll_offset=poll,
                poll_arguments=list(POLL_ARGUMENTS), status_poll_executed=False,
                nested_stack_verified=True, stock_page_table_preserved=True,
                branch_selector=seed, branch_setup_result=word(remote, SLAVE_BRANCH_WORDS[0]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    try:
        images = dict(master=args.master.read_bytes(), slave=args.slave.read_bytes())
        structures = {r: analyze_eg(i, r) for r, i in images.items()}
        addresses = sorted({a for a, _ in SYSTEM_WRITES} | set(SLAVE_BRANCH_WORDS))
        for role, image in images.items():
            mappings = [section_mapping(image, a) for a in addresses]
            require(all(m['virtual_address'] == m['physical_address'] and m['execute_never']
                        for m in mappings), 'Expected native XN configuration mappings')
            structures[role]['system_mappings'] = mappings
        destination = args.destination.resolve()
        destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, qemu_version=subprocess.check_output(
            [args.qemu, '--version'], text=True).splitlines()[0], contexts=[],
            full_boot_verified=False, menu_verified=False,
            assumptions=['Independent experimental cortex-a7 per role; stock EG preloaded.',
                         'Configuration reset is experimental; control writes may publish completion.',
                         'Stock instructions and page table execute; first readiness poll is not executed.',
                         'Seeded selector, poisoned registers and invalid section are separate controls.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'],
                           section_mappings=structures[role]['system_mappings'], scenarios={})
            scenarios = ['stock', 'poisoned-config', 'invalid-system-section']
            if role == 'slave':
                scenarios.append('shared-path')
            for scenario in scenarios:
                with reset_machine(args.qemu, destination / f'{role}-{scenario}', image, role) as remote:
                    context['scenarios'][scenario] = trace_system(remote, structures[role], image, scenario)
                print('PASS', role, scenario, flush=True)
            context['passed'] = True
            report['contexts'].append(context)
        report['passed'] = True
        (destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print('Report:', destination / 'report.json')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
