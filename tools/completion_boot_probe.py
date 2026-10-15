# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute stock system configuration with command completion and timeout controls."""
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
from analyze.system_configuration import (COMPLETION_STATUS, COMMAND_RESULT,
    CONFIGURATION_WORDS, completion_path, expected_completion_writes, system_path)
from tools.boot_probe import reset_machine
from tools.early_boot_probe import word
from tools.system_boot_probe import trace_system


def trace_completion(remote, structure, image, scenario):
    role = structure['role']
    shared = scenario == 'shared-path'
    timed_out = scenario == 'no-completion'
    prefix = trace_system(remote, structure, image, 'shared-path' if shared else 'stock')
    saved_registers = struct.unpack('<10I', remote.read(0x04008ED0, 40))
    stores = prefix['stores']
    expected = expected_completion_writes(role, shared)
    if timed_out:
        # Timeouts omit both acknowledgements and the entire command sequence.
        expected = tuple((a, v) for a, v in expected[:96] if a not in COMPLETION_STATUS)
    return_offset, training, next_entry = completion_path(role, shared)
    start, _, poll = system_path(role, shared)
    end = 0x3D10 if role == 'slave' and not shared else 0x5354 + (0x4C if role == 'slave' else 0)
    polls, results, trace = [], [], []
    # A timeout executes all 40 million original iterations. It does not
    # replace the bound, loop instructions or CPU return state.
    remote.sock.settimeout(60)
    for _ in range(1500):
        regs = remote.regs()
        offset = remote.get(regs, 'pc') - BASE
        require(remote.get(regs, 'cpsr') & 0x3F == 0x13, 'Completion left ARM SVC')
        trace.append(dict(offset=offset, sp=remote.get(regs, 'sp')))
        if offset == return_offset:
            break
        require(start <= offset < end or training <= offset < training + 0x370 or offset == poll,
                f'Unexpected completion PC {offset:#x}')
        if offset == poll:
            address, mask, limit = (remote.get(regs, f'r{i}') for i in range(3))
            resume = remote.get(regs, 'lr')
            require(address in COMPLETION_STATUS and mask == 1 and limit == 40000000,
                    'Unexpected original status poll arguments')
            require(word(remote, address) == (0 if timed_out else 1),
                    'Completion bit does not match device mode')
            remote.breakpoint(resume)
            try:
                require(remote.command('c').startswith('T05'), 'Poll failed to return')
            finally:
                remote.breakpoint(resume, False)
            after = remote.regs()
            terminal = remote.get(after, 'r0')
            iterations = remote.get(after, 'r3')
            require(terminal == (0xFFFFFFFF if timed_out else 0) and
                    iterations == (40000000 if timed_out else 0),
                    'Original poll return or iteration count mismatch')
            polls.append(dict(address=address, mask=mask, limit=limit,
                result=terminal, failed_iterations=iterations, return_offset=resume-BASE))
            continue
        instruction = struct.unpack_from('<I', image, offset)[0]
        condition = instruction >> 28
        active = condition == 14 or (condition == 0 and remote.get(regs, 'cpsr') & (1 << 30))
        is_memory = instruction & 0x0E400000 == 0x04000000
        if is_memory and active:
            base_register = (instruction >> 16) & 15
            base = (BASE + offset + 8 if base_register == 15 else
                    remote.get(regs, f'r{base_register}'))
            displacement = instruction & 0xFFF
            address = base + (displacement if instruction & (1 << 23) else -displacement)
            is_store = not instruction & (1 << 20)
            if is_store:
                value = remote.get(regs, 'r' + str((instruction >> 12) & 15))
                require(len(stores) < len(expected) and (address, value) == expected[len(stores)],
                        f'Completion store mismatch at {offset:#x}')
            elif address == COMMAND_RESULT:
                results.append(dict(offset=offset, address=address, value=word(remote, address)))
        else:
            is_store = False
        remote.command('s')
        if is_store:
            require(word(remote, address) == (0 if address in COMPLETION_STATUS else value),
                    'Completion store readback mismatch')
            stores.append(dict(offset=offset, address=address, value=value))
    else:
        raise ValueError('Completion path exceeded instruction bound')
    require(remote.get(regs, 'sp') == 0x04008EF8 and remote.get(regs, 'r4') == 0,
            'System callee failed to restore caller stack/registers')
    require(tuple(remote.get(regs, f'r{i}') for i in range(4, 13)) == saved_registers[:9]
            and saved_registers[9] == BASE + return_offset,
            'System callee did not restore all saved registers')
    result = remote.get(regs, 'r0')
    require(result == (0x4000 if timed_out else 0), 'System configuration result mismatch')
    require(len(stores) == len(expected), 'Incomplete configuration store sequence')
    if timed_out:
        require([p['address'] for p in polls] == list(COMPLETION_STATUS[:2]) and not results,
                'Timeout failed to bypass command-result path')
    else:
        require([p['address'] for p in polls] == [*COMPLETION_STATUS[:2], *([COMPLETION_STATUS[2]] * 5)]
                and len(stores) == 106 and len(results) == 3
                and all(r['value'] == 0 for r in results), 'Incomplete command sequence')
    require(all(word(remote, a) == 0 for a in COMPLETION_STATUS),
            'Completion acknowledgement left pending status')
    require(remote.read(BASE + 0x10000, 0x4000) == image[0x10000:0x14000],
            'Completion changed the stock page table')
    # Follow the original caller to the next initialization routine's entry.
    for offset in (return_offset, return_offset + 4):
        require(remote.get(remote.regs(), 'pc') == BASE + offset, 'Unexpected caller continuation')
        remote.command('s')
    next_regs = remote.regs()
    require(remote.get(next_regs, 'pc') == BASE + next_entry and
            remote.get(next_regs, 'r0') == 1 and
            remote.get(next_regs, 'lr') == BASE + return_offset + 8,
            'Next initialization entry/arguments mismatch')
    return dict(stores=stores, trace=trace, polls=polls, command_results=results,
                system_return=result, return_offset=return_offset, stop_offset=next_entry,
                stock_page_table_preserved=True, caller_stack_restored=True,
                original_timeout_bound_executed=timed_out, next_initialization_executed=False)


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
        for role, image in images.items():
            mappings = [section_mapping(image, a) for a in CONFIGURATION_WORDS]
            require(all(m['virtual_address'] == m['physical_address'] and m['execute_never']
                        for m in mappings), 'Expected native XN completion mappings')
        destination = args.destination.resolve()
        destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, qemu_version=subprocess.check_output(
            [args.qemu, '--version'], text=True).splitlines()[0], contexts=[],
            full_boot_verified=False, menu_verified=False,
            assumptions=['Synchronous bit-0 completion after selected control/command stores.',
                         'Status acknowledges written bits; command result is read-only zero.',
                         'These are experimental device contracts, not measured hardware timing.',
                         'Stock reset, instructions, page table and timeout bound execute unchanged.',
                         'One independent experimental cortex-a7 per role; stock images preloaded.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], scenarios={})
            for scenario in ['stock', 'no-completion'] + (['shared-path'] if role == 'slave' else []):
                with reset_machine(args.qemu, destination/f'{role}-{scenario}', image, role,
                                   auto_complete=scenario != 'no-completion') as remote:
                    context['scenarios'][scenario] = trace_completion(remote, structures[role], image, scenario)
                print('PASS', role, scenario, flush=True)
            context['passed'] = True
            report['contexts'].append(context)
        report['passed'] = True
        (destination/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
        print('Report:', destination/'report.json')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
