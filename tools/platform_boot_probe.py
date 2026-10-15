# SPDX-License-Identifier: GPL-2.0-or-later
"""Follow stock reset through all four initial platform configuration calls."""
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
from analyze.platform_configuration import (ALL_STATUS_WORDS, PENDING_STATUS_WORDS, RESULT_WORDS,
    PLATFORM_WORDS, platform_calls, platform_writes)
from tools.boot_probe import reset_machine
from tools.early_boot_probe import trace_early, word

BLOCKED_CONTROL = 0x20024100
BLOCKED_STATUS = 0x20024300


def trace_platform(remote, structure, image, scenario):
    role = structure['role']
    shared = scenario == 'shared-path'
    blocked = scenario == 'blocked-group-start'
    trace_early(remote, structure, image, 'stock')
    if shared:
        remote.write(0x0428202C, struct.pack('<I', 4))
    entries, returns, poll = platform_calls(role, shared)
    expected = platform_writes(role, shared)
    if blocked:
        expected = tuple((a, v) for a, v in expected if a != BLOCKED_STATUS)
    expected_returns = [0, 0x4000 if blocked else 0, 0, 0]
    stores, polls, results, calls, completed, trace = [], [], [], [], [], []
    saved = None
    remote.sock.settimeout(60)
    for _ in range(4000):
        regs = remote.regs()
        offset = remote.get(regs, 'pc') - BASE
        require(remote.get(regs, 'cpsr') & 0x3F == 0x13, 'Platform configuration left ARM SVC')
        trace.append(dict(offset=offset, sp=remote.get(regs, 'sp')))
        if offset in returns:
            index = len(completed)
            require(index < 4 and offset == returns[index], 'Platform return order mismatch')
            require(saved is not None and tuple(remote.get(regs, f'r{i}') for i in range(4, 13))
                    == saved[:9], 'Platform callee failed to restore saved registers')
            require(remote.get(regs, 'sp') == (0x04008F00 if index == 3 else 0x04008EF8),
                    'Platform caller stack mismatch')
            value = remote.get(regs, 'r0')
            require(value == expected_returns[index], 'Platform configuration return value mismatch')
            completed.append(dict(offset=offset, result=value))
            if index == 3:
                break
        require(0x394 <= offset <= 0x6300, f'Unexpected platform PC {offset:#x}')
        if offset in entries:
            index = len(calls)
            require(index < 4 and offset == entries[index % 2], 'Platform call order mismatch')
            channel = 1 if index < 2 else 2
            require(remote.get(regs, 'r0') == (0 if index % 2 == 0 else channel),
                    'Platform entry r0 mismatch')
            if index % 2 == 0:
                require(remote.get(regs, 'r1') == channel, 'Platform channel mask mismatch')
            saved = tuple(remote.get(regs, f'r{i}') for i in range(4, 13))
            calls.append(dict(offset=offset, channel=channel, r0=remote.get(regs, 'r0'),
                              r1=remote.get(regs, 'r1')))
        if offset == poll:
            address, mask, limit = (remote.get(regs, f'r{i}') for i in range(3))
            resume = remote.get(regs, 'lr')
            timeout = blocked and address == BLOCKED_STATUS
            require(address in ALL_STATUS_WORDS and mask == 1 and limit == 40000000,
                    'Unexpected platform poll arguments')
            require(word(remote, address) == (0 if timeout else 1), 'Unexpected completion state')
            remote.breakpoint(resume)
            try:
                require(remote.command('c').startswith('T05'), 'Platform poll failed to return')
            finally:
                remote.breakpoint(resume, False)
            after = remote.regs()
            result, count = remote.get(after, 'r0'), remote.get(after, 'r3')
            require(result == (0xFFFFFFFF if timeout else 0) and
                    count == (40000000 if timeout else 0), 'Stock platform poll result mismatch')
            polls.append(dict(address=address, result=result, failed_iterations=count,
                              return_offset=resume-BASE))
            continue
        instruction = struct.unpack_from('<I', image, offset)[0]
        condition = instruction >> 28
        active = condition == 14 or (condition == 0 and remote.get(regs, 'cpsr') & (1 << 30))
        is_store = False
        if active and instruction & 0x0E400000 == 0x04000000:
            rn = (instruction >> 16) & 15
            base = BASE + offset + 8 if rn == 15 else remote.get(regs, f'r{rn}')
            delta = instruction & 0xFFF
            address = base + (delta if instruction & (1 << 23) else -delta)
            is_store = not instruction & (1 << 20)
            value = remote.get(regs, f'r{(instruction >> 12) & 15}') if is_store else None
            if is_store and address in (0x0428242C, 0x0428202C):
                require(role == 'slave' and address == 0x0428242C and value == 4,
                        'Unexpected slave selector write')
                is_store = False
            elif is_store:
                require(len(stores) < len(expected) and (address, value) == expected[len(stores)],
                        f'Platform store sequence mismatch at {offset:#x}')
            elif address in RESULT_WORDS:
                results.append(dict(offset=offset, address=address, value=word(remote, address)))
        remote.command('s')
        if is_store:
            require(word(remote, address) == (0 if address in ALL_STATUS_WORDS else value),
                    'Platform store readback mismatch')
            stores.append(dict(offset=offset, address=address, value=value))
    else:
        raise ValueError('Platform configuration exceeded instruction bound')
    require(len(calls) == 4 and len(completed) == 4 and len(stores) == len(expected),
            'Incomplete platform call/store sequence')
    require(len(polls) == 48 and len(results) == 6 and all(r['value'] == 0 for r in results),
            'Incomplete platform polls/results')
    require(sum(p['failed_iterations'] for p in polls) == (40000000 if blocked else 0),
            'Unexpected additional platform timeout')
    require(all(word(remote, a) == (1 if a in PENDING_STATUS_WORDS else 0)
                for a in ALL_STATUS_WORDS), 'Final platform status mismatch')
    require(remote.get(regs, 'r4') == structure['startup']['core_zero_stack_tops'][-1],
            'System initializer did not restore original r4')
    require(remote.read(BASE+0x10000, 0x4000) == image[0x10000:0x14000],
            'Platform configuration modified stock page table')
    return dict(stores=stores, polls=polls, results=results, calls=calls, returns=completed,
                trace=trace, stop_offset=returns[-1], temporary_stack_restored=True,
                pending_status_words=list(PENDING_STATUS_WORDS),
                stock_page_table_preserved=True, boot_continuation_executed=False)


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
        for image in images.values():
            mappings = [section_mapping(image, a) for a in PLATFORM_WORDS]
            require(all(m['virtual_address'] == m['physical_address'] and m['execute_never']
                        for m in mappings), 'Expected native XN platform mappings')
        destination = args.destination.resolve()
        destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, qemu_version=subprocess.check_output(
            [args.qemu, '--version'], text=True).splitlines()[0], contexts=[],
            full_boot_verified=False, menu_verified=False,
            assumptions=['Explicit synchronous completion pairs and zero result words are experimental.',
                         'Stock reset, page table, instructions and poll limits execute unchanged.',
                         'Independent experimental cortex-a7 per role, with preloaded stock EG.',
                         'Shared-path selector changes instance memory; blocked control changes device policy.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], scenarios={})
            for scenario in ['stock', 'blocked-group-start'] + (['shared-path'] if role == 'slave' else []):
                with reset_machine(args.qemu, destination/f'{role}-{scenario}', image, role,
                    blocked_control=BLOCKED_CONTROL if scenario == 'blocked-group-start' else None) as remote:
                    context['scenarios'][scenario] = trace_platform(remote, structures[role], image, scenario)
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
