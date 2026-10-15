# SPDX-License-Identifier: GPL-2.0-or-later
"""Run stock reset through early configuration and its original delay loops."""
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
from tools.boot_probe import reset_machine, trace_prefix

REGISTERS = (0x04264000, 0x04264020, 0x04281028, 0x0428102C)
SEED = (0xA5A5FC00, 0xDAFEDC73)


def word(remote, address):
    return struct.unpack('<I', remote.read(address, 4))[0]


def trace_early(remote, structure, image, scenario):
    role = structure['role']
    start = structure['boot_prefix']['stop_offset']
    config = 0xD700 if role == 'master' else 0xD740
    stub = 0x914 if role == 'master' else 0x960
    delay = config + 0x100
    initial = SEED if scenario == 'seeded-config' else (0, 0)
    if scenario == 'seeded-config':
        for address, value in zip(REGISTERS[2:], initial):
            remote.write(address, struct.pack('<I', value))
    require(tuple(word(remote, a) for a in REGISTERS) == (0, 0, *initial),
            'Unexpected initial configuration registers')
    prefix = trace_prefix(remote, structure)
    trace, loops = [], []

    def checkpoint(offset):
        regs = remote.regs()
        pc, cpsr = remote.get(regs, 'pc'), remote.get(regs, 'cpsr')
        require(pc == BASE + offset, f'Unexpected early boot PC {pc:#x}, expected {BASE + offset:#x}')
        require(cpsr & 0x3F == 0x13, 'Early boot must remain ARM SVC')
        trace.append(dict(offset=offset, pc=pc, sp=remote.get(regs, 'sp'),
                          r0=remote.get(regs, 'r0'), cpsr=cpsr))
        return regs

    # Execute both initial stores and the stock no-op hook before entering the
    # configuration routine. No registers or instructions are replaced.
    for offset in [*range(start, start + 0x18, 4), 0x2B8, stub, start + 0x18]:
        checkpoint(offset)
        remote.command('s')
    regs = checkpoint(config)
    require(remote.get(regs, 'sp') == 0x04008F00 and
            remote.get(regs, 'r4') == structure['startup']['core_zero_stack_tops'][-1],
            'Temporary or saved SVC stack mismatch')
    require(tuple(word(remote, a) for a in REGISTERS[:2]) == (0x21, 0x153B0902),
            'Initial stock configuration writes mismatch')
    if scenario == 'invalid-stack':
        # Change the page table in this negative-control instance only.
        remote.write(structure['startup']['ttbr'] + (0x04008F00 >> 20) * 4, bytes(4))
        remote.command('s')
        regs = remote.regs()
        require(remote.get(regs, 'pc') == structure['startup']['vector_address'] + 0x10 and
                remote.get(regs, 'cpsr') & 0x1F == 0x17,
                'Invalid temporary stack did not cause a data abort')
        return dict(prefix_verified=True, temporary_stack_data_abort=True,
                    fault_offset=config, fault_pc=remote.get(regs, 'pc'),
                    fault_cpsr=remote.get(regs, 'cpsr'), trace=trace)

    remote.command('s')  # Original PUSH {r4,lr} must use the temporary SRAM.
    require(remote.read(0x04008EF8, 8) == struct.pack('<II',
            structure['startup']['core_zero_stack_tops'][-1], BASE + start + 0x1C),
            'Original PUSH did not save r4/lr in temporary SRAM')
    for offset in range(config + 4, config + 0x68, 4):
        checkpoint(offset)
        remote.command('s')
        if offset in (config + 0x34, config + 0x60):
            regs = checkpoint(delay)
            count = 40000 if offset == config + 0x34 else 8000
            require(remote.get(regs, 'r0') == count, 'Stock delay count mismatch')
            remote.breakpoint(BASE + delay + 8)
            try:
                require(remote.command('c').startswith('T05'), 'Delay did not reach its return')
            finally:
                remote.breakpoint(BASE + delay + 8, False)
            regs = checkpoint(delay + 8)
            require(remote.get(regs, 'r0') == 0xFFFFFFFF, 'Stock delay failed to underflow')
            loops.append(dict(offset=delay, initial_count=count,
                              terminal_r0=0xFFFFFFFF, stock_loop_executed=True))
            remote.command('s')
    regs = checkpoint(start + 0x1C)
    require(remote.get(regs, 'sp') == 0x04008F00 and
            remote.get(regs, 'r4') == structure['startup']['core_zero_stack_tops'][-1],
            'Configuration routine did not restore its stack and r4')
    remote.command('s')
    checkpoint(0x394)
    expected = (0x21, 0x153B0902, initial[0] & ~0xC00,
                (initial[1] & ~0x01FF0073) | 0x01630000)
    actual = tuple(word(remote, a) for a in REGISTERS)
    require(actual == expected, 'Stock read/modify/write result mismatch')
    require(remote.read(BASE + 0x10000, 0x4000) == image[0x10000:0x14000],
            'Early boot modified the stock page table')
    return dict(prefix_instructions=prefix['instructions_executed'], trace=trace,
                delay_loops=loops, register_results=[dict(address=a, value=v)
                    for a, v in zip(REGISTERS, actual)], temporary_stack_verified=True,
                stock_page_table_preserved=True, stop_offset=0x394,
                system_initialization_executed=False)


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
            mappings = [section_mapping(image, address) for address in
                        (0x04008EF8, 0x04008EFC, *REGISTERS)]
            require(all(m['virtual_address'] == m['physical_address'] for m in mappings),
                    'Early boot requires native stack and configuration mappings')
            structures[role]['early_mappings'] = mappings
        destination = args.destination.resolve()
        destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, qemu_version=subprocess.check_output(
            [args.qemu, '--version'], text=True).splitlines()[0], contexts=[],
            full_boot_verified=False, menu_verified=False,
            assumptions=['Stock EG images preloaded at 0x10020000; one independent cortex-a7 per role.',
                         'Four configuration words provide storage; zero reset state is experimental.',
                         'Temporary stack has a 4 KiB RAM window; hardware capacity is unconfirmed.',
                         'Stock entry, page table and delay loops execute unchanged.',
                         'Seeded-register and invalid-stack scenarios modify only instance memory.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'],
                           section_mappings=structures[role]['early_mappings'], scenarios={})
            for scenario in ('stock', 'seeded-config', 'invalid-stack'):
                with reset_machine(args.qemu, destination / f'{role}-{scenario}', image, role) as remote:
                    context['scenarios'][scenario] = trace_early(remote, structures[role], image, scenario)
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
