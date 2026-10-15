# SPDX-License-Identifier: GPL-2.0-or-later
"""Run original counter initialization through kernel setup and its core barrier."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from analyze.runtime_counter import counter_profile
from tools.boot_probe import reset_machine
from tools.early_boot_probe import word
from tools.service_boot_probe import trace_services, reach as reach_native

COUNTER = 0x04266000


def trace_counter(remote, image, structure, scenario):
    profile = counter_profile(image, structure['role'])
    prefix = trace_services(remote, image, structure,
                            'shared-path' if scenario == 'shared-path' else 'stock',
                            stop_before_counter=False)
    vectors = structure['startup']['vector_address']
    if scenario == 'counter-disabled':
        reach_native(remote, 0x134, vectors)
        remote.command('s')
        regs = remote.regs()
        require(remote.get(regs, 'pc') == vectors+16 and
                remote.get(regs, 'cpsr') & 0x1F == 0x17 and
                remote.get(regs, 'lr') == BASE+0x13C, 'Disabled counter did not cause original data abort')
        return dict(prefix=prefix, disabled_counter_data_abort_verified=True,
                    kernel_module_initialization_completed=False)
    initial_control = None
    events, stores = [], []
    monitored = {0xD4: ('cpu-timer-initialize', 9), 0x158: ('counter-enable', 6),
                 0x120: ('frequency-getter', 3), 0x12C: ('counter-initialize', 11)}
    for offset in monitored:
        remote.breakpoint(BASE+offset)
    remote.sock.settimeout(10)
    def reach(offset):
        nonlocal initial_control
        target = BASE+offset
        addresses = [target, *[vectors+n for n in (4, 12, 16)]]
        for address in addresses:
            remote.breakpoint(address)
        try:
            for _ in range(20):
                require(remote.command('c').startswith('T05'), 'Kernel execution did not stop')
                regs = remote.regs()
                pc = remote.get(regs, 'pc')
                require(remote.get(regs, 'cpsr') & 0x3F == 0x13, 'Kernel left ARM SVC mode')
                if pc == target:
                    return regs
                callback = pc-BASE
                require(callback in monitored, 'Kernel reached an unexpected exception or callback')
                name, length = monitored[callback]
                if callback == 0x12C:
                    if scenario == 'seeded-counter':
                        for register, value in ((8, 0x89ABCDEF), (12, 0x01234567), (16, 48000000), (0, 3)):
                            remote.write(COUNTER+register, struct.pack('<I', value))
                    initial_control = word(remote, COUNTER)
                for index in range(length):
                    regs = remote.regs()
                    require(remote.get(regs, 'pc') == BASE+callback+index*4,
                            'Original timer callback changed its instruction path')
                    if callback == 0xD4 and index == 2:
                        require(remote.get(regs, 'r2') == profile['frequency'], 'CPU timer literal mismatch')
                    instruction = callback+index*4
                    if callback == 0x12C and instruction in (0x13C, 0x144, 0x148, 0x150):
                        address = remote.get(regs, 'r0') + {0x13C:0, 0x144:8, 0x148:12, 0x150:16}[instruction]
                        stores.append(dict(offset=instruction, address=address, value=remote.get(regs, 'r1')))
                    remote.command('s')
                if callback == 0x12C:
                    require([s['value'] for s in stores] == [0, 0, 0, profile['frequency']] and
                            word(remote, COUNTER) == 0 and remote.read(COUNTER+8, 8) == bytes(8) and
                            word(remote, COUNTER+16) == profile['frequency'], 'Original counter reset/programming mismatch')
                if callback == 0x158:
                    require(word(remote, COUNTER) == 3, 'Original counter enable failed')
                if callback == 0x120:
                    require(remote.get(remote.regs(), 'r0') == profile['frequency'], 'CPU frequency getter mismatch')
                events.append(dict(name=name, offset=callback))
            raise ValueError('Kernel callback count exceeded bound')
        finally:
            for address in addresses:
                remote.breakpoint(address, False)
    modules = []
    stack = structure['startup']['core_zero_stack_tops'][-1]-16
    try:
        for index, (call, entry) in enumerate(zip(profile['calls'], profile['entries'])):
            regs = reach(entry)
            require(remote.get(regs, 'lr') == BASE+call+4, 'Kernel module caller mismatch')
            regs = reach(call+4)
            result = remote.get(regs, 'r0')
            require(result < 0x80000000 and remote.get(regs, 'sp') == stack,
                    'Kernel module returned an error or changed caller stack')
            modules.append(dict(entry=entry, return_offset=call+4, result=result))
        regs = reach(profile['task_create_call'])
        require(remote.get(regs, 'r0') == profile['task_descriptor'], 'Original task descriptor mismatch')
        regs = reach(profile['task_create_call']+4)
        task_id = remote.get(regs, 'r0')
        require(0 < task_id < 0x80000000, 'Original startup task creation failed')
        regs = reach(profile['task_start_call'])
        require(remote.get(regs, 'r0') == task_id and remote.get(regs, 'r1') == 0,
                'Original startup task arguments mismatch')
        regs = reach(profile['task_start_call']+4)
        require(remote.get(regs, 'r0') == 0, 'Original task start failed')
        regs = reach(profile['core_setup_call']+4)
        require(remote.get(regs, 'r0') == 0, 'Original per-core setup failed')
        regs = reach(profile['barrier_wait'])
        peers_expected = remote.get(regs, 'r0')
        peers_arrived = word(remote, profile['peer_count_word'])
        require(peers_expected == 1 and peers_arrived == 0,
                'Unexpected original core-barrier contract')
        for _ in range(4):
            for offset in range(profile['barrier_wait'], profile['barrier_wait']+12, 4):
                require(remote.get(remote.regs(), 'pc') == BASE+offset, 'Core wait left its original loop')
                remote.command('s')
        require(remote.get(remote.regs(), 'pc') == BASE+profile['barrier_wait'] and
                word(remote, profile['peer_count_word']) == 0, 'Single-CPU model fabricated peer readiness')
    finally:
        for offset in monitored:
            remote.breakpoint(BASE+offset, False)
    require(any(e['name'] == 'cpu-timer-initialize' for e in events) and
            any(e['name'] == 'counter-enable' for e in events), 'Incomplete original timer setup')
    return dict(prefix=prefix, initial_counter_control=initial_control, stores=stores,
        frequency=profile['frequency'], timer_callbacks=events, kernel_modules=modules,
        kernel_module_count=len(modules), kernel_module_initialization_completed=True,
        created_task_id=task_id, task_start_return=0, task_entry=profile['task_entry'],
        task_stack_bytes=profile['task_stack_bytes'], startup_task_execution_verified=False,
        counter_control=word(remote, COUNTER), barrier_wait=profile['barrier_wait'],
        peer_count_word=profile['peer_count_word'], peers_expected=peers_expected,
        peers_arrived=peers_arrived, core_barrier_wait_verified=True)


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
        args.destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, contexts=[], full_boot_verified=False, menu_verified=False,
            qemu_version=subprocess.check_output([args.qemu, '--version'], text=True).splitlines()[0],
            assumptions=['Stock reset and instructions; original images preloaded.',
                'MMIO counter uses CPU virtual-clock period; CPU counter gating/origin remain unmodeled.',
                'Declared 48 MHz uses QEMU integer-nanosecond timer rounding.',
                'Experimental GIC/CPU layout, platform completion and bounded clearing remain unchanged.',
                'One CPU per role; original peer-ready count is never fabricated.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], scenarios={})
            scenarios = ['stock', 'seeded-counter', 'counter-disabled'] + (['shared-path'] if role == 'slave' else [])
            for scenario in scenarios:
                with reset_machine(args.qemu, args.destination/f'{role}-{scenario}', image, role,
                                   counter_enabled=scenario != 'counter-disabled') as remote:
                    context['scenarios'][scenario] = trace_counter(remote, image, structures[role], scenario)
                print('PASS', role, scenario, flush=True)
            context['passed'] = True
            report['contexts'].append(context)
        report['passed'] = True
        (args.destination/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
        print('Report:', args.destination/'report.json')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
