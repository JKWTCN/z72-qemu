# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify original secondary startup, peer readiness and startup-task execution."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from analyze.runtime_smp import smp_profile
from tools.boot_probe import reset_machine
from tools.early_boot_probe import word


def stop_registers(remote, response):
    require(response.startswith('T05'), 'Expected debugger stop')
    match = re.search(r'(?:^|;)thread:([0-9a-f]+);', response[3:])
    require(match is not None, 'Missing debugger stop thread')
    thread = int(match[1], 16)
    remote.select_thread(thread)
    return thread, remote.regs()


def reach(remote, address, action='vCont;c'):
    remote.breakpoint(address)
    try:
        thread, regs = stop_registers(remote, remote.command(action))
        require(remote.get(regs, 'pc') == address,
                f'Unexpected execution stop at {remote.get(regs, "pc"):#x}')
        return thread, regs
    except TimeoutError:
        remote.interrupt()
        raise
    finally:
        remote.breakpoint(address, False)


def snapshot(remote, thread, regs):
    return dict(thread=thread, **{name: remote.get(regs, name)
        for name in ('pc', 'sp', 'lr', 'cpsr', 'r0', 'r1', 'r2', 'r3')})


def trace_smp(remote, image, structure, scenario, stop_after_task=False,
              observe_secondary_wait=True):
    profile = smp_profile(image, structure)
    vectors = structure['startup']['vector_address']
    exceptions = [vectors+n for n in (4, 12, 16)]
    remote.sock.settimeout(15)
    for address in exceptions:
        remote.breakpoint(address)
    try:
        result = dict(scenario=scenario, events=[])
        if scenario != 'single-core' and observe_secondary_wait:
            # Run only the secondary to its original WFE. The primary remains
            # at reset; this checks waiting without supplying the release word.
            thread, regs = reach(remote, BASE+profile['secondary_wait'], 'vCont;c:2')
            require(thread == 2 and remote.get(regs, 'sp') == profile['secondary_stack'] and
                    remote.get(regs, 'r0') == profile['release_word'] and
                    remote.get(regs, 'r2') == profile['release_value'] and
                    word(remote, profile['release_word']) == 0,
                    'Secondary reset wait or stack mismatch')
            result['events'].append(dict(name='secondary-reset-wait', **snapshot(remote, thread, regs)))
            remote.select_thread(1)
            require(remote.get(remote.regs(), 'pc') == BASE, 'Primary ran during secondary-only execution')
        action = 'vCont;c' if scenario == 'concurrent' else 'vCont;c:1'
        thread, regs = reach(remote, BASE+profile['barrier_wait'], action)
        require(thread == 1 and remote.get(regs, 'r0') == 1 and
                remote.get(regs, 'r1') == profile['peer_count_word'], 'Primary barrier contract mismatch')
        arrived = word(remote, profile['peer_count_word'])
        result['events'].append(dict(name='primary-barrier', peers_arrived=arrived,
                                     **snapshot(remote, thread, regs)))
        if scenario != 'concurrent':
            require(arrived == 0, 'Inactive secondary fabricated readiness')
            for _ in range(4):
                for offset in range(profile['barrier_wait'], profile['barrier_wait']+12, 4):
                    require(remote.get(remote.regs(), 'pc') == BASE+offset, 'Primary left original peer loop')
                    stop_registers(remote, remote.command('vCont;s:1'))
            require(word(remote, profile['peer_count_word']) == 0,
                    'Primary manufactured readiness while peer was inactive')
            result['inactive_peer_wait_verified'] = True
        if scenario == 'single-core':
            result['startup_task_execution_verified'] = False
            return result
        if scenario == 'held-secondary':
            require(word(remote, profile['release_word']) == profile['release_value'],
                    'Primary did not publish original release marker')
            # Catch the original exclusive store before it executes, then step
            # it once with the watchpoint removed. No readiness memory is written
            # by the probe, and both CPUs keep their original register state.
            address = profile['peer_count_word']
            require(remote.command(f'Z2,{address:x},4') == 'OK', 'Peer watchpoint failed')
            try:
                thread, regs = stop_registers(remote, remote.command('vCont;c:2'))
                require(thread == 2 and remote.get(regs, 'pc') == BASE+profile['ready_store'] and
                        remote.get(regs, 'r0') == address and remote.get(regs, 'r1') == 1 and
                        word(remote, address) == 0, 'Original peer-ready store mismatch')
                result['events'].append(dict(name='secondary-ready-store', **snapshot(remote, thread, regs)))
            finally:
                require(remote.command(f'z2,{address:x},4') == 'OK', 'Peer watchpoint removal failed')
            thread, regs = stop_registers(remote, remote.command('vCont;s:2'))
            require(thread == 2 and remote.get(regs, 'r2') == 0 and word(remote, address) == 1,
                    'Original exclusive store did not publish readiness')
            result['original_ready_store_verified'] = True
        else:
            require(arrived in (0, 1), 'Unexpected concurrent peer count')
        thread, regs = reach(remote, profile['task_entry'])
        stack = remote.get(regs, 'sp')
        require(thread == 1 and remote.get(regs, 'cpsr') & 0xFF == 0x13 and
                remote.get(regs, 'lr') == 0 and remote.get(regs, 'r0') == 0 and
                word(remote, profile['peer_count_word']) == 0,
                'Original startup task state or barrier acknowledgement mismatch')
        heap_start, heap_end = ((0xB2C00000, 0xB5F00000) if structure['role'] == 'master'
                               else (0xC1940000, 0xC5000000))
        require(heap_start <= stack-profile['task_stack_bytes'] < stack < heap_end,
                'Startup task stack is outside original heap')
        require(remote.read(profile['release_word'], 4) == bytes(4) and
                remote.read(profile['copied_table'], 0x4000) == image[0x10000:0x14000] and
                remote.read(BASE+0x10000, 0x4000) == image[0x10000:0x14000],
                'Release acknowledgement or original page tables mismatch')
        result['events'].append(dict(name='startup-task-entry', **snapshot(remote, thread, regs)))
        result['startup_task_execution_verified'] = True
        if stop_after_task:
            return result
        # Keep all native exception breakpoints active. The very next stop must
        # establish the unsupported device boundary rather than bypass it.
        thread, regs = stop_registers(remote, remote.command('vCont;c'))
        require(thread == 1 and remote.get(regs, 'pc') == vectors+16 and
                remote.get(regs, 'cpsr') & 0x1F == 0x17 and
                remote.get(regs, 'lr') == BASE+profile['peripheral_fault_offset']+8 and
                remote.get(regs, 'r3')+1 == profile['peripheral_fault_address'],
                'Unexpected post-task exception boundary')
        result['events'].append(dict(name='startup-device-data-abort', address=profile['peripheral_fault_address'],
                                     **snapshot(remote, thread, regs)))
        result['next_device_boundary_verified'] = True
        return result
    finally:
        for address in exceptions:
            remote.breakpoint(address, False)


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
        profiles = {role: smp_profile(image, structures[role]) for role, image in images.items()}
        args.destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, contexts=[], full_boot_verified=False, menu_verified=False,
            qemu_version=subprocess.check_output([args.qemu, '--version'], text=True).splitlines()[0],
            assumptions=['One or two experimental Cortex-A7 execution cores per isolated role.',
                'Original images preloaded; each initial PC supplied only at reset by the loader.',
                'No instruction, register, page-table or readiness writes by the probe.',
                'Experimental platform completion, RAM and counter contracts remain in use.',
                'CPU SMP does not supply communication between master and slave machines.',
                'Console interface disabled to retain the previous startup device boundary.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], profile=profiles[role], scenarios={})
            for scenario in ('single-core', 'held-secondary', 'concurrent'):
                with reset_machine(args.qemu, args.destination/f'{role}-{scenario}', image, role,
                                   cpus=1 if scenario == 'single-core' else 2, uart_enabled=False) as remote:
                    context['scenarios'][scenario] = trace_smp(remote, image, structures[role], scenario)
                if scenario != 'single-core':
                    log = (args.destination/f'{role}-{scenario}'/'qemu.log').read_text(encoding='utf-8')
                    require('with DFSR 0x1808 DFAR 0x2c090001' in log,
                            'Startup device fault status/address mismatch')
                    context['scenarios'][scenario]['fault_status'] = 0x1808
                    context['scenarios'][scenario]['fault_address'] = 0x2C090001
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
