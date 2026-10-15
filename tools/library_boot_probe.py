# SPDX-License-Identifier: GPL-2.0-or-later
"""Follow original startup through the pin-group stores to the next controller."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from analyze.library_boot import (PIN_GROUP_COUNT, library_profile, library_table,
                                   pin_words)
from tools.boot_probe import reset_machine
from tools.smp_boot_probe import trace_smp, reach, stop_registers, snapshot


def read_words(remote, address, count):
    blob = remote.read(address, count * 4)
    return [int.from_bytes(blob[index:index+4], 'little') for index in range(0, count * 4, 4)]


def trace_library(remote, image, structure, disabled):
    role = structure['role']
    profile = library_profile(image, role)
    table = library_table(image, structure, role)
    expected = pin_words(table['words'])
    # Instruction-count scheduling needs both CPUs to advance together.
    prefix = trace_smp(remote, image, structure, 'concurrent',
                       stop_after_task=True, observe_secondary_wait=False)
    vectors = structure['startup']['vector_address']
    exceptions = [vectors+n for n in (4, 12, 16)]
    for address in exceptions:
        remote.breakpoint(address)
    try:
        thread, regs = reach(remote, BASE+profile['entry'])
        require(thread == 1 and remote.get(regs, 'cpsr') & 0x20,
                'Original pin initializer did not enter Thumb state')
        source = read_words(remote, profile['table_source'], PIN_GROUP_COUNT * 5)
        require(source == list(table['words']),
                'Original early copy did not deliver the pin table')
        stack = remote.get(regs, 'sp')
        names = ('r4', 'r5', 'r6', 'r7', 'lr') if role == 'master' else ('r4', 'r5', 'r6', 'lr')
        saved = [remote.get(regs, name) for name in names]
        if disabled:
            thread, after = stop_registers(remote, remote.command('vCont;c'))
            require(thread == 1 and remote.get(after, 'pc') == vectors+16 and
                    remote.get(after, 'cpsr') & 31 == 0x17 and
                    remote.get(after, 'lr') == BASE+profile['config_store']+8,
                    'Disabled pin words did not abort on the configuration store')
            return dict(prefix=prefix, pin_words_disabled_data_abort_verified=True,
                        initializer_completed=False, fault=snapshot(remote, thread, after))
        remote.breakpoint(BASE+profile['call_return'])
        try:
            thread, after = stop_registers(remote, remote.command('vCont;c'))
        finally:
            remote.breakpoint(BASE+profile['call_return'], False)
        require(thread == 1 and remote.get(after, 'pc') == BASE+profile['call_return'] and
                remote.get(after, 'sp') == stack and
                [remote.get(after, name) for name in names] == saved,
                'Original pin initializer did not restore caller state')
        observed_words = {address: read_words(remote, address, 1)[0] for address in expected}
        require(observed_words == expected, 'Original pin bank stores mismatch')
        observed = dict(pin_base=read_words(remote, 0x04282000, 12),
                        pin_banks=[read_words(remote, 0x04282000+bank*0x100, 12)
                                   for bank in range(5)])
        require(int.from_bytes(remote.read(profile['base']+0x30, 4), 'little') == profile['value'],
                'Original pin configuration word mismatch')
        for offset in (0x34, 0x38):
            value = int.from_bytes(remote.read(profile['base']+offset, 4), 'little')
            require(value == (profile['final_control'] if offset == 0x34 else
                              profile['final_mux']), 'Original pin modification mismatch')
        thread, after = stop_registers(remote, remote.command('vCont;c'))
        require(thread == 1 and remote.get(after, 'pc') == vectors+16 and
                remote.get(after, 'cpsr') & 31 == 0x17 and
                remote.get(after, 'lr') == BASE+profile['next_store']+8 and
                remote.get(after, 'r0') + 0x138 == 0x04281138,
                'Unexpected next controller boundary')
        return dict(prefix=prefix, initializer_completed=True, caller_stack_restored=True,
            original_table_source=hex(profile['table_source']),
            original_table_words=list(table['words']), pin_banks=observed,
            next_controller_boundary_verified=True, fault=snapshot(remote, thread, after),
            next_address=0x04281138, full_startup_verified=False)
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
        args.destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, contexts=[], full_boot_verified=False, menu_verified=False,
            qemu_version=subprocess.check_output([args.qemu, '--version'], text=True).splitlines()[0],
            assumptions=['Two execution cores per isolated role; original reset and startup task.',
                'Original images preloaded; no register, instruction, table or handshake patches.',
                'Instruction-count virtual clock prevents host-speed timer starvation.',
                'Pin words are passive storage; no pin, pad or electrical behavior is modeled.',
                'Controller-chain words disabled to retain the recorded pin-group boundary.',
                'Release-path storage disabled to retain the recorded boundary.',
                'Existing experimental console, platform, memory and counter contracts remain in use.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], scenarios={})
            for disabled in (False, True):
                name = 'pin-disabled' if disabled else 'stock'
                with reset_machine(args.qemu, args.destination/f'{role}-{name}', image, role,
                                   cpus=2, uart_enabled=True,
                                   console=args.destination/f'{role}-{name}-console.txt',
                                   pin_config=not disabled,
                                   controller_config=False,
                                   release_config=False,
                                   icount='shift=0,sleep=off') as remote:
                    result = trace_library(remote, image, structures[role], disabled)
                log = (args.destination/f'{role}-{name}'/'qemu.log').read_text(encoding='utf-8')
                fault_address = 0x04280030 if disabled else 0x04281138
                fault_status = 0x808
                require(f'with DFSR {fault_status:#x} DFAR {fault_address:#x}' in log,
                        'Pin configuration fault status/address mismatch')
                result.update(fault_status=fault_status, fault_address=fault_address)
                context['scenarios'][name] = result
                print('PASS', role, name, flush=True)
            context['passed'] = True
            report['contexts'].append(context)
        report['passed'] = True
        (args.destination/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
