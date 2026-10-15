# SPDX-License-Identifier: GPL-2.0-or-later
"""Follow original startup through console setup to the next library configuration."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from analyze.console_boot import console_profile
from tools.boot_probe import reset_machine
from tools.smp_boot_probe import trace_smp, reach, stop_registers, snapshot


def trace_console(remote, image, structure, disabled):
    profile = console_profile(image, structure['role'])
    prefix = trace_smp(remote, image, structure, 'concurrent', stop_after_task=True)
    vectors = structure['startup']['vector_address']
    exceptions = [vectors+n for n in (4, 12, 16)]
    for address in exceptions:
        remote.breakpoint(address)
    try:
        thread, regs = reach(remote, BASE+profile['initializer'])
        require(thread == 1 and [remote.get(regs, f'r{i}') for i in range(3)] ==
                [profile['base'], 0, 1], 'Original console initialization arguments mismatch')
        stack = remote.get(regs, 'sp')
        saved = [remote.get(regs, name) for name in ('r4', 'r5', 'lr')]
        stores = []
        by_offset = {store['offset']: store for store in profile['stores']}
        for offset in range(profile['initializer'], profile['initializer_return']+4, 4):
            regs = remote.regs()
            require(remote.get(regs, 'pc') == BASE+offset, 'Console initializer changed its original path')
            store = by_offset.get(offset)
            if store:
                source = {0x19C:'r4', 0x1A4:'r12', 0x1AC:'r5', 0x1B0:'r4',
                          0x1B4:'r12', 0x1B8:'r4'}.get(offset, 'r0')
                require(remote.get(regs, source) == store['value'], 'Original console store value mismatch')
            thread, after = stop_registers(remote, remote.command('vCont;s:1'))
            if disabled and offset == 0x19C:
                require(thread == 1 and remote.get(after, 'pc') == vectors+16 and
                        remote.get(after, 'cpsr') & 31 == 0x17 and
                        remote.get(after, 'lr') == BASE+0x1A4, 'Disabled console did not abort on first store')
                return dict(prefix=prefix, console_disabled_data_abort_verified=True,
                            initializer_completed=False, fault=snapshot(remote, thread, after))
            require(thread == 1 and remote.get(after, 'cpsr') & 0x3F == 0x13,
                    'Console initializer entered an exception')
            if store:
                address = profile['base']+store['register']
                value = int.from_bytes(remote.read(address, store['size']), 'little')
                require(value == (store['value'] | 2 if store['register'] == 3 else store['value']),
                        'Original console store readback mismatch')
                stores.append(store)
        regs = remote.regs()
        require(remote.get(regs, 'pc') == BASE+profile['caller_return'] and
                remote.get(regs, 'sp') == stack and
                [remote.get(regs, name) for name in ('r4', 'r5', 'lr')] == saved,
                'Original console initializer did not restore caller state')
        require([remote.read(profile['base']+i, 1)[0] for i in range(4)] == profile['final_bytes'] and
                int.from_bytes(remote.read(profile['base']+6, 2), 'little') == profile['divisor'] and
                int.from_bytes(remote.read(profile['base']+12, 2), 'little') == profile['format'],
                'Final console register configuration mismatch')
        thread, regs = stop_registers(remote, remote.command('vCont;c'))
        require(thread == 1 and remote.get(regs, 'pc') == vectors+16 and
                remote.get(regs, 'lr') == BASE+profile['next_fault_offset']+8 and
                remote.get(regs, 'cpsr') & 31 == 0x17 and
                remote.get(regs, 'r2')+0x30 == profile['next_fault_address'] and
                remote.get(regs, 'r1') == profile['next_fault_value'],
                'Unexpected next library configuration boundary')
        return dict(prefix=prefix, initializer_completed=True, original_stores=stores,
            caller_stack_restored=True, next_library_boundary_verified=True,
            fault=snapshot(remote, thread, regs), next_address=profile['next_fault_address'],
            native_console_output_verified=False)
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
        profiles = {role: console_profile(image, role) for role, image in images.items()}
        args.destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, contexts=[], full_boot_verified=False, menu_verified=False,
            qemu_version=subprocess.check_output([args.qemu, '--version'], text=True).splitlines()[0],
            assumptions=['Two execution cores per isolated role; original reset and startup task.',
                'Original images preloaded; no register, instruction, table or handshake patches.',
                'Bounded console TX completes synchronously; receive, IRQ and baud timing unmodeled.',
                'Pin-group words disabled to retain the recorded pre-library startup boundary.',
                'Existing experimental platform, memory and counter contracts remain in use.'
                'Release-path storage disabled to retain the recorded boundary.',])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], profile=profiles[role], scenarios={})
            for disabled in (False, True):
                name = 'console-disabled' if disabled else 'stock'
                with reset_machine(args.qemu, args.destination/f'{role}-{name}', image, role, cpus=2,
                                   uart_enabled=not disabled, console=args.destination/f'{role}-{name}-console.txt',
                                   pin_config=False,
                                   release_config=False) as remote:
                    result = trace_console(remote, image, structures[role], disabled)
                log = (args.destination/f'{role}-{name}'/'qemu.log').read_text(encoding='utf-8')
                fault_address = 0x2C090001 if disabled else profiles[role]['next_fault_address']
                fault_status = 0x1808 if disabled else 0x808
                require(f'with DFSR {fault_status:#x} DFAR {fault_address:#x}' in log,
                        'Console fault status/address mismatch')
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
