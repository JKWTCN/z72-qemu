# SPDX-License-Identifier: GPL-2.0-or-later
"""Follow original startup through the controller chain to its next boundary."""
import argparse
import json
import re
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from analyze.controller_boot import GATE_BASE, controller_profile
from tools.boot_probe import reset_machine
from tools.smp_boot_probe import trace_smp, reach, stop_registers, snapshot


def trace_controller(remote, image, structure, disabled, next_fault):
    profile = controller_profile(image, structure['role'])
    prefix = trace_smp(remote, image, structure, 'concurrent', stop_after_task=True)
    vectors = structure['startup']['vector_address']
    exceptions = [vectors+n for n in (4, 12, 16)]
    for address in exceptions:
        remote.breakpoint(address)
    try:
        thread, regs = reach(remote, BASE+profile['entry'])
        require(thread == 1 and remote.get(regs, 'cpsr') & 0x20,
                'Original controller chain did not enter Thumb state')
        stack = remote.get(regs, 'sp')
        names = ('r4', 'r5', 'r6', 'r7', 'r8', 'lr')
        saved = [remote.get(regs, name) for name in names]
        if disabled:
            thread, after = stop_registers(remote, remote.command('vCont;c'))
            require(thread == 1 and remote.get(after, 'pc') == vectors+16 and
                    remote.get(after, 'cpsr') & 31 == 0x17 and
                    remote.get(after, 'lr') == BASE+profile['first_store']+8,
                    'Disabled controller words did not abort on the first store')
            return dict(prefix=prefix, chain_completed=False,
                        controller_disabled_data_abort_verified=True,
                        fault=snapshot(remote, thread, after))
        before = int.from_bytes(remote.read(profile['delay'][0]+8, 4), 'little')
        remote.breakpoint(BASE+profile['call_return'])
        try:
            thread, after = stop_registers(remote, remote.command('vCont;c'))
        finally:
            remote.breakpoint(BASE+profile['call_return'], False)
        require(thread == 1 and remote.get(after, 'pc') == BASE+profile['call_return'] and
                remote.get(after, 'sp') == stack and
                [remote.get(after, name) for name in names] == saved,
                'Original controller chain did not restore caller state')
        after_count = int.from_bytes(remote.read(profile['delay'][0]+8, 4), 'little')
        require(after_count - before >= profile['delay'][2],
                'Original controller delay did not elapse on the counter')
        for address, value in profile['words'].items():
            observed = int.from_bytes(remote.read(address, 4), 'little')
            require(observed == value,
                    f'Original controller store mismatch at {address:#x}')
        thread, after = stop_registers(remote, remote.command('vCont;c'))
        require(thread == 1 and remote.get(after, 'pc') == vectors+16 and
                remote.get(after, 'cpsr') & 31 == 0x17,
                'Expected a data abort at the next startup boundary')
        return dict(prefix=prefix, chain_completed=True, delay_verified=True,
            caller_stack_restored=True, gate_final=profile['words'][GATE_BASE],
            gate_calls=profile['gate_calls'], word_count=len(profile['words']),
            fault=snapshot(remote, thread, after), full_startup_verified=False)
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
                'Controller words are passive storage; no bus, clock or gate behavior is modeled.',
                'The existing counter device provides the original delay reference.',
                'Snapshot words disabled to retain the recorded controller boundary.',
                'Existing experimental console and pin-group contracts remain in use.'])
        profiles = {role: controller_profile(image, role) for role, image in images.items()}
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], scenarios={})
            for disabled in (False, True):
                name = 'controller-disabled' if disabled else 'stock'
                with reset_machine(args.qemu, args.destination/f'{role}-{name}', image, role,
                                   cpus=2, uart_enabled=True,
                                   console=args.destination/f'{role}-{name}-console.txt',
                                   controller_config=not disabled,
                                   snapshot_config=False) as remote:
                    result = trace_controller(remote, image, structures[role], disabled, None)
                log = (args.destination/f'{role}-{name}'/'qemu.log').read_text(encoding='utf-8')
                matches = re.findall(r'with DFSR (\w+) DFAR (\w+)', log)
                require(matches and matches[-1][0] == '0x808',
                        'Controller chain fault status mismatch')
                fault_address = int(matches[-1][1], 16)
                if disabled:
                    require(fault_address == 0x04281138 and
                            result['fault']['lr'] == BASE + profiles[role]['first_store'] + 8,
                            'Disabled controller words aborted elsewhere')
                else:
                    require(fault_address == profiles[role]['next_fault_address'] and
                            result['fault']['lr'] == BASE + profiles[role]['next_store'] + 8,
                            'Unexpected next startup boundary')
                    result['next_address'] = fault_address
                result.update(fault_status=0x808, fault_address=fault_address)
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
