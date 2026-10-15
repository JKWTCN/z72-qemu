# SPDX-License-Identifier: GPL-2.0-or-later
"""Follow original startup through the parameter restore to its mirror write."""
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
from analyze.parameter_boot import parameter_profile
from tools.boot_probe import reset_machine
from tools.smp_boot_probe import trace_smp, reach, stop_registers, snapshot


def trace_parameter(remote, image, structure, disabled):
    role = structure['role']
    profile = parameter_profile(image, structure, role)
    prefix = trace_smp(remote, image, structure, 'concurrent', stop_after_task=True)
    vectors = structure['startup']['vector_address']
    exceptions = [vectors+n for n in (4, 12, 16)]
    for address in exceptions:
        remote.breakpoint(address)
    try:
        thread, regs = reach(remote, BASE+profile['entry'])
        require(thread == 1 and remote.get(regs, 'cpsr') & 0x20,
                'Original parameter restore did not enter Thumb state')
        if disabled:
            thread, after = stop_registers(remote, remote.command('vCont;c'))
            require(thread == 1 and remote.get(after, 'pc') == vectors+16 and
                    remote.get(after, 'cpsr') & 31 == 0x17 and
                    remote.get(after, 'lr') == BASE+profile['first_store']+8,
                    'Disabled parameter words did not abort on the first store')
            return dict(prefix=prefix, restore_completed=False,
                        parameter_disabled_data_abort_verified=True,
                        fault=snapshot(remote, thread, after))
        remote.breakpoint(BASE+profile['function_end'])
        try:
            thread, after = stop_registers(remote, remote.command('vCont;c'))
        finally:
            remote.breakpoint(BASE+profile['function_end'], False)
        require(thread == 1 and remote.get(after, 'pc') == BASE+profile['function_end'],
                'Original parameter tail did not run to its completion')
        for address, source in profile['words'].items():
            if address == profile['trigger']:
                continue  # cleared before completion; verified separately
            stored = int.from_bytes(remote.read(address, 4), 'little')
            expected = int.from_bytes(remote.read(source, 4), 'little')
            require(stored == expected,
                    f'Original parameter store mismatch at {address:#x}')
        restored = [int.from_bytes(remote.read(address, 4), 'little')
                    for address in profile['pointers']]
        saved = [int.from_bytes(remote.read(profile['snapshot']+i*4, 4), 'little')
                 for i in range(profile['restore_count'])]
        require(restored == saved, 'Original register restore mismatch')
        base, size = profile['mirror_window']
        mirrored = [int.from_bytes(remote.read(base+i*4, 4), 'little')
                    for i in (0, 1, size//4-2, size//4-1)]
        require(mirrored == [0, 0, 0, 0], 'Original mirror copy mismatch')
        for index, address in enumerate(profile['final_words'][:4]):
            stored = int.from_bytes(remote.read(address, 4), 'little')
            expected = int.from_bytes(remote.read(
                profile['source']+0x270+index*4, 4), 'little')
            require(stored == expected,
                    f'Original final store mismatch at {address:#x}')
        for index, address in enumerate(profile['block_words']):
            stored = int.from_bytes(remote.read(address, 4), 'little')
            expected = int.from_bytes(remote.read(
                profile['source']+0x280+(index % 3)*4, 4), 'little')
            require(stored == expected,
                    f'Original block store mismatch at {address:#x}')
        scatter_base = profile['pointer']
        for address, index in profile['scatter']:
            stored = int.from_bytes(remote.read(address, 4), 'little')
            expected = int.from_bytes(remote.read(
                scatter_base+index*4, 4), 'little')
            require(stored == expected,
                    f'Original scatter store mismatch at {address:#x}')
        require(int.from_bytes(remote.read(profile['trigger'], 4), 'little') == 0,
                'Original trigger was not cleared at completion')
        require(int.from_bytes(remote.read(0x20010034, 4), 'little') == 1,
                'Original second-poll trigger mismatch')
        remote.breakpoint(BASE+profile['chain_return'])
        try:
            # Continue only the primary core: the secondary may independently
            # fault in its own idle path once the primary progresses this far.
            thread, after = stop_registers(remote, remote.command('vCont;c:1'))
        finally:
            remote.breakpoint(BASE+profile['chain_return'], False)
        require(thread == 1 and remote.get(after, 'pc') == BASE+profile['chain_return'],
                'Original parameter tail did not return to the chain')
        staging = dict(staging_copy_verified=False)
        if profile.get('staging'):
            spec = profile['staging']
            remote.breakpoint(BASE+spec['copy_return'])
            try:
                thread, after = stop_registers(remote, remote.command('vCont;c:1'))
            finally:
                remote.breakpoint(BASE+spec['copy_return'], False)
            require(thread == 1 and
                    remote.get(after, 'pc') == BASE+spec['copy_return'],
                    'Original staging copy did not return')
            for offset in (0, spec['length']//2 & ~3, spec['length']-4):
                landed = remote.read(spec['dest']+offset, 4)
                expected = image[spec['source_file']+offset:
                                 spec['source_file']+offset+4]
                require(landed == expected,
                        'Original staging copy payload mismatch')
            staging.update(staging_copy_verified=True)
        bounded = dict(bounded_continue_timed_out=False)
        remote.sock.settimeout(60)
        try:
            thread, after = stop_registers(remote, remote.command('vCont;c:1'))
            require(thread == 1 and remote.get(after, 'pc') == vectors+16 and
                    remote.get(after, 'cpsr') & 31 == 0x17,
                    'Expected the next data abort in the initializer chain')
            bounded.update(fault=snapshot(remote, thread, after))
        except TimeoutError:
            # The outstanding vCont reply never arrived; interrupt the target
            # so the pending stop reply drains and the connection resyncs.
            remote.sock.settimeout(20)
            try:
                remote.interrupt()
            except TimeoutError:
                pass
            bounded.update(bounded_continue_timed_out=True)
        remote.sock.settimeout(10)
        return dict(prefix=prefix, restore_completed=True, tail_completed=True,
            chain_return_verified=True, **staging, **bounded,
            segment_words=len(profile['words'])-1, trigger_verified=True,
            register_restore_verified=True, mirror_verified=True,
            block_words=len(profile['block_words']),
            scatter_words=len(profile['scatter']),
            next_address=None, full_startup_verified=False)
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
        profiles = {role: parameter_profile(image, structures[role], role)
                    for role, image in images.items()}
        args.destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, contexts=[], full_boot_verified=False, menu_verified=False,
            qemu_version=subprocess.check_output([args.qemu, '--version'], text=True).splitlines()[0],
            assumptions=['Two execution cores per isolated role; original reset and startup task.',
                'Original images preloaded; no register, instruction, table or handshake patches.',
                'Parameter words are passive storage; the poll register reports ready.',
                'The snapshot stage stays enabled; its recorded source model remains in use.',
                'Existing experimental console, pin-group, controller and snapshot contracts remain in use.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], scenarios={})
            for disabled in (False, True):
                name = 'parameter-disabled' if disabled else 'stock'
                with reset_machine(args.qemu, args.destination/f'{role}-{name}', image, role,
                                   cpus=2, uart_enabled=True,
                                   console=args.destination/f'{role}-{name}-console.txt',
                                   parameter_config=not disabled) as remote:
                    result = trace_parameter(remote, image, structures[role], disabled)
                log = (args.destination/f'{role}-{name}'/'qemu.log').read_text(encoding='utf-8')
                if disabled or not result.get('bounded_continue_timed_out'):
                    matches = re.findall(r'with DFSR (\w+) DFAR (\w+)', log)
                    require(matches and matches[-1][0] == '0x808',
                            'Parameter restore fault status mismatch')
                    fault_address = int(matches[-1][1], 16)
                    if disabled:
                        require(fault_address == 0x20013000,
                                'Disabled parameter words aborted elsewhere')
                    else:
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
