# SPDX-License-Identifier: GPL-2.0-or-later
"""Follow original startup through the configuration snapshot to its source read."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from analyze.snapshot_boot import snapshot_profile
from tools.boot_probe import reset_machine
from tools.smp_boot_probe import trace_smp, reach, stop_registers, snapshot


def trace_snapshot(remote, image, structure, disabled):
    role = structure['role']
    profile = snapshot_profile(image, structure, role)
    prefix = trace_smp(remote, image, structure, 'concurrent', stop_after_task=True)
    vectors = structure['startup']['vector_address']
    exceptions = [vectors+n for n in (4, 12, 16)]
    for address in exceptions:
        remote.breakpoint(address)
    try:
        thread, regs = reach(remote, BASE+profile['entry'])
        require(thread == 1 and remote.get(regs, 'cpsr') & 0x20,
                'Original configuration snapshot did not enter Thumb state')
        pointers = [int.from_bytes(remote.read(profile['table_source']+i*4, 4), 'little')
                    for i in range(len(profile['pointers']))]
        require(pointers == list(profile['pointers']),
                'Original early copy did not deliver the snapshot pointer table')
        if disabled:
            thread, after = stop_registers(remote, remote.command('vCont;c'))
            require(thread == 1 and remote.get(after, 'pc') == vectors+16 and
                    remote.get(after, 'cpsr') & 31 == 0x17 and
                    remote.get(after, 'lr') == BASE+profile['gate_store']+8,
                    'Disabled snapshot words did not abort on the gate store')
            return dict(prefix=prefix, snapshot_completed=False,
                        snapshot_disabled_data_abort_verified=True,
                        fault=snapshot(remote, thread, after))
        require(int.from_bytes(remote.read(profile['gate'], 4), 'little') == 0,
                'Original snapshot did not begin with a clear gate')
        thread, after = stop_registers(remote, remote.command('vCont;c'))
        tail = profile['tail']
        require(thread == 1 and remote.get(after, 'pc') == vectors+16 and
                remote.get(after, 'cpsr') & 31 == 0x17 and
                remote.get(after, 'lr') == BASE+tail['store']+8,
                'Expected the original data abort at the tail parameter store')
        require(int.from_bytes(remote.read(profile['gate'], 4), 'little') == 0,
                'Original snapshot gate was not restored to zero')
        registers = [int.from_bytes(remote.read(profile['destination']+i*4, 4), 'little')
                     for i in range(len(profile['deref']))]
        expected = [int.from_bytes(remote.read(address, 4), 'little')
                    for address in profile['deref']]
        require(registers == expected, 'Original snapshot register copy mismatch')
        table = [int.from_bytes(remote.read(profile['source']+i*4, 4), 'little')
                 for i in (0, 1, 0x1FE, 0x1FF)]
        copied = [int.from_bytes(remote.read(
            profile['destination']+0x4C+i*4, 4), 'little') for i in (0, 1, 0x1FE, 0x1FF)]
        require(table == copied == [0, 0, 0, 0],
                'Original zero-source bulk copy mismatch')
        landed = min((tail['fault'] - tail['dest']) >> 2, 23)
        if landed:
            source = [int.from_bytes(remote.read(tail['source']+i*4, 4), 'little')
                      for i in range(landed)]
            written = [int.from_bytes(remote.read(tail['dest']+i*4, 4), 'little')
                       for i in range(landed)]
            require(written == source, 'Original tail parameter copy mismatch')
        return dict(prefix=prefix, snapshot_completed=True,
            bulk_copy_verified=True, gate_restored_verified=True,
            pointer_provenance_verified=True,
            dereference_count=len(profile['deref']),
            tail_landed_words=landed,
            fault=snapshot(remote, thread, after),
            next_address=profile['next_fault_address'], full_startup_verified=False)
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
                'Snapshot words are passive storage; register reset values are assumed zero.',
                'Parameter words disabled to retain the recorded snapshot boundary.',
                'Existing experimental console, pin-group and controller contracts remain in use.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], scenarios={})
            for disabled in (False, True):
                name = 'snapshot-disabled' if disabled else 'stock'
                with reset_machine(args.qemu, args.destination/f'{role}-{name}', image, role,
                                   cpus=2, uart_enabled=True,
                                   console=args.destination/f'{role}-{name}-console.txt',
                                   snapshot_config=not disabled,
                                   parameter_config=False) as remote:
                    result = trace_snapshot(remote, image, structures[role], disabled)
                log = (args.destination/f'{role}-{name}'/'qemu.log').read_text(encoding='utf-8')
                fault_address = 0x20010044 if disabled else result['next_address']
                fault_status = 0x808
                require(f'with DFSR {fault_status:#x} DFAR {fault_address:#x}' in log,
                        'Configuration snapshot fault status/address mismatch')
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
