# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute stock master/slave initialization routines in isolated QEMU contexts."""
import argparse
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, digest, require
from analyze.firmware_structure import PROFILES, analyze_eg
from analyze.qemu_display import Machine, table_for


def poison(remote, address, size):
    for offset in range(0, size, 512):
        remote.write(address + offset, b'\xA5' * min(512, size - offset))


def execute(remote, entry, stop, **registers):
    remote.breakpoint(stop)
    try:
        remote.set(pc=entry, **registers)
        remote.command('c')
        require(remote.get(remote.regs(), 'pc') == stop,
                'Initialization routine failed or reached an exception vector')
    finally:
        remote.breakpoint(stop, False)


def verify_copy(remote, image, record, operation):
    source, destination, size = (record[k] for k in ('source', 'destination', 'size'))
    poison(remote, destination, max(size, 4))
    guard_address = destination + max(size, 4)
    remote.write(guard_address, b'Z72!')
    operation()
    expected = image[source - BASE:source - BASE + size] if size else b'\xA5' * 4
    require(remote.read(destination, max(size, 4)) == expected, 'Copied data mismatch')
    require(remote.read(guard_address, 4) == b'Z72!', 'Copy exceeded destination')
    return dict(source=source, destination=destination, size=size,
                copied_sha256=digest(expected) if size else None,
                zero_length_preserved=size == 0, trailing_guard_preserved=True)


def verify_communication_header(remote, header, stack):
    # Enter after OS-dependent calls; stop before the stack-restoring POP.
    # Distinct fill patterns expose accidental writes to the untouched words.
    address = header['local_address']
    trials = []
    for fill in (0xA5, 0x5A):
        before = b'Z72!' + bytes([fill]) * 0x18 + b'Z72!'
        remote.write(address - 4, before)
        expected = bytearray(before)
        for write in header['writes']:
            struct.pack_into('<I', expected, 4 + write['offset'], write['value'])
        execute(remote, BASE + header['entry_offset'], BASE + header['stop_offset'],
                cpsr=0x1F3, sp=stack, r0=0, r1=0xFFFFFFFF, r2=0, r3=0)
        actual = remote.read(address - 4, len(before))
        require(actual == expected, 'Communication header stores or preserved bytes mismatch')
        trials.append(dict(fill=fill, words=list(struct.unpack('<6I', actual[4:-4])),
                           untouched_words_preserved=True, guards_preserved=True))
    return dict(local_address=address, entry_offset=header['entry_offset'],
                stop_offset=header['stop_offset'], trials=trials,
                full_initializer_verified=False, inter_engine_transport_verified=False)


def probe(args):
    # Validate both complete images before creating the run directory.
    images = {'master': args.master.read_bytes(), 'slave': args.slave.read_bytes()}
    structures = {role: analyze_eg(image, role) for role, image in images.items()}
    destination = args.destination.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    subprocess.run([args.clang, '--target=arm-none-eabi', '-c',
                    str(ROOT / 'analyze/qemu_harness.S'), '-o', str(destination / 'harness.o')], check=True)
    subprocess.run([args.linker, '-Ttext=0x40100000', '--oformat=binary',
                    str(destination / 'harness.o'), '-o', str(destination / 'harness.bin')], check=True)
    report = dict(format=1, backend=args.backend,
                  qemu_version=subprocess.check_output([args.qemu, '--version'], text=True).splitlines()[0],
                  contexts=[], natural_boot_verified=False, dual_engine_execution_verified=False,
                  assumptions=['Each image runs in a separate one-CPU QEMU instance.',
                      'Synthetic MMU/vector setup with native section attributes; generic-loader preload.',
                      'Communication windows are plain RAM; no inter-engine transport is modeled.',
                      'Only one bounded zero-table record per role is executed; full clearing is not attempted.',
                      'Communication header stores run after OS calls and stop before the return POP.'])
    for role, image in images.items():
        structure = structures[role]
        machine = Machine(args.qemu, destination / role, image,
                          table_for(image, backend=args.backend, role=role), args.backend, role)
        remote = machine.remote
        stack = structure['startup']['core_zero_stack_tops'][-1]
        context = dict(role=role, sha256=digest(image), early_copies=[], table_copies=[])
        try:
            for record in structure['startup']['early_copies']:
                context['early_copies'].append(verify_copy(remote, image, record,
                    lambda r=record: execute(remote, BASE + r['entry_offset'], BASE + r['stop_offset'],
                                            cpsr=0x1D3, sp=stack)))
            for record in structure['initialization']['records']:
                if record['kind'] == 'copy':
                    context['table_copies'].append(verify_copy(remote, image, record,
                        lambda r=record: execute(remote, r['handler'], 0x40100080,
                            cpsr=0x1F3, sp=stack, lr=0x40100080, r0=r['source'],
                            r1=r['destination'], r2=r['size'])))
            # Both tables have a bounded 0xC618-byte communication-RAM zero record.
            zero = next(r for r in structure['initialization']['records']
                        if r['kind'] == 'zero' and r['size'] == 0xC618)
            address, size = zero['destination'], zero['size']
            poison(remote, address, size)
            remote.write(address - 4, b'Z72!')
            remote.write(address + size, b'Z72!')
            execute(remote, zero['handler'], 0x40100080, cpsr=0x1F3, sp=stack,
                    lr=0x40100080, r0=zero['source'], r1=address, r2=size)
            require(remote.read(address, size) == bytes(size), 'Zero handler failed')
            require(remote.read(address - 4, 4) == remote.read(address + size, 4) == b'Z72!',
                    'Zero handler exceeded destination')
            context['zero_sample'] = dict(destination=address, size=size, guards_preserved=True)
            context['communication_header'] = verify_communication_header(
                remote, structure['communication'], stack)
            context['passed'] = True
            report['contexts'].append(context)
            print('PASS', role, 'early loops, table copies, bounded zero and communication header stores', flush=True)
        finally:
            machine.close()
    report['passed'] = True
    (destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('Report:', destination / 'report.json')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True, help='New run directory')
    parser.add_argument('--backend', choices=('virt', 'nikon-z72-lab'), default='virt')
    for name in ('qemu', 'clang', 'linker'):
        binary = {'qemu': 'qemu-system-arm', 'clang': 'clang', 'linker': 'ld.lld'}[name]
        parser.add_argument('--' + name, default=shutil.which(binary) or binary)
    args = parser.parse_args()
    try:
        probe(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
