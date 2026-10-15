# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify bounded boot memory clearing and the original completion/error wait."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, digest, require
from analyze.firmware_structure import analyze_eg
from analyze.boot_continuation import continuation_profile
from tools.boot_probe import reset_machine
from tools.continuation_boot_probe import trace_continuation
from tools.early_boot_probe import word


def trace_memory(remote, structure, image, scenario, directory):
    role = structure['role']
    error = scenario == 'forced-error'
    profile = continuation_profile(role)
    destination = profile['transfer_destination']
    length = ((profile['transfer_size'] + 0x3FFF) >> 14) * 0x4000
    continuation = trace_continuation(remote, structure, image,
                                    'shared-path' if scenario == 'shared-path' else 'stock')
    # Dump physical RAM for a whole-range comparison; GDB state and firmware
    # instructions remain unchanged. The dump is local runtime output only.
    dump = (directory / 'memory.bin').resolve()
    command = f'pmemsave {destination - 4:#x} {length + 8:#x} {json.dumps(str(dump))}'
    require(remote.command('qRcmd,' + command.encode().hex()) == 'OK', 'Physical RAM dump failed')
    actual = dump.read_bytes()
    expected = b'Z72!' + (b'\xA5' * length if error else bytes(length)) + b'Z72!'
    require(actual == expected, 'Memory initialization bytes or guards mismatch')
    status = 0x10 if error else 1
    require(word(remote, 0x20070008) == status, 'Memory initialization status mismatch')
    wait_return = profile['wait_call'] + 4
    app_entry = 0x416C60 if role == 'master' else 0x1474A8
    trace, acknowledgements = [], []
    hook_seen = False
    return_seen = False
    for _ in range(35):
        regs = remote.regs()
        offset = remote.get(regs, 'pc') - BASE
        trace.append(dict(offset=offset, r0=remote.get(regs, 'r0')))
        require(remote.get(regs, 'cpsr') & 0x3F == 0x13, 'Memory wait left ARM SVC')
        if offset == app_entry:
            break
        require(profile['wait_entry'] <= offset <= profile['wait_entry'] + 0x48 or
                wait_return <= offset <= wait_return + 0x10 or offset == 0x2B4,
                f'Unexpected memory-wait PC {offset:#x}')
        if offset == wait_return:
            require(remote.get(regs, 'r0') == (0xFFFFFFFF if error else 0), 'Memory wait result mismatch')
            return_seen = True
        if offset == 0x2B4:
            require(error and remote.get(regs, 'r0') == 0 and
                    remote.get(regs, 'lr') == BASE + wait_return + 0xC,
                    'Memory error hook arguments mismatch')
            hook_seen = True
            require(struct.unpack_from('<I', image, offset)[0] == 0xEAFFFFFE,
                    'Expected original fatal self-loop')
            for _ in range(3):
                remote.command('s')
                require(remote.get(remote.regs(), 'pc') == BASE + 0x2B4,
                        'Original fatal loop did not remain stopped')
            break
        instruction = struct.unpack_from('<I', image, offset)[0]
        if instruction in (0xE5801008, 0x15801008):
            require(remote.get(regs, 'r0') == 0x20070000 and remote.get(regs, 'r1') == status,
                    'Memory status acknowledgement mismatch')
            remote.command('s')
            require(word(remote, 0x20070008) == 0, 'Memory acknowledgement did not clear status')
            acknowledgements.append(dict(offset=offset, value=status))
        else:
            remote.command('s')
    else:
        raise ValueError('Memory completion path exceeded instruction bound')
    require(return_seen and hook_seen == error and len(acknowledgements) == 1,
            'Incomplete memory return/error path')
    require(remote.get(regs, 'sp') == structure['startup']['core_zero_stack_tops'][-1],
            'Memory wait changed original SVC stack')
    require(remote.read(BASE + 0x10000, 0x4000) == image[0x10000:0x14000],
            'Memory completion modified stock page table')
    return dict(continuation=continuation, destination=destination,
                requested_size=profile['transfer_size'], rounded_size=length,
                whole_range_verified=True, guards_preserved=True,
                memory_sha256=digest(actual[4:-4]), status=status,
                wait_result=0xFFFFFFFF if error else 0, trace=trace,
                acknowledgements=acknowledgements, error_hook_executed=hook_seen,
                stop_offset=0x2B4 if error else app_entry, application_entry_reached=not error,
                fatal_loop_verified=error,
                application_entry_executed=False, stock_page_table_preserved=True)


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
        report = dict(format=1, qemu_version=subprocess.check_output(
            [args.qemu, '--version'], text=True).splitlines()[0], contexts=[],
            full_boot_verified=False, menu_verified=False,
            assumptions=['Stock reset, instructions and page table; stock EG preloaded.',
                'Zero fill, rounded 16 KiB extent and synchronous completion are experimental.',
                'Forced memory error changes device policy only; no firmware instruction patches.',
                'Physical RAM is preloaded with poison and guards; application entry is not executed.'])
        for role, image in images.items():
            profile = continuation_profile(role)
            length = ((profile['transfer_size'] + 0x3FFF) >> 14) * 0x4000
            poison = args.destination / f'{role}-poison.bin'
            poison.write_bytes(b'Z72!' + b'\xA5' * length + b'Z72!')
            context = dict(role=role, sha256=structures[role]['sha256'], scenarios={})
            for scenario in ['stock', 'forced-error'] + (['shared-path'] if role == 'slave' else []):
                directory = args.destination / f'{role}-{scenario}'
                with reset_machine(args.qemu, directory, image, role,
                    memory_init_error=scenario == 'forced-error',
                    ram_images=[(poison, profile['transfer_destination'] - 4)]) as remote:
                    context['scenarios'][scenario] = trace_memory(remote, structures[role], image, scenario, directory)
                print('PASS', role, scenario, flush=True)
            context['passed'] = True
            report['contexts'].append(context)
        report['passed'] = True
        (args.destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print('Report:', args.destination / 'report.json')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
