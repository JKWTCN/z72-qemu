# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify the original runtime gate request, interrupt and task resumption."""
import argparse
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, digest, require
from analyze.firmware_structure import analyze_eg
from tools.dual_boot_probe import dual_machine
from tools.smp_boot_probe import reach, stop_registers


def scenario(qemu, directory, images, enabled):
    directory.mkdir()
    process = remote = None
    try:
        process, remote = dual_machine(qemu, directory, images['master'],
            images['slave'], directory/'console.txt', globals_=(
                'nikon-z72-boot-config.timer-tick-us=10000',
                'nikon-z72-boot-config.gate-completion=' +
                ('on' if enabled else 'off'),))
        remote.sock.settimeout(30)
        thread, regs = reach(remote, BASE + 0x36664a)
        require(remote.get(regs, 'r0') == 0x04287010 and
                remote.get(regs, 'r1') == 0xa1,
                'Original gate request arguments differ')
        print(directory.name + ': original gate command reached', flush=True)
        result = dict(command_thread=thread, command='0xa1',
                      interrupt_id=250, completion_enabled=enabled)
        handler = BASE + 0x3665a8
        resumed = BASE + 0x349a56
        remote.breakpoint(handler)
        if not enabled:
            remote.breakpoint(resumed)
        try:
            if enabled:
                thread, regs = stop_registers(remote, remote.command('vCont;c'))
                require(remote.get(regs, 'pc') == handler,
                        'Original gate handler not reached')
                result['handler_thread'] = thread
                print(directory.name + ': original handler reached', flush=True)
            else:
                remote.sock.settimeout(3)
                try:
                    stop_registers(remote, remote.command('vCont;c'))
                    raise ValueError('Disabled completion invoked the handler or resumed the task')
                except TimeoutError:
                    remote.interrupt()
        except TimeoutError:
            remote.interrupt()
            raise
        finally:
            remote.breakpoint(handler, False)
            if not enabled:
                remote.breakpoint(resumed, False)
        remote.select_thread(1)
        bank_status = struct.unpack('<I', remote.read(0x0428700c, 4))[0]
        require(bank_status == (1 if enabled else 0),
                'Unexpected completed gate bank')
        result['completed_banks'] = bank_status
        if enabled:
            thread, regs = reach(remote, resumed)
            result['resumed_thread'] = thread
            result['resumed_pc'] = hex(remote.get(regs, 'pc'))
            # The same request routine subsequently removes the final bank
            # reference. Completion must clear its status and wake that wait.
            _, regs = reach(remote, BASE + 0x36664a)
            control = struct.unpack('<I', remote.read(0x04287000, 4))[0]
            require(control & 0x7100 == 0, 'Expected original bank-zero disable request')
            reach(remote, handler)
            reach(remote, BASE + 0x349ab0)
            remote.select_thread(1)
            require(struct.unpack('<I', remote.read(0x0428700c, 4))[0] == 0,
                    'Gate disable did not clear bank status')
            result['disable_completed'] = True
        result['task_resumed'] = enabled
    finally:
        if remote is not None:
            remote.sock.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    log = (directory/'qemu.log').read_text(errors='replace')
    require(not re.search(r'with (?:DFSR|IFSR)', log),
            'Gate scenario encountered a memory fault')
    result['faults'] = []
    result['passed'] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    images = {role: getattr(args, role).read_bytes() for role in ('master', 'slave')}
    structures = {role: analyze_eg(image, role) for role, image in images.items()}
    # Verified stock gate-command window, pinned by offset, length and
    # SHA-256 instead of redistributing the original instruction bytes.
    require(digest(images['master'][0x366648:0x36664C]) ==
            'feb923d5b98428dc6f705aeb3dd8c074c94c08b2cf8632362e68b8c516e3ebb6',
            'Unsupported gate command code window')
    args.destination.mkdir(parents=True, exist_ok=False)
    results = {name: scenario(args.qemu, args.destination/name, images, enabled)
               for name, enabled in (('completion', True), ('completion-disabled', False))}
    report = dict(format=1, scenarios=results,
        firmware_sha256={role: item['sha256'] for role, item in structures.items()},
        assumptions=['Synchronous runtime gate completion with retained bank status.',
                     'Experimental tick interval of 10 ms to bound interrupt load.',
                     'Original reset paths and handlers; no debugger writes to guest state.',
                     'Hardware timing remains unconfirmed.'],
        full_boot_verified=False, menu_verified=False, passed=True)
    (args.destination/'report.json').write_text(
        json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print('Report:', args.destination/'report.json')


if __name__ == '__main__':
    main()
