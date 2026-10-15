# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify original sequencer command, acknowledgement and callback completion."""
import argparse
import json
import hashlib
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from tools.dual_boot_probe import dual_machine
from tools.smp_boot_probe import reach, stop_registers


def scenario(qemu, directory, images, enabled):
    directory.mkdir()
    process = remote = None
    result = dict(completion_enabled=enabled, interrupt_id=45)
    try:
        process, remote = dual_machine(qemu, directory, images['master'],
            images['slave'], directory/'console.txt', globals_=(
                'nikon-z72-boot-config.sequencer-completion=' +
                ('on' if enabled else 'off'),))
        remote.sock.settimeout(30)
        thread, regs = reach(remote, BASE + 0x274d22)
        require(thread <= 2 and remote.get(regs, 'r0') == 0x04251028 and
                remote.get(regs, 'r1') & 0x10000003 == 0x10000003,
                'Original channel-zero command differs')
        result['command_thread'] = thread
        descriptor = remote.read(0x04251010, 12)
        count, source, destination = [int.from_bytes(descriptor[i:i+4], 'little')
                                      for i in range(0, 12, 4)]
        length = count + 1
        require(BASE <= source and source + length <= BASE + len(images['master']),
                'First transfer is outside the supplied firmware image')
        expected = images['master'][source - BASE:source - BASE + length]
        result['transfer'] = dict(source=hex(source), destination=hex(destination),
                                  length=length)
        handler, resumed = BASE + 0x274bfa, BASE + 0x383a18
        if enabled:
            thread, _ = reach(remote, handler)
            remote.select_thread(1)
            require(int.from_bytes(remote.read(0x04251030, 4), 'little') & 0xf == 8,
                    'Channel completion status differs')
            result['handler_thread'] = thread
            thread, regs = reach(remote, BASE + 0x383900)
            require(remote.read(remote.get(regs, 'r1'), 1) == b'\x08',
                    'Original callback did not receive completion status')
            thread, regs = reach(remote, resumed)
            require(remote.read(remote.get(regs, 'r4') + 8, 1) == b'\x08',
                    'Original wait did not retain completion result')
            remote.select_thread(1)
            require(int.from_bytes(remote.read(0x04251030, 4), 'little') & 0xf == 0 and
                    int.from_bytes(remote.read(0x04251028, 4), 'little') & 3 == 0,
                    'Original handler did not clear status and command')
            result['resumed_thread'] = thread
            actual = b''.join(remote.read(destination + offset,
                             min(1024, length - offset))
                             for offset in range(0, length, 1024))
            require(actual == expected, 'Channel did not copy the original firmware bytes')
            result['transfer']['sha256'] = hashlib.sha256(actual).hexdigest()
        else:
            for address in (handler, resumed):
                remote.breakpoint(address)
            try:
                remote.sock.settimeout(3)
                try:
                    stop_registers(remote, remote.command('vCont;c'))
                    raise ValueError('Disabled completion invoked the handler or continuation')
                except TimeoutError:
                    remote.interrupt()
            finally:
                for address in (handler, resumed):
                    remote.breakpoint(address, False)
            remote.select_thread(1)
            require(int.from_bytes(remote.read(0x04251030, 4), 'little') & 0xf == 0,
                    'Disabled completion fabricated status')
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
    require(not re.search(r'with (?:DFSR|IFSR)', log), 'Sequencer wait encountered a fault')
    result.update(passed=True, faults=[])
    print('PASS ' + directory.name, flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    images = dict(master=args.master.read_bytes(), slave=args.slave.read_bytes())
    structures = {role: analyze_eg(data, role) for role, data in images.items()}
    args.destination.mkdir(parents=True, exist_ok=False)
    report = dict(format=1, firmware={role: data['sha256'] for role, data in structures.items()},
        full_boot_verified=False, menu_verified=False,
        assumptions=['Original reset, waits and interrupt handlers; no debugger state writes.',
                     'Experimental GIC v1 and instruction-count virtual clock.',
                     'Synchronous incrementing memory transfer; peripheral modes remain unmodeled.'],
        scenarios={})
    for enabled in (True, False):
        name = 'completion' if enabled else 'completion-disabled'
        report['scenarios'][name] = scenario(args.qemu, args.destination/name, images, enabled)
    (args.destination/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
