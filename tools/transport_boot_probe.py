# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify the original two-endpoint transport startup exchange."""
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
from tools.dual_boot_probe import dual_machine
from tools.smp_boot_probe import reach, stop_registers


def scenario(qemu, directory, images, enabled):
    directory.mkdir()
    process = remote = None
    result = dict(link_enabled=enabled)
    try:
        process, remote = dual_machine(qemu, directory, images['master'],
            images['slave'], directory/'console.txt', icount='shift=4,sleep=off', trace=None, globals_=(
                'nikon-z72-boot-config.transport-link=' + ('on' if enabled else 'off'),))
        remote.sock.settimeout(30)
        thread, regs = reach(remote, BASE + 0x2be346)
        require(thread in (1, 2) and remote.get(regs, 'r4') == 0x2013c90c
                and remote.get(regs, 'r0') == 6, 'Original initiator command differs')
        result['request_thread'] = thread
        resumed = BASE + 0x2be352
        if enabled:
            result['continued_thread'], _ = reach(remote, resumed)
            remote.select_thread(1)
            require(int.from_bytes(remote.read(0x20134908, 4), 'little') & 1,
                    'Initiator did not observe link state')
            result['reset_thread'], _ = reach(remote, BASE + 0x2be6c8)
            result['initialized_thread'], _ = reach(remote, BASE + 0x1e0c52)
            thread, regs = reach(remote, BASE + 0x40e3c)
            require(thread in (3, 4), 'Message receiver ran on the wrong engine')
            result['message_receiver_thread'] = thread
            _, _ = reach(remote, BASE + 0x40f7e)
            remote.select_thread(3)
            header = remote.read(0x47cf0000, 24)
            require(header[:8] == bytes.fromhex('0801c000010055aa'),
                    'Receiver did not observe the original message header')
            written = int.from_bytes(header[8:12], 'little')
            consumed = int.from_bytes(header[16:20], 'little')
            require(0 < written < 0xc0 and consumed == written,
                    'Original receiver did not consume the queued messages')
            result['message_indices'] = dict(written=written, consumed=consumed)
            # The original main task reaches its recurring delay after startup.
            result['main_initialized_thread'], _ = reach(remote, BASE + 0x1e0196)
            remote.select_thread(1)
            backend = int.from_bytes(remote.read(0xB18A7A50, 4), 'little')
            require(backend == 0xB18A7A78,
                    'Original controller callback table was not installed')
            require(remote.read(backend, 8) == bytes.fromhex('4565201049652010'),
                    'Original controller callbacks differ')
            result['controller_callback_table'] = hex(backend)
        else:
            remote.breakpoint(resumed)
            try:
                remote.sock.settimeout(3)
                try:
                    stop_registers(remote, remote.command('vCont;c'))
                    raise ValueError('Disconnected transport resumed communication initialization')
                except TimeoutError:
                    remote.interrupt()
            finally:
                remote.breakpoint(resumed, False)
            remote.select_thread(1)
            require(int.from_bytes(remote.read(0x20134908, 4), 'little') & 1 == 0,
                    'Disconnected transport became ready')
        faults = []
        for core in (1, 2, 3, 4):
            remote.select_thread(core)
            state = {name: remote.read_register(name)
                     for name in remote.register_numbers
                     if any(field in name for field in ('DFSR', 'IFSR'))}
            require(state and not any(state.values()),
                    'Transport startup recorded a processor fault')
            faults.append(dict(thread=core, status=state))
        result.update(passed=True, wait_resumed=enabled, fault_status=faults)
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
    require(not re.search(r'with (?:DFSR|IFSR)', log), 'Transport startup encountered a memory fault')
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
        assumptions=['Functional command exchange and quiescent stop states; lane payload transfers remain unmodeled.',
                     'Original reset and pin writes; no debugger state writes.'], scenarios={})
    for enabled in (True, False):
        name = 'connected' if enabled else 'disconnected'
        report['scenarios'][name] = scenario(args.qemu, args.destination/name, images, enabled)
    (args.destination/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
