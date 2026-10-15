# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify stock kernel delays and transfer reset completion without state writes."""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, digest, require
from analyze.firmware_structure import analyze_eg
from tools.dual_boot_probe import dual_machine
from tools.smp_boot_probe import reach, stop_registers


def scenario(qemu, directory, images, enabled):
    directory.mkdir()
    process = remote = None
    result = dict(completion_enabled=enabled, delay_returns=[])
    try:
        process, remote = dual_machine(qemu, directory, images['master'],
            images['slave'], directory/'console.txt', globals_=(
                'nikon-z72-boot-config.transfer-reset-completion=' +
                ('on' if enabled else 'off'),))
        remote.sock.settimeout(30)
        for _ in range(2):
            thread, regs = reach(remote, BASE + 0x44bd4e)
            require(thread <= 2, 'Controller delay returned on the wrong engine')
            result['delay_returns'].append(dict(thread=thread,
                pc=hex(remote.get(regs, 'pc'))))
        thread, regs = reach(remote, BASE + 0x39d4b6)
        require(remote.get(regs, 'r1') == 0x20100000 and
                remote.get(regs, 'r0') == 0, 'Original reset request differs')
        result['request_thread'] = thread
        handler, resumed = BASE + 0x39ce38, BASE + 0x368828
        if enabled:
            thread, _ = reach(remote, handler)
            remote.select_thread(1)
            require(struct.unpack('<I', remote.read(0x20100018, 4))[0] == 1,
                    'Reset completion status differs')
            result['handler_thread'] = thread
            thread, _ = reach(remote, BASE + 0x368c18)
            require(remote.get(remote.regs(), 'r1') == 1,
                    'Original reset callback did not receive bit zero')
            thread, _ = reach(remote, resumed)
            remote.select_thread(1)
            require(remote.read(0x20100018, 12) == bytes(12),
                    'Original handler did not acknowledge status')
            result['resumed_thread'] = thread
            thread, regs = reach(remote, BASE + 0x39c68a)
            require(thread <= 2 and remote.get(regs, 'r6') == 1000,
                    'Original serial task did not reach its periodic delay')
            serial_format = int.from_bytes(remote.read(0x2c09000c, 2), 'little')
            require(serial_format & 0x802 == 0x802 and
                    remote.read(0x2c09000f, 1) == b'\x02' and
                    remote.read(0x2c090001, 1)[0] & 2,
                    'Original serial byte configuration differs')
            result['serial_configuration_thread'] = thread
            result['serial_format'] = hex(serial_format)
        else:
            for address in (handler, resumed):
                remote.breakpoint(address)
            try:
                remote.sock.settimeout(3)
                try:
                    stop_registers(remote, remote.command('vCont;c'))
                    raise ValueError('Disabled reset completion invoked handler or continuation')
                except TimeoutError:
                    remote.interrupt()
            finally:
                for address in (handler, resumed):
                    remote.breakpoint(address, False)
            remote.select_thread(1)
            require(remote.read(0x20100018, 12) == bytes(12),
                    'Disabled reset completion fabricated status')
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
    require(not re.search(r'with (?:DFSR|IFSR)', log), 'Runtime wait encountered a fault')
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
    # Verified stock reset wait-helper window, pinned by offset, length
    # and SHA-256 instead of redistributing the original instruction bytes.
    require(digest(images['master'][0x39D4B2:0x39D4BA]) ==
            'd44daede85478abd026f83f8e5c231b4cc1a5441c655aae5239da37168cd953b',
            'Original reset wait-helper code window differs')
    args.destination.mkdir(parents=True, exist_ok=False)
    report = dict(format=1, firmware={role: data['sha256'] for role, data in structures.items()},
        full_boot_verified=False, menu_verified=False,
        assumptions=['Original reset, kernel, waits and interrupt handlers; no debugger state writes.',
                     'Experimental GIC v1 interface and per-engine CPU numbering.',
                     'Instruction-count virtual clock: shift=0,sleep=off.',
                     'Synchronous transfer reset completion; data transfer execution is unmodeled.'],
        scenarios={})
    for enabled in (True, False):
        name = 'completion' if enabled else 'completion-disabled'
        report['scenarios'][name] = scenario(args.qemu, args.destination/name, images, enabled)
    (args.destination/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
