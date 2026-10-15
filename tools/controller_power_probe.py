# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe original battery-contact handling and regular analog conversions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from analyze.qemu_display import Remote
from tools.controller_core_probe import CONTROLLER_SHA256
from tools.smp_boot_probe import reach


def scenario(args, name, contact, completion):
    directory = args.destination / name
    directory.mkdir()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    command = [args.qemu, '-M', 'nikon-z72-controller-lab,battery-contact=' +
               ('on' if contact else 'off'), '-kernel', str(args.firmware.resolve()),
               '-display', 'none', '-serial', 'none', '-monitor', 'none', '-nic', 'none',
               '-S', '-gdb', f'tcp:127.0.0.1:{port}', '-icount', 'shift=4,sleep=off',
               '-d', 'guest_errors', '-global', 'nikon-z72-controller-adc.channel1=3001',
               '-global', 'nikon-z72-controller-adc.completion=' +
               ('on' if completion else 'off')]
    (directory/'command.json').write_text(json.dumps(command, indent=2)+'\n')
    remote = process = None
    result = dict(battery_contact=contact, conversion_completion=completion, channel1_sample=3001)
    try:
        with (directory/'qemu.log').open('wb') as log:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        deadline = time.monotonic() + 10
        while remote is None:
            try:
                remote = Remote(port)
            except ConnectionRefusedError:
                require(process.poll() is None and time.monotonic() < deadline,
                        'Controller power probe could not connect')
                time.sleep(.05)
        def word(address):
            return int.from_bytes(remote.read(address, 4), 'little')
        regs = remote.regs()
        require(remote.get(regs, 'pc') == 0x080002b4 and
                remote.get(regs, 'sp') == 0x20000c08,
                'Controller did not reset from its original vectors')
        for address in (0x080200a4, 0x080200b6, 0x080200c8, 0x080200da):
            remote.breakpoint(address)
        remote.sock.settimeout(15)
        if not contact:
            _, regs = reach(remote, 0x080383f8)
            result['original_battery_result'] = remote.read(remote.get(regs, 'r1'), 12).hex()
            require(result['original_battery_result'] == bytes(12).hex() and
                    word(0x2001f3ec) == 0 and not word(0x40020810) & 32,
                    'Low contact did not preserve the original disconnected path')
            result['original_disconnected_path_verified'] = True
        elif completion:
            values = []
            for _ in range(3):
                _, regs = reach(remote, 0x0802320e)
                values.append(remote.get(regs, 'r0'))
                remote.command('s')
            reach(remote, 0x0802a6c2)
            average = int.from_bytes(remote.read(0x2001f5c6, 2), 'little')
            require(values == [3001] * 3 and average == 3001 and
                    word(0x2001f3ec) == 0x40012000 and
                    word(0x40020810) & 32 and not word(0x40012008) & 1,
                    'Original conversion data, averaging or disable differs')
            result.update(original_conversion_values=values, original_average=average,
                          original_regular_conversions_verified=True,
                          original_average_and_disable_verified=True)
        else:
            reach(remote, 0x0804317a)
            tick = word(0x20022d58)
            remote.breakpoint(0x0802320e)
            try:
                for _ in range(32):
                    reach(remote, 0x080202da)
                    remote.command('s')
                reach(remote, 0x0804317a)
            finally:
                remote.breakpoint(0x0802320e, False)
            result['wait_state'] = dict(tick_before=tick, tick_after=word(0x20022d58),
                status=word(0x40012000), control=word(0x40012008),
                data=word(0x4001204c), callback=word(0x20015df0))
            (directory/'wait-state.json').write_text(json.dumps(result['wait_state'], indent=2)+'\n')
            require(word(0x20022d58) >= tick + 32 and word(0x40012000) & 18 == 16 and
                    word(0x40012008) & 1 and word(0x4001204c) == 0 and
                    word(0x20015df0) == 0x080383f9,
                    'Disabled completion did not retain the original conversion wait')
            result['original_conversion_wait_preserved'] = True
        require(remote.read(0xe000ed28, 8) == bytes(8),
                'Controller power probe recorded a native fault')
        result.update(original_reset_verified=True, native_faults_absent=True, passed=True)
        print('PASS ' + name, flush=True)
        return result
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--firmware', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    image = args.firmware.read_bytes()
    require(len(image) == 524290 and hashlib.sha256(image).hexdigest() == CONTROLLER_SHA256,
            'Expected the original controller C 1.30.00 image')
    args.destination.mkdir(parents=True, exist_ok=False)
    report = dict(format=1, firmware=CONTROLLER_SHA256, full_boot_verified=False,
        controller_link_verified=False, menu_verified=False,
        assumptions=['Isolated Cortex-M4 controller with fixed experimental clocks.',
                     'C5 is an externally driven contact level; physical contact identity is inferred.',
                     'Channel 1 sample 3001 is an experimental twelve-bit input, not measured battery data.',
                     'Only software-triggered independent regular single conversions; fixed 1 us completion.',
                     'Stock reset and runtime; breakpoints and reads, no debugger guest state writes.',
                     'Attached power devices and controller-to-engine wiring remain incomplete.'], scenarios={})
    for name, contact, completion in (('contact-low', False, True),
                                      ('contact-high', True, True),
                                      ('conversion-disabled', True, False)):
        report['scenarios'][name] = scenario(args, name, contact, completion)
    (args.destination/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
