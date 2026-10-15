# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe stock controller register transfers with an explicit experimental target."""
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


def scenario(args, name, attached, auxiliary=False):
    directory = args.destination / name
    directory.mkdir()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    command = [args.qemu, '-M', 'nikon-z72-controller-lab,battery-contact=on',
               '-kernel', str(args.firmware.resolve()), '-display', 'none',
               '-serial', 'none', '-monitor', 'none', '-nic', 'none', '-S',
               '-gdb', f'tcp:127.0.0.1:{port}', '-icount', 'shift=4,sleep=off',
               '-global', 'nikon-z72-controller-adc.channel1=3001',
               '-global', 'nikon-z72-controller-adc.channel0=1800',
               '-d', 'guest_errors']
    if attached:
        seed = bytearray(256)
        seed[11] = 1
        initial = directory / 'experimental-registers.bin'
        initial.write_bytes(seed)
        command += ['-device', 'nikon-z72-controller-register-bank,'
                    'bus=controller-i2c0,address=107,initial-state=' + str(initial.resolve())]
    if auxiliary:
        seed = bytearray(256)
        seed[9] = 8
        seed[12] = 0xc9
        initial = directory / 'experimental-auxiliary.bin'
        initial.write_bytes(seed)
        command += ['-device', 'nikon-z72-controller-register-bank,'
                    'bus=controller-i2c0,address=13,initial-state=' + str(initial.resolve())]
    (directory / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    remote = process = None
    result = dict(attached=attached, address=107, experimental_identity=1 if attached else None)
    try:
        with (directory / 'qemu.log').open('wb') as log:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        deadline = time.monotonic() + 10
        while remote is None:
            try:
                remote = Remote(port)
            except ConnectionRefusedError:
                require(process.poll() is None and time.monotonic() < deadline,
                        'Controller register probe could not connect')
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
        if auxiliary:
            _, regs = reach(remote, 0x0802b822)
            status = remote.read(0x2001f64c, 3).hex()
            success = word(0x2001f650)
            require(status == '010002' and success == 1 and remote.get(regs, 'r0') == 2,
                    'Original four-byte status transfer or classification differs')
            result['auxiliary_status_read'] = dict(address=13, experimental_response='080000c9',
                original_status=status, success=success, return_value=2,
                tick=word(0x20022d58))
            result['original_four_byte_receive_verified'] = True
            remote.command('s')
        _, regs = reach(remote, 0x0802ad8e)
        identity = remote.read(0x2001f654, 1)[0]
        success = word(0x2001f658)
        result['identity_read'] = dict(value=identity, success=success,
                                       tick=word(0x20022d58))
        require(success == int(attached) and identity == int(attached),
                'Original identity transfer did not distinguish the attached target')
        remote.command('s')
        if attached:
            _, regs = reach(remote, 0x0802b3f4)
            require(remote.get(regs, 'r0') == 1,
                    'Original register writes and readback validation did not succeed')
            result['configuration_write_and_readback'] = dict(return_value=1,
                                                              tick=word(0x20022d58))
            result['original_register_validation_verified'] = True
        else:
            result['original_disconnected_transfer_preserved'] = True
        require(remote.read(0xe000ed28, 8) == bytes(8),
                'Controller register probe recorded a native fault')
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
                     'Explicit register bank at address 0x6b; no default attached target.',
                     'Identity byte 1 and analog samples 3001/1800 are experimental inputs.',
                     'The register bank is storage, not a physical power device model.',
                     'The optional auxiliary bank supplies an experimental four-byte status response.',
                     'Stock reset and runtime; breakpoints and reads, no debugger guest state writes.',
                     'Power readiness, controller-to-engine wiring and menu output remain unverified.'],
        scenarios={})
    for name, attached, auxiliary in (('disconnected', False, False),
                                      ('attached-register-bank', True, False),
                                      ('attached-with-auxiliary-bank', True, True)):
        report['scenarios'][name] = scenario(args, name, attached, auxiliary)
    (args.destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n',
                                                 encoding='utf-8')


if __name__ == '__main__':
    main()
