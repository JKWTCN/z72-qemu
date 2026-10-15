# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe stock supply selection and preparation with explicit experimental flash data."""
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


def scenario(args, name, valid_header, supply, auxiliary=False, power_target=False):
    directory = args.destination / name
    directory.mkdir()
    data = bytearray(0xc000)
    if valid_header:
        data[:4] = b'MAKE'
    flash = directory / 'experimental-flash-data.bin'
    flash.write_bytes(data)
    primary = bytearray(256)
    primary[11] = 1
    auxiliary_seed = bytearray(256)
    auxiliary_seed[9] = 8
    auxiliary_seed[12] = 0xc9
    for filename, seed in (('primary.bin', primary), ('auxiliary.bin', auxiliary_seed)):
        (directory / filename).write_bytes(seed)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    command = [args.qemu, '-M', 'nikon-z72-controller-lab,battery-contact=on,'
               'supply-input=' + ('on' if supply else 'off') +
               ',auxiliary-input=' + ('on' if auxiliary else 'off') +
               ',flash-data=' + str(flash.resolve()),
               '-kernel', str(args.firmware.resolve()), '-display', 'none', '-serial', 'none',
               '-monitor', 'none', '-nic', 'none', '-S', '-gdb', f'tcp:127.0.0.1:{port}',
               '-icount', 'shift=4,sleep=off', '-d', 'guest_errors']
    for channel, value in ((0, 1800), (1, 3001), (3, 3001)):
        command += ['-global', f'nikon-z72-controller-adc.channel{channel}={value}']
    for address, filename in ((107, 'primary.bin'), (13, 'auxiliary.bin')):
        command += ['-device', 'nikon-z72-controller-register-bank,bus=controller-i2c0,'
                    f'address={address},initial-state=' + str((directory / filename).resolve())]
    if power_target:
        command += ['-device', 'nikon-z72-controller-register-bank,'
                    'bus=controller-i2c0,address=79']
    (directory / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    remote = process = None
    result = dict(valid_experimental_header=valid_header, supply_input=supply,
                  auxiliary_input=auxiliary, power_target=power_target,
                  power_ready_verified=False)
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
                        'Controller flash probe could not connect')
                time.sleep(.05)
        def word(address):
            return int.from_bytes(remote.read(address, 4), 'little')
        regs = remote.regs()
        require(remote.get(regs, 'pc') == 0x080002b4 and
                remote.get(regs, 'sp') == 0x20000c08,
                'Resident data changed the original reset vectors')
        require(remote.read(0x08004000, 4) == bytes(data[:4]) and
                remote.read(0x00004000, 4) == bytes(data[:4]),
                'Resident data did not reach both flash addresses')
        for address in (0x080200a4, 0x080200b6, 0x080200c8, 0x080200da):
            remote.breakpoint(address)
        remote.sock.settimeout(15)
        reach(remote, 0x08024cae)
        flags = remote.read(0x2001f644, 5).hex()
        require(flags == ('0000000000' if valid_header else '0100000000'),
                'Original configuration acceptance or fallback differs')
        result['original_configuration_flags'] = flags
        result['original_configuration_path_verified'] = True
        if valid_header:
            _, regs = reach(remote, 0x08025dd0 if supply else 0x08025dbe)
            require(remote.get(regs, 'r0') == int(not supply) and
                    bool(word(0x40020c10) & 8192) == supply,
                    'Original supply selection did not follow D13')
            result['original_supply_selection'] = remote.get(regs, 'r0')
            result['original_supply_selection_verified'] = True
            remote.command('s')
            if auxiliary:
                _, regs = reach(remote, 0x080383f8)
                battery = remote.read(remote.get(regs, 'r1'), 12).hex()
                require(battery == bytes(12).hex(),
                        'High auxiliary input did not preserve the original battery result')
                result['original_battery_result'] = battery
                remote.command('s')
                if power_target:
                    _, regs = reach(remote, 0x08021418)
                    require(remote.get(regs, 'r0') == 0x04060002,
                            'Original power-ready callback event differs')
                    result['original_power_ready_event'] = dict(event=0x04060002,
                                                               tick=word(0x20022d58))
                    remote.command('s')
                    _, regs = reach(remote, 0x0802137c)
                    require(word(remote.get(regs, 'sp') + 12) & 1,
                            'Original initialization wait did not receive the ready bit')
                    result['original_initialization_wait_completed'] = True
                    remote.command('s')
                    reach(remote, 0x080343a4)
                    result['original_transmit_initialization_entered'] = True
                    result['power_ready_verified'] = True
                else:
                    remote.breakpoint(0x08021418)
                    try:
                        reach(remote, 0x08038380)
                    finally:
                        remote.breakpoint(0x08021418, False)
                    result['original_failed_power_configuration_preserved'] = True
            elif supply:
                _, regs = reach(remote, 0x080293a4)
                voltage = int.from_bytes(remote.read(0x2001f5ca, 2), 'little')
                threshold = int.from_bytes(remote.read(0x2001fa3c, 2), 'little')
                require(remote.get(regs, 'r0') == 1 and word(0x2001f650) == 1 and
                        word(0x2001f658) == 1 and word(0x2000ed90) == 1 and
                        voltage == 3001 and threshold == 850,
                        'Original preparation gate did not validate transfers and voltage')
                result['original_preparation_gate'] = dict(return_value=1,
                    auxiliary_transfer_success=1, identity_transfer_success=1,
                    configuration_transfer_success=1, voltage_sample=voltage,
                    minimum_sample=threshold, tick=word(0x20022d58))
                result['original_preparation_gate_verified'] = True
            else:
                _, regs = reach(remote, 0x080383f8)
                battery = remote.read(remote.get(regs, 'r1'), 12).hex()
                require(battery == '010000000000000001000000',
                        'Low D13 did not preserve the original alternate source result')
                result['original_alternate_source_result'] = battery
        require(remote.read(0xe000ed28, 8) == bytes(8),
                'Controller flash probe recorded a native fault')
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
        power_ready_verified=False, controller_link_verified=False, menu_verified=False,
        assumptions=['Isolated controller with fixed experimental clocks.',
                     'Explicit experimental flash data; only MAKE header is populated.',
                     'D13 supply selection, E9 auxiliary signal and C5 contact are experimental levels.',
                     'Analog samples and register targets are experimental, not measured hardware data.',
                     'Program bytes and input files are unchanged; no debugger guest state writes.',
                     'Power-ready validation uses an explicit register bank at address 0x4f.',
                     'Transmit initialization entry does not prove serial transfers or menu output.'],
        scenarios={})
    for name, valid_header, supply, auxiliary, power_target in (
            ('invalid-header', False, True, False, False),
            ('valid-header-low-supply', True, False, False, False),
            ('valid-header-high-supply', True, True, False, False),
            ('power-target-disconnected', True, True, True, False),
            ('power-target-attached', True, True, True, True)):
        report['scenarios'][name] = scenario(args, name, valid_header, supply, auxiliary, power_target)
    report['power_ready_verified'] = report['scenarios']['power-target-attached']['power_ready_verified']
    require(args.firmware.read_bytes() == image, 'Probe modified the firmware input')
    (args.destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n',
                                                 encoding='utf-8')


if __name__ == '__main__':
    main()
