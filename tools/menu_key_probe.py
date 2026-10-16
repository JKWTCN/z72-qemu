# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe a menu-key press and release through the original input path."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from analyze.firmware_structure import analyze_eg
from tools.controller_core_probe import CONTROLLER_SHA256
from tools.graphics_boot_probe import (application_observation,
                                       capture_health_observation,
                                       controller_input_observation,
                                       graphics_observation, system_observation)
from tools.battery_boot_probe import shooting_active
from tools.create_lab_parameters import parameter_images, resource_header_image
from tools.dual_boot_probe import dual_machine, sample_cores

MENU_PIN = 9


def linux(path):
    text = str(path)
    return re.sub(r'([A-Za-z]):[\\/][^,]*',
                  lambda m: '/mnt/' + m[1].lower() + '/' +
                            m[0][3:].replace('\\', '/'), text)


def run(args):
    require(0 < args.seconds <= 30, 'Window seconds must be in (0, 30]')
    require(0 < args.windows <= 24, 'Window count must be in (0, 24]')
    require(0 <= args.settle_seconds <= 10, 'Settling time must be in [0, 10]')
    master, slave = args.master.read_bytes(), args.slave.read_bytes()
    identities = {role: analyze_eg(data, role)['sha256']
                  for role, data in (('master', master), ('slave', slave))}
    require(hashlib.sha256(args.controller.read_bytes()).hexdigest() ==
            CONTROLLER_SHA256, 'Expected the original controller image')
    launched = []
    original = subprocess.Popen
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0))
        qtest_port = server.getsockname()[1]
    args.destination.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='menu-key-', dir=ROOT / '.local') as folder:
        work = Path(folder)

        class WslProcess(original):
            """Add the battery peer and qtest port; wrap for WSL on Windows."""

            def __init__(self, command, *extra, **keywords):
                index = command.index('-M')
                command[index + 1] += ",controller-battery-peer=on"
                command += ['-qtest', f'tcp:127.0.0.1:{qtest_port},server=on,wait=off',
                            '-qtest-log', '/dev/null']
                if os.name == 'nt':
                    self.pid_file = work / str(time.monotonic_ns())
                    wrapped = ['wsl.exe', '--exec', 'sh', '-c',
                               'echo $$ > ' + shlex.quote(linux(self.pid_file)) +
                               '; exec ' +
                               shlex.join([linux(part) for part in command])]
                    super().__init__(wrapped, *extra, **keywords)
                else:
                    super().__init__(command, *extra, **keywords)
                launched.append(self)

            def terminate(self):
                if os.name != 'nt' or self.poll() is not None:
                    super().terminate()
                    return
                if self.pid_file.exists():
                    pid = self.pid_file.read_text().strip()
                    if pid.isdecimal():
                        with original(['wsl.exe', '--exec', 'kill', '-TERM', pid],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL) as reaper:
                            reaper.wait(timeout=5)

        subprocess.Popen = WslProcess
        remote = wire = None
        report = dict(format=1, passed=False, menu_pin=MENU_PIN,
                      firmware_sha256=identities, controller_sha256=CONTROLLER_SHA256,
                      firmware_modified=False, experimental_nonce_bridge=True,
                      factory_calibration=False, full_boot_verified=False,
                      menu_verified=False, resource_header_only=args.resource_header,
                      sync_pulse_requested=args.sync_pulse, sync_pulse_supplied=False,
                      observations=[])
        try:
            resident = bytearray(0xC000)
            resident[:4] = b'MAKE'
            (work / 'resident.bin').write_bytes(resident)
            primary = bytearray(256)
            primary[11] = 1
            (work / 'primary.bin').write_bytes(primary)
            auxiliary = bytearray(256)
            auxiliary[9] = 8
            auxiliary[12] = 0xC9
            (work / 'aux.bin').write_bytes(auxiliary)
            for name, data in zip(('group17.bin', 'group18.bin'), parameter_images()):
                (work / name).write_bytes(data)
            devices = (
                'nikon-z72-controller-register-bank,bus=controller-i2c0,address=79',
                'nikon-z72-controller-expander,bus=controller-i2c0,address=34,id=keys',
                f"nikon-z72-controller-register-bank,bus=controller-i2c0,"
                f"address=107,initial-state={work / 'primary.bin'}",
                f"nikon-z72-controller-register-bank,bus=controller-i2c0,"
                f"address=13,initial-state={work / 'aux.bin'}")
            devices += tuple(
                f"loader,file={work / name},addr={address:#x},force-raw=on"
                for name, address in (('group17.bin', 0x132C0000),
                                      ('group18.bin', 0x132E0000)))
            devices += tuple(
                f"nikon-z72-controller-register-bank,bus=master-i2c{i},address=104"
                for i in range(4))
            if args.resource_header:
                (work / 'group32.bin').write_bytes(resource_header_image())
                devices += (f"loader,file={work / 'group32.bin'},"
                            "addr=0x13e80000,force-raw=on",)
            process, remote = dual_machine(
                args.qemu, work,
                master, slave,
                work / 'console.txt',
                icount='shift=0,sleep=off', trace='guest_errors',
                controller_firmware=args.controller,
                controller_link=True,
                controller_flash_data=work / 'resident.bin',
                devices=devices,
                globals_=tuple(
                    f"nikon-z72-controller-adc.channel{channel}={value}"
                    for channel, value in ((0, 1800), (1, 3001), (3, 3001))),
                extra_arguments=())
            wire = socket.create_connection(('127.0.0.1', qtest_port), timeout=10)
            reply = remote.command('qRcmd,' +
                                   'qom-list /machine/unattached'.encode().hex())
            listing = bytearray()
            while reply.startswith('O') and reply != 'OK':
                listing.extend(bytes.fromhex(reply[1:]))
                reply = remote.receive()
            gpios = re.findall(r"(device\[\d+\]) \(child<nikon-z72-controller-gpio>\)",
                               listing.decode())
            gpios.sort(key=lambda item: int(re.search(r'\d+', item)[0]))
            if args.sync_pulse:
                configs = re.findall(
                    r"(device\[\d+\]) \(child<nikon-z72-boot-config>\)", listing.decode())
                configs.sort(key=lambda item: int(re.search(r'\d+', item)[0]))
                require(len(configs) == 2, 'Expected two engine synchronization receivers')
                require(remote.command('Z0,102d949e,2') == 'OK',
                        'Could not observe the original synchronization wait')
            for index, pin, level in ((2, 5, 0), (3, 13, 1), (4, 9, 1),
                                      (6, 7, 1), (1, 11, 1), (6, 14, 1), (6, 15, 1)):
                wire.sendall(f"set_irq_in /machine/unattached/{gpios[index]} "
                             f"unnamed-gpio-in {pin} {level}\n".encode())
                assert wire.recv(1024).strip() == b'OK'

            def resume():
                remote.sock.settimeout(args.seconds)
                try:
                    response = remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()
                    return
                if args.sync_pulse and not report['sync_pulse_supplied']:
                    match = re.search(r'thread:([0-9a-f]+);', response)
                    require(match is not None, 'Missing synchronization stop thread')
                    remote.select_thread(int(match[1], 16))
                    registers = remote.regs()
                    require(remote.get(registers, 'pc') == 0x102d949e and
                            remote.get(registers, 'r0') == 0xb18a764c and
                            remote.get(registers, 'r1') == 8 and
                            remote.get(registers, 'r3') == 50,
                            'Unexpected original synchronization wait')
                    mask = int.from_bytes(remote.read(0x20060040, 4), 'little')
                    require(mask & 0x10, 'Synchronization event is masked')
                    for level in (1, 0):
                        wire.sendall(f"set_irq_in /machine/unattached/{configs[0]} "
                                     f"sync-event 15 {level}\n".encode())
                        require(wire.recv(1024).strip() == b'OK', 'Synchronization input failed')
                    report['sync_pulse_supplied'] = True
                    report['sync_pulse'] = dict(line=15, status_bit=4, irq=87,
                        wait_address='0x102d949e', mask=hex(mask),
                        counter_ticks=int.from_bytes(remote.read(0x04266008, 8), 'little'))
                    require(remote.command('z0,102d949e,2') == 'OK',
                            'Could not remove synchronization observation point')
                    try:
                        remote.command('vCont;c')
                    except TimeoutError:
                        remote.interrupt()

            def sample(stage):
                observation = dict(stage=stage,
                    application=application_observation(remote),
                    system=system_observation(remote),
                    graphics=graphics_observation(remote),
                    capture_health=capture_health_observation(remote),
                    controller_input=controller_input_observation(remote))
                remote.select_thread(1)
                observation['counter_ticks'] = int.from_bytes(
                    remote.read(0x04266008, 8), 'little')
                observation['counter_frequency'] = int.from_bytes(
                    remote.read(0x04266010, 4), 'little')
                observation['cores'] = sample_cores(remote)
                observation['engine_faults'] = []
                for thread in range(1, 5):
                    remote.select_thread(thread)
                    observation['engine_faults'].append(dict(thread=thread,
                        registers={name: hex(remote.read_register(name)) for name in
                                   ('DFAR_S', 'IFAR_S', 'DFSR_S', 'IFSR_S')}))
                remote.select_thread(5)
                observation['controller_fault_status'] = remote.read(0xe000ed28, 8).hex()
                report['observations'].append(observation)
                return observation

            def observe(stage, predicate):
                for _ in range(args.windows):
                    resume()
                    observation = sample(stage)
                    require(not any(int(value, 16) for core in observation['engine_faults']
                                    for value in core['registers'].values()),
                            'Engine recorded an execution fault')
                    require(observation['controller_fault_status'] == '0000000000000000',
                            'Controller recorded an execution fault')
                    print(f'{stage}: app={observation["application"]["current_index"]} '
                          f'menu={observation["controller_input"]["decoded_menu_bit"]}',
                          flush=True)
                    if predicate(observation):
                        return observation
                raise ValueError(f'{stage} did not reach the expected state')

            expander = '/machine/peripheral/keys'

            def drive(pin, level):
                wire.sendall(f'set_irq_in {expander} pins {pin} {level}\n'.encode())
                assert wire.recv(1024).strip() == b'OK'

            settle_start = None

            def settled(item):
                nonlocal settle_start
                if not shooting_active(item) or item['controller_input']['decoded_menu_bit']:
                    settle_start = None
                    return False
                if settle_start is None:
                    settle_start = item['counter_ticks']
                require(item['counter_frequency'] > 0, 'Counter frequency is unavailable')
                item['settled_seconds'] = ((item['counter_ticks'] - settle_start) /
                                           item['counter_frequency'])
                return item['settled_seconds'] >= args.settle_seconds

            baseline = observe('baseline', settled)
            require(int(baseline['controller_input']['decoded_switch_words'][0], 16)
                    & 0x0c000000 == 0, 'External shutter inputs remain asserted')
            # Hold the menu input: the original pipeline needs the key level
            # present across its polling cycles to start the menu application.
            drive(MENU_PIN, 0)
            pressed = observe('pressed',
                              lambda item: item['controller_input']['decoded_menu_bit'])
            menu_opened = observe('menu-start',
                                  lambda item: item['application']['current_index'] == 1)
            drive(MENU_PIN, 1)
            observe('released',
                    lambda item: not item['controller_input']['decoded_menu_bit'])
            report['key_transport_verified'] = True
            report['menu_application_observed'] = True
            report['menu_start_held_virtual_seconds'] = menu_opened.get(
                'settled_seconds', menu_opened.get('counter_ticks'))
            # The menu application must remain foreground after the release.
            stayed = observe('menu-steady',
                             lambda item: item['application']['current_index'] == 1
                             and not item['controller_input']['decoded_menu_bit'])
            report['menu_application_steady'] = stayed['application']['current_index'] == 1
            screenshot = str(args.destination.resolve() / 'interface.ppm')
            if os.name == 'nt':
                screenshot = linux(screenshot)
            response = remote.command('qRcmd,' +
                ('screendump ' + json.dumps(screenshot)).encode().hex())
            while response.startswith('O') and response != 'OK':
                response = remote.receive()
            require(response == 'OK', 'Interface capture failed')
            report['screenshot'] = 'interface.ppm'
            report['passed'] = True
        except Exception as error:
            report['error'] = str(error)
            raise
        finally:
            if wire is not None:
                wire.close()
            if remote is not None:
                remote.sock.close()
            subprocess.Popen = original
            for item in launched:
                if item.poll() is None:
                    item.terminate()
                    try:
                        item.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        item.kill()
                        item.wait(timeout=5)
            (args.destination / 'report.json').write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + '\n',
                encoding='utf-8')
    print(('PASS ' if report['passed'] else 'FAIL ') +
          'menu key transport observation', flush=True)
    require(report['passed'], 'Menu key transport observation failed')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--slave', required=True, type=Path)
    parser.add_argument('--controller', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--seconds', type=int, default=15)
    parser.add_argument('--windows', type=int, default=24)
    parser.add_argument('--settle-seconds', type=float, default=5)
    parser.add_argument('--resource-header', action='store_true',
                        help='Load an experimental group-32 header with a zero resource body')
    parser.add_argument('--sync-pulse', action='store_true',
                        help='Supply one external synchronization pulse at the original wait')
    arguments = parser.parse_args()
    run(arguments)


if __name__ == '__main__':
    main()
