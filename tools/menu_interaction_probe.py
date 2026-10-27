# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify steady-state menu interaction through the original firmware.

The machine boots with the periodic frame synchronization source and the
controller key interrupt wired, mirroring the interactive console. After the
shooting application has fully stabilised (long past any startup window), the
probe taps the menu input for a tenth of a guest second and requires the
original menu application to become foreground; it then taps the input that
leaves the menu and requires the shooting application back. A later second
menu tap is recorded but not required: a capture status raised while the menu
application runs is not cleared again in this combination, which is the
documented reopen boundary.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import struct
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
                                       graphics_observation, system_observation)
from tools.battery_boot_probe import shooting_active
from tools.create_lab_parameters import parameter_images, resource_header_image
from tools.dual_boot_probe import dual_machine

MENU_PIN = 9
EXIT_PIN = 0
SYNC_WAIT = 0x102d949e


def linux(path):
    text = str(path)
    return re.sub(r'([A-Za-z]):[\\/][^,]*',
                  lambda m: '/mnt/' + m[1].lower() + '/' +
                            m[0][3:].replace('\\', '/'), text)


def run(args):
    require(0 < args.seconds <= 30, 'Window seconds must be in (0, 30]')
    require(0 < args.windows <= 24, 'Window count must be in (0, 24]')
    require(0 < args.settle_seconds <= 60, 'Settling time must be in (0, 60]')
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
    with tempfile.TemporaryDirectory(prefix='menu-interact-', dir=ROOT / '.local') as folder:
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
        report = dict(format=1, passed=False, menu_pin=MENU_PIN, exit_pin=EXIT_PIN,
                      firmware_sha256=identities, controller_sha256=CONTROLLER_SHA256,
                      firmware_modified=False, runtime_state_written=False,
                      full_boot_verified=True, periodic_frame_sync=True,
                      sampling_source=True,
                      key_interrupt_wired=True, sync_pulse_supplied=False,
                      observations=[], screenshots=[], errors=[])
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
            (work / 'group32.bin').write_bytes(resource_header_image())
            devices = (
                'nikon-z72-controller-register-bank,bus=controller-i2c0,address=79',
                'nikon-z72-controller-expander,bus=controller-i2c0,address=34,id=keys,'
                'interrupt-gpio=/machine/controller/keys-gpio,interrupt-pin=8',
                f"nikon-z72-controller-register-bank,bus=controller-i2c0,"
                f"address=107,initial-state={work / 'primary.bin'}",
                f"nikon-z72-controller-register-bank,bus=controller-i2c0,"
                f"address=13,initial-state={work / 'aux.bin'}")
            devices += tuple(
                f"loader,file={work / name},addr={address:#x},force-raw=on"
                for name, address in (('group17.bin', 0x132C0000),
                                      ('group18.bin', 0x132E0000),
                                      ('group32.bin', 0x13E80000)))
            devices += tuple(
                f"nikon-z72-controller-register-bank,bus=master-i2c{i},address=104"
                for i in range(4))
            process, remote = dual_machine(
                args.qemu, work, master, slave, work / 'console.txt',
                icount='shift=0,sleep=off', trace='guest_errors',
                controller_firmware=args.controller, controller_link=True,
                controller_flash_data=work / 'resident.bin', devices=devices,
                globals_=('nikon-z72-boot-config.frame-sync=on',
                         'nikon-z72-boot-config.sensor-sample=on',
                         'nikon-z72-boot-config.sample-counter=on') +
                tuple(f"nikon-z72-controller-adc.channel{channel}={value}"
                     for channel, value in ((0, 1800), (1, 3001), (3, 3001))),
                extra_arguments=())
            wire = socket.create_connection(('127.0.0.1', qtest_port), timeout=10)
            reply = remote.command('qRcmd,' + 'qom-list /machine/unattached'.encode().hex())
            listing = bytearray()
            while reply.startswith('O') and reply != 'OK':
                listing.extend(bytes.fromhex(reply[1:]))
                reply = remote.receive()
            gpios = re.findall(r"(device\[\d+\]) \(child<nikon-z72-controller-gpio>\)",
                               listing.decode())
            gpios.sort(key=lambda item: int(re.search(r'\d+', item)[0]))
            configs = re.findall(r"(device\[\d+\]) \(child<nikon-z72-boot-config>\)",
                                 listing.decode())
            configs.sort(key=lambda item: int(re.search(r'\d+', item)[0]))
            for index, pin, level in ((2, 5, 0), (3, 13, 1), (4, 9, 1),
                                      (6, 7, 1), (1, 11, 1), (6, 14, 1), (6, 15, 1)):
                wire.sendall(f"set_irq_in /machine/unattached/{gpios[index]} "
                             f"unnamed-gpio-in {pin} {level}\n".encode())
                assert wire.recv(1024).strip() == b'OK'
            # One pulse satisfies the first original synchronization wait; the
            # periodic source keeps every later wait satisfied.
            require(remote.command(f'Z0,{SYNC_WAIT:x},2') == 'OK',
                    'Could not observe the original synchronization wait')
            remote.sock.settimeout(120)
            response = remote.command('vCont;c')
            match = re.search(r'thread:([0-9a-f]+);', response or '')
            require(match is not None, 'The synchronization wait did not run')
            remote.select_thread(int(match[1], 16))
            registers = remote.regs()
            require(remote.get(registers, 'pc') == SYNC_WAIT,
                    'Unexpected synchronization stop')
            for level in (1, 0):
                wire.sendall(f"set_irq_in /machine/unattached/{configs[0]} "
                             f"sync-event 15 {level}\n".encode())
                require(wire.recv(1024).strip() == b'OK', 'Synchronization input failed')
            wire.sendall(f"set_irq_in /machine/unattached/{configs[0]} "
                         f"frame-sync-enable 0 1\n".encode())
            require(wire.recv(1024).strip() == b'OK', 'Periodic frame sync failed')
            require(remote.command(f'z0,{SYNC_WAIT:x},2') == 'OK',
                    'Could not remove the synchronization observation')
            report['sync_pulse_supplied'] = True

            def resume(seconds=None):
                remote.sock.settimeout(args.seconds if seconds is None else seconds)
                try:
                    remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()

            def sample(stage):
                remote.select_thread(1)
                observation = dict(stage=stage,
                    application=application_observation(remote),
                    system=system_observation(remote),
                    graphics=graphics_observation(remote),
                    capture_health=capture_health_observation(remote),
                    counter_ticks=int.from_bytes(remote.read(0x04266008, 8), 'little'),
                    counter_frequency=int.from_bytes(remote.read(0x04266010, 4), 'little'))
                report['observations'].append(observation)
                return observation

            def ticks():
                remote.select_thread(1)
                return int.from_bytes(remote.read(0x04266008, 8), 'little')

            def frequency():
                remote.select_thread(1)
                return int.from_bytes(remote.read(0x04266010, 4), 'little')

            def settle(seconds):
                require(frequency() > 0, 'Counter frequency is unavailable')
                target = ticks() + seconds * frequency()
                while ticks() < target:
                    resume()

            def tap(pin, want_index):
                """One short press: a tenth of a guest second, then release."""
                wire.sendall(f'set_irq_in /machine/peripheral/keys pins {pin} 0\n'.encode())
                require(wire.recv(1024).strip() == b'OK', 'Key press failed')
                release_at = ticks() + frequency() // 10
                released = False
                for _ in range(args.windows):
                    resume(4)
                    if not released and ticks() >= release_at:
                        wire.sendall(
                            f'set_irq_in /machine/peripheral/keys pins {pin} 1\n'.encode())
                        require(wire.recv(1024).strip() == b'OK', 'Key release failed')
                        released = True
                    observation = sample('tap')
                    if released and observation['application']['current_index'] == want_index:
                        return observation
                return sample('tap-final')

            def capture(name):
                # Screenshots stay in the local run directory; only their
                # names are published in the report.
                screenshot = str(work / name)
                if os.name == 'nt':
                    screenshot = linux(screenshot)
                response = remote.command('qRcmd,' +
                    ('screendump ' + json.dumps(screenshot)).encode().hex())
                while response.startswith('O') and response != 'OK':
                    response = remote.receive()
                require(response == 'OK', 'Interface capture failed')
                report['screenshots'].append(name)

            for _ in range(args.windows):
                resume()
                if shooting_active(dict(application=application_observation(remote),
                                        graphics=graphics_observation(remote),
                                        capture_health=capture_health_observation(remote))):
                    break
            baseline = sample('baseline')
            require(shooting_active(baseline), 'The shooting application did not start')
            settle(args.settle_seconds)
            steady = sample('steady')
            require(steady['application']['current_index'] == 3,
                    'The shooting application is not foreground after settling')
            report['steady_seconds'] = ((steady['counter_ticks'] -
                                         baseline['counter_ticks']) /
                                        steady['counter_frequency'])

            opened = tap(MENU_PIN, 1)
            report['menu_opened_at_steady_state'] = \
                opened['application']['current_index'] == 1
            require(report['menu_opened_at_steady_state'],
                    'A steady-state menu tap did not open the menu application')
            capture('menu-open.ppm')
            report['menu_open_status'] = opened['capture_health']['status_codes']

            closed = tap(EXIT_PIN, 3)
            report['menu_closed_after_exit_tap'] = \
                closed['application']['current_index'] == 3
            require(report['menu_closed_after_exit_tap'],
                    'The exit tap did not return to the shooting application')
            settle(args.settle_seconds)
            capture('after-exit.ppm')

            reopened = tap(MENU_PIN, 1)
            report['menu_reopened_after_exit'] = \
                reopened['application']['current_index'] == 1
            report['reopen_status'] = reopened['capture_health']['status_codes']
            report['reopen_boundary_expected'] = not report['menu_reopened_after_exit']
            report['passed'] = (report['menu_opened_at_steady_state'] and
                                report['menu_closed_after_exit_tap'])
        except Exception as error:
            report['errors'].append(f'{type(error).__name__}: {error}')
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
          'steady-state menu interaction', flush=True)
    require(report['passed'], 'Steady-state menu interaction failed')
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
    parser.add_argument('--settle-seconds', type=float, default=8)
    arguments = parser.parse_args()
    run(arguments)


if __name__ == '__main__':
    main()
