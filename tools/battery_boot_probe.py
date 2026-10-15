# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe the original combined boot with the synthetic battery peer.

Boots both original engine images plus the original controller image with
the experimental battery peer enabled and records the battery status, the
power record, the application timeout policy and the mode transitions
across observation windows.
"""
import argparse
import hashlib
import json
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
from tools.create_lab_parameters import parameter_images
from tools.dual_boot_probe import dual_machine
from tools.graphics_boot_probe import (application_observation,
                                       graphics_observation,
                                       idle_timer_observation,
                                       system_observation)


def linux(path):
    text = str(path)
    return re.sub(r'([A-Za-z]):[\\/][^,]*',
                  lambda m: '/mnt/' + m[1].lower() + '/' +
                            m[0][3:].replace('\\', '/'), text)


def run(args):
    require(0 < args.seconds <= 60 and 0 < args.windows <= 24,
            'Observation bounds must be in (0, 60] and (0, 24]')
    require(0 < args.shooting_seconds <= 20,
            'Shooting observation must be in (0, 20] virtual seconds')
    master, slave = args.master.read_bytes(), args.slave.read_bytes()
    identities = {role: analyze_eg(data, role)['sha256']
                  for role, data in (('master', master), ('slave', slave))}
    require(hashlib.sha256(args.controller.read_bytes()).hexdigest() ==
            CONTROLLER_SHA256, 'Expected the original controller image')
    args.destination.mkdir(parents=True, exist_ok=False)
    launched = []
    original = subprocess.Popen
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0))
        qtest_port = server.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='battery-peer-', dir=ROOT / '.local') as folder:
        work = Path(folder)

        class WslProcess(original):
            """Launch the Linux binary through WSL and stop it by pid."""

            def __init__(self, command, *extra, **keywords):
                self.pid_file = work / str(time.monotonic_ns())
                index = command.index('-M')
                command[index + 1] += ",controller-battery-peer=on"
                command += ['-qtest', f'tcp:127.0.0.1:{qtest_port},server=on,wait=off',
                            '-qtest-log', '/dev/null']
                wrapped = ['wsl.exe', '--exec', 'sh', '-c',
                           'echo $$ > ' + shlex.quote(linux(self.pid_file)) +
                           '; exec ' + shlex.join([linux(part) for part in command])]
                super().__init__(wrapped, *extra, **keywords)
                launched.append(self)

            def terminate(self):
                if self.poll() is None and self.pid_file.exists():
                    pid = self.pid_file.read_text().strip()
                    if pid.isdecimal():
                        with original(['wsl.exe', '--exec', 'kill', '-TERM', pid],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL,
                                      creationflags=subprocess.CREATE_NO_WINDOW) as reaper:
                            reaper.wait(timeout=5)

        subprocess.Popen = WslProcess
        remote = wire = None
        report = dict(format=1, passed=False, controller_sha256=CONTROLLER_SHA256,
                      firmware_sha256=identities, experimental_nonce_bridge=True,
                      factory_calibration=False, firmware_modified=False,
                      instruction_time='shift=0,sleep=off',
                      full_boot_verified=False, menu_verified=False)
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
            for index, pin, level in ((2, 5, 0), (3, 13, 1), (4, 9, 1),
                                      (6, 7, 1), (1, 11, 1)):
                wire.sendall(f"set_irq_in /machine/unattached/{gpios[index]} "
                             f"unnamed-gpio-in {pin} {level}\n".encode())
                assert wire.recv(1024).strip() == b'OK'
            report.update(windows=[], inputs=dict(battery_peer=True,
                                                  supply_peer=False))
            remote.sock.settimeout(args.seconds)
            try:
                remote.command('vCont;c')
            except TimeoutError:
                remote.interrupt()
            observation = {}
            shooting_start = None
            for window in range(args.windows):
                remote.select_thread(5)
                observation = dict(
                    battery_status=f"0x{remote.read(0x2001FA79, 1).hex()}",
                    power_record=remote.read(0x20016040, 0x18).hex(),
                    idle=idle_timer_observation(remote),
                    application=application_observation(remote),
                    system=system_observation(remote),
                    graphics=graphics_observation(remote))
                remote.select_thread(1)
                ticks = int.from_bytes(remote.read(0x04266008, 8), 'little')
                frequency = int.from_bytes(remote.read(0x04266010, 4), 'little')
                require(frequency > 0, 'Counter frequency is unavailable')
                if observation['system']['current_mode'] == 3:
                    if shooting_start is None:
                        shooting_start = ticks
                else:
                    shooting_start = None
                elapsed = (ticks - shooting_start) / frequency if shooting_start is not None else 0
                observation.update(counter_ticks=ticks, counter_frequency=frequency,
                                   shooting_elapsed_seconds=elapsed)
                report['windows'].append(observation)
                report['maximum_shooting_elapsed_seconds'] = max(
                    report.get('maximum_shooting_elapsed_seconds', 0), elapsed)
                report['battery_exchange_verified'] = (
                    observation['battery_status'] == '0x02' and
                    observation['idle']['policy_flags'] == 0 and
                    observation['idle']['timeout_seconds'] == 30 and
                    observation['system']['control_ready_bitmap'] == 15)
                print(f'Window {window}: mode={observation["system"]["current_mode"]} '
                      f'policy={observation["idle"]["policy_flags"]} '
                      f'shooting={elapsed:.3f}s', flush=True)
                if elapsed >= args.shooting_seconds:
                    break
                if window + 1 < args.windows:
                    remote.sock.settimeout(args.seconds)
                    try:
                        remote.command('vCont;c')
                    except TimeoutError:
                        remote.interrupt()
            final = report['windows'][-1]
            faults = 0
            for core in range(1, 5):
                remote.select_thread(core)
                for name in ('DFAR_S', 'IFAR_S', 'DFSR_S', 'IFSR_S'):
                    faults += remote.read_register(name)
            report['engine_fault_status_sum'] = faults
            remote.select_thread(5)
            report['controller_fault_status'] = remote.read(0xe000ed28, 8).hex()
            require(final['battery_status'] == '0x02',
                    'Battery status did not settle on the recognized value')
            require(final['idle']['policy_flags'] == 0 and
                    not final['idle']['five_second_policy'] and
                    final['idle']['timeout_seconds'] == 30,
                    'Application timeout policy did not clear the boot limit')
            require(bytes.fromhex(final['power_record'])[2] != 9,
                    'Power record still reports the serial failure class')
            require(final['system']['current_mode'] == 3 and
                    final['graphics']['rendered_commands'] > 0 and
                    final['graphics']['failed_requests'] == 0,
                    'Original shooting interface did not remain active')
            require(final['shooting_elapsed_seconds'] >= args.shooting_seconds,
                    'Shooting interface observation was too short')
            require(faults == 0, 'Engine recorded an execution fault')
            require(report['controller_fault_status'] == '0000000000000000',
                    'Controller recorded an execution fault')
            screenshot = linux(args.destination.resolve() / 'shooting.ppm')
            response = remote.command('qRcmd,' +
                ('screendump ' + json.dumps(screenshot)).encode().hex())
            while response.startswith('O') and response != 'OK':
                response = remote.receive()
            require(response == 'OK', 'Shooting interface capture failed')
            report['screenshot'] = 'shooting.ppm'
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
                json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(('PASS ' if report['passed'] else 'FAIL ') + 'battery peer observation',
          flush=True)
    require(report['passed'], 'Battery peer observation failed')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--slave', required=True, type=Path)
    parser.add_argument('--controller', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--windows', type=int, default=24)
    parser.add_argument('--seconds', type=int, default=15)
    parser.add_argument('--shooting-seconds', type=float, default=5)
    arguments = parser.parse_args()
    run(arguments)


if __name__ == '__main__':
    main()
