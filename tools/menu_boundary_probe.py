# SPDX-License-Identifier: GPL-2.0-or-later
"""Measure the steady-state menu-key boundary inside the original firmware.

The probe boots the original pair with the experimental resource header, one
synchronization pulse and the battery peer, waits for the shooting application
to stabilise, then presses and releases the menu input while observing:

* the application input-method key parameters at their stored values,
* the input request ring indices around the key edges,
* the actions handed to the application action router.

No firmware state is written and no callback is replaced; the menu key is
driven through the controller expander input like every other probe.
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
PARAMS = {0x1145: 0xb25845e8, 0x114a: 0xb25845fc, 0x114f: 0xb2584610,
          0x1153: 0xb2584620, 0x1158: 0xb2584634, 0x115c: 0xb2584644,
          0x1182: 0xb25846dc, 0x1278: 0xb25846b4, 0x168c: 0xb2584704}
RING_WRITE = 0xb181d308
RING_READ = 0xb181d309
ROUTER_CALL = 0x10542032


def linux(path):
    text = str(path)
    return re.sub(r'([A-Za-z]):[\\/][^,]*',
                  lambda m: '/mnt/' + m[1].lower() + '/' +
                            m[0][3:].replace('\\', '/'), text)


def run(args):
    require(0 < args.seconds <= 30, 'Window seconds must be in (0, 30]')
    require(0 < args.windows <= 24, 'Window count must be in (0, 24]')
    require(0 < args.settle_seconds <= 20, 'Settling time must be in (0, 20]')
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
    with tempfile.TemporaryDirectory(prefix='menu-boundary-', dir=ROOT / '.local') as folder:
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
                      firmware_modified=False, runtime_state_written=False,
                      full_boot_verified=True, menu_verified=False,
                      resource_header_only=True, sync_pulse_supplied=False,
                      observations=[], routed_actions=[], errors=[])
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
                'nikon-z72-controller-expander,bus=controller-i2c0,address=34,id=keys',
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
            configs = re.findall(r"(device\[\d+\]) \(child<nikon-z72-boot-config>\)",
                                 listing.decode())
            configs.sort(key=lambda item: int(re.search(r'\d+', item)[0]))
            require(remote.command('Z0,102d949e,2') == 'OK',
                    'Could not observe the original synchronization wait')
            for index, pin, level in ((2, 5, 0), (3, 13, 1), (4, 9, 1),
                                      (6, 7, 1), (1, 11, 1), (6, 14, 1), (6, 15, 1)):
                wire.sendall(f"set_irq_in /machine/unattached/{gpios[index]} "
                             f"unnamed-gpio-in {pin} {level}\n".encode())
                assert wire.recv(1024).strip() == b'OK'

            def sample(stage):
                remote.select_thread(1)
                observation = dict(stage=stage,
                    application=application_observation(remote),
                    system=system_observation(remote),
                    graphics=graphics_observation(remote),
                    capture_health=capture_health_observation(remote),
                    counter_ticks=int.from_bytes(remote.read(0x04266008, 8), 'little'),
                    counter_frequency=int.from_bytes(remote.read(0x04266010, 4), 'little'),
                    key_parameters={f'{key:#06x}':
                                    int.from_bytes(remote.read(address, 4), 'little')
                                    for key, address in PARAMS.items()},
                    ring_write=remote.read(RING_WRITE, 1)[0] & 0xF,
                    ring_read=remote.read(RING_READ, 1)[0] & 0xF)
                report['observations'].append(observation)
                return observation

            synced = [False]

            def resume():
                remote.sock.settimeout(args.seconds)
                try:
                    response = remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()
                    return
                if not synced[0]:
                    match = re.search(r'thread:([0-9a-f]+);', response)
                    if match:
                        remote.select_thread(int(match[1], 16))
                        registers = remote.regs()
                        if remote.get(registers, 'pc') == 0x102d949e:
                            for level in (1, 0):
                                wire.sendall(
                                    f"set_irq_in /machine/unattached/{configs[0]} "
                                    f"sync-event 15 {level}\n".encode())
                                require(wire.recv(1024).strip() == b'OK',
                                        'Synchronization input failed')
                            synced[0] = True
                            report['sync_pulse_supplied'] = True
                            require(remote.command('z0,102d949e,2') == 'OK',
                                    'Could not remove the synchronization observation')
                            try:
                                remote.command('vCont;c')
                            except TimeoutError:
                                remote.interrupt()

            def observe(stage, predicate):
                for _ in range(args.windows):
                    resume()
                    observation = sample(stage)
                    print(f'{stage}: app={observation["application"]["current_index"]} '
                          f'ring={observation["ring_write"]}/{observation["ring_read"]}',
                          flush=True)
                    if predicate(observation):
                        return observation
                raise ValueError(f'{stage} did not reach the expected state')

            settle_start = None

            def settled(item):
                nonlocal settle_start
                if not shooting_active(item):
                    settle_start = None
                    return False
                if settle_start is None:
                    settle_start = item['counter_ticks']
                require(item['counter_frequency'] > 0, 'Counter frequency is unavailable')
                item['settled_seconds'] = ((item['counter_ticks'] - settle_start) /
                                           item['counter_frequency'])
                return item['settled_seconds'] >= args.settle_seconds

            observe('baseline', settled)
            baseline = report['observations'][-1]
            report['steady_parameters'] = baseline['key_parameters']
            report['steady_ring'] = [baseline['ring_write'], baseline['ring_read']]

            # One observation point only: this QEMU reports just the first
            # inserted software breakpoint per run.
            require(remote.command(f'Z0,{ROUTER_CALL:x},2') == 'OK',
                    'Could not observe the original action router')
            wire.sendall(f'set_irq_in /machine/peripheral/keys pins {MENU_PIN} 0\n'.encode())
            assert wire.recv(1024).strip() == b'OK'
            stops = 0
            released = False
            while stops < args.router_windows:
                remote.sock.settimeout(4)
                try:
                    response = remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()
                    if not released:
                        wire.sendall(
                            f'set_irq_in /machine/peripheral/keys pins {MENU_PIN} 1\n'.encode())
                        assert wire.recv(1024).strip() == b'OK'
                        released = True
                    else:
                        break
                    continue
                match = re.search(r'thread:([0-9a-f]+);', response or '')
                if not match:
                    continue
                remote.select_thread(int(match[1], 16))
                registers = remote.regs()
                require(remote.get(registers, 'pc') == ROUTER_CALL,
                        'Unexpected observation point stop')
                report['routed_actions'].append(dict(
                    stop=stops, phase=('pressed' if not released else 'released'),
                    action=remote.get(registers, 'r4'),
                    ticks=int.from_bytes(remote.read(0x04266008, 8), 'little'),
                    application=application_observation(remote)['current_index']))
                stops += 1
            require(remote.command(f'z0,{ROUTER_CALL:x},2') == 'OK',
                    'Could not remove the action router observation')
            final = sample('after-release')
            report['final_ring'] = [final['ring_write'], final['ring_read']]
            report['final_application'] = final['application']['current_index']
            actions = [item['action'] for item in report['routed_actions']]
            report['menu_action_routed'] = 0x1C in actions
            report['switch_action_routed'] = 0x50 in actions
            report['passed'] = (report['menu_action_routed'] and
                                not report['switch_action_routed'] and
                                final['application']['current_index'] == 3)
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
          'steady-state menu boundary observation', flush=True)
    require(report['passed'], 'Steady-state menu boundary observation failed')
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
    parser.add_argument('--settle-seconds', type=float, default=6)
    parser.add_argument('--router-windows', type=int, default=24)
    arguments = parser.parse_args()
    run(arguments)


if __name__ == '__main__':
    main()
