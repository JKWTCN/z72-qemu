# SPDX-License-Identifier: GPL-2.0-or-later
"""Walk original menu pages with real key presses toward the update item.

The machine boots with the interactive console inputs (controller key
interrupt wired, periodic frame synchronization). Every requested tab index
gets its own fresh machine: the menu application opens once, the tab strip
moves right to the index, the item list walks downward and the OK key
confirms the lowest reached item, with the display recorded after each
step. One fresh boot per tab avoids the documented menu reopen boundary. A breakpoint on the original firmware-management service
eligibility entry reports whether the key path alone reaches the service
that the whole update flow starts from. The probe changes no firmware
bytes and writes no runtime state; menu settings changed by OK presses on
unrelated items live only inside this ephemeral machine.
"""
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
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from tools.controller_core_probe import CONTROLLER_SHA256
from tools.graphics_boot_probe import (application_observation,
                                       capture_health_observation,
                                       graphics_observation, system_observation)
from tools.battery_boot_probe import shooting_active
from tools.create_lab_parameters import parameter_images, resource_header_image
from tools.dual_boot_probe import dual_machine
from tools.menu_navigation_probe import frame_profile

MENU_PIN = 9
EXIT_PIN = 0
OK_PIN = 3
DOWN_PIN = 4
RIGHT_PIN = 7
SYNC_WAIT = 0x102d949e
# CFirmwareManagementService entries: the eligibility check (master file
# offset 0x747048) runs when an update is offered; the version-list method
# (0x747092) is what a firmware-version page would call first.
SERVICE_ENTRY = BASE + 0x747048
VERSION_ENTRY = BASE + 0x747092
WATCHED = (SERVICE_ENTRY, VERSION_ENTRY)
DEFAULT_TABS = (4, 5, 3, 2, 1, 0)
DEFAULT_ITEMS = 24


def linux(path):
    text = str(path)
    return re.sub(r'([A-Za-z]):[\\/][^,]*',
                  lambda m: '/mnt/' + m[1].lower() + '/' +
                            m[0][3:].replace('\\', '/'), text)


def run_tab(args, tab):
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
    with tempfile.TemporaryDirectory(prefix='menu-fwupdate-', dir=ROOT / '.local') as folder:
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
        report = dict(format=1, passed=False, tab=tab, menu_pin=MENU_PIN, exit_pin=EXIT_PIN,
                      ok_pin=OK_PIN, down_pin=DOWN_PIN, right_pin=RIGHT_PIN,
                      service_entry=hex(SERVICE_ENTRY), firmware_sha256=identities,
                      controller_sha256=CONTROLLER_SHA256, firmware_modified=False,
                      runtime_state_written=False, full_boot_verified=True,
                      periodic_frame_sync=True, key_interrupt_wired=True,
                      sync_pulse_supplied=False, service_activated=False,
                      steps=[], errors=[])
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
                globals_=('nikon-z72-boot-config.frame-sync=on',) +
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
            require(remote.command(f'Z0,{SYNC_WAIT:x},2') == 'OK',
                    'Could not observe the original synchronization wait')
            remote.sock.settimeout(120)
            response = remote.command('vCont;c')
            match = re.search(r'thread:([0-9a-f]+);', response or '')
            require(match is not None, 'The synchronization wait did not run')
            remote.select_thread(int(match[1], 16))
            require(remote.get(remote.regs(), 'pc') == SYNC_WAIT,
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
            for watched in WATCHED:
                require(remote.command(f'Z0,{watched:x},2') == 'OK',
                'Could not arm the service entry observation')

            def step(window=4.0):
                """Run one observation window; stop records go to the report."""
                remote.sock.settimeout(window)
                try:
                    response = remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()
                    return None
                match = re.search(r'thread:([0-9a-f]+)', response or '')
                if match is None:
                    return None
                remote.select_thread(int(match[1], 16))
                registers = remote.regs()
                return dict(thread=int(match[1], 16),
                            pc=remote.get(registers, 'pc'),
                            lr=remote.get(registers, 'lr'))

            def ticks():
                remote.select_thread(1)
                return int.from_bytes(remote.read(0x04266008, 8), 'little')

            def frequency():
                remote.select_thread(1)
                return int.from_bytes(remote.read(0x04266010, 4), 'little')

            def settle(seconds):
                require(frequency() > 0, 'Counter frequency is unavailable')
                target = ticks() + seconds * frequency()
                for _ in range(24):
                    if ticks() >= target:
                        return None
                    stop = step()
                    if stop and stop['pc'] in WATCHED:
                        return stop
                return None

            def press(pin, hold_windows=1):
                wire.sendall(f'set_irq_in /machine/peripheral/keys pins {pin} 0\n'.encode())
                require(wire.recv(1024).strip() == b'OK', 'Key press failed')
                stop = settle(0.1)
                wire.sendall(f'set_irq_in /machine/peripheral/keys pins {pin} 1\n'.encode())
                require(wire.recv(1024).strip() == b'OK', 'Key release failed')
                return settle(0.2) or stop

            def capture(name):
                screenshot = str(work / name)
                if os.name == 'nt':
                    screenshot = linux(screenshot)
                response = remote.command('qRcmd,' +
                    ('screendump ' + json.dumps(screenshot)).encode().hex())
                while response.startswith('O') and response != 'OK':
                    response = remote.receive()
                require(response == 'OK', 'Interface capture failed')
                data = Path(work / name).read_bytes()
                rows = frame_profile(data)
                return dict(total_rows=sum(rows),
                            bands=[index for index, weight in enumerate(rows)
                                   if weight > 8])

            def foreground():
                remote.select_thread(1)
                return application_observation(remote)['current_index']

            def recover_menu():
                """Leave an opened item page; reopen the menu if it closed."""
                press(EXIT_PIN)
                for _ in range(4):
                    state = foreground()
                    if state == 1:
                        return
                    press(MENU_PIN if state == 3 else EXIT_PIN)

            for _ in range(args.windows):
                step(args.seconds)
                remote.select_thread(1)
                if shooting_active(dict(application=application_observation(remote),
                                        graphics=graphics_observation(remote),
                                        capture_health=capture_health_observation(remote))):
                    break
            remote.select_thread(1)
            require(shooting_active(dict(
                application=application_observation(remote),
                graphics=graphics_observation(remote),
                capture_health=capture_health_observation(remote))),
                'The shooting application did not start')
            settle(4.0)

            opened = press(MENU_PIN)
            report['steps'].append(dict(step='menu', foreground=foreground(),
                                        display=capture('menu-open.ppm')))
            require(foreground() == 1, 'The menu application did not open')

            # One tab per fresh boot: the EXIT key that leaves an opened
            # item page closes the whole menu on this machine combination,
            # and a closed menu cannot be reopened (documented boundary), so
            # each tab index gets its own machine and the walk ends at OK.
            stop = opened
            for _ in range(tab):
                stop = press(RIGHT_PIN) or stop
                if stop and stop['pc'] in WATCHED:
                    break
            display = capture(f'tab-{tab}.ppm')
            walked = 0
            for index in range(args.items):
                stop = press(DOWN_PIN) or stop
                walked = index + 1
                if stop and stop['pc'] in WATCHED:
                    break
            record = dict(step=f'tab-{tab}', down_presses=walked,
                          display=display)
            for _ in range(2):
                if stop and stop['pc'] in WATCHED:
                    break
                stop = press(OK_PIN) or stop
            record['after_ok_display'] = capture(f'tab-{tab}-after-ok.ppm')
            if stop and stop['pc'] in WATCHED:
                record['service_thread'] = stop['thread']
                record['service_return'] = hex(stop['lr'])
                record['entry'] = ('eligibility' if stop['pc'] == SERVICE_ENTRY
                                   else 'version_list')
                report['service_activated'] = True
            report['steps'].append(record)
            report['final_foreground'] = foreground()
            report['final_display'] = capture('final.ppm')
            system = system_observation(remote)
            report['final_system'] = dict(
                initialization=system.get('initialization'),
                status_codes=system.get('status_codes'))
            report['passed'] = True
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
    return report


def run(args):
    require(0 < args.seconds <= 30, 'Window seconds must be in (0, 30]')
    require(0 < args.windows <= 24, 'Window count must be in (0, 24]')
    require(0 < args.items <= 40, 'Item count must be in (0, 40]')
    tabs = tuple(int(value) for value in args.tabs.split(','))
    report = dict(format=1, passed=False, tabs=list(tabs), items=args.items,
                  service_entry=hex(SERVICE_ENTRY), service_activated=False,
                  runs=[], errors=[])
    for tab in tabs:
        for attempt in range(3):
            try:
                record = run_tab(args, tab)
                break
            except ValueError as error:
                # The gdb and qtest ports are picked through bind-and-release;
                # retry a fresh pick when two launches race for one number.
                if 'Address already in use' not in str(error) or attempt == 2:
                    raise
                time.sleep(2)
        report['runs'].append(record)
        if record.get('service_activated'):
            report['service_activated'] = True
            break
    report['passed'] = bool(report['runs']) and all(
        'steps' in record and record['steps'] for record in report['runs'])
    args.destination.mkdir(parents=True, exist_ok=False)
    (args.destination / 'report.json').write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + chr(10),
        encoding='utf-8')
    print(('PASS ' if report['passed'] else 'FAIL ') +
          f"menu update navigation, tabs={len(report["runs"])}, "
          f"service activated: {report["service_activated"]}", flush=True)
    require(report['passed'], 'Menu update navigation failed')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--slave', required=True, type=Path)
    parser.add_argument('--controller', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--tabs', default=','.join(str(t) for t in DEFAULT_TABS),
                        help='Comma separated tab indices, setup tab first')
    parser.add_argument("--items", type=int, default=DEFAULT_ITEMS)
    parser.add_argument('--seconds', type=int, default=15)
    parser.add_argument('--windows', type=int, default=24)
    arguments = parser.parse_args()
    run(arguments)


if __name__ == '__main__':
    main()
