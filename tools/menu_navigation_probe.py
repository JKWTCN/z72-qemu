# SPDX-License-Identifier: GPL-2.0-or-later
"""Sweep controller inputs inside the open menu and record native reactions.

For every expander input the probe presses once while the original menu
application is foreground, records the engine's decoded switch words around
the press and release, and captures the display after each step. The report
supports naming inputs from firmware behavior; it does not modify firmware
state or synthesize events.
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
from analyze.decode_z72 import require
from analyze.firmware_structure import analyze_eg
from tools.controller_core_probe import CONTROLLER_SHA256
from tools.graphics_boot_probe import (application_observation,
                                       capture_health_observation,
                                       controller_input_observation,
                                       graphics_observation)
from tools.create_lab_parameters import parameter_images, resource_header_image
from tools.dual_boot_probe import dual_machine

MENU_PIN = 9
PRESS_LIMIT = 4
SETTLE_WINDOWS = 2
RENDER_THRESHOLD = 0.05


def linux(path):
    text = str(path)
    return re.sub(r'([A-Za-z]):[\\/][^,]*',
                  lambda m: '/mnt/' + m[1].lower() + '/' +
                            m[0][3:].replace('\\', '/'), text)


def frame_profile(data):
    """Summarize a captured frame as per-row difference weight against black."""
    header = re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\r?\n', data)
    require(header is not None, 'Unexpected frame format')
    width, height = map(int, header.groups())
    pixels = data[header.end():]
    rows = []
    for y in range(height):
        row = pixels[y * width * 3:(y + 1) * width * 3]
        rows.append(sum(1 for i in range(0, len(row), 3)
                        if row[i] > 24 or row[i + 1] > 24 or row[i + 2] > 24))
    return rows


def changed_bands(before, after, threshold=12):
    bands, start = [], None
    for y, (a, b) in enumerate(zip(before, after)):
        if abs(a - b) > threshold and start is None:
            start = y
        elif abs(a - b) <= threshold and start is not None:
            bands.append((start, y - 1))
            start = None
    if start is not None:
        bands.append((start, len(before) - 1))
    return bands


def run(args):
    require(0 < args.seconds <= 30, 'Window seconds must be in (0, 30]')
    require(0 < args.windows <= 48, 'Window count must be in (0, 48]')
    pins = [int(value) for value in args.pins.split(',')]
    require(all(0 <= pin < 24 for pin in pins) and len(set(pins)) == len(pins),
            'Pins must be distinct values in [0, 24)')
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
    with tempfile.TemporaryDirectory(prefix='menu-nav-', dir=ROOT / '.local') as folder:
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
        report = dict(format=1, passed=False, menu_pin=MENU_PIN, sweep_pins=pins,
                      firmware_sha256=identities, controller_sha256=CONTROLLER_SHA256,
                      firmware_modified=False, runtime_state_written=False,
                      resource_header_only=True, sync_pulse_supplied=False,
                      full_boot_verified=False, steps=[], error=None)
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
            for name, data in zip(('group17.bin', 'group18.bin', 'group32.bin'),
                                  (*parameter_images(), resource_header_image())):
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
                                      ('group18.bin', 0x132E0000),
                                      ('group32.bin', 0x13E80000)))
            devices += tuple(
                f"nikon-z72-controller-register-bank,bus=master-i2c{i},address=104"
                for i in range(4))
            process, remote = dual_machine(
                args.qemu, work, master, slave, work / 'console.txt',
                icount='shift=0,sleep=off', trace='guest_errors',
                controller_firmware=args.controller,
                controller_link=True,
                controller_flash_data=work / 'resident.bin',
                devices=devices,
                globals_=('nikon-z72-boot-config.frame-sync=on',) + tuple(
                    f"nikon-z72-controller-adc.channel{channel}={value}"
                    for channel, value in ((0, 1800), (1, 3001), (3, 3001))))
            wire = socket.create_connection(('127.0.0.1', qtest_port), timeout=10)
            reply = remote.command('qRcmd,' +
                                   'qom-list /machine/unattached'.encode().hex())
            listing = bytearray()
            while reply.startswith('O') and reply != 'OK':
                listing.extend(bytes.fromhex(reply[1:]))
                reply = remote.receive()
            text = listing.decode()
            gpios = re.findall(r"(device\[\d+\]) \(child<nikon-z72-controller-gpio>\)", text)
            gpios.sort(key=lambda item: int(re.search(r'\d+', item)[0]))
            configs = re.findall(r"(device\[\d+\]) \(child<nikon-z72-boot-config>\)", text)
            configs.sort(key=lambda item: int(re.search(r'\d+', item)[0]))
            require(len(configs) == 2, 'Expected two engine synchronization receivers')

            def qtest(line):
                wire.sendall(line.encode() + b'\n')
                assert wire.recv(1024).strip() == b'OK'

            for index, pin, level in ((2, 5, 0), (3, 13, 1), (4, 9, 1),
                                      (6, 7, 1), (1, 11, 1), (6, 14, 1), (6, 15, 1)):
                qtest(f"set_irq_in /machine/unattached/{gpios[index]} "
                      f"unnamed-gpio-in {pin} {level}")

            def resume(timeout=None):
                remote.sock.settimeout(timeout or args.seconds)
                try:
                    return remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()
                    return None

            def sample():
                observation = dict(
                    application=application_observation(remote),
                    controller_input=controller_input_observation(remote),
                    graphics=graphics_observation(remote))
                remote.select_thread(1)
                observation['counter_ticks'] = int.from_bytes(
                    remote.read(0x04266008, 8), 'little')
                return observation

            def observe(predicate, limit=None):
                for _ in range(limit or args.windows):
                    resume()
                    observation = sample()
                    if predicate(observation):
                        return observation
                return None

            def switches(item):
                return [int(value, 16) for value in
                        item['controller_input']['decoded_switch_words']]

            def drive(pin, level):
                qtest(f'set_irq_in /machine/peripheral/keys pins {pin} {level}')

            def capture(name):
                path = args.destination / name
                target = str(path.resolve())
                if os.name == 'nt':
                    target = linux(target)
                remote.sock.settimeout(20)
                response = remote.command('qRcmd,' +
                    ('screendump ' + json.dumps(target)).encode().hex())
                while response.startswith('O') and response != 'OK':
                    response = remote.receive()
                require(response == 'OK', 'Interface capture failed')
                return path

            # Supply the initial synchronization pulse at the original wait.
            require(remote.command('Z0,102d949e,2') == 'OK',
                    'Could not observe the original synchronization wait')
            encoded = b'vCont;c'
            remote.sock.sendall(b'$' + encoded + b'#' +
                                f'{sum(encoded) & 255:02x}'.encode())
            response = None
            remote.sock.settimeout(5)
            deadline = time.monotonic() + 240
            while response is None:
                try:
                    response = remote.receive()
                except TimeoutError:
                    require(time.monotonic() < deadline,
                            'Synchronization wait stop missing')
            match = re.search(r'thread:([0-9a-f]+);', response or '')
            require(match is not None, 'Missing synchronization stop thread')
            remote.select_thread(int(match[1], 16))
            registers = remote.regs()
            require(remote.get(registers, 'pc') == 0x102d949e,
                    'Unexpected original synchronization wait')
            for level in (1, 0):
                qtest(f"set_irq_in /machine/unattached/{configs[0]} "
                      f"sync-event 15 {level}")
            report['sync_pulse_supplied'] = True
            require(remote.command('z0,102d949e,2') == 'OK',
                    'Could not remove synchronization observation point')
            qtest(f"set_irq_in /machine/unattached/{configs[0]} "
                  f"frame-sync-enable 0 1")

            def frame_ratio(path):
                rows = frame_profile(path.read_bytes())
                lit = sum(1 for count in rows if count > 3)
                return lit / max(len(rows), 1)

            def menu_rendered(checks=8):
                for index in range(checks):
                    resume()
                    item = sample()
                    health = capture_health_observation(remote)
                    print(f"  render[{index}]: index={item['application']['current_index']} "
                          f"statuses={health.get('status_codes')}", flush=True)
                    if item['application']['current_index'] != 1:
                        continue
                    path = capture('menu-check.ppm')
                    if frame_ratio(path) >= RENDER_THRESHOLD:
                        return item, path
                return None, None

            ready = observe(lambda item: item['application']['initialization_complete']
                            and item['application']['current_index'] == 3)
            require(ready is not None, 'Shooting application did not become ready')
            baseline_switches = switches(ready)
            report['baseline_switch_words'] = [hex(value) for value in baseline_switches]

            def open_menu(label='open'):
                drive(MENU_PIN, 0)
                menu_bit = lambda item: item['controller_input']['decoded_menu_bit']
                pressed = observe(menu_bit, limit=6)
                print(f"  {label}: menu bit observed={pressed is not None}", flush=True)
                if pressed is None:
                    drive(MENU_PIN, 1)
                    return None, None
                # The direct menu start executes while the key stays held;
                # release only after the foreground switches.
                switched = observe(
                    lambda item: item['application']['current_index'] == 1)
                drive(MENU_PIN, 1)
                print(f"  {label}: foreground switched={switched is not None}",
                      flush=True)
                if switched is None:
                    return None, None
                return menu_rendered()

            item, path = open_menu()
            require(item is not None, 'Menu application did not open and render')
            report['menu_opened'] = True
            base_frame = capture('menu-baseline.ppm')
            base_profile = frame_profile(base_frame.read_bytes())
            menu_baseline = switches(sample())
            report['menu_baseline_switch_words'] = [hex(value)
                                                    for value in menu_baseline]

            for pin in pins:
                step = dict(pin=pin, screenshots={}, observations=[])
                foreground = sample()['application']['current_index']
                if foreground != 1:
                    step['skipped'] = f'foreground {foreground} is not the menu'
                    report['steps'].append(step)
                    print(f"pin {pin}: {step['skipped']}", flush=True)
                    continue
                drive(pin, 0)
                before = None
                for _ in range(PRESS_LIMIT):
                    resume()
                    before = sample()
                    step['observations'].append(dict(phase='press', pin=pin,
                        switches=before['controller_input']['decoded_switch_words'],
                        ticks=before['counter_ticks'],
                        application=before['application']['current_index']))
                    if switches(before) != menu_baseline:
                        break
                drive(pin, 1)
                after = None
                for _ in range(PRESS_LIMIT):
                    resume()
                    after = sample()
                    step['observations'].append(dict(phase='release', pin=pin,
                        switches=after['controller_input']['decoded_switch_words'],
                        ticks=after['counter_ticks'],
                        application=after['application']['current_index']))
                    if switches(after) == menu_baseline:
                        break
                for _ in range(SETTLE_WINDOWS):
                    resume()
                frame = capture(f'pin-{pin}.ppm')
                step['screenshots']['after'] = frame.name
                if before is not None and after is not None:
                    pressed_words = switches(before)
                    step['switch_delta_during_press'] = [
                        hex(pressed ^ base)
                        for pressed, base in zip(pressed_words, menu_baseline)]
                    step['press_reached_engine'] = pressed_words != menu_baseline
                    step['released'] = switches(after) == menu_baseline
                    step['foreground_after'] = after['application']['current_index']
                    profile = frame_profile(frame.read_bytes())
                    step['changed_row_bands'] = changed_bands(base_profile, profile)
                report['steps'].append(step)
                print(f"pin {pin}: delta={step.get('switch_delta_during_press')} "
                      f"reached={step.get('press_reached_engine')} "
                      f"foreground={step.get('foreground_after')} "
                      f"bands={step.get('changed_row_bands')}", flush=True)

            report['passed'] = all(
                'skipped' not in step for step in report['steps']) and \
                len(report['steps']) == len(pins)
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
          'menu navigation sweep', flush=True)
    require(report['passed'], 'Menu navigation sweep failed')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--slave', required=True, type=Path)
    parser.add_argument('--controller', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--seconds', type=int, default=5)
    parser.add_argument('--windows', type=int, default=24)
    parser.add_argument('--pins', default=','.join(
        str(pin) for pin in range(24) if pin != MENU_PIN),
        help='Comma-separated expander inputs to sweep inside the menu')
    arguments = parser.parse_args()
    run(arguments)


if __name__ == '__main__':
    main()
