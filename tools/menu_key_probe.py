# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe a menu-key press and release through the original input path."""
import argparse
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
from analyze.decode_z72 import BASE, digest, require
from analyze.firmware_structure import application_manager, PROFILES, thumb_literal
from tools.graphics_boot_probe import (application_observation,
                                       capture_health_observation,
                                       controller_input_observation,
                                       graphics_observation, system_observation)
from tools.battery_boot_probe import shooting_active
from tools.create_lab_parameters import parameter_images, resource_header_image
from tools.dual_boot_probe import dual_machine, sample_cores
from tools.smp_boot_probe import stop_registers

MENU_PIN = 9


def mode_layout(master):
    # The transition routine selects a mode object through a literal pointer
    # table. Each initialized object's first word points back to the system.
    select = list(re.finditer(rb'\xf0\xb4\x15\x46\x90\xf9\x58\x21\x8a\x42\x0f\xd0'
                              rb'\x80\xf8\x59\x21.\x4a\x80\xf8\x58\x11\x52\xf8\x21\x40',
                              master, re.S))
    group = list(re.finditer(rb'\x00\xeb\x81\x00\xd0\xf8(.)\x13\x01\x20\x00\x29'
                             rb'\x00\xd1\x00\x20\x70\x47', master, re.S))
    require(len(select) == len(group) == 1, 'Expected unique mode selection and inhibitor access')
    table = thumb_literal(master, select[0].start() + 16, 2)
    offset = 0x300 + group[0].group(1)[0]
    # Check the deferred-flags and target-mode stores in the adjacent setter.
    pos = group[0].start()
    for instruction, halfword, displacement, register in (
            (0x26, 0xf8c0, 12, 4), (0x34, 0xf880, 20, 3)):
        require(struct.unpack_from('<2H', master, pos + instruction) ==
                (halfword, register << 12 | (offset + displacement)),
                'Unexpected deferred mode fields')
    return table, offset, BASE + select[0].start(), BASE + pos + 0x1c


def historical_mode(remote, layout):
    remote.select_thread(1)
    table, groups = layout[:2]
    obj = int.from_bytes(remote.read(table, 4), 'little')
    context = int.from_bytes(remote.read(obj, 4), 'little')
    if not context:
        return dict(system_context=None)
    modes = remote.read(context + 0x158, 2)
    transition = remote.read(context + groups, 24)
    inhibitors = list(struct.unpack_from('<3I', transition))
    flags = struct.unpack_from('<I', transition, 12)[0]
    return dict(system_context=hex(context), current_mode=modes[0], previous_mode=modes[1],
                transition_inhibitors=inhibitors, deferred_transition_flags=flags,
                deferred_target_mode=transition[20] if flags & 4 else None)


def mode_event_sites(master):
    entry = bytes.fromhex('70b50446006800260d463146d0f890209047')
    setup = bytes.fromhex('2068002307220a21')
    require(master.count(entry) == 1, 'Expected one mode event handler')
    start = master.index(entry)
    body = master[start:start + 0xc0]
    require(body.count(setup) == 1, 'Expected one shared mode notification call')
    site = body.index(setup) + len(setup)
    first, second, resume = struct.unpack_from('<3H', body, site)
    require(first & 0xf800 == 0xf000 and second & 0xd000 == 0xd000 and resume == 0xe7d5,
            'Unexpected mode notification call or return path')
    return BASE + start, BASE + start + site


def mode_gate_sites(master):
    entry = bytes.fromhex('2de9f0410129984692b016460f4604464ff00105')
    checks = bytes.fromhex('8847c0b9d4f8bc10204688478df800508df8015078b9')
    require(master.count(entry) == 1, 'Expected one system event dispatcher')
    start = master.index(entry)
    body = master[start:start + 0xc0]
    require(body.count(checks) == 1, 'Expected one startup event gate')
    site = BASE + start + body.index(checks)
    sender = bytes.fromhex('feb50446d0f80801052849d10020c4f80801')
    require(master.count(sender) == 1, 'Expected one startup notification producer')
    ready = bytes.fromhex('2068d0f8a4108847e0b10520c4f808012068d0f8b0108847'
                          '05462068d0f8b400804705402068d0f8b4008047854211d1')
    require(master.count(ready) == 1, 'Expected one mode entry readiness check')
    gate = BASE + master.index(ready)
    return {BASE + master.index(sender): 'producer', BASE + start: 'dispatch',
            site + 2: 'mode_check', site + 20: 'system_check',
            gate + 8: 'entry_check', gate + 24: 'available_bits',
            gate + 44: 'required_bits'}


def readiness_sites(master):
    sites = {}
    for name, signature, offset in (
            ('update_type', '10b501284ff0000406d0022806d00428', 0),
            ('pending_bits', '009941f6283001f0010252420a409207', 2),
            ('service_status', '0546087893b0c043e1784007', 4),
            ('ready_message', '20780128d5f8', 2)):
        pattern = bytes.fromhex(signature)
        require(master.count(pattern) == 1, f'Expected one {name} observation point')
        sites[BASE + master.index(pattern) + offset] = name
    return sites


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
    identities = dict(master=digest(master), slave=digest(slave))
    controller_hash = digest(args.controller.read_bytes())
    history = json.loads((ROOT / 'artifacts/early_boot_history/report.json').read_text())
    matches = [p for p in history['packages']
               if {e['role']: e['sha256'] for e in p['engines']} == identities and
               p['controller_request']['sha256'] == controller_hash]
    require(len(matches) == 1, 'Expected three firmware members from the same historical update')
    manager, getters = application_manager(master)
    press_on_entry = getattr(args, 'press_on_live_view_entry', False)
    tap_seconds = getattr(args, 'tap_seconds', None)
    require(tap_seconds is None or 0 < tap_seconds <= 2, 'Tap duration must be in (0, 2] seconds')
    interactive_inputs = getattr(args, 'interactive_inputs', False)
    require(not interactive_inputs or args.sync_pulse,
            'Interactive inputs require --sync-pulse to start the periodic source')
    require(not press_on_entry or args.settle_seconds == 0,
            'Pressing on live-view entry requires --settle-seconds 0')
    switch_word = matches[0]['controller_request']['menu_samples'][0]['switch_address']
    current_profile = identities['master'] == PROFILES['master'].sha256
    trace_modes = getattr(args, 'trace_modes', False)
    layout = mode_layout(master) if trace_modes or not current_profile else None
    wait_setup = bytes.fromhex('40ea04086a4632230821a7f15000')
    require(master.count(wait_setup) == 1, 'Expected one synchronization wait setup')
    wait = BASE + master.index(wait_setup) + len(wait_setup)
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
                      firmware_sha256=identities, controller_sha256=controller_hash,
                      package=matches[0]['package'],
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
            key_irq, frame_inputs = '', ()
            if interactive_inputs:
                key_irq = ',interrupt-gpio=/machine/controller/keys-gpio,interrupt-pin=8'
                frame_inputs = ('nikon-z72-boot-config.frame-sync=on',
                                'nikon-z72-boot-config.sensor-sample=on',
                                'nikon-z72-boot-config.sample-counter=on')
            report['interactive_inputs'] = interactive_inputs
            report['press_on_live_view_entry'] = press_on_entry
            report['tap_seconds'] = tap_seconds
            devices = (
                'nikon-z72-controller-register-bank,bus=controller-i2c0,address=79',
                'nikon-z72-controller-expander,bus=controller-i2c0,address=34,id=keys' + key_irq,
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
            sample_axes = getattr(args, 'acceleration_sample', None)
            if sample_axes is not None:
                require(all(-2048 <= axis <= 2047 for axis in sample_axes),
                        'Acceleration axes must fit signed 12-bit samples')
                x, y, z = sample_axes
                devices += ('nikon-z72-acceleration,bus=master-i2c2,address=29,'
                            f'sample-present=on,sample-x={x},sample-y={y},sample-z={z}',)
                report['acceleration_sample'] = sample_axes
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
                globals_=frame_inputs + tuple(
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
            foreground_watch = f'2,{manager + 16:x},1'
            if press_on_entry:
                require(remote.command('Z' + foreground_watch) == 'OK',
                        'Could not watch the foreground application index')
            if trace_modes:
                report['mode_calls'] = []
                event_entry, notify = mode_event_sites(master)
                report['mode_events'] = []
                gates = mode_gate_sites(master)
                gates.update(readiness_sites(master))
                report['mode_gates'] = []
                trace_sites = (*layout[2:], event_entry, notify, *gates)
                for pc in trace_sites:
                    remote.breakpoint(pc)
            if args.sync_pulse:
                configs = re.findall(
                    r"(device\[\d+\]) \(child<nikon-z72-boot-config>\)", listing.decode())
                configs.sort(key=lambda item: int(re.search(r'\d+', item)[0]))
                require(len(configs) == 2, 'Expected two engine synchronization receivers')
                require(remote.command(f'Z0,{wait:x},2') == 'OK',
                        'Could not observe the original synchronization wait')
            for index, pin, level in ((2, 5, 0), (3, 13, 1), (4, 9, 1),
                                      (6, 7, 1), (1, 11, 1), (6, 14, 1), (6, 15, 1)):
                wire.sendall(f"set_irq_in /machine/unattached/{gpios[index]} "
                             f"unnamed-gpio-in {pin} {level}\n".encode())
                assert wire.recv(1024).strip() == b'OK'

            def resume():
                deadline = time.monotonic() + args.seconds
                while time.monotonic() < deadline:
                    remote.sock.settimeout(max(.1, deadline - time.monotonic()))
                    try:
                        response = remote.command('vCont;c')
                    except TimeoutError:
                        remote.sock.settimeout(10)
                        remote.interrupt()
                        return
                    remote.sock.settimeout(10)
                    thread, registers = stop_registers(remote, response)
                    pc = remote.get(registers, 'pc')
                    if press_on_entry and 'watch:' in response:
                        require(remote.command('z' + foreground_watch) == 'OK',
                                'Could not remove foreground watchpoint')
                        stop_registers(remote, remote.command(f'vCont;s:{thread:x}'))
                        if thread in (1, 2) and remote.read(manager + 16, 1) == b'\x03':
                            report['live_view_entry_store'] = hex(pc)
                            return
                        require(remote.command('Z' + foreground_watch) == 'OK',
                                'Could not restore foreground watchpoint')
                        continue
                    if trace_modes and pc in trace_sites:
                        require(thread in (1, 2), 'Mode call stopped outside master')
                        ctx, r1, r2, r3 = (remote.get(registers, f'r{i}') for i in range(4))
                        call = dict(pc=hex(pc), r1=r1, r2=r2, r3=r3,
                                    caller_return=hex(remote.get(registers, 'lr') & ~1),
                                    counter_ticks=int.from_bytes(remote.read(0x04266008, 8), 'little'))
                        if pc in gates:
                            call.update(kind=gates[pc], r0=ctx)
                            if gates[pc] == 'producer':
                                call['substate'] = int.from_bytes(remote.read(ctx + 0x108, 4), 'little')
                            elif gates[pc] == 'required_bits':
                                call['matched_bits'] = remote.get(registers, 'r5')
                            report['mode_gates'].append(call)
                        elif pc in layout[2:]:
                            call.update(kind='select' if pc == layout[2] else 'defer',
                                        current=remote.read(ctx + 0x158, 1)[0])
                            report['mode_calls'].append(call)
                        else:
                            call['kind'] = 'event' if pc == event_entry else 'notify'
                            if pc == event_entry:
                                call['event_bytes'] = remote.read(r1, 2).hex()
                            else:
                                call['callback'] = hex(int.from_bytes(remote.read(ctx + 0x88, 4), 'little'))
                            report['mode_events'].append(call)
                        remote.breakpoint(pc, False)
                        stop_registers(remote, remote.command(f'vCont;s:{thread:x}'))
                        remote.breakpoint(pc)
                        continue
                    require(args.sync_pulse and not report['sync_pulse_supplied'] and pc == wait and
                            remote.get(registers, 'r0') == remote.get(registers, 'r7') - 0x50 and
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
                    if interactive_inputs:
                        wire.sendall(f'set_irq_in /machine/unattached/{configs[0]} '
                                     'frame-sync-enable 0 1\n'.encode())
                        require(wire.recv(1024).strip() == b'OK', 'Periodic frame sync failed')
                    report['sync_pulse'] = dict(line=15, status_bit=4, irq=87,
                        wait_address=hex(wait), mask=hex(mask),
                        counter_ticks=int.from_bytes(remote.read(0x04266008, 8), 'little'))
                    require(remote.command(f'z0,{wait:x},2') == 'OK',
                            'Could not remove synchronization observation point')

            def sample(stage):
                app = application_observation(remote, manager)
                if app['initialization_complete']:
                    require(tuple(int(item['getter'], 16) for item in app['applications']) == getters,
                            'Runtime application table differs from firmware')
                observation = dict(stage=stage, application=app, graphics=graphics_observation(remote))
                if current_profile:
                    observation.update(system=system_observation(remote),
                                       capture_health=capture_health_observation(remote),
                                       controller_input=controller_input_observation(remote))
                else:
                    observation['system'] = historical_mode(remote, layout)
                    remote.select_thread(1)
                    words = struct.unpack('<3I', remote.read(switch_word - 4, 12))
                    observation['controller_input'] = dict(decoded_switch_words=list(map(hex, words)),
                                                           decoded_menu_bit=bool(words[1] & 0x8000))
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
                if press_on_entry:
                    return ('live_view_entry_store' in report and
                            item['application']['initialization_complete'] == 1 and
                            item['application']['current_index'] == 3 and
                            not item['controller_input']['decoded_menu_bit'])
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
            require(baseline['counter_frequency'] > 0, 'Counter frequency is unavailable')

            def elapsed(item):
                return (item['counter_ticks'] - baseline['counter_ticks']) / baseline['counter_frequency']

            def menu_active(item):
                return item['application']['current_index'] == 1

            drive(MENU_PIN, 0)
            pressed = observe('pressed', lambda item: item['controller_input']['decoded_menu_bit']
                              and (tap_seconds is None or elapsed(item) >= tap_seconds))
            menu_opened = pressed if menu_active(pressed) else None
            last_held = pressed
            if tap_seconds is None and menu_opened is None:
                last_held = observe('menu-start', menu_active)
                menu_opened = last_held
            drive(MENU_PIN, 1)
            report['menu_held_virtual_seconds'] = elapsed(last_held)
            if menu_opened is not None:
                report['menu_start_held_virtual_seconds'] = elapsed(menu_opened)
            released = observe('released', lambda item: not item['controller_input']['decoded_menu_bit'])
            report['key_transport_verified'] = True
            if menu_opened is None:
                menu_opened = released if menu_active(released) else observe('menu-start', menu_active)
            # The menu application must remain foreground after the release.
            stayed = observe('menu-steady',
                             lambda item: item['application']['current_index'] == 1
                             and not item['controller_input']['decoded_menu_bit'])
            report['menu_application_steady'] = stayed['application']['current_index'] == 1
            report['menu_application_observed'] = True
            report['menu_start_virtual_seconds_since_press'] = elapsed(menu_opened)
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
    parser.add_argument('--press-on-live-view-entry', action='store_true',
                        help='Press MENU at the native APPLV foreground write (requires --settle-seconds 0)')
    parser.add_argument('--interactive-inputs', action='store_true',
                        help='Wire the key interrupt and enable periodic frame and sample inputs')
    parser.add_argument('--tap-seconds', type=float,
                        help='Release at the first decoded press sample after this many guest seconds')
    parser.add_argument('--resource-header', action='store_true',
                        help='Load an experimental group-32 header with a zero resource body')
    parser.add_argument('--trace-modes', action='store_true',
                        help='Record master mode events, notifications, selections and deferred requests')
    parser.add_argument('--acceleration-sample', type=int, nargs=3, metavar=('X', 'Y', 'Z'),
                        help='Attach the acceleration device with three signed 12-bit raw axes')
    parser.add_argument('--sync-pulse', action='store_true',
                        help='Supply one external synchronization pulse at the original wait')
    arguments = parser.parse_args()
    run(arguments)


if __name__ == '__main__':
    main()
