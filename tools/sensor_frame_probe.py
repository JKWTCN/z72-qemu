# SPDX-License-Identifier: GPL-2.0-or-later
"""Survey and verify the original sensor-sample chain in the combined machine.

The machine boots with the full interactive-console inputs (battery peer,
resource header, parameter groups, key interrupt and the periodic frame
synchronization source). After the shooting application stabilises, the
probe samples the recovered capture chain - the capture control block, the
capture event byte, operation 14's completion slot, the second-level
interrupt registrations for the capture family and the sensor sampling
result window - and runs bounded watchpoint windows over the event byte,
the sampling result words and the sub-state machine entry to see whether
the original producers and consumers execute.

With --sample-source the laboratory sensor-sample source is armed as well:
every frame tick then latches the recovered sample-ready line (bank 2
bit 0) and one automatic-sample event, and the probe additionally drives a
menu open/exit/reopen sequence, because a capture status raised while the
menu runs is exactly what the sample chain is expected to clear. Nothing
is written into guest state.
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
from tools.battery_boot_probe import shooting_active
from tools.controller_core_probe import CONTROLLER_SHA256
from tools.create_lab_parameters import parameter_images, resource_header_image
from tools.dual_boot_probe import dual_machine, sample_cores
from tools.graphics_boot_probe import (application_observation,
                                       capture_health_observation,
                                       graphics_observation, system_observation)

SYNC_WAIT = 0x102d949e
SUBSTATE_ENTRY = 0x103e5190
MENU_PIN = 9
EXIT_PIN = 0
CONTROL_BLOCK = 0xb23f6a7c      # +4 capture state, +5 sub-state, +0x1c pending
EVENT_BYTE = 0xb23f6848         # capture event bits, gate mask for the sub-state
OPERATION_SLOT = 0xb23f701c     # operation 14 completion trampoline slot
HANDLE_TABLE = 0xb2b5df20       # second-level device handlers, word per INTID
CAPTURE_INTIDS = tuple(range(192, 206)) + (208, 209, 210, 211)
SUBDRIVER_BLOCK = 0xb1864d48    # +1 state, +2 category
SAMPLING_MASK = 0x20061000      # word 0 enables the sampled result words
SAMPLING_RESULTS = tuple(0x20061300 + index * 4 for index in range(5))
THIRD_STATUS = 0x20060050       # INTID 88 status word (mask at +0x4c)
THIRD_SLOT = 0xb1806da0         # INTID 88 single callback slot
DEFAULT_HANDLER = 0x103a04e9


def linux(path):
    text = str(path)
    return re.sub(r'([A-Za-z]):[\\/][^,]*',
                  lambda m: '/mnt/' + m[1].lower() + '/' +
                            m[0][3:].replace('\\', '/'), text)


def watch(remote, address, size, kind, seconds):
    """Run one bounded watchpoint window; return the stops it produced."""
    require(remote.command(f'Z{kind},{address:x},{size}') == 'OK',
            'Watchpoint rejected')
    stops = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and len(stops) < 12:
        remote.sock.settimeout(3)
        try:
            reply = remote.command('vCont;c')
        except TimeoutError:
            # Synchronize with the stopped machine before the next command.
            remote.interrupt()
            continue
        match = re.search(r'thread:([0-9a-f]+);', reply or '')
        if not match:
            break
        thread = int(match[1], 16)
        remote.select_thread(thread)
        registers = remote.regs()
        stops.append(dict(thread=thread, pc=remote.get(registers, 'pc'),
                          value=int.from_bytes(remote.read(address, min(size, 4)),
                                               'little')))
    remote.sock.settimeout(15)
    remote.interrupt()
    require(remote.command(f'z{kind},{address:x},{size}') == 'OK',
            'Watchpoint removal failed')
    return stops


def try_read(remote, address, size):
    """Read guest memory; unmapped device windows read back as None."""
    try:
        return remote.read(address, size)
    except ValueError:
        return None


def word(value):
    return None if value is None else hex(struct.unpack('<I', value)[0])


def capture_chain_observation(remote):
    """Read every recovered link of the capture pipeline once."""
    remote.select_thread(1)
    block = remote.read(CONTROL_BLOCK, 0x24)
    event = remote.read(EVENT_BYTE, 4)
    slot = remote.read(OPERATION_SLOT, 4)
    table = remote.read(HANDLE_TABLE + CAPTURE_INTIDS[0] * 4, len(CAPTURE_INTIDS) * 4)
    handlers = [struct.unpack_from('<I', table, index * 4)[0]
                for index in range(len(CAPTURE_INTIDS))]
    subdriver = remote.read(SUBDRIVER_BLOCK, 4)
    results = [try_read(remote, address, 4) for address in SAMPLING_RESULTS]
    return dict(capture_state=block[4], sub_state=block[5],
                pending_words=[hex(struct.unpack_from('<I', block, 0x1c)[0])],
                event_bits=[hex(byte) for byte in event],
                operation14_trampoline=hex(struct.unpack('<I', slot)[0]),
                capture_handlers=[hex(handler) for handler in handlers],
                capture_interrupts_registered=sum(
                    handler != DEFAULT_HANDLER for handler in handlers),
                subdriver=dict(state=subdriver[1], category=subdriver[2]),
                sampling_mask=word(try_read(remote, SAMPLING_MASK, 4)),
                sampling_control=word(try_read(remote, 0x200610ec, 4)),
                third_status=word(try_read(remote, THIRD_STATUS, 4)),
                third_mask=word(try_read(remote, THIRD_STATUS - 4, 4)),
                group2_mask=word(try_read(remote, 0x20060040, 4)),
                group2_status=word(try_read(remote, 0x20060044, 4)),
                third_callback=word(try_read(remote, THIRD_SLOT, 4)),
                sampling_results=[word(value) for value in results])


def run(args):
    require(10 <= args.settle_seconds <= 900, 'Settle seconds out of bounds')
    require(5 <= args.watch_seconds <= 120, 'Watch seconds out of bounds')
    master, slave = args.master.read_bytes(), args.slave.read_bytes()
    identities = {role: analyze_eg(data, role)['sha256']
                  for role, data in (('master', master), ('slave', slave))}
    require(hashlib.sha256(args.controller.read_bytes()).hexdigest() ==
            CONTROLLER_SHA256, 'Expected the original controller image')
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0))
        qtest_port = server.getsockname()[1]
    args.destination.mkdir(parents=True, exist_ok=False)
    original = subprocess.Popen
    with tempfile.TemporaryDirectory(prefix='sensor-frame-', dir=ROOT / '.local') as folder:
        work = Path(folder)

        class WslProcess(original):
            def __init__(child, command, *extra, **keywords):
                index = command.index('-M')
                command[index + 1] += ',controller-battery-peer=on'
                command += ['-qtest', f'tcp:127.0.0.1:{qtest_port},server=on,wait=off',
                            '-qtest-log', '/dev/null']
                if os.name == 'nt':
                    child.pid_file = work / str(time.monotonic_ns())
                    wrapped = ['wsl.exe', '--exec', 'sh', '-c',
                               'echo $$ > ' + shlex.quote(linux(child.pid_file)) +
                               '; exec ' + shlex.join([linux(part) for part in command])]
                    super().__init__(wrapped, *extra, **keywords)
                else:
                    super().__init__(command, *extra, **keywords)

            def terminate(child):
                if os.name != 'nt' or child.poll() is not None:
                    super().terminate()
                    return
                if child.pid_file.exists():
                    pid = child.pid_file.read_text().strip()
                    if pid.isdecimal():
                        with original(['wsl.exe', '--exec', 'kill', '-TERM', pid],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL) as reaper:
                            reaper.wait(timeout=5)

        subprocess.Popen = WslProcess
        process = remote = wire = None
        report = dict(format=1, firmware_sha256=identities,
                      controller_sha256=CONTROLLER_SHA256,
                      firmware_modified=False, runtime_state_written=False,
                      periodic_frame_sync=True, sample_source=args.sample_source,
                      errors=[])
        try:
            resident = bytearray(0xC000)
            resident[:4] = b'MAKE'
            (work / 'resident.bin').write_bytes(resident)
            primary = bytearray(256)
            primary[11] = 1
            auxiliary = bytearray(256)
            auxiliary[9], auxiliary[12] = 8, 0xC9
            (work / 'primary.bin').write_bytes(primary)
            (work / 'aux.bin').write_bytes(auxiliary)
            for name, data in zip(('group17.bin', 'group18.bin', 'group32.bin'),
                                  (*parameter_images(), resource_header_image())):
                (work / name).write_bytes(data)
            devices = (
                'nikon-z72-controller-register-bank,bus=controller-i2c0,address=79',
                'nikon-z72-controller-expander,bus=controller-i2c0,address=34,id=keys,'
                'interrupt-gpio=/machine/controller/keys-gpio,interrupt-pin=8',
                f"nikon-z72-controller-register-bank,bus=controller-i2c0,"
                f"address=107,initial-state={work / 'primary.bin'}",
                f"nikon-z72-controller-register-bank,bus=controller-i2c0,"
                f"address=13,initial-state={work / 'aux.bin'}")
            devices += tuple(
                f'loader,file={work / name},addr={address:#x},force-raw=on'
                for name, address in (('group17.bin', 0x132C0000),
                                      ('group18.bin', 0x132E0000),
                                      ('group32.bin', 0x13E80000)))
            devices += tuple(f'nikon-z72-controller-register-bank,bus=master-i2c{i},'
                             'address=104' for i in range(4))
            settings = ['nikon-z72-boot-config.frame-sync=on']
            if args.sample_source:
                settings.append('nikon-z72-boot-config.sensor-sample=on')
                settings.append(f'nikon-z72-boot-config.sample-lines='
                                f'{args.sample_lines:#x}')
            process, remote = dual_machine(
                str(args.qemu), work, master, slave, work / 'console.txt',
                icount='shift=0,sleep=off', trace='guest_errors',
                controller_firmware=args.controller, controller_link=True,
                controller_flash_data=work / 'resident.bin', devices=devices,
                globals_=tuple(settings) +
                tuple(f'nikon-z72-controller-adc.channel{channel}={value}'
                     for channel, value in ((0, 1800), (1, 3001), (3, 3001))))
            wire = socket.create_connection(('127.0.0.1', qtest_port), timeout=10)

            def qtest(command):
                wire.sendall((command + '\n').encode())
                require(wire.recv(1024).strip() == b'OK', 'Input delivery failed')

            reply = remote.command('qRcmd,' + 'qom-list /machine/unattached'.encode().hex())
            listing = bytearray()
            while reply.startswith('O') and reply != 'OK':
                listing.extend(bytes.fromhex(reply[1:]))
                reply = remote.receive()
            text = listing.decode()
            gpios = sorted(re.findall(r"(device\[\d+\]) \(child<nikon-z72-controller-gpio>\)",
                                      text), key=lambda item: int(re.search(r'\d+', item)[0]))
            configs = sorted(re.findall(r"(device\[\d+\]) \(child<nikon-z72-boot-config>\)",
                                        text), key=lambda item: int(re.search(r'\d+', item)[0]))
            for index, pin, level in ((2, 5, 0), (3, 13, 1), (4, 9, 1), (6, 7, 1),
                                      (1, 11, 1), (6, 14, 1), (6, 15, 1)):
                qtest(f'set_irq_in /machine/unattached/{gpios[index]} '
                      f'unnamed-gpio-in {pin} {level}')
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
                qtest(f'set_irq_in /machine/unattached/{configs[0]} sync-event 15 {level}')
            qtest(f'set_irq_in /machine/unattached/{configs[0]} frame-sync-enable 0 1')
            require(remote.command(f'z0,{SYNC_WAIT:x},2') == 'OK',
                    'Could not remove the synchronization observation')

            def pause(seconds):
                remote.sock.settimeout(seconds)
                try:
                    remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()

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
                    pause(8)

            def foreground():
                remote.select_thread(1)
                data = remote.read(0xb1811e40, 0x30)
                return struct.unpack_from('<I', data, 0)[0], data[0x2c]

            deadline = time.monotonic() + args.settle_seconds
            steady = False
            while time.monotonic() < deadline:
                pause(8)
                if shooting_active(dict(application=application_observation(remote),
                                        graphics=graphics_observation(remote))):
                    steady = True
                    break
            report['shooting_steady'] = steady
            report['steady_observation'] = dict(
                application=application_observation(remote),
                system=system_observation(remote),
                graphics=graphics_observation(remote),
                capture_health=capture_health_observation(remote),
                chain=capture_chain_observation(remote))
            # Interactive watchpoints make the debugger connection unreliable
            # under the steady interrupt load, so the windows sample state
            # instead: any producer or consumer movement shows up here.
            def progress(seconds, step=5):
                snapshots = []
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    pause(step)
                    snapshots.append(capture_chain_observation(remote))
                return snapshots

            report['progress_snapshots'] = progress(args.watch_seconds)
            report['chain_after_windows'] = capture_chain_observation(remote)
            distinct_events = sorted({tuple(item['event_bits'])
                                      for item in report['progress_snapshots']})
            distinct_states = sorted({(item['capture_state'], item['sub_state'])
                                      for item in report['progress_snapshots']})
            report['distinct_event_bits'] = [list(item) for item in distinct_events]
            report['distinct_capture_states'] = [list(item) for item in distinct_states]

            if args.sample_source:
                settle(5)

                def tap(pin):
                    """One short press: a tenth of a guest second, then release."""
                    qtest(f'set_irq_in /machine/peripheral/keys pins {pin} 0')
                    release_at = ticks() + frequency() // 10
                    released = False
                    for _ in range(20):
                        pause(4)
                        if not released and ticks() >= release_at:
                            qtest(f'set_irq_in /machine/peripheral/keys pins {pin} 1')
                            released = True
                        ready, index = foreground()
                        if released and ready and index == 1:
                            return True
                    return False

                report['menu_opened'] = tap(MENU_PIN)
                report['codes_while_menu_open'] = (
                    capture_health_observation(remote).get('status_codes'))
                report['chain_while_menu_open'] = capture_chain_observation(remote)
                qtest(f'set_irq_in /machine/peripheral/keys pins {EXIT_PIN} 0')
                time.sleep(0.2)
                qtest(f'set_irq_in /machine/peripheral/keys pins {EXIT_PIN} 1')
                for _ in range(20):
                    pause(4)
                    ready, index = foreground()
                    if ready and index == 3:
                        break
                report['codes_after_exit'] = (
                    capture_health_observation(remote).get('status_codes'))
                settle(5)
                report['menu_reopened'] = tap(MENU_PIN)
                report['codes_after_reopen_attempt'] = (
                    capture_health_observation(remote).get('status_codes'))
                report['chain_final'] = capture_chain_observation(remote)
            report['cores'] = sample_cores(remote)
            log = (work / 'qemu.log').read_text(errors='replace')
            report['sampling_faults'] = sorted(set(
                re.findall(r'0x2006[0-9a-f]{3}', log)))
            report['console_lines'] = len(
                (work / 'console.txt').read_text(errors='replace').splitlines())
        except Exception as error:
            report['errors'].append(f'{type(error).__name__}: {error}')
            raise
        finally:
            subprocess.Popen = original
            if remote is not None:
                remote.sock.close()
            if wire is not None:
                wire.close()
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                log = work / 'qemu.log'
                if log.exists():
                    (args.destination / 'qemu.log').write_text(
                        log.read_text(errors='replace'), encoding='utf-8')
            (args.destination / 'report.json').write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    keys = ('shooting_steady', 'distinct_event_bits', 'distinct_capture_states',
            'menu_opened', 'menu_reopened')
    print(json.dumps({key: report[key] for key in keys if key in report},
                     indent=2, ensure_ascii=False))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True, type=Path)
    for name in ('master', 'slave', 'controller'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--settle-seconds', type=int, default=600,
                        help='Host-time bound for reaching the shooting foreground')
    parser.add_argument('--watch-seconds', type=int, default=30,
                        help='Host-time bound per watchpoint window')
    parser.add_argument('--sample-source', action='store_true',
                        help='Arm the laboratory sensor-sample source with the '
                             'recovered sample-ready and automatic-sample events')
    parser.add_argument('--sample-lines', type=lambda text: int(text, 0),
                        default=0,
                        help='Line pattern held in the sampled result words')
    arguments = parser.parse_args()
    try:
        run(arguments)
    except Exception as error:
        import traceback
        traceback.print_exc()
        print(f'Probe failed: {error}', file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
