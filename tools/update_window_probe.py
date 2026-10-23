# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify the explicit decoded-window boot fixture.

The window address is a laboratory input, also supplied by the bounded
update probe. It is not an observed fixed programming destination. This
probe explicitly enables window harvesting and preloads a decoded container,
then checks the machine-visible consequences:

- a valid decoded container boots as its own master member after a machine
  reset, and keeps booting across a second reset;
- a corrupted copy (one flipped payload byte) is rejected with the stock
  master still booting.

Only the master engine harvests; the slave engine keeps its stored image
and the mixed-version machine is not expected to reach a shooting state.
Firmware bytes stay local; no firmware file is modified. This fixture does
not execute authentication or native flash programming.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
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
from analyze.update_container import describe_container, master_member
from analyze.upgrade_signature import HEADER_LENGTH, decode
from analyze.firmware_structure import analyze_eg
from tools.controller_core_probe import CONTROLLER_SHA256
from tools.create_lab_parameters import parameter_images, resource_header_image
from tools.dual_boot_probe import dual_machine

WINDOW = 0x52000000
SYNC_WAIT = 0x102d949e
STOCK_VERSION = b'Ver.01.70.02'
VERSION_RECORD = BASE + 0x20


def linux(path):
    text = str(path)
    return re.sub(r'([A-Za-z]):[\\/][^,]*',
                  lambda m: '/mnt/' + m[1].lower() + '/' +
                            m[0][3:].replace('\\', '/'), text)


def version_record(remote):
    remote.select_thread(1)
    return bytes(remote.read(VERSION_RECORD, 12))


def run_case(args, work, label, window_data, expect_version, second_reset):
    """Boot with a planted window, reset, and read the running record."""
    master, slave = args.master.read_bytes(), args.slave.read_bytes()
    stock = work / f'stock-{label}.bin'
    stock.write_bytes(master)
    planted = work / f'window-{label}.bin'
    planted.write_bytes(window_data)
    (work / label).mkdir()
    # The gdb and qtest ports are picked through bind-and-release, so two
    # machine launches can race for the same number; retry a fresh pick.
    for attempt in range(3):
        try:
            return launch_case(args, work, label, window_data,
                               expect_version, second_reset)
        except ValueError as error:
            if 'Address already in use' not in str(error) or attempt == 2:
                raise
            time.sleep(2)


def launch_case(args, work, label, window_data, expect_version, second_reset):
    master, slave = args.master.read_bytes(), args.slave.read_bytes()
    stock = work / f'stock-{label}.bin'
    planted = work / f'window-{label}.bin'
    launched = []
    original = subprocess.Popen
    # Pick below the Windows dynamic-port range: released picks inside it
    # are immediately re-contended by the WSL relay sockets.
    qtest_port = None
    while qtest_port is None:
        candidate = random.randint(20000, 45000)
        with socket.socket() as probe_socket:
            try:
                probe_socket.bind(('127.0.0.1', candidate))
            except OSError:
                continue
        qtest_port = candidate

        class WslProcess(original):
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
        record = dict(case=label, window_sha256=hashlib.sha256(window_data).hexdigest(),
                      window_length=len(window_data),
                      expected_after_reset=expect_version.decode('ascii'))
        try:
            resident = bytearray(0xC000)
            resident[:4] = b'MAKE'
            (work / 'resident.bin').write_bytes(resident)
            for name, data in zip(('group17.bin', 'group18.bin'), parameter_images()):
                (work / name).write_bytes(data)
            (work / 'group32.bin').write_bytes(resource_header_image())
            devices = (
                'nikon-z72-controller-register-bank,bus=controller-i2c0,address=79',
                'nikon-z72-controller-register-bank,bus=controller-i2c0,address=107',
                'nikon-z72-controller-register-bank,bus=controller-i2c0,address=13')
            devices += tuple(
                f"loader,file={work / name},addr={address:#x},force-raw=on"
                for name, address in (('group17.bin', 0x132C0000),
                                      ('group18.bin', 0x132E0000),
                                      ('group32.bin', 0x13E80000)))
            devices += tuple(
                f"nikon-z72-controller-register-bank,bus=master-i2c{i},address=104"
                for i in range(4))
            process, remote = dual_machine(
                args.qemu, work / label, master, slave,
                work / f'console-{label}.txt',
                icount='shift=0,sleep=off', trace='guest_errors',
                controller_firmware=args.controller, controller_link=True,
                controller_flash_data=work / 'resident.bin', devices=devices,
                globals_=('nikon-z72-boot-config.frame-sync=on',
                          'nikon-z72-boot-store.harvest-update=on'),
                machine_options=(f'master-boot-image={stock}',),
                extra_arguments=(
                    '-device',
                    f'loader,file={planted},addr={WINDOW:#x},force-raw=on',))
            assert process.poll() is None
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
            # Either the stored stock image reaches its synchronization wait,
            # or the window already harvested at the initial reset and the
            # other image runs instead; both record their version.
            record['boot_record'] = None
            hit_sync_wait = False
            require(remote.command(f'Z0,{SYNC_WAIT:x},2') == 'OK',
                    'Could not observe the original synchronization wait')
            remote.sock.settimeout(240)
            try:
                response = remote.command('vCont;c')
                match = re.search(r'thread:([0-9a-f]+);', response or '')
                if match:
                    remote.select_thread(int(match[1], 16))
                    hit_sync_wait = (remote.get(remote.regs(), 'pc') == SYNC_WAIT)
            except TimeoutError:
                remote.interrupt()
            record['boot_record'] = version_record(remote).decode('ascii', 'ignore')
            if hit_sync_wait:
                for level in (1, 0):
                    wire.sendall(f"set_irq_in /machine/unattached/{configs[0]} "
                                 f"sync-event 15 {level}\n".encode())
                    require(wire.recv(1024).strip() == b'OK',
                            'Synchronization input failed')
                wire.sendall(f"set_irq_in /machine/unattached/{configs[0]} "
                             f"frame-sync-enable 0 1\n".encode())
                require(wire.recv(1024).strip() == b'OK', 'Periodic frame sync failed')
            require(remote.command(f'z0,{SYNC_WAIT:x},2') == 'OK',
                    'Could not remove the synchronization observation')

            def machine_reset():
                reply = remote.command('qRcmd,' + b'system_reset'.hex())
                while reply.startswith('O') and reply != 'OK':
                    reply = remote.receive()
                require(reply == 'OK', 'Machine reset failed')
                # The boot-store pass happens inside the reset; give the
                # restarted cores a brief run before reading the record.
                remote.sock.settimeout(8)
                try:
                    remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()

            machine_reset()
            first = version_record(remote)
            record['first_reset_record'] = first.decode('ascii', 'ignore')
            record['matches_expectation'] = first == expect_version
            if second_reset:
                machine_reset()
                record['second_reset_record'] = version_record(remote).decode(
                    'ascii', 'ignore')
        except Exception as error:
            record['error'] = f'{type(error).__name__}: {error}'
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
        return record


def run(args):
    master = args.master.read_bytes()
    package = args.update_package.read_bytes()
    # The marked body prefix enters the stream verbatim; the payload region
    # decodes from stream index 0x20. master_member adds the space marker
    # itself, so it receives the payload without the prefix.
    payload = decode(master, package[HEADER_LENGTH * 2:], HEADER_LENGTH)
    body = package[HEADER_LENGTH:HEADER_LENGTH * 2] + payload
    described = describe_container(body)
    candidate = master_member(payload)
    member = next(member for member in described['members']
                  if member['name'].startswith('eg1840_mas_'))
    expect_version = candidate[0x20:0x2C]
    require(expect_version.startswith(b'Ver.'),
            'The update master lacks a version record')
    # The staging stream: digest area plus the decoded body.
    window_data = package[:HEADER_LENGTH] + body
    corrupted_body = bytearray(body)
    corrupted_body[member['offset'] + 0x100] ^= 1
    corrupted_window = package[:HEADER_LENGTH] + bytes(corrupted_body)
    record = dict(
        format=1, passed=False,
        window_base=hex(WINDOW),
        update_package_sha256=hashlib.sha256(package).hexdigest(),
        update_members=[member['name'] for member in described['members']],
        update_master_sha256=hashlib.sha256(candidate).hexdigest(),
        update_master_version=expect_version.decode('ascii'),
        firmware_sha256={'master': analyze_eg(master, 'master')['sha256']},
        controller_sha256=CONTROLLER_SHA256,
        firmware_modified=False, runtime_state_written=False,
        window_supplied_by_host=True, window_is_firmware_selected=False,
        harvest_update_explicit=True, native_authentication_verified=False,
        native_programming_verified=False,
        cases=[])
    with tempfile.TemporaryDirectory(prefix='window-', dir=ROOT / '.local') as folder:
        work = Path(folder)
        record['cases'].append(run_case(
            args, work, 'valid', window_data, expect_version, True))
        record['cases'].append(run_case(
            args, work, 'corrupted', corrupted_window, STOCK_VERSION, False))
    record['passed'] = all(case.get('matches_expectation')
                           for case in record['cases'])
    args.destination.mkdir(parents=True, exist_ok=True)
    (args.destination / 'report.json').write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(('PASS ' if record['passed'] else 'FAIL ') +
          'update window harvest', flush=True)
    require(record['passed'], 'Update window harvest failed')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--slave', required=True, type=Path)
    parser.add_argument('--controller', required=True, type=Path)
    parser.add_argument('--update-package', required=True, type=Path,
                        help='Encoded stock update package for the window')
    parser.add_argument('--destination', required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments)


if __name__ == '__main__':
    main()
