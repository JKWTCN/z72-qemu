# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe the runtime registration of the card slot driver table.

A write watchpoint on the slot driver table pointer (0xB18105BC, zero in
initialized data) stops the machine when the card service module registers
its slot drivers. The dump records the table address, the per-slot driver
objects and every function pointer resolved to a master file offset, so
the driver entry points can be analyzed for their hardware register
window without guessing. The probe reads state only; it changes no
firmware bytes.
"""
import argparse
import json
import os
from pathlib import Path
import random
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
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from tools.controller_core_probe import CONTROLLER_SHA256
from tools.create_lab_parameters import parameter_images, resource_header_image
from tools.dual_boot_probe import dual_machine

SLOT_TABLE = 0xB18105BC
SYNC_WAIT = 0x102d949e


def linux(path):
    text = str(path)
    return re.sub(r'([A-Za-z]):[\\/][^,]*',
                  lambda m: '/mnt/' + m[1].lower() + '/' +
                            m[0][3:].replace('\\', '/'), text)


def word(remote, address):
    remote.select_thread(1)
    return struct.unpack('<I', remote.read(address, 4))[0]


def dump_table(remote, table, report):
    record = dict(table=hex(table))
    slots = []
    for slot in range(2):
        base = table + slot * 0x38
        words = struct.unpack('<14I', remote.read(base, 0x38))
        slots.append(dict(slot=slot, words=[hex(value) for value in words],
                          code_offsets=[hex(value - BASE)
                                        if BASE < value < BASE + 0x4000000 else None
                                        for value in words]))
    record['slots'] = slots
    report['registrations'].append(record)
    return record


def run(args, observe=None):
    master, slave = args.master.read_bytes(), args.slave.read_bytes()
    launched = []
    original = subprocess.Popen
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
        """Add the battery peer and qtest port; wrap for WSL on Windows."""

        def __init__(self, command, *extra, **keywords):
            index = command.index('-M')
            command[index + 1] += ",controller-battery-peer=on"
            command += ['-qtest', f'tcp:127.0.0.1:{qtest_port},server=on,wait=off',
                        '-qtest-log', '/dev/null']
            if os.name == 'nt':
                self.pid_file = args.work / str(time.monotonic_ns())
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
    report = dict(format=1, passed=False, slot_table=hex(SLOT_TABLE),
                  firmware_sha256={'master': analyze_eg(master, 'master')['sha256']},
                  controller_sha256=CONTROLLER_SHA256,
                  firmware_modified=False, runtime_state_written=False,
                  registrations=[], errors=[])
    try:
        work = args.work
        work.mkdir(parents=True, exist_ok=True)
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
        globals_ = ('nikon-z72-boot-config.frame-sync=on',)
        extra_arguments = ()
        if args.sd_card_image is not None:
            globals_ += ('nikon-z72-boot-config.sd-host=on',)
            extra_arguments = ('-drive',
                f'if=none,id=research-card,file={args.sd_card_image.resolve()},format=raw,snapshot=on')
            devices += (f'sd-card,drive=research-card,bus=/z72-sd-{args.sd_card_engine}/sd-bus',)
            report['sd_card_engine'] = args.sd_card_engine
            report['sd_card_writes_use_overlay'] = True
        process, remote = dual_machine(
            args.qemu, work, master, slave, work / 'console.txt',
            icount='shift=0,sleep=off', trace='guest_errors',
            controller_firmware=args.controller, controller_link=True,
            controller_flash_data=work / 'resident.bin', devices=devices,
            globals_=globals_, extra_arguments=extra_arguments)
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

        # Watch the table pointer; each write stops the machine and the
        # current table state is recorded. Registrations may be partial.
        require(remote.command(f'Z2,{SLOT_TABLE:x},4') == 'OK',
                'Could not arm the slot table watchpoint')
        for registration in range(args.registrations):
            remote.sock.settimeout(args.window)
            try:
                response = remote.command('vCont;c')
            except TimeoutError:
                remote.interrupt()
                break
            match = re.search(r'thread:([0-9a-f]+)', response or '')
            if match is None:
                continue
            remote.select_thread(int(match[1], 16))
            registers = remote.regs()
            table = word(remote, SLOT_TABLE)
            record = dump_table(remote, table, report) if table else \
                dict(table='0')
            record['writer_thread'] = int(match[1], 16)
            record['writer_pc'] = hex(remote.get(registers, 'pc'))
            record['writer_lr'] = hex(remote.get(registers, 'lr'))
        require(remote.command(f'z2,{SLOT_TABLE:x},4') == 'OK',
                'Could not remove the slot table watchpoint')
        # After the last registration, run a settling window and dump again:
        # later initialization may fill more of the driver objects.
        remote.sock.settimeout(args.window)
        try:
            remote.command('vCont;c')
        except TimeoutError:
            remote.interrupt()
        table = word(remote, SLOT_TABLE)
        if table:
            report['settled'] = dump_table(remote, table, report)
            # Each slot object keeps runtime context pointers at +0x04 and
            # +0x0C; their fields include the hardware register window the
            # driver drives. Dump both contexts and list register-looking
            # words (the platform peripheral span).
            contexts = []
            for slot in range(2):
                base = table + slot * 0x38
                for index, name in ((4, 'primary'), (0x0C, 'secondary')):
                    pointer = word(remote, base + index)
                    if not 0x10000000 < pointer < 0xC0000000:
                        continue
                    words = struct.unpack(
                        '<24I', remote.read(pointer, 0x60))
                    contexts.append(dict(
                        slot=slot, name=name, address=hex(pointer),
                        words=[hex(value) for value in words],
                        register_like=[hex(value) for value in words
                                       if 0x20010000 <= value <= 0x2FFFFFFF]))
            report['contexts'] = contexts
        if args.sd_card_image is not None:
            report['engine_states'] = []
            for thread in (1, 2, 3, 4):
                remote.select_thread(thread)
                registers = remote.regs()
                report['engine_states'].append(dict(thread=thread,
                    pc=hex(remote.get(registers, 'pc')),
                    cpsr=hex(remote.get(registers, 'cpsr')),
                    faults={name: hex(remote.read_register(name)) for name in
                            ('DFAR_S', 'IFAR_S', 'DFSR_S', 'IFSR_S')}))
            report['engine_fault_free'] = all(
                int(state['faults'][name], 0) == 0
                for state in report['engine_states'] for name in ('DFSR_S', 'IFSR_S'))
            report['sd_host_registers'] = []
            for engine, thread in (('master', 1), ('slave', 3)):
                remote.select_thread(thread)
                registers = {}
                for address in (0x2B000010, 0x2B200000, 0x2B200024, 0x2B200058,
                                0x2A900004, 0x2A900098,
                                0x2A800010, 0x2A800014, 0x2A800064,
                                0x2A810024, 0x2A81002C, 0x2A810030):
                    try:
                        registers[hex(address)] = hex(struct.unpack(
                            '<I', remote.read(address, 4))[0])
                    except Exception as error:
                        registers[hex(address)] = dict(error=str(error))
                report['sd_host_registers'].append(dict(engine=engine, registers=registers))
            remote.select_thread(1)
            report['card_slot_enable_bytes'] = list(remote.read(0xB1808B50, 2))
            report['foreground_application_index'] = remote.read(0xB1811E50, 1)[0]
            report['observation_window_seconds'] = args.window
        if args.ram_dump is not None:
            # Snapshot the initialized runtime RAM for bounded execution
            # of the card worker chain outside the machine.
            target = str(args.ram_dump)
            if os.name == 'nt':
                target = linux(args.ram_dump)
            for base, size in ((0x10000000, 0x4000000),
                               (0xB1800000, 0x4800000),
                               (0x0, 0x100000)):
                reply = remote.command('qRcmd,' + (
                    f'memsave {base:#x} {size:#x} ' + json.dumps(
                        target + f'.{base:X}')
                ).encode().hex())
                while reply.startswith('O') and reply != 'OK':
                    reply = remote.receive()
                require(reply == 'OK', 'Runtime RAM snapshot failed')
            report['ram_dump'] = str(args.ram_dump)
        elif not args.registration_only:
            # The slot driver reads its enabled byte at 0xB1808B50 + slot.
            # Force slot 0 on, then trigger card consumers (playback and
            # menu open) and diff the platform peripheral span: the SD
            # command registers live in that span and a mount attempt
            # writes command words that stay visible in the RAM window.
            span_base, span_bytes = 0x20020000, 0x10000
            def read_span(base, size):
                words = {}
                for block in range(0, size, 0x100):
                    try:
                        data = remote.read(base + block, 0x100)
                        for step in range(0, 0x100, 4):
                            words[block + step] = struct.unpack_from(
                                '<I', data, step)[0]
                        continue
                    except Exception:
                        pass
                    for step in range(0, 0x100, 4):
                        try:
                            words[block + step] = struct.unpack_from(
                                '<I', remote.read(base + block + step, 4))[0]
                        except Exception:
                            continue
                return words
            remote.select_thread(1)
            before = read_span(span_base, span_bytes)
            remote.write(0xB1808B50, struct.pack('<I', 1))
            remote.sock.settimeout(4)
            try:
                remote.command('vCont;c')
            except TimeoutError:
                pass
            for pin in (8, 8, 9, 0):
                wire.sendall(f'set_irq_in /machine/peripheral/keys pins '
                             f'{pin} 0'.encode())
                assert wire.recv(1024).strip() == b'OK'
                time.sleep(4)
                wire.sendall(f'set_irq_in /machine/peripheral/keys pins '
                             f'{pin} 1'.encode())
                assert wire.recv(1024).strip() == b'OK'
                time.sleep(4)
            remote.interrupt()
            remote.select_thread(1)
            after = read_span(span_base, span_bytes)
            changes = []
            for offset, new_word in sorted(after.items()):
                old_word = before.get(offset)
                if old_word is not None and old_word != new_word:
                    changes.append(dict(address=hex(span_base + offset),
                                        before=hex(old_word),
                                        after=hex(new_word)))
            report['peripheral_words_readable'] = len(after)
            report['slot0_forced'] = True
            report['peripheral_span_changes'] = changes
        report['passed'] = bool(report['registrations'])
        if observe is not None:
            observe(remote, report)
    except Exception as error:
        report['passed'] = False
        import traceback
        report['errors'].append(f'{type(error).__name__}: {error}')
        report['traceback'] = traceback.format_exc()
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
        args.destination.mkdir(parents=True, exist_ok=True)
        (args.destination / 'report.json').write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str)
            + chr(10), encoding='utf-8')
    label = 'card slot table registrations' if observe is None else 'card slot and attached check'
    print(('PASS ' if report['passed'] else 'FAIL ') +
          f"{label}: {len(report['registrations'])}",
          flush=True)
    require(report['passed'], 'Card slot observation or attached check failed')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--slave', required=True, type=Path)
    parser.add_argument('--controller', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--registrations', type=int, default=4)
    parser.add_argument('--window', type=float, default=120.0)
    parser.add_argument('--ram-dump', type=Path,
                        help='Snapshot runtime RAM (0xB1800000, 14MB) and stop')
    parser.add_argument('--registration-only', action='store_true',
                        help='Observe registration without forcing slot state or sending keys')
    parser.add_argument('--sd-card-image', type=Path,
                        help='Attach a raw card image through the optional SD host, with an overlay')
    parser.add_argument('--sd-card-engine', choices=('master', 'slave'), default='slave',
                        help='Engine owning the attached card (default: slave)')
    parser.add_argument('--work', type=Path,
                        help='Persistent work directory (default: temporary)')
    arguments = parser.parse_args()
    if arguments.work is None:
        folder = tempfile.TemporaryDirectory(prefix='card-slot-',
                                             dir=ROOT / '.local')
        arguments.work = Path(folder.name)
        try:
            run(arguments)
        finally:
            folder.cleanup()
    else:
        arguments.work.mkdir(parents=True, exist_ok=True)
        run(arguments)


if __name__ == '__main__':
    main()
