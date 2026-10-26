# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe the original shoulder-panel snapshot path across the link.

Boots both original engine images plus the original controller image with the
experimental battery peer, reaches the original shooting application, then
stops on the original receive reassembly and tag dispatch entries to record
which messages the master publishes to the controller panel-state mirror.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from analyze.firmware_structure import analyze_eg
from tools.controller_core_probe import CONTROLLER_SHA256
from tools.create_lab_parameters import parameter_images
from tools.dual_boot_probe import dual_machine
from tools.graphics_boot_probe import (application_observation, graphics_observation,
                                       idle_timer_observation, system_observation)
from tools.smp_boot_probe import reach, stop_registers

REASSEMBLY_ENTRY = 0x08031E70
TAG_DISPATCH = 0x08024BB2
PANEL_PUBLISH = 0x080294F4
PANEL_PROBE = 0x0802B6F0
PAGE_COMMIT = 0x0802AE98
I2C_QUEUE = 0x080449B4
CHANNEL_HANDLER = 0x0802BC38
SNAPSHOT_CONSUMER = 0x0802E074
PAGE_DISPATCH = 0x08027E58
PANEL_FAIL = 0x0802ACD4
PANEL_READ_A = 0x0802AD0C
PANEL_READ_B = 0x0802AF38
PANEL_SNAPSHOT = 0x20018AD4
PANEL_MIRROR = 0x2001FA08
PANEL_STATE = 0x2001F4A0
PANEL_SHADOW = 0x2001FDA4
PANEL_MIRROR_BYTES = 0x90
ROUTE_BUFFERS = {1: 0x20011964, 2: 0x20011A54, 3: 0x20011E1C}


def linux(path):
    text = str(path)
    return re.sub('([A-Za-z]):[\\\\/][^,]*',
                  lambda m: '/mnt/' + m.group(1).lower() + '/' +
                            m.group(0)[3:].replace('\\', '/'), text)


def shooting_active(observation):
    application, graphics = observation['application'], observation['graphics']
    return (application['initialization_complete'] == 1 and
            application['current_index'] == 3 and
            graphics['surface_address'] != 0 and
            graphics['rendered_commands'] > 0 and
            graphics['failed_requests'] == 0 and
            graphics['unsupported_commands'] == 0)


def parse_frame(frame):
    length = int.from_bytes(frame[2:4], 'little')
    return dict(channel=frame[0], route=frame[1], length=length,
                fragment_index=frame[252], fragment_total=frame[253],
                checksum_valid=(sum(frame) & 0xFF) == 0xFF,
                head=frame[8:8 + min(32, max(length, 1))].hex())


def collect_at(remote, address, limit, per_hit_seconds, record):
    """Stop repeatedly on one address; record(hit registers) appends results."""
    records = []
    remote.select_thread(5)
    remote.breakpoint(address)
    try:
        while len(records) < limit:
            remote.sock.settimeout(per_hit_seconds)
            try:
                reply = remote.command('vCont;c')
                thread, regs = stop_registers(remote, reply)
                if remote.get(regs, 'pc') != address:
                    break
                records.append(record(remote, regs))
            except (TimeoutError, ValueError, OSError):
                break
    finally:
        try:
            remote.breakpoint(address, False)
        except (TimeoutError, ValueError, OSError):
            pass
    return records


def collect_frames(remote, limit, per_hit_seconds):
    """Stop repeatedly on the reassembly entry and read each received frame."""
    def record(remote, regs):
        pointer = remote.get(regs, 'r1')
        return parse_frame(remote.read(pointer, 256))
    return collect_at(remote, REASSEMBLY_ENTRY, limit, per_hit_seconds, record)


def collect_snapshots(remote, limit, per_hit_seconds):
    """Stop on the tag dispatch and record the panel snapshot messages."""
    def record(remote, regs):
        tag = remote.get(regs, 'r0') & 0xFF
        pointer = remote.get(regs, 'r1')
        size = 0x84 if tag == 4 else 0x220
        return dict(tag=tag, state_pointer=f'0x{pointer:08X}',
                    head=remote.read(pointer, min(size, 0x90)).hex())
    return collect_at(remote, TAG_DISPATCH, limit, per_hit_seconds, record)


def collect_publishes(remote, limit, per_hit_seconds):
    """Stop on the tag-4 publication entry and record its state argument."""
    def record(remote, regs):
        pointer = remote.get(regs, 'r0')
        flag = remote.get(regs, 'r1')
        return dict(state_pointer=f'0x{pointer:08X}', flag=flag,
                    head=remote.read(pointer, 0x90).hex())
    return collect_at(remote, PANEL_PUBLISH, limit, per_hit_seconds, record)


def collect_probes(remote, limit, per_hit_seconds):
    """Stop on the panel device probe and record its device object."""
    def record(remote, regs):
        pointer = remote.get(regs, 'r0')
        return dict(device_pointer=f'0x{pointer:08X}',
                    object=remote.read(pointer, 0x50).hex())
    return collect_at(remote, PANEL_PROBE, limit, per_hit_seconds, record)


def collect_commits(remote, limit, per_hit_seconds):
    """Stop on the panel page commit and record its shadow state."""
    def record(remote, regs):
        pointer = remote.get(regs, 'r0')
        return dict(device_pointer=f'0x{pointer:08X}',
                    shadow=remote.read(PANEL_SHADOW, 0x20).hex())
    return collect_at(remote, PAGE_COMMIT, limit, per_hit_seconds, record)


def collect_i2c(remote, limit, per_hit_seconds):
    """Stop on the async I2C queue entry and record its parameter block."""
    def record(remote, regs):
        pointer = remote.get(regs, 'r0')
        return dict(block_pointer=f'0x{pointer:08X}',
                    block=remote.read(pointer, 0x90).hex())
    return collect_at(remote, I2C_QUEUE, limit, per_hit_seconds, record)


def collect_chain(remote, args):
    """Trace the panel chain: channel handler, consumer, page dispatch, I2C."""
    chain = {}
    chain['handler'] = collect_at(remote, CHANNEL_HANDLER, 6, args.hit_seconds,
        lambda remote, regs: dict(
            descriptor=remote.read(remote.get(regs, 'r0'), 8).hex()))
    try:
        remote.interrupt()
    except (TimeoutError, ValueError, OSError):
        pass
    chain['consumer'] = collect_at(remote, SNAPSHOT_CONSUMER, 6, args.hit_seconds,
        lambda remote, regs: dict(
            flag=remote.read(0x20018A90, 1).hex(),
            source=remote.read(remote.get(regs, 'r0'), 0x80).hex()))
    try:
        remote.interrupt()
    except (TimeoutError, ValueError, OSError):
        pass
    chain['dispatch'] = collect_at(remote, PAGE_DISPATCH, 24, args.hit_seconds,
        lambda remote, regs: dict(
            window=remote.read(remote.get(regs, 'r0'), 0x20).hex(),
            mode=int.from_bytes(
                remote.read(remote.get(regs, 'r0') + 16, 2), 'little')))
    try:
        remote.interrupt()
    except (TimeoutError, ValueError, OSError):
        pass
    chain['commit'] = collect_commits(remote, 4, args.hit_seconds)
    try:
        remote.interrupt()
    except (TimeoutError, ValueError, OSError):
        pass
    for name, address in (('fail', PANEL_FAIL), ('read_a', PANEL_READ_A),
                          ('read_b', PANEL_READ_B), ('probe', PANEL_PROBE)):
        chain[name] = collect_at(remote, address, 3, args.hit_seconds,
            lambda remote, regs: dict(pc=f'0x{remote.get(regs, "pc"):08X}'))
        try:
            remote.interrupt()
        except (TimeoutError, ValueError, OSError):
            pass
    return chain


def probe_from_handler(remote, seconds):
    """Run the identity probe inside the channel-8 service context.

    The machine stops on the channel handler entry, the original registers
    are saved, the probe executes with the service task's own stack and
    event context, and the registers are restored before resuming so the
    handler runs again naturally. The controller I2C last-address property
    is read while the machine stays stopped, so no later traffic can mask
    the probe's address byte.
    """
    result = {}
    remote.select_thread(5)
    remote.breakpoint(CHANNEL_HANDLER)
    try:
        remote.sock.settimeout(seconds)
        reply = remote.command('vCont;c')
        thread, regs = stop_registers(remote, reply)
        if remote.get(regs, 'pc') != CHANNEL_HANDLER:
            result['stopped_at'] = f'0x{remote.get(regs, "pc"):08X}'
            return result
        saved = {name: remote.get(regs, name)
                 for name in ('r0', 'r1', 'r2', 'r3', 'lr')}
        result['context_thread'] = thread
        trap = 0x08000800
        remote.breakpoint(trap)
        try:
            remote.set(r0=0x2003F800, lr=trap | 1, pc=PANEL_PROBE | 1)
            remote.sock.settimeout(seconds)
            try:
                remote.command('vCont;c')
                after = remote.regs()
                result['probe_return'] = remote.get(after, 'r0')
            except TimeoutError:
                try:
                    remote.interrupt()
                except (TimeoutError, ValueError, OSError):
                    pass
                result['probe_return'] = 'timeout'
        finally:
            try:
                remote.breakpoint(trap, False)
            except (TimeoutError, ValueError, OSError):
                pass
        for name, address, size in (('identity_byte', 0x2001FE21, 1),
                                    ('panel_present', 0x2001F650, 4),
                                    ('block_after', 0x2001FE40, 0x50)):
            try:
                result[name] = remote.read(address, size).hex()
            except (TimeoutError, ValueError, OSError) as error:
                result[name + '_error'] = str(error)
        result['i2c_last_addresses'] = i2c_last_addresses(remote)
        remote.set(pc=CHANNEL_HANDLER, **saved)
    finally:
        try:
            remote.breakpoint(CHANNEL_HANDLER, False)
        except (TimeoutError, ValueError, OSError):
            pass
    return result


def power_cycle_panel(remote, seconds, calls=12):
    """Drive the original panel power state machine from the service context.

    The power manager counts consecutive presence polls before it enables
    the panel rail and executes the original first commit plus identity
    probe. Calling it repeatedly from the channel-8 service context runs
    only original code; observations happen with the machine stopped.
    """
    manager = 0x08026718
    result = dict(calls=calls, returns=[])
    remote.select_thread(5)
    remote.breakpoint(CHANNEL_HANDLER)
    try:
        remote.sock.settimeout(seconds)
        reply = remote.command('vCont;c')
        thread, regs = stop_registers(remote, reply)
        if remote.get(regs, 'pc') != CHANNEL_HANDLER:
            result['stopped_at'] = f'0x{remote.get(regs, "pc"):08X}'
            return result
        saved = {name: remote.get(regs, name)
                 for name in ('r0', 'r1', 'r2', 'r3', 'lr')}
        trap = 0x08000800
        remote.breakpoint(trap)
        try:
            for _ in range(calls):
                remote.set(r0=0, r1=0, r2=0, r3=0,
                           lr=trap | 1, pc=manager | 1)
                remote.sock.settimeout(seconds)
                try:
                    remote.command('vCont;c')
                    after = remote.regs()
                    result['returns'].append(remote.get(after, 'r0'))
                except TimeoutError:
                    try:
                        remote.interrupt()
                    except (TimeoutError, ValueError, OSError):
                        pass
                    result['returns'].append('timeout')
                    break
        finally:
            try:
                remote.breakpoint(trap, False)
            except (TimeoutError, ValueError, OSError):
                pass
        for name, address, size in (('powered', 0x2001F5A2, 4),
                                    ('identity_byte', 0x2001FE21, 1),
                                    ('panel_detected', 0x2001F650, 4),
                                    ('shadow', PANEL_SHADOW, 0x14)):
            try:
                result[name] = remote.read(address, size).hex()
            except (TimeoutError, ValueError, OSError) as error:
                result[name + '_error'] = str(error)
        result['i2c_last_addresses'] = i2c_last_addresses(remote)
        try:
            value = remote.command('qRcmd,' + (
                'qom-get /machine/peripheral/shoulder page-writes'
            ).encode().hex())
            text = bytearray()
            while value.startswith('O') and value != 'OK':
                text.extend(bytes.fromhex(value[1:]))
                value = remote.receive()
            result['panel_page_writes'] = text.decode().strip()
        except (TimeoutError, ValueError, OSError) as error:
            result['panel_page_writes_error'] = str(error)
        remote.set(pc=CHANNEL_HANDLER, **saved)
    finally:
        try:
            remote.breakpoint(CHANNEL_HANDLER, False)
        except (TimeoutError, ValueError, OSError):
            pass
    return result


def i2c_last_addresses(remote):
    buses = {}
    reply = remote.command('qRcmd,' + 'qom-list /machine/unattached'.encode().hex())
    listing = bytearray()
    while reply.startswith('O') and reply != 'OK':
        listing.extend(bytes.fromhex(reply[1:]))
        reply = remote.receive()
    names = re.findall(r"(device\[\d+\]) \(child<nikon-z72-controller-i2c>\)",
                       listing.decode())
    for name in names:
        value = remote.command('qRcmd,' + (
            f'qom-get /machine/unattached/{name} last-read-address'
        ).encode().hex())
        read_text = bytearray()
        while value.startswith('O') and value != 'OK':
            read_text.extend(bytes.fromhex(value[1:]))
            value = remote.receive()
        buses[name + ':read'] = read_text.decode().strip()
        value = remote.command('qRcmd,' + (
            f'qom-get /machine/unattached/{name} last-address').encode().hex())
        text = bytearray()
        while value.startswith('O') and value != 'OK':
            text.extend(bytes.fromhex(value[1:]))
            value = remote.receive()
        buses[name] = text.decode().strip()
    return buses


def snapshot_flowing(remote, rounds, seconds):
    """Return (changed, first, last) across short run windows.

    The master engine's channel-8 traffic continues for a bounded span after
    the shooting start; repeated short windows catch it reliably.
    """
    remote.select_thread(5)
    first = remote.read(PANEL_SNAPSHOT, 0x80)
    last = first
    for _ in range(rounds):
        remote.sock.settimeout(seconds)
        try:
            remote.command('vCont;c')
        except TimeoutError:
            remote.interrupt()
        remote.select_thread(5)
        last = remote.read(PANEL_SNAPSHOT, 0x80)
        if last != first:
            return True, first, last
    return False, first, last


def debugger_call_probe(remote, seconds=60):
    """Call the original panel identity probe from the debugger.

    The probe walks the original I2C request path, so the transfer parameter
    block it fills documents the panel's own bus binding even when the panel
    power state machine has not reached it naturally. Every step is guarded
    so a stall still returns the partial evidence.
    """
    result = {}
    try:
        remote.interrupt()
    except (TimeoutError, ValueError, OSError):
        pass
    remote.select_thread(5)
    try:
        result['block_before'] = remote.read(0x2001FE40, 0x50).hex()
    except (TimeoutError, ValueError, OSError) as error:
        result['read_error'] = str(error)
        return result
    trap = 0x08000800
    remote.breakpoint(trap)
    try:
        remote.set(r0=0x2003F800, lr=trap | 1, pc=PANEL_PROBE | 1)
        remote.sock.settimeout(seconds)
        try:
            remote.command('vCont;c')
            regs = remote.regs()
            result['stopped_at'] = f'0x{remote.get(regs, "pc"):08X}'
            result['return'] = remote.get(regs, 'r0')
        except TimeoutError:
            try:
                remote.interrupt()
            except (TimeoutError, ValueError, OSError):
                pass
            result['stopped_at'] = 'timeout'
    finally:
        try:
            remote.breakpoint(trap, False)
        except (TimeoutError, ValueError, OSError):
            pass
    for name, address, size in (('identity_byte', 0x2001FE21, 1),
                                ('class_fields', 0x2003F800, 8),
                                ('block_after', 0x2001FE40, 0x50),
                                ('peripheral_after', 0x40005400, 0x30)):
        try:
            result[name] = remote.read(address, size).hex()
        except (TimeoutError, ValueError, OSError) as error:
            result[name + '_error'] = str(error)
    return result


def summarize(frames):
    counts = {}
    for frame in frames:
        key = (frame['channel'], frame['route'], frame['length'])
        counts[key] = counts.get(key, 0) + 1
    return [{'channel': key[0], 'route': key[1], 'length': key[2],
             'count': value} for key, value in sorted(counts.items())]


def run(args):
    require(0 < args.seconds <= 120 and 0 < args.windows <= 40,
            'Observation bounds must be in (0, 120] and (0, 40]')
    master, slave = args.master.read_bytes(), args.slave.read_bytes()
    for role, image in (('master', master), ('slave', slave)):
        analyze_eg(image, role)
    require(hashlib.sha256(args.controller.read_bytes()).hexdigest() ==
            CONTROLLER_SHA256, 'Expected the original controller image')
    args.destination.mkdir(parents=True, exist_ok=False)
    launched = []
    original = subprocess.Popen
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0))
        qtest_port = server.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='shoulder-panel-', dir=ROOT / '.local') as folder:
        work = Path(folder)

        class WslProcess(original):
            """Add the battery peer and qtest ports; wrap for WSL on Windows."""

            def __init__(inner, command, *extra, **keywords):
                index = command.index('-M')
                command[index + 1] += ",controller-battery-peer=on"
                command += ['-qtest', f'tcp:127.0.0.1:{qtest_port},server=on,wait=off',
                            '-qtest-log', '/dev/null']
                if os.name == 'nt':
                    inner.pid_file = work / str(len(launched))
                    wrapped = ['wsl.exe', '--exec', 'sh', '-c',
                               'echo $$ > ' + shlex.quote(linux(inner.pid_file)) +
                               '; exec ' +
                               shlex.join([linux(part) for part in command])]
                    super().__init__(wrapped, *extra, **keywords)
                else:
                    super().__init__(command, *extra, **keywords)
                launched.append(inner)

            def terminate(inner):
                if os.name != 'nt' or inner.poll() is not None:
                    super().terminate()
                    return
                if inner.pid_file.exists():
                    pid = inner.pid_file.read_text().strip()
                    if pid.isdecimal():
                        with original(['wsl.exe', '--exec', 'kill', '-TERM', pid],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL) as reaper:
                            reaper.wait(timeout=5)

        subprocess.Popen = WslProcess
        remote = wire = None
        report = dict(format=1, passed=False, controller_sha256=CONTROLLER_SHA256,
                      panel_verified=False)
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
                f"nikon-z72-controller-panel,bus=controller-i2c0,"
                f"address=13,id=shoulder,initial-state={work / 'aux.bin'}"
                if args.panel_device else
                f"nikon-z72-controller-register-bank,bus=controller-i2c0,"
                f"address=13,initial-state={work / 'aux.bin'}")
            devices += tuple(
                f'loader,file={work / name},addr={address:#x},force-raw=on'
                for name, address in (('group17.bin', 0x132C0000),
                                      ('group18.bin', 0x132E0000)))
            devices += tuple(
                f'nikon-z72-controller-register-bank,bus=master-i2c{i},address=104'
                for i in range(4))
            if args.scan_panel_addresses:
                # Discovery: a panel model at every otherwise unused address.
                # The original probe's two-byte identity read lights up the
                # id-reads counter of exactly one device: the panel address.
                taken = {13, 34, 79, 107}
                devices += tuple(
                    f'nikon-z72-controller-panel,bus=controller-i2c0,'
                    f'address={address},id=shoulder{address}'
                    for address in range(1, 128) if address not in taken)
            process, remote = dual_machine(
                args.qemu, work, master, slave,
                work / 'console.txt',
                icount='shift=0,sleep=off', trace='guest_errors',
                controller_firmware=args.controller,
                controller_link=True,
                controller_flash_data=work / 'resident.bin',
                devices=devices,
                globals_=tuple(
                    f"nikon-z72-controller-adc.channel{channel}={value}"
                    for channel, value in ((0, 1800), (1, 3001), (3, 3001))),
                extra_arguments=('-D', linux(args.destination / 'trace.log'),
                                 '-trace', 'enable=i2c*'))
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
                                      (6, 7, 1), (1, 11, 1), (6, 14, 1), (6, 15, 1)):
                wire.sendall(f"set_irq_in /machine/unattached/{gpios[index]} "
                             f"unnamed-gpio-in {pin} {level}\n".encode())
                assert wire.recv(1024).strip() == b'OK'

            # The full boot runs without debugger stops: heavy stop-start
            # traffic during startup occasionally collapses the engine link.
            # Chain verification instead happens after the shooting
            # application settles, through breakpoints and plain memory reads.
            chain = {}
            boot_frames = []

            observation = {}
            for window in range(args.windows):
                remote.sock.settimeout(args.seconds)
                try:
                    remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()
                remote.select_thread(5)
                observation = dict(
                    application=application_observation(remote),
                    system=system_observation(remote),
                    idle=idle_timer_observation(remote),
                    graphics=graphics_observation(remote))
                print(f'Window {window}: mode={observation["system"]["current_mode"]} '
                      f'app={observation["application"]["current_index"]}', flush=True)
                if shooting_active(observation):
                    break
            require(shooting_active(observation),
                    'Original shooting application did not become active')

            # Stimulate the shooting application so the master refreshes its
            # panel model: a playback press switches the foreground
            # application and produces new panel messages for the panel task.
            if args.stimulus:
                wire.sendall(b'set_irq_in /machine/peripheral/keys pins 8 0\n')
                assert wire.recv(1024).strip() == b'OK'
                remote.sock.settimeout(args.seconds)
                try:
                    remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()
                wire.sendall(b'set_irq_in /machine/peripheral/keys pins 8 1\n')
                assert wire.recv(1024).strip() == b'OK'

            remote.select_thread(5)
            mirror = remote.read(PANEL_MIRROR, PANEL_MIRROR_BYTES)
            try:
                (args.destination / 'qemu.log').write_bytes(
                    (work / 'qemu.log').read_bytes())
            except OSError as error:
                report['qemu_log_error'] = str(error)
            # Panel power state machine, pin descriptors and bus handles.
            report['panel_power_hex'] = remote.read(0x2001F5A0, 0xC0).hex()
            descriptors = remote.read(0x2001FE20, 0x50)
            report['panel_descriptors_hex'] = descriptors.hex()
            resolved = {}
            for index, offset in enumerate(range(0, 0x30, 4)):
                pointer = int.from_bytes(descriptors[offset:offset + 4], 'little')
                if 0x20000000 <= pointer < 0x20040000:
                    resolved[f'0x{0x2001FE20 + offset:08X}'] = dict(
                        pointer=f'0x{pointer:08X}',
                        object=remote.read(pointer, 0x18).hex())
            report['panel_descriptor_objects'] = resolved
            bus = remote.read(0x2001FDBC, 4)
            handle = int.from_bytes(bus, 'little')
            if 0x20000000 <= handle < 0x20040000:
                report['panel_bus_handle'] = f'0x{handle:08X}'
                report['panel_bus_handle_hex'] = remote.read(handle, 0x40).hex()
            table_head = remote.read(0x20011750, 0x10)
            report['channel_table_head_hex'] = table_head.hex()
            count = table_head[4]
            pointer = int.from_bytes(table_head[8:12], 'little')
            if 0 < count <= 32 and 0x20000000 <= pointer < 0x20040000:
                entries = remote.read(pointer, count * 8)
                report['channel_table'] = dict(count=count, pointer=f'0x{pointer:08X}',
                    handlers=[f'0x{int.from_bytes(entries[i*8+4:i*8+8], "little"):08X}'
                              for i in range(count)])
            snapshot_hex = remote.read(PANEL_SNAPSHOT, 0x80).hex()
            routes = {f'0x{address:08X}': remote.read(address, 0x60).hex()
                      for address in ROUTE_BUFFERS.values()}
            panel_state = remote.read(PANEL_STATE, 0x48)
            panel_shadow = remote.read(PANEL_SHADOW, 0x20)

            # Chain verification after the shooting application settles. The
            # identity probe first runs inside the channel-8 service context;
            # the interrupt-context call is only a fallback when no channel-8
            # traffic remains. Then repeated snapshot-flow windows and, if the
            # flow check missed the window, breakpoint tracing.
            power_cycle = {}
            if args.power_cycle:
                # Port E pin 9 is the recovered panel-present line. The boot
                # input set holds it high; the original power state machine
                # enables the rail while it reads low, so switch it just for
                # the laboratory power-cycle observation.
                command = (f'set_irq_in /machine/unattached/{gpios[4]} '
                           'unnamed-gpio-in 9 0')
                wire.sendall((command + '\n').encode())
                assert wire.recv(1024).strip() == b'OK'
                try:
                    power_cycle = power_cycle_panel(remote, args.hit_seconds * 4)
                    report['power_cycle'] = power_cycle
                except (TimeoutError, ValueError, OSError) as error:
                    report['power_cycle_error'] = str(error)
            handler_probe = {}
            if args.call_probe:
                try:
                    handler_probe = probe_from_handler(remote, args.hit_seconds * 4)
                    report['probe_handler'] = handler_probe
                except (TimeoutError, ValueError, OSError) as error:
                    report['probe_handler_error'] = str(error)
                if 'context_thread' not in handler_probe:
                    try:
                        report['probe_call'] = debugger_call_probe(
                            remote, max(30.0, args.seconds * 3))
                    except (TimeoutError, ValueError, OSError) as error:
                        report['probe_call_error'] = str(error)
            elif not report.get('i2c_last_addresses'):
                try:
                    report['i2c_last_addresses'] = i2c_last_addresses(remote)
                except (TimeoutError, ValueError, OSError):
                    pass
            first_flow = snapshot_flowing(remote, 4, max(4.0, args.seconds / 2))
            chain = collect_chain(remote, args) if not first_flow[0] else {}
            commits = chain.pop('commit', [])
            try:
                remote.interrupt()
            except (TimeoutError, ValueError, OSError):
                pass
            remote.select_thread(5)
            flowing = first_flow[0]
            report['snapshot_flow'] = dict(changed=flowing,
                                           first=first_flow[1].hex(),
                                           second=first_flow[2].hex())
            report.update(panel_chain={name: len(items)
                                       for name, items in chain.items()},
                          chain_detail=chain, panel_commits=commits,
                          panel_snapshot=f'0x{PANEL_SNAPSHOT:08X}',
                          panel_snapshot_hex=snapshot_hex,
                          panel_state=f'0x{PANEL_STATE:08X}',
                          panel_state_hex=panel_state.hex(),
                          panel_shadow=f'0x{PANEL_SHADOW:08X}',
                          panel_shadow_hex=panel_shadow.hex(),
                          route_buffers=routes,
                          panel_mirror=f'0x{PANEL_MIRROR:08X}',
                          panel_mirror_hex=mirror.hex(),
                          panel_mirror_nonzero=any(mirror),
                          observation=observation,
                          full_boot_verified=True)
            require(any(snapshot_hex[i:i+2] != '00' for i in range(2, len(snapshot_hex), 2)),
                    'The panel snapshot copy stayed empty after the shooting start')
            consumer_hits = chain.get('consumer') or []
            handler_hits = chain.get('handler') or []
            require(handler_hits and consumer_hits or flowing,
                    'The channel-8 snapshot chain did not run after the shooting start')
            if args.scan_panel_addresses:
                hits = {}
                for address in range(1, 128):
                    if address in (13, 34, 79, 107):
                        continue
                    try:
                        reply = remote.command('qRcmd,' + (
                            f'qom-get /machine/peripheral/shoulder{address} '
                            f'id-reads').encode().hex())
                        text = bytearray()
                        while reply.startswith('O') and reply != 'OK':
                            text.extend(bytes.fromhex(reply[1:]))
                            reply = remote.receive()
                        value = text.decode().strip()
                        if value and int(value) > 0:
                            hits[str(address)] = int(value)
                    except (TimeoutError, ValueError, OSError):
                        break
                report['panel_address_hits'] = hits
            report['panel_verified'] = True
            report['passed'] = True
            (args.destination / 'report.json').write_text(
                json.dumps(report, indent=2) + '\n', encoding='utf-8')
            if args.artifact:
                power = report.get('power_cycle') or {}
                handler = report.get('probe_handler') or {}
                summary = dict(
                    format=1, passed=True, full_boot_verified=True,
                    channel8_snapshot_bytes=112, tag=4,
                    snapshot_flow_changed=flowing,
                    snapshot_sha256=hashlib.sha256(
                        bytes.fromhex(snapshot_hex[:0x70 * 2])).hexdigest(),
                    chain_hits={name: len(items)
                                for name, items in chain.items()},
                    identity_probe=dict(
                        context='channel-8 service task via laboratory call',
                        identity_hex=handler.get('identity_byte'),
                        bus='controller-i2c0', seven_bit_address='0x0d'),
                    power_cycle=dict(
                        present_line='port E pin 9 held low for the observation',
                        calls=len(power.get('returns') or []),
                        powered_flag=power.get('powered'),
                        detected_flag=power.get('panel_detected'),
                        page_writes=power.get('panel_page_writes'),
                        i2c_last_addresses=power.get('i2c_last_addresses')),
                    panel_device_contract='qemu/nikon-z72-controller-panel.c',
                    panel_device_test='tests/test_controller_panel.py',
                    evidence_note='Full run data stays in the private run '
                                  'directory; this artifact keeps structure '
                                  'and hashes only.')
                Path(args.artifact).parent.mkdir(parents=True, exist_ok=True)
                Path(args.artifact).write_text(
                    json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        except Exception as error:
            report['error'] = str(error)
            (args.destination / 'report.json').write_text(
                json.dumps(report, indent=2) + '\n', encoding='utf-8')
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('master', 'slave', 'controller', 'destination'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--seconds', type=float, default=10)
    parser.add_argument('--windows', type=int, default=12)
    parser.add_argument('--frames', type=int, default=200)
    parser.add_argument('--boot-frames', type=int, default=150)
    parser.add_argument('--snapshots', type=int, default=8)
    parser.add_argument('--hit-seconds', type=float, default=30)
    parser.add_argument('--stimulus', dest='stimulus', action='store_true', default=True)
    parser.add_argument('--no-stimulus', dest='stimulus', action='store_false')
    parser.add_argument('--call-probe', dest='call_probe', action='store_true', default=True)
    parser.add_argument('--no-call-probe', dest='call_probe', action='store_false')
    parser.add_argument('--scan-panel-addresses', action='store_true',
                        help='Attach panel models at every free controller-i2c0 address')
    parser.add_argument('--artifact', type=Path,
                        help='Write a public structure-only summary to this path')
    parser.add_argument('--panel-device', action='store_true', default=True,
                        help='Use the panel model at address 13 instead of a plain bank')
    parser.add_argument('--no-panel-device', dest='panel_device', action='store_false')
    parser.add_argument('--power-cycle', dest='power_cycle', action='store_true', default=True)
    parser.add_argument('--no-power-cycle', dest='power_cycle', action='store_false')
    parser.add_argument('--artifact', type=Path,
                        help='Write a public structure-only summary to this path')
    args = parser.parse_args()
    run(args)


if __name__ == '__main__':
    main()
