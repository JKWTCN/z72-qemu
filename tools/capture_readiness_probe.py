# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe the recovered capture-readiness boundary after the input-path stage.

Analysis of the original firmware recovered the wait structure that keeps the
foreground in the live-view application without a display request: the capture
operation table, its sub-state dispatch and local resource bitmap. This probe runs
the combined machine with the documented experimental inputs and verifies each
recovered contract against original execution. It does not modify guest state.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import socket
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.dual_boot_probe import dual_machine, sample_cores
from tools.smp_boot_probe import stop_registers
from tools.graphics_boot_probe import (application_observation, graphics_observation,
                                       system_observation)
from tools.create_lab_parameters import parameter_images
from analyze.decode_z72 import require
from analyze.firmware_structure import analyze_eg

CALLBACK_TABLE = 0xB23F6FE4
OPERATION_14 = 14
OPERATION_14_CALLBACK = 0xB23F6FE4 + OPERATION_14 * 4
RECOVERED_CALLBACK = 0x10204D47
CONTROL_BLOCK = 0xB23F6A7C
READINESS_WORD = 0xB23F6848
STATE_MACHINE = 0x103E5190
RESOURCE_MARK = 0x10229DB0
STATE_TRANSITION = 0x103E7312
OPERATION_14_COMPLETION = 0x10247DEA
CAPTURE_RESOURCE = 0x3F
RESOURCE_BITMAP_CONTEXT = 0xB1869878
MASTER_DISPATCH_TABLE = 0xB2B5DF20
DISPATCH_ANCHOR = (237, 0x105165D5)
SLAVE_TASK_3F = (0xC19C9BCC, 0x100003F, 0x1006A7ED)
SLAVE_TASK_43 = (0xC16CD0B8, 0x1000043, 0x1012F8B9)
SLAVE_LEVEL_ONE = (0xC18B2948, 223, 0x10167EC0)
GPIO_LEVELS = ((2, 5, 0), (3, 13, 1), (4, 9, 1), (6, 7, 1), (1, 11, 1))
ADC_CHANNELS = ((0, 1800), (1, 3001), (3, 3001))


def reach_mode_two(remote, seconds):
    """Run original execution until the system reports live-view mode 2."""
    deadline = time.monotonic() + seconds
    remote.sock.settimeout(20)
    for attempt in range(24):
        state = None
        try:
            thread, regs = stop_registers(remote, remote.command('vCont;c'))
            require(thread in (1, 2), 'Unexpected engine stop thread')
            remote.breakpoint(remote.get(regs, 'pc'), False)
            remote.command('vCont;s:' + format(thread, 'x'))
        except TimeoutError:
            remote.interrupt()
        state = system_observation(remote)
        require(time.monotonic() < deadline, 'Original execution did not reach mode 2')
        if state['current_mode'] == 2:
            return state, attempt
    raise ValueError('Original execution did not settle in mode 2')


def loop_membership(remote, seconds):
    """Count stops at the recovered wait-loop sites over a bounded window."""
    points = {STATE_MACHINE: 'state-machine', RESOURCE_MARK: 'resource-mark',
              STATE_TRANSITION: 'state-transition', OPERATION_14_COMPLETION: 'completion'}
    for address in points:
        remote.breakpoint(address)
    counts = {name: 0 for name in points.values()}
    resources = []
    detail = []
    started = time.monotonic()
    deadline = started + seconds
    try:
        for _ in range(64):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            remote.sock.settimeout(remaining)
            thread, regs = stop_registers(remote, remote.command('vCont;c'))
            pc = remote.get(regs, 'pc')
            name = points.get(pc, hex(pc))
            counts[name] = counts.get(name, 0) + 1
            if pc == RESOURCE_MARK:
                r0 = remote.get(regs, 'r0')
                if r0 == CAPTURE_RESOURCE:
                    counts['capture-resource-mark'] = counts.get('capture-resource-mark', 0) + 1
                    resources.append(dict(resource=r0, lr=hex(remote.get(regs, 'lr'))))
            detail.append(dict(site=name, thread=thread, pc=hex(pc),
                               lr=hex(remote.get(regs, 'lr'))))
            remote.breakpoint(pc, False)
            remote.command('vCont;s:' + format(thread, 'x'))
            remote.breakpoint(pc)
    except TimeoutError:
        remote.interrupt()
    finally:
        for address in points:
            remote.breakpoint(address, False)
    return counts, resources, detail, time.monotonic() - started


def local_wait_observation(remote):
    """Read the sub-state branch table and the local bitmap descriptors."""
    remote.select_thread(1)
    table = remote.read(0x103E51A2, 4)
    targets = [0x103E51A2 + entry * 2 for entry in table]
    require(targets == [0x103E51B8, 0x103E51B6, 0x103E51A6, 0x103E51A6],
            'Capture sub-state branch table differs')
    bitmaps = []
    for offset in (0x20, 0x28, 0x30, 0x38):
        address = RESOURCE_BITMAP_CONTEXT + offset
        count, pointer = struct.unpack('<2I', remote.read(address, 8))
        require(count == 0x7C, 'Resource bitmap capacity differs')
        words = struct.unpack('<4I', remote.read(pointer, 16))
        bitmaps.append(dict(descriptor=hex(address), capacity=count,
                            storage=hex(pointer), words=[hex(word) for word in words],
                            resource_3f_set=bool(words[1] & 0x80000000)))
    return dict(substate_dispatch=dict(table=hex(0x103E51A2),
                entries=list(table), targets=[hex(target) for target in targets],
                state_zero_returns=True, readiness_check_states=[2, 3]),
                local_resource_bitmaps=bitmaps)


def find_registration(remote, center, pattern, radius=0x100000):
    """Locate an adjacent word pair in slave RAM near the observed address."""
    remote.select_thread(3)
    needle = struct.pack('<2I', *pattern)
    start = max(0xC1000000, center - radius) & ~0xFFF
    end = min(0xC1A00000, center + radius)
    chunk = 0x1000
    for base in range(start, end, chunk):
        data = remote.read(base, min(chunk + 8, end - base))
        position = data.find(needle)
        while position >= 0:
            yield base + position
            position = data.find(needle, position + 1)


def dispatch_table(remote):
    remote.select_thread(1)
    data = remote.read(MASTER_DISPATCH_TABLE, 256 * 4)
    words = struct.unpack('<256I', data)
    frequency = {}
    for word in words:
        frequency[word] = frequency.get(word, 0) + 1
    default = max(frequency, key=frequency.get)
    registered = {str(index): hex(word) for index, word in enumerate(words)
                  if word and word != default}
    return default, registered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller', 'destination'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--seconds', type=float, default=8.0,
                        help='Bounded loop-membership window in seconds')
    parser.add_argument('--boot-seconds', type=float, default=240.0,
                        help='Bound for reaching system mode 2')
    parser.add_argument('--icount-shift', type=int, choices=range(7), default=0)
    args = parser.parse_args()
    require(0 < args.seconds <= 60 and 0 < args.boot_seconds <= 900,
            'Observation bounds must be in (0, 60] and (0, 900] seconds')
    destination = args.destination
    master = args.master.read_bytes()
    slave = args.slave.read_bytes()
    controller = args.controller.read_bytes()
    from tools.controller_core_probe import CONTROLLER_SHA256
    require(hashlib.sha256(controller).hexdigest() == CONTROLLER_SHA256,
            'Expected the original controller image')
    identities = {role: analyze_eg(image, role)['sha256']
                  for role, image in (('master', master), ('slave', slave))}
    destination.mkdir(parents=True, exist_ok=False)
    resident = bytearray(0xC000)
    resident[:4] = b'MAKE'
    (destination / 'resident.bin').write_bytes(resident)
    primary = bytearray(256); primary[11] = 1
    (destination / 'primary.bin').write_bytes(primary)
    auxiliary = bytearray(256); auxiliary[9] = 8; auxiliary[12] = 0xC9
    (destination / 'auxiliary.bin').write_bytes(auxiliary)
    for name, image in zip(('group17.bin', 'group18.bin'), parameter_images()):
        (destination / name).write_bytes(image)
    devices = [
        'nikon-z72-controller-register-bank,bus=controller-i2c0,address=79',
        'nikon-z72-controller-expander,bus=controller-i2c0,address=34,id=keys',
        f'nikon-z72-controller-register-bank,bus=controller-i2c0,address=107,'
        f'initial-state={destination / "primary.bin"}',
        f'nikon-z72-controller-register-bank,bus=controller-i2c0,address=13,'
        f'initial-state={destination / "auxiliary.bin"}',
        f'loader,file={destination / "group17.bin"},addr=0x132C0000,force-raw=on',
        f'loader,file={destination / "group18.bin"},addr=0x132E0000,force-raw=on',
        *('nikon-z72-controller-register-bank,bus=master-i2c%d,address=104' % index
          for index in range(4)),
    ]
    process = remote = None
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            signal_port = listener.getsockname()[1]
        process, remote = dual_machine(args.qemu, destination, master, slave,
            destination / 'console.txt', icount=f'shift={args.icount_shift},sleep=off',
            trace='guest_errors', controller_firmware=args.controller.resolve(),
            controller_link=True, controller_flash_data=(destination / 'resident.bin').resolve(),
            devices=devices,
            globals_=tuple('nikon-z72-controller-adc.channel%d=%d' % channel
                           for channel in ADC_CHANNELS),
            extra_arguments=('-qtest', f'tcp:127.0.0.1:{signal_port},server=on,wait=off',
                             '-qtest-log', '/dev/null'))
        # Present the recovered wake/input pin combination to the controller.
        wire = socket.create_connection(('127.0.0.1', signal_port), timeout=10)
        try:
            stream = wire.makefile('rb')
            def qtest(command):
                wire.sendall((command + '\n').encode())
                line = stream.readline().decode().strip()
                require(line == 'OK', 'Signal command failed: ' + line)
            reply = remote.command('qRcmd,' + 'qom-list /machine/unattached'.encode().hex())
            listing = bytearray()
            while reply.startswith('O') and reply != 'OK':
                listing.extend(bytes.fromhex(reply[1:]))
                reply = remote.receive()
            pins = re.findall(r'(device\[\d+\]) \(child<nikon-z72-controller-gpio>\)',
                              listing.decode())
            pins.sort(key=lambda name: int(re.search(r'\d+', name)[0]))
            require(len(pins) == 8, 'Expected eight controller pin banks')
            for bank, pin, level in GPIO_LEVELS:
                qtest(f'set_irq_in /machine/unattached/{pins[bank]} unnamed-gpio-in {pin} {level}')
        finally:
            wire.close()
        state, attempts = reach_mode_two(remote, args.boot_seconds)
        require(state['control_ready_bitmap'] == 15, 'Controller readiness differs')
        # The capture operation is registered shortly after the mode transition;
        # wait for the original registration instead of assuming it completed.
        deadline = time.monotonic() + 60
        callback = 0
        while callback != RECOVERED_CALLBACK:
            remote.select_thread(1)
            callback = struct.unpack('<I', remote.read(OPERATION_14_CALLBACK, 4))[0]
            if callback == RECOVERED_CALLBACK:
                break
            require(time.monotonic() < deadline,
                    'Operation 14 completion callback was not retained')
            remote.sock.settimeout(3)
            try:
                remote.command('vCont;c')
            except TimeoutError:
                remote.interrupt()
        applications = application_observation(remote)
        require(applications['current_index'] == 3,
                'Foreground is not the live-view application')
        remote.select_thread(1)
        control = remote.read(CONTROL_BLOCK, 8)
        armed, substate = control[4], control[5]
        require(armed == 1, 'Capture control state differs')
        require(substate == 0, 'Capture sub-state differs')
        readiness_before = remote.read(READINESS_WORD, 4)
        local_wait = local_wait_observation(remote)
        counts, resources, detail, elapsed = loop_membership(remote, args.seconds)
        remote.select_thread(1)
        require(counts['state-transition'] == 0,
                'Capture sub-state advanced; boundary assumptions stale')
        require(counts['completion'] == 0,
                'Operation 14 completion ran; boundary assumptions stale')
        readiness_after = remote.read(READINESS_WORD, 4)
        require(readiness_before == readiness_after == bytes(4),
                'Capture readiness byte was written; boundary assumptions stale')
        default, registered = dispatch_table(remote)
        anchor = registered.get(str(DISPATCH_ANCHOR[0]))
        require(anchor == hex(DISPATCH_ANCHOR[1]), 'Dispatch table anchor differs')
        remote.select_thread(3)
        slave_level_one = struct.unpack(
            '<I', remote.read(SLAVE_LEVEL_ONE[0] + SLAVE_LEVEL_ONE[1] * 4, 4))[0]
        require(slave_level_one == SLAVE_LEVEL_ONE[2],
                'Slave dispatch registration differs')
        found_3f = list(find_registration(remote, SLAVE_TASK_3F[0], SLAVE_TASK_3F[1:]))
        require(found_3f, 'Slave task registration is missing')
        found_43 = list(find_registration(remote, SLAVE_TASK_43[0], SLAVE_TASK_43[1:]))
        require(found_43, 'Slave task registration is missing')
        faults = []
        for core in range(1, 5):
            remote.select_thread(core)
            fault = {name: remote.read_register(name) for name in
                     ('DFAR_S', 'IFAR_S', 'DFSR_S', 'IFSR_S')}
            require(not any(fault.values()), 'Engine recorded an execution fault')
            faults.append(dict(thread=core, registers=fault))
        graphics = graphics_observation(remote)
        require(graphics['render_requests'] == 0,
                'A display render request was submitted; boundary assumptions stale')
        require(graphics['surface_address'] == 0, 'Display surface address differs')
        require(graphics['failed_requests'] == 0, 'Graphics requests failed')
        report = dict(format=2, passed=True, firmware_sha256=identities,
            controller_sha256=CONTROLLER_SHA256,
            operation14_callback=dict(address=hex(OPERATION_14_CALLBACK),
                                      value=hex(callback), registration=hex(0x10228284),
                                      notification_family='0x04100000 | operation'),
            capture_control=dict(address=hex(CONTROL_BLOCK), armed=armed, substate=substate,
                                 state_machine=hex(STATE_MACHINE),
                                 readiness_byte=dict(address=hex(READINESS_WORD), mask=1,
                                 value_stayed_zero=True, checked_in_current_substate=False)),
            local_wait=local_wait,
            loop_membership=dict(requested_seconds=args.seconds, elapsed_seconds=elapsed,
                                 counts=counts, resources=resources[:8]),
            master_dispatch=dict(address=hex(MASTER_DISPATCH_TABLE),
                                 default_handler=hex(default), registered=registered),
            slave_registrations=dict(
                task_3f=dict(observed_near=hex(SLAVE_TASK_3F[0]),
                                 found=[hex(address) for address in found_3f],
                                 task_id=hex(SLAVE_TASK_3F[1]),
                                 entry=hex(SLAVE_TASK_3F[2])),
                task_43=dict(observed_near=hex(SLAVE_TASK_43[0]),
                                 found=[hex(address) for address in found_43],
                                 task_id=hex(SLAVE_TASK_43[1]),
                                 entry=hex(SLAVE_TASK_43[2])),
                level_one=dict(address=hex(SLAVE_LEVEL_ONE[0]),
                               line=SLAVE_LEVEL_ONE[1], handler=hex(SLAVE_LEVEL_ONE[2]))),
            engine_fault_registers=faults,
            system_controller=system_observation(remote),
            application_manager=applications, graphics=graphics,
            cores=sample_cores(remote), boot_attempts=attempts,
            experimental_parameters=True, firmware_modified=False,
            full_boot_verified=False, menu_verified=False)
        (destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n',
                                                 encoding='utf-8', newline='\n')
        print('PASS capture readiness boundary', destination, flush=True)
    finally:
        if remote is not None:
            remote.sock.close()
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


if __name__ == '__main__':
    main()
