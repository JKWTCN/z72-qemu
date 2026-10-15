# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe stock power readiness and serial configuration with default controller inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from analyze.qemu_display import Remote
from tools.controller_core_probe import CONTROLLER_SHA256
from tools.smp_boot_probe import reach


def scenario(args, name, attached):
    directory = args.destination / name
    directory.mkdir()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    command = [args.qemu, '-M', 'nikon-z72-controller-lab', '-kernel', str(args.firmware.resolve()),
               '-display', 'none', '-serial', 'none', '-monitor', 'none', '-nic', 'none',
               '-S', '-gdb', f'tcp:127.0.0.1:{port}', '-icount', 'shift=4,sleep=off',
               '-d', 'guest_errors']
    if attached:
        command += ['-device', 'nikon-z72-controller-register-bank,bus=controller-i2c0,address=79']
    (directory / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    remote = process = None
    result = dict(power_target_attached=attached, power_ready_verified=False)
    try:
        with (directory / 'qemu.log').open('wb') as log:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        deadline = time.monotonic() + 10
        while remote is None:
            try:
                remote = Remote(port)
            except ConnectionRefusedError:
                require(process.poll() is None and time.monotonic() < deadline,
                        'Controller start probe could not connect')
                time.sleep(.05)
        def word(address):
            return int.from_bytes(remote.read(address, 4), 'little')
        regs = remote.regs()
        require(remote.get(regs, 'pc') == 0x080002b4 and
                remote.get(regs, 'sp') == 0x20000c08,
                'Controller did not reset from its original vectors')
        for address in (0x080200a4, 0x080200b6, 0x080200c8, 0x080200da):
            remote.breakpoint(address)
        remote.sock.settimeout(15)
        if attached:
            _, regs = reach(remote, 0x08021418)
            require(remote.get(regs, 'r0') == 0x04060002,
                    'Original power-ready callback event differs')
            result['original_power_ready_event'] = dict(event=0x04060002, tick=word(0x20022d58))
            remote.command('s')
            _, regs = reach(remote, 0x0802137c)
            ready = word(remote.get(regs, 'sp') + 12)
            require(ready & 1, 'Original initialization wait did not receive its ready bit')
            result['original_initialization_wait'] = dict(ready_bits=ready, tick=word(0x20022d58))
            remote.command('s')
            reach(remote, 0x080343a4)
            result.update(power_ready_verified=True, original_transmit_initialization_entered=True)
            remote.command('s')
            ports = []
            for stop, handle, base, dma, stream, channel, direction, dma_control in (
                    (0x08034574, 0x20017c88, 0x40013000, 0x20017ce0, 0x40026410, 3, 0, 0x06020400),
                    (0x08034846, 0x20017eac, 0x40013400, 0x20017f04, 0x40026428, 4, 1, 0x08000440)):
                reach(remote, stop)
                require(word(handle) == base and remote.read(handle + 81, 1) == b'\x01',
                        'Original serial driver did not reach its ready state')
                require(word(base) == 0x289 and word(base + 4) == 0 and word(base + 8) == 2,
                        'Original slave serial configuration differs')
                require(word(dma) == stream and word(stream) == dma_control,
                        'Original serial DMA resource or channel differs')
                ports.append(dict(configuration_return=stop, serial_base=base, driver_ready=1,
                                  control=word(base), status=word(base + 8), dma_stream=stream,
                                  dma_channel=channel, dma_direction=direction, dma_control=dma_control,
                                  tick=word(0x20022d58)))
                remote.command('s')
            result.update(original_serial_configuration_verified=True, serial_ports=ports)
            reach(remote, 0x080309a8)
            require(word(0x20018a48) == 0x40001800 and
                    remote.read(0x20018a48 + 57, 1) == b'\x01' and
                    word(0x40001828) == 499 and word(0x4000182c) == 0xffff and
                    word(0x40001834) == 0xffff,
                    'Original link timer configuration differs')
            result['original_link_timer_configuration'] = dict(configuration_return=0x080309a8,
                timer_base=0x40001800, driver_ready=1, prescaler=499, period=0xffff,
                compare=0xffff, tick=word(0x20022d58))
            remote.command('s')
            reach(remote, 0x0803ad58)
            require(word(0x20020364) == 0x40003c00 and
                    remote.read(0x20020364 + 81, 1) == b'\x01' and
                    word(0x40003c00) == 0x2bb and word(0x40003c04) == 0 and word(0x40003c08) == 2,
                    'Original additional serial configuration differs')
            result['original_additional_serial_configuration'] = dict(configuration_return=0x0803ad58,
                serial_base=0x40003c00, driver_ready=1, control=0x2bb, status=2, tick=word(0x20022d58))
            remote.command('s')
            reach(remote, 0x0803cdf4)
            require(word(0x200183f0) == 0x40014400 and
                    remote.read(0x200183f0 + 57, 1) == b'\x01' and
                    word(0x40014428) == 49 and word(0x4001442c) == 499 and word(0x40014434) == 0xffff,
                    'Original shared update timer configuration differs')
            result['original_shared_update_timer_configuration'] = dict(configuration_return=0x0803cdf4,
                timer_base=0x40014400, driver_ready=1, prescaler=49, period=499,
                compare=0xffff, tick=word(0x20022d58))
            remote.command('s')
            reach(remote, 0x08035708)
            require(word(0x200187ac) == 0x40000400 and
                    remote.read(0x200187ac + 57, 1) == b'\x01' and
                    word(0x40000418) == 0x101 and word(0x40000420) == 0x22,
                    'Original input capture register configuration differs')
            result['original_capture_register_configuration'] = dict(configuration_return=0x08035708,
                timer_base=0x40000400, driver_ready=1, channel_mode=0x101, channel_control=0x22,
                external_capture_verified=False, tick=word(0x20022d58))
            remote.command('s')
            reach(remote, 0x080213c2)
            require(word(0x200187e8) == 0x40000000 and word(0x20018770) == 0x40000800 and
                    remote.read(0x200187e8 + 57, 1) == b'\x01' and
                    remote.read(0x20018770 + 57, 1) == b'\x01',
                    'Original post-power initialization did not configure its counters')
            result['original_post_power_initialization'] = dict(completion_point=0x080213c2,
                two_phases_completed=True, timer_bases=[0x40000000, 0x40000800], tick=word(0x20022d58))
            remote.command('s')
            _, regs = reach(remote, 0x08041710)
            require(remote.get(regs, 'xpsr') & 0x1ff == 59,
                    'Original shared link timer handler did not enter IRQ43')
            result['original_shared_link_timer_interrupt'] = dict(handler=0x08041710, irq=43,
                tick=word(0x20022d58))
            remote.command('s')
            reach(remote, 0x0802d62e)
            require(word(0x200195b4) == 0x40003800 and
                    remote.read(0x200195b4 + 81, 1) == b'\x01' and word(0x40003800) == 0x31f,
                    'Original master serial configuration differs')
            start_tick = word(0x20022d58)
            result['original_master_serial_configuration'] = dict(configuration_return=0x0802d62e,
                serial_base=0x40003800, driver_ready=1, control=0x31f, tick=start_tick)
            remote.command('s')
            remote.sock.settimeout(2)
            try:
                remote.command('vCont;c')
            except TimeoutError:
                remote.interrupt()
            regs = remote.regs()
            end_tick = word(0x20022d58)
            require(end_tick - start_tick >= 32 and remote.get(regs, 'pc') not in
                    (0x080200a4, 0x080200b6, 0x080200c8, 0x080200da),
                    'Controller did not continue executing without native faults')
            result['bounded_execution'] = dict(start_tick=start_tick, end_tick=end_tick,
                observation_seconds=2, stop_pc=remote.get(regs, 'pc'))
            result['post_power_initialization_verified'] = True
        else:
            remote.breakpoint(0x08021418)
            try:
                reach(remote, 0x08038380)
            finally:
                remote.breakpoint(0x08021418, False)
            result['original_failed_power_configuration_preserved'] = True
        require(remote.read(0xe000ed28, 8) == bytes(8),
                'Controller start probe recorded a native fault')
        result.update(original_reset_verified=True, native_faults_absent=True, passed=True)
        print('PASS ' + name, flush=True)
        return result
    finally:
        if remote is not None:
            remote.sock.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--firmware', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    image = args.firmware.read_bytes()
    require(len(image) == 524290 and hashlib.sha256(image).hexdigest() == CONTROLLER_SHA256,
            'Expected the original controller C 1.30.00 image')
    args.destination.mkdir(parents=True, exist_ok=False)
    report = dict(format=2, firmware=CONTROLLER_SHA256, full_boot_verified=False,
        controller_link_verified=False, menu_verified=False,
        assumptions=['Isolated controller with fixed experimental clocks and default inputs.',
                     'Original image, no resident data fixture or analog sample overrides.',
                     'Explicit experimental register storage at address 0x4f; not a physical power device.',
                     'Breakpoints and reads, no debugger guest state writes.',
                     'Two post-power initialization phases, a shared timer interrupt and bounded isolated execution are observed.',
                     'Original controller-link transfers, external capture, full board boot and menu remain unverified.'],
        scenarios={})
    for name, attached in (('power-target-disconnected', False), ('power-target-attached', True)):
        report['scenarios'][name] = scenario(args, name, attached)
    report['power_ready_verified'] = report['scenarios']['power-target-attached']['power_ready_verified']
    require(args.firmware.read_bytes() == image, 'Probe modified the firmware input')
    (args.destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
