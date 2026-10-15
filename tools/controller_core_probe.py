# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe the stock controller reset, clock setup and vector relocation."""
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
from tools.smp_boot_probe import reach, stop_registers

CONTROLLER_SHA256 = 'cb10af00b9485567453d448020892836ea48637bd638f4cf7cc1c9777a128a9a'


def scenario(args, image, enabled, power_switch=False):
    name = 'power-switch-on' if power_switch else ('completion' if enabled else 'completion-disabled')
    directory = args.destination / name
    directory.mkdir()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    command = [args.qemu, '-M', 'nikon-z72-controller-lab,power-switch=' +
               ('on' if power_switch else 'off'), '-kernel',
               str(args.firmware.resolve()), '-display', 'none', '-serial', 'none',
               '-monitor', 'none', '-nic', 'none', '-S', '-gdb', f'tcp:127.0.0.1:{port}',
               '-icount', 'shift=4,sleep=off', '-d', 'int,guest_errors',
               '-global', 'nikon-z72-controller-config.clock-completion=' +
               ('on' if enabled else 'off')]
    (directory/'command.json').write_text(json.dumps(command, indent=2)+'\n')
    remote = process = None
    result = dict(clock_completion=enabled, power_switch=power_switch)
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL,
            stderr=(directory/'qemu.log').open('wb'),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        deadline = time.monotonic() + 10
        while remote is None:
            try:
                remote = Remote(port)
            except ConnectionRefusedError:
                require(process.poll() is None, 'Controller machine exited during startup')
                require(time.monotonic() < deadline, 'Controller debugger startup timed out')
                time.sleep(0.05)
        regs = remote.regs()
        require(remote.get(regs, 'pc') == 0x080002B4 and
                remote.get(regs, 'sp') == 0x20000C08,
                'Controller did not reset from the original vectors')
        result['original_reset_verified'] = True
        faults = (0x080200A4, 0x080200B6, 0x080200C8, 0x080200DA)
        for address in faults:
            remote.breakpoint(address)
        if enabled:
            remote.sock.settimeout(15)
            reach(remote, 0x08000F70)
            require(int.from_bytes(remote.read(0x40023800, 4), 'little') &
                    0x03030003 == 0x03030003, 'Original clock setup did not complete')
            result['original_clock_return_verified'] = True
            reach(remote, 0x080002E2)
            require(remote.read(0x20000000, 0x1C4) == image[:0x1C4] and
                    int.from_bytes(remote.read(0xE000ED08, 4), 'little') == 0x20000000,
                    'Original controller vector relocation differs')
            result['original_vector_copy_verified'] = True
            require(remote.read(0xE000ED28, 8) == bytes(8),
                    'Controller recorded a fault during reset setup')
            reach(remote, 0x08020084)
            reach(remote, 0x08020120)
            require(remote.get(remote.regs(), 'xpsr') & 0x1ff == 110,
                    'Controller runtime did not dispatch its original software interrupt')
            result['original_runtime_interrupt_verified'] = True
            reach(remote, 0x08043ADE)
            timer = remote.read(0x40000C00, 0x30)
            require(int.from_bytes(timer[:4], 'little') & 1 and
                    int.from_bytes(timer[0x28:0x2c], 'little') == 4 and
                    int.from_bytes(timer[0x2c:0x30], 'little') == 0xffffffff and
                    remote.read(0xE000ED28, 8) == bytes(8),
                    'Original runtime did not configure its timer before pin setup')
            require(remote.get(remote.regs(), 'r0') == 0x40020800,
                    'Controller did not reach the original pin output helper')
            result['original_timer_setup_verified'] = True
            result['original_pin_setup_entry_verified'] = True
            reach(remote, 0x08048A28)
            latches = [int.from_bytes(remote.read(0x40020014 + port * 0x400, 4), 'little')
                       for port in range(8)]
            require(latches == [0, 0, 0x800, 0x8a20, 0, 0x2090, 0x200, 0] and
                    remote.read(0xE000ED28, 8) == bytes(8),
                    'Original pin initialization did not reach its return with expected latches')
            result['original_pin_setup_return_verified'] = True
            result['output_latches_verified'] = latches
            reach(remote, 0x080398EE)
            require(int.from_bytes(remote.read(0x20017F68, 4), 'little') == 0x40002800 and
                    int.from_bytes(remote.read(0x40007000, 4), 'little') & 0x100 and
                    remote.read(0xE000ED28, 8) == bytes(8),
                    'Original controller clock access setup did not return without faults')
            result['original_clock_access_setup_return_verified'] = True
            _, regs = reach(remote, 0x08043F92)
            handle = remote.get(regs, 'r4')
            require(remote.get(regs, 'r0') == 0 and
                    int.from_bytes(remote.read(handle, 4), 'little') == 0x40005400 and
                    remote.read(handle + 61, 1) == b'\x20' and
                    int.from_bytes(remote.read(0x40005400, 4), 'little') & 1 and
                    remote.read(0xE000ED28, 8) == bytes(8),
                    'Original disconnected bus configuration did not return successfully')
            result['original_bus_configuration_return_verified'] = True
            _, regs = reach(remote, 0x080438D0)
            require(remote.get(regs, 'r4') == 0x40020400 and
                    int.from_bytes(remote.read(0x40020400, 4), 'little') & 0xf0000 == 0 and
                    remote.read(0xE000ED28, 8) == bytes(8),
                    'Original bus pin cleanup did not return without faults')
            result['original_pin_cleanup_return_verified'] = True
            trace = (directory/'qemu.log').read_text(encoding='utf-8', errors='replace')
            event_count = trace.count('nonsecure exception 47\n')
            error_count = trace.count('nonsecure exception 48\n')
            require(event_count > 0 and error_count > 0,
                    'Original disconnected bus did not dispatch both interrupt classes')
            result['native_bus_interrupts'] = dict(event=event_count, error=error_count)
            _, regs = reach(remote, 0x08043758)
            handle = remote.get(regs, 'r4')
            require(remote.get(regs, 'r0') == 0 and
                    int.from_bytes(remote.read(handle, 4), 'little') == 0x40026040 and
                    remote.read(handle + 53, 1) == b'\x01' and
                    int.from_bytes(remote.read(0x40026040, 4), 'little') == 0x0e000400 and
                    remote.read(0xE000ED28, 8) == bytes(8),
                    'Original DMA channel configuration did not return ready')
            result['original_dma_configuration_return_verified'] = True
            _, regs = reach(remote, 0x08039394)
            require(remote.get(regs, 'r0') == 0 and
                    int.from_bytes(remote.read(0x2001F338, 4), 'little') == 0x40014800 and
                    remote.read(0x2001F338 + 57, 1) == b'\x01' and
                    int.from_bytes(remote.read(0x40014800, 4), 'little') & 1 and
                    int.from_bytes(remote.read(0x4001480c, 4), 'little') & 2 and
                    int.from_bytes(remote.read(0x40014828, 4), 'little') == 49 and
                    int.from_bytes(remote.read(0x4001482c, 4), 'little') == 0xffff and
                    remote.read(0xE000ED28, 8) == bytes(8),
                    'Original compare timer configuration did not return ready')
            result['original_compare_timer_start_verified'] = True
            _, regs = reach(remote, 0x08041318)
            require(remote.get(regs, 'xpsr') & 0x1ff == 42 and
                    int.from_bytes(remote.read(0x40014810, 4), 'little') & 2 and
                    int.from_bytes(remote.read(0x4001480c, 4), 'little') & 2 and
                    remote.read(0xE000ED28, 8) == bytes(8),
                    'Original compare timer interrupt was not dispatched')
            result['original_compare_timer_interrupt_verified'] = True
            require((int.from_bytes(remote.read(0x40021810, 4), 'little') & 0x20 != 0)
                    == power_switch and
                    int.from_bytes(remote.read(0x40021800, 4), 'little') >> 10 & 3 == 0,
                    'External switch level did not reach the original input pin')
            result['external_switch_input_verified'] = True
            require(int.from_bytes(remote.read(0x4001380c, 4), 'little') >> 12 & 15 == 6 and
                    all(int.from_bytes(remote.read(0x40013c00 + offset, 4), 'little') & 0x80
                        for offset in (0, 8, 12)),
                    'Original controller did not configure both edges on pin G7')
            for high in (True, False):
                command = 'qom-set /machine wake-input ' + ('true' if high else 'false')
                require(remote.command('qRcmd,' + command.encode().hex()) == 'OK' and
                        int.from_bytes(remote.read(0x40013c14, 4), 'little') & 0x80,
                        'External controller edge did not latch its pending bit')
                for attempt in range(8):
                    _, regs = reach(remote, 0x080201FC)
                    if remote.get(regs, 'xpsr') & 0x1ff == 39:
                        break
                    remote.command('s')
                require(remote.get(regs, 'xpsr') & 0x1ff == 39,
                        'Original external interrupt was not dispatched')
                _, regs = reach(remote, 0x08020238)
                require(remote.get(regs, 'xpsr') & 0x1ff == 39 and
                        not int.from_bytes(remote.read(0x40013c14, 4), 'little') & 0x80 and
                        remote.read(0xE000ED28, 8) == bytes(8),
                        'Original external interrupt did not acknowledge its edge without faults')
            result['original_external_edges_verified'] = dict(pin='G7', irq=23,
                exception=39, rising=True, falling=True, native_acknowledgement=True)
        else:
            remote.breakpoint(0x08000F70)
            remote.sock.settimeout(3)
            try:
                stop_registers(remote, remote.command('vCont;c'))
                raise ValueError('Disabled clock completion unexpectedly resumed controller reset')
            except TimeoutError:
                remote.interrupt()
            require(int.from_bytes(remote.read(0x40023800, 4), 'little') &
                    ((1 << 17) | (1 << 25)) == 0 and
                    remote.read(0x20000000, 0x1C4) == bytes(0x1C4) and
                    remote.read(0xE000ED28, 8) == bytes(8),
                    'Disabled controller completion did not preserve the original clock wait')
            result['original_wait_preserved'] = True
        result['passed'] = True
        print('PASS ' + directory.name, flush=True)
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
    report = dict(format=1, firmware=CONTROLLER_SHA256, full_boot_verified=False,
        controller_link_verified=False, menu_verified=False,
        assumptions=['Experimental Cortex-M4 execution core, 96 external interrupt lines.',
                     'Fixed 100 MHz CPU clock, 12.5 MHz reference and 1 MiB flash window.',
                     'Synchronous clock completion and passive power/flash configuration storage.',
                     'Existing timer model at 0x40000c00, fixed 100 MHz clock, interrupt 50.',
                     'Eight isolated pin ports; no external controller-to-engine wiring.',
                     'Experimental external switch on port G pin 5 is tested at both levels; physical switch identity is inferred.',
                     'Clock initialization status is synchronous; calendar advancement and alarms are absent.',
                     'Two disconnected buses support START, address NACK and event/error interrupts; data transfers are absent.',
                     'Sixteen routed pad edges deliver seven external interrupt groups; event-only wake and remapping are absent.',
                     'Experimental external G7 input exercises native edge acknowledgement; its physical signal identity is unconfirmed.',
                     'Bounded DMA supports equal widths and linear buffers; peripheral request lines are disconnected.',
                     'Two bounded 16-bit timers use a fixed 100 MHz clock and shared interrupt 26; capture and PWM wiring are absent.',
                     'Original kernel-loaded vectors; no debugger guest state writes.'], scenarios={})
    for enabled in (True, False):
        report['scenarios']['completion' if enabled else 'completion-disabled'] = scenario(args, image, enabled)
    report['scenarios']['power-switch-on'] = scenario(args, image, True, True)
    (args.destination/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
