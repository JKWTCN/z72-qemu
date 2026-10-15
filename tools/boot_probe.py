# SPDX-License-Identifier: GPL-2.0-or-later
"""Step stock EG reset code with its own MMU table, stopping before first MMIO."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from analyze.qemu_display import Remote


@contextmanager
def reset_machine(qemu, directory, image, role, auto_complete=None, blocked_control=None,
                  memory_init_error=False, ram_images=(), counter_enabled=None, cpus=1,
                  uart_enabled=None, console=None, pin_config=None,
                  controller_config=None, snapshot_config=None,
                  parameter_config=None, stage_config=None, release_config=None,
                  timer_tick=None, icount=None, devices=()):
    require(cpus in (1, 2), 'Unsupported execution core count')
    directory.mkdir()
    firmware = directory / 'stock.bin'
    firmware.write_bytes(image)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    machine = 'nikon-z72-lab' if role == 'master' else 'nikon-z72-slave-lab'
    command = [qemu, '-M', machine, '-smp', str(cpus), '-display', 'none', '-serial', 'none',
               '-monitor', 'none', '-nic', 'none', '-d', 'int,mmu', '-S', '-gdb', f'tcp:127.0.0.1:{port}',
               '-device', f'loader,file={firmware},addr={BASE:#x},cpu-num=0,force-raw=on']
    if icount is not None:
        command += ['-icount', icount]
    for device in devices:
        command += ['-device', device]
    for cpu in range(1, cpus):
        command += ['-device', f'loader,addr={BASE:#x},cpu-num={cpu}']
    if auto_complete is not None:
        command += ['-global', 'nikon-z72-boot-config.auto-complete=' +
                    ('on' if auto_complete else 'off')]
    if blocked_control is not None:
        command += ['-global', f'nikon-z72-boot-config.blocked-control={blocked_control:#x}']
    if memory_init_error:
        command += ['-global', 'nikon-z72-boot-config.memory-init-error=on']
    if counter_enabled is not None:
        command += ['-global', 'nikon-z72-counter.enabled=' +
                    ('on' if counter_enabled else 'off')]
    if uart_enabled is not None:
        command += ['-global', 'nikon-z72-uart.enabled=' + ('on' if uart_enabled else 'off')]
    if console is not None:
        command += ['-chardev', f'file,id=z72-console,path={console}',
                    '-global', 'nikon-z72-uart.chardev=z72-console']
    if pin_config is not None:
        command += ['-global', 'nikon-z72-boot-config.pin-config=' +
                    ('on' if pin_config else 'off')]
    if controller_config is not None:
        command += ['-global', 'nikon-z72-boot-config.controller-config=' +
                    ('on' if controller_config else 'off')]
    if snapshot_config is not None:
        command += ['-global', 'nikon-z72-boot-config.snapshot-config=' +
                    ('on' if snapshot_config else 'off')]
    if parameter_config is not None:
        command += ['-global', 'nikon-z72-boot-config.parameter-config=' +
                    ('on' if parameter_config else 'off')]
    if stage_config is not None:
        command += ['-global', 'nikon-z72-boot-config.stage-config=' +
                    ('on' if stage_config else 'off')]
    if release_config is not None:
        command += ['-global', 'nikon-z72-boot-config.release-config=' +
                    ('on' if release_config else 'off')]
    if timer_tick is not None:
        command += ['-global', 'nikon-z72-boot-config.timer-tick=' +
                    ('on' if timer_tick else 'off')]
    for path, address in ram_images:
        command += ['-device', f'loader,file={path},addr={address:#x},force-raw=on']
    (directory / 'command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='utf-8')
    remote = None
    with (directory / 'qemu.log').open('wb') as log:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        try:
            deadline = time.monotonic() + 10
            while remote is None:
                try:
                    remote = Remote(port)
                except ConnectionRefusedError:
                    require(process.poll() is None, 'QEMU exited during startup')
                    require(time.monotonic() < deadline, 'QEMU startup timed out')
                    time.sleep(0.05)
            yield remote
        finally:
            if remote is not None:
                remote.sock.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def trace_prefix(remote, structure, fault=False):
    prefix = structure['boot_prefix']
    boot = structure['startup']['entry_offset']
    require(remote.get(remote.regs(), 'pc') == BASE, 'Loader did not select EG entry')
    if fault:
        # Change only the in-memory test instance, never the input image.
        # Invalidate the code section used immediately after SCTLR enables MMU.
        remote.write(structure['startup']['ttbr'] + (BASE >> 20) * 4, bytes(4))
    offsets = [0, *range(boot, prefix['stop_offset'] + 4, 4)]
    checkpoints = {c['offset']: c for c in prefix['stack_checkpoints']}
    trace, stacks = [], []
    for index, offset in enumerate(offsets):
        registers = remote.regs()
        pc = remote.get(registers, 'pc')
        cpsr = remote.get(registers, 'cpsr')
        trace.append(dict(pc=pc, cpsr=cpsr, sp=remote.get(registers, 'sp')))
        if pc != BASE + offset:
            require(fault and offset == boot + 0x94 and cpsr & 0x1F == 0x17,
                    f'Unexpected boot path at {pc:#x}, expected {BASE + offset:#x}')
            require(pc == 0x0C, 'Expected prefetch abort before VBAR setup')
            return dict(invalid_code_section=True, prefetch_abort_verified=True, trace=trace)
        require(not cpsr & 0x20, 'Reset prefix unexpectedly entered Thumb state')
        if offset in checkpoints:
            checkpoint = checkpoints[offset]
            require(cpsr & 0x1F == checkpoint['mode'] and
                    remote.get(registers, 'sp') == checkpoint['stack_top'],
                    'Banked stack initialization mismatch')
            stacks.append(dict(**checkpoint, verified=True))
        if index < len(offsets) - 1:
            remote.command('s')
    require(not fault, 'Invalid code section did not prevent boot prefix execution')
    require(remote.get(registers, 'r0') == prefix['first_mmio']['address'] and
            remote.get(registers, 'r1') == prefix['first_mmio']['value'],
            'First MMIO arguments mismatch')
    return dict(instructions_executed=len(trace) - 1, stack_checkpoints=stacks,
                first_mmio=prefix['first_mmio'], mmio_executed=False, trace=trace)


def probe(args):
    images = {'master': args.master.read_bytes(), 'slave': args.slave.read_bytes()}
    structures = {role: analyze_eg(image, role) for role, image in images.items()}
    destination = args.destination.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    report = dict(format=1, backend='nikon-z72-lab',
                  qemu_version=subprocess.check_output([args.qemu, '--version'], text=True).splitlines()[0],
                  contexts=[], full_boot_verified=False, menu_verified=False,
                  assumptions=['Stock images preloaded by generic loader at 0x10020000.',
                      'One experimental cortex-a7 CPU per independent role; hardware CPU model unconfirmed.',
                      'Stock reset instructions and page table; no synthetic startup or register setup.',
                      'Execution stops before the first MMIO store; peripherals remain unimplemented.'])
    for role, image in images.items():
        context = dict(role=role, sha256=structures[role]['sha256'])
        for fault in (False, True):
            name = role + ('-invalid-section' if fault else '-stock')
            with reset_machine(args.qemu, destination / name, image, role) as remote:
                result = trace_prefix(remote, structures[role], fault)
                if not fault:
                    require(remote.read(BASE + 0x10000, 0x4000) == image[0x10000:0x14000],
                            'Stock boot modified its page table')
                    result['stock_page_table_preserved'] = True
                context['negative_control' if fault else 'stock'] = result
        context['passed'] = True
        report['contexts'].append(context)
        print('PASS', role, 'stock reset/MMU/stacks and invalid-section prefetch abort', flush=True)
    report['passed'] = True
    (destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('Report:', destination / 'report.json')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--qemu', required=True, help='QEMU built with the native Z72 laboratories')
    parser.add_argument('--destination', type=Path, required=True, help='New run directory')
    args = parser.parse_args()
    try:
        probe(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
