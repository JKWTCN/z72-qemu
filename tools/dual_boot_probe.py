# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe original dual-engine startup in one machine."""
import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from analyze.kernel_boot import kernel_profile
from analyze.qemu_display import Remote
from tools.smp_boot_probe import stop_registers

# Communication-area constants recovered from both images: each engine's
# local ring header and the per-core scheduler current-task table.
MASTER_MSG = 0xB7CF0000
SLAVE_MSG = 0xC60F0000
MASTER_MAGIC = bytes.fromhex('0801c000010055aa')
READY_TASK_TABLE = 0xB2B41604
# Master payload service block (scheduler and interrupt machinery).
MASTER_PAYLOAD = (0x10100000, 0x10121538)
MASTER_APPLICATION = (0x10200000, 0x10800000)
# Slave service block (its scheduler idles inside this span).
SLAVE_SERVICE = (0x10038000, 0x1003A000)


def dual_machine(qemu, directory, master, slave, console, globals_=(),
                 icount="shift=0,sleep=off", trace="int", controller_firmware=None,
                 devices=(), controller_link=False, controller_flash_data=None,
                 extra_arguments=(), process_factory=None, machine_options=()):
    require(not controller_link or controller_firmware is not None,
            'Controller link requires a controller firmware image')
    require(controller_flash_data is None or controller_firmware is not None,
            'Controller flash data requires a controller firmware image')
    master_bin = directory/'master.bin'
    master_bin.write_bytes(master)
    slave_bin = directory/'slave.bin'
    slave_bin.write_bytes(slave)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    machine = 'nikon-z72-dual-lab'
    if controller_firmware is not None:
        machine += ',controller-firmware=' + str(controller_firmware)
        if controller_flash_data is not None:
            machine += ',controller-flash-data=' + str(controller_flash_data)
        if controller_link:
            machine += ',controller-link=on'
    for option in machine_options:
        machine += ',' + option
    # A file-backed generic loader restores its ROM blob on every reset.
    # Let the boot store own image loading so that blob cannot overwrite a
    # reprogrammed image after a menu update.
    master_loader = f'loader,addr={BASE:#x},cpu-num=0'
    if not any(option.startswith('master-boot-image=') for option in machine_options):
        master_loader = f'loader,file={master_bin},addr={BASE:#x},cpu-num=0,force-raw=on'
    slave_loader = f'loader,addr={BASE:#x},cpu-num=2'
    if not any(option.startswith('slave-boot-image=') for option in machine_options):
        slave_loader = f'loader,file={slave_bin},addr={BASE:#x},cpu-num=2,force-raw=on'
    command = [qemu, '-M', machine, '-smp',
               '4,maxcpus=5' if controller_firmware is not None else '4', '-display', 'none',
               '-serial', 'none', '-monitor', 'none', '-nic', 'none',
               '-S', '-gdb', f'tcp:127.0.0.1:{port}',
               '-chardev', f'file,id=z72-console,path={console}',
               '-global', 'nikon-z72-uart.enabled=on',
               '-device', master_loader,
               '-device', f'loader,addr={BASE:#x},cpu-num=1',
               '-device', slave_loader,
               '-device', f'loader,addr={BASE:#x},cpu-num=3']
    if icount is not None:
        command.extend(('-icount', icount))
    if trace is not None:
        command.extend(('-d', trace))
    for setting in globals_:
        command.extend(('-global', setting))
    for device in devices:
        command.extend(('-device', device))
    command.extend(extra_arguments)
    (directory/'command.json').write_text(json.dumps(command, indent=2)+'\n',
                                          encoding='utf-8')
    process = (process_factory or subprocess.Popen)(command, stdout=subprocess.DEVNULL,
        stderr=(directory/'qemu.log').open('wb'),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    try:
        remote = None
        deadline = time.monotonic() + 30
        while remote is None:
            try:
                remote = Remote(port)
            except ConnectionRefusedError:
                require(process.poll() is None,
                        'QEMU exited during startup: ' +
                        (directory/'qemu.log').read_text(errors='replace'))
                require(time.monotonic() < deadline, 'QEMU startup timed out')
                time.sleep(0.05)
        return process, remote
    except BaseException:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        raise


def sample_cores(remote):
    state = []
    for thread in (1, 2, 3, 4):
        remote.select_thread(thread)
        regs = remote.regs()
        state.append(dict(thread=thread, pc=remote.get(regs, 'pc'),
                          mode=remote.get(regs, 'cpsr') & 0x1f))
    return state


def trace_dual(remote, console, log_path, seconds):
    """Run both engines without debugger writes to guest runtime state."""
    remote.sock.settimeout(seconds)
    timed_out = False
    try:
        stop_registers(remote, remote.command('vCont;c'))
    except TimeoutError:
        timed_out = True
        try:
            remote.interrupt()
        except TimeoutError:
            pass
    cores = sample_cores(remote)
    remote.select_thread(1)
    slave_seen = 0
    master_seen = 0
    master_application_seen = 0
    for core in cores:
        if core['thread'] <= 2 and MASTER_PAYLOAD[0] <= core['pc'] < MASTER_PAYLOAD[1]:
            master_seen += 1
        if core['thread'] <= 2 and MASTER_APPLICATION[0] <= core['pc'] < MASTER_APPLICATION[1]:
            master_application_seen += 1
        if core['thread'] >= 3 and SLAVE_SERVICE[0] <= core['pc'] < SLAVE_SERVICE[1]:
            slave_seen += 1
    require(master_seen + master_application_seen >= 1,
            'Master cores did not execute the payload service or application code')
    require(slave_seen >= 1,
            'Slave cores did not settle in their service block')
    master_head = remote.read(MASTER_MSG, 8)
    slave_head = remote.read(0x460F0000, 8)
    require(slave_head == MASTER_MAGIC,
            'Slave communication header missing: ' + slave_head.hex())
    ready = struct.unpack('<2I', remote.read(READY_TASK_TABLE, 8))
    result = dict(timed_out=timed_out,
                  cores=[{**core, 'pc': hex(core['pc'])} for core in cores],
                  master_comm_header=master_head.hex(),
                  slave_comm_header=slave_head.hex(),
                  ready_tasks=[hex(word) for word in ready],
                  sampled_master_application_cores=master_application_seen,
                  comm_active=False, full_startup_verified=False,
                  menu_verified=False, fault_log_pending=str(log_path),
                  console_pending=str(console))
    return result


def verify_dual_log(result):
    log = Path(result.pop('fault_log_pending')).read_text(encoding='utf-8',
                                                          errors='replace')
    parsed = [(int(status, 16), int(address, 16)) for status, address in
              re.findall(r'with DFSR (\w+) DFAR (\w+)', log)]
    require(not parsed,
            'The dual run reached a data-abort boundary: ' +
            str([[hex(status), hex(address)] for status, address in parsed]))
    events = log.count('Taking exception')
    require(events > 100, 'Dual boot lacked kernel activity')
    console = Path(result.pop('console_pending')).read_bytes()
    result.update(exception_events=events,
                  irqs=len(re.findall(r'Taking exception 5 \[IRQ\]', log)),
                  observed_faults=[], console_bytes=len(console))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--seconds', type=float, default=60)
    args = parser.parse_args()
    try:
        args.destination.mkdir(parents=True, exist_ok=False)
        images = dict(master=args.master.read_bytes(), slave=args.slave.read_bytes())
        structures = {role: analyze_eg(image, role) for role, image in images.items()}
        profiles = {role: kernel_profile(image, structures[role], role)
                    for role, image in images.items()}
        process = remote = None
        try:
            process, remote = dual_machine(args.qemu, args.destination,
                                           images['master'], images['slave'],
                                           args.destination/'console.txt')
            result = trace_dual(remote, args.destination/'console.txt',
                                args.destination/'qemu.log', args.seconds)
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
        verify_dual_log(result)
        report = dict(format=1, contexts=[dict(
            role='dual', passed=True,
            master_sha256=structures['master']['sha256'],
            slave_sha256=structures['slave']['sha256'],
            scenarios={'dual-natural-boot': result})],
            qemu_version=subprocess.check_output(
                [args.qemu, '--version'], text=True).splitlines()[0],
            assumptions=['Both engines execute in one machine through private '
                'address-space views and shared communication RAM aliases.',
                'Original images and reset paths; the debugger does not patch '
                'guest registers, code or runtime tables.',
                'The board retains experimental peer descriptor defaults; '
                'the complete response protocol remains unverified.',
                'Timer and message notifications use recovered interrupt paths; '
                'transport timing and lane transfers remain unverified.',
                'Full startup, display initialization and menus remain pending.'],
            full_boot_verified=False, menu_verified=False, passed=True)
        (args.destination/'report.json').write_text(
            json.dumps(report, indent=2)+'\n', encoding='utf-8')
        print('Report:', args.destination/'report.json')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
