#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check graphics upload completion, command errors, cancellation and reset."""
import argparse
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from tools.boot_probe import reset_machine
from tools.web_console import QmpClient, free_port
from tools.smp_boot_probe import reach
from tools.graphics_boot_probe import graphics_observation


def check(qemu):
    image = struct.pack('<11I', 0xe5810000, 0xe5912000, 0xe5c10000,
                        0, 0, 0, 0, 0, 0xe2500001, 0x1afffffd, 0xeafffffe)
    with tempfile.TemporaryDirectory(prefix='z72-graphics-') as directory:
        with reset_machine(qemu, Path(directory) / 'machine', image, 'master',
                           icount='shift=4,sleep=off') as remote:
            def access(address, value=0, read=False, byte=False, fault=False):
                index = 2 if byte else 1 if read else 0
                remote.set(pc=BASE + index * 4, cpsr=0xd3, r0=value, r1=address)
                remote.command('s')
                regs = remote.regs()
                if fault:
                    require(remote.get(regs, 'pc') == 16, 'Invalid graphics access did not abort')
                    return
                require(remote.get(regs, 'pc') == BASE + index * 4 + 4,
                        'Graphics register access failed')
                return remote.get(regs, 'r2') if read else None

            def advance():
                remote.set(pc=BASE + 32, cpsr=0xd3, r0=10000)
                reach(remote, BASE + 40)

            source = 0xb2000800
            remote.write(source, struct.pack('<2I', 0x0040f004, 0x3f800000))
            for channel in range(2):
                base = 0x201810d0 + channel * 16
                access(0x20181020, 0)
                access(base + 4, source)
                access(base + 12, 1)
                access(base, 1)
                require(access(0x20180058, read=True) == 1 << 26,
                        'Queued graphics upload did not report busy')
                advance()
                require(access(base, read=True) == 0 and
                        access(0x20181020, read=True) == 1 and
                        access(0x20180c18, read=True) == 0,
                        'Valid graphics command did not complete')
                require(access(0x20180058, read=True) == 0,
                        'Completed upload retained busy state')
                require(access(0x04001210, read=True) & 2,
                        'Upload completion did not reach interrupt 129')
            access(0x20181020, 0)
            state = graphics_observation(remote)
            require(state['successful_uploads'] == 2 and state['rendered_commands'] == 0 and
                    state['failed_requests'] == 0, 'Graphics observation did not reflect actual uploads')
            remote.write(source, struct.pack('<2I', 7, 0))
            access(0x201810d0, 1)
            advance()
            require(access(0x20180c18, read=True) == 1 and
                    access(0x20181020, read=True) == 0 and
                    access(0x04001210, read=True) & 8,
                    'Malformed graphics command did not report an error on interrupt 131')
            access(0x20180c18, 0)
            access(0x201810d4, 0x04001000)
            access(0x201810d0, 1)
            advance()
            require(access(0x20180c18, read=True) == 1,
                    'Graphics upload read an interrupt-controller region as command memory')
            state = graphics_observation(remote)
            require(state['failed_requests'] == 2 and state['unsupported_commands'] == 1,
                    'Graphics observation lost rejected or malformed requests')
            access(0x20180c18, 0)
            access(0x201810d0, 1)
            access(0x201810d0, 0)
            advance()
            require(access(0x20180c18, read=True) == 0 and
                    access(0x20181020, read=True) == 0,
                    'Cancelled upload performed work')
            access(0x201810d0, 1)
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK', 'Graphics reset failed')
            advance()
            require(access(0x201810d0, read=True) == 0 and
                    access(0x20181020, read=True) == 0 and
                    access(0x20180c18, read=True) == 0,
                    'Reset retained queued graphics work or completion state')
            require(not any(graphics_observation(remote).values()),
                    'Reset retained graphics observation state')
            access(0x20181020, 0, byte=True, fault=True)
    print('PASS graphics: two upload channels, IRQs, malformed input, memory bounds, cancellation and reset')


def check_snapshot(qemu):
    port = free_port()
    with tempfile.TemporaryDirectory() as directory:
        disk = Path(directory) / 'scratch.raw'
        disk.write_bytes(bytes(512))
        with subprocess.Popen([
            qemu, '-M', 'nikon-z72-lab', '-accel', 'qtest', '-display', 'none',
            '-serial', 'none', '-drive', f'if=none,id=scratch,file={disk},format=raw,snapshot=on',
            '-qmp', f'tcp:127.0.0.1:{port},server=on,wait=off',
            '-qtest', 'stdio', '-qtest-log', '/dev/null',
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as process:
            try:
                def command(line):
                    process.stdin.write(line + '\n')
                    process.stdin.flush()
                    reply = process.stdout.readline().split()
                    require(reply and reply[0] == 'OK', f'{line}: {reply}')
                    return int(reply[1], 0) if len(reply) > 1 else None

                def upload(channel, words):
                    data = struct.pack(f'<{len(words)}I', *words)
                    data += bytes(-len(data) % 8)
                    source = 0xb2000800
                    command(f'write {source} {len(data)} 0x{data.hex()}')
                    base = 0x201810d0 + channel * 16
                    command(f'writel {base + 4} {source}')
                    command(f'writel {base + 12} {len(data) // 8}')
                    command(f'writel {base} 1')

                def registers(pairs):
                    words = []
                    for index, value in pairs:
                        words.extend([(index << 16) | 0xf004, value])
                    return words

                one = 0x3f800000
                rectangle = registers([(3, 5), (5, 8), (0x65, 0x100), (0x41, one),
                                       (0x45, one), (0x49, one), (0x5e, one), (6, 1)])
                rectangle += [10, 0x04040402, 0, 0x1003a, 0, 0, 8, 0, 8, 6, 0, 6]
                upload(0, rectangle + registers([(0x85, 1)]) + rectangle)
                command('clock_step 100000')
                upload(0, registers([(0x85, 2)]))
                command('clock_step 60000')

                monitor = QmpClient(port)
                try:
                    for action in ('savevm graphics', 'loadvm graphics'):
                        reply = monitor.command('human-monitor-command', {'command-line': action})
                        require(not reply, f'{action}: {reply}')
                        if action.startswith('savevm'):
                            monitor.command('system_reset')
                            require(command('readl 0x20180058') == 0, 'Reset retained pending upload')
                    command('clock_step 39999')
                    require(command('readl 0x20180058') == 1 << 26, 'Upload completed early')
                    command('clock_step 1')
                    require(command('readl 0x20180058') == 0, 'Upload missed its deadline')
                    for key in (1, 2):
                        target = 0xb2010000 + 4096 * key
                        require(command(f'readl {target + 2 * 8 * 4}') == 0, 'Target already drawn')
                        upload(1, registers([(0x1a3, 0x80008), (0xc0, 7 << 16),
                                             (0xc1, 7 << 16), (0x184, 8), (0x1a4, target),
                                             (0x185, 0xffffffff), (0xa6, key), (0x1a6, 1)]))
                        command('clock_step 100000')
                        require(command('readl 0x20180c18') == 0, 'Path draw failed')
                        require(command(f'readl {target}') == 0 and
                                command(f'readl {target + 2 * 8 * 4}') == 0xffffffff,
                                'Rectangle pixels differ')
                finally:
                    monitor.close()
            finally:
                process.terminate()
    print('PASS graphics snapshot: cached path, active path, timer deadline and rectangle pixels')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    qemu = parser.parse_args().qemu
    check(qemu)
    check_snapshot(qemu)
