# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the optional eye register profile through the engine I2C bus."""
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
from tools.smp_boot_probe import reach
from tools.web_console import QmpClient, free_port


def check(qemu):
    image = struct.pack('<6I', 0xe5810000, 0xe5912000, 0xeafffffe,
                        0xe2500001, 0x1afffffd, 0xeafffffe)
    with tempfile.TemporaryDirectory() as folder:
        target = 'nikon-z72-eye,bus=master-i2c2,address=56'
        with reset_machine(qemu, Path(folder) / 'machine', image, 'master',
                           icount='shift=4,sleep=off', devices=(target,)) as remote:
            bus = 0x2c01a000

            def access(offset, value=0, read=False):
                pc = BASE + (4 if read else 0)
                remote.set(pc=pc, cpsr=0xd3, r0=value, r1=bus + offset)
                remote.command('s')
                regs = remote.regs()
                require(remote.get(regs, 'pc') == pc + 4, 'I2C access aborted')
                return remote.get(regs, 'r2')

            def transfer(values=(), count=0, accepted=True):
                access(0, 0x63 if count else 0x62)
                if count:
                    access(20, count)
                else:
                    for value in values:
                        access(12, value)
                access(0, 0x2b if count else 0x2a)
                access(8, 0x38)
                remote.set(pc=BASE + 12, cpsr=0xd3, r0=16384)
                reach(remote, BASE + 20)
                status = access(16, read=True)
                require(bool(status & 4) != accepted, 'Unexpected ACK/NACK')
                if count and accepted:
                    return [access(12, read=True) for _ in range(count)]

            def read(reg, count=1):
                transfer((reg,))
                return transfer(count=count)

            require(read(0x40, 4) == [10, 0, 2, 1], 'Reset defaults differ')
            require(read(0x92, 3) == [0xe0, 0xff, 0xff], 'ID bounds differ')
            transfer(count=1, accepted=False)
            transfer((0x41, 0xc6, 0x25, 0x11))
            require(read(0x41, 3) == [0xc6, 0x25, 0x11], 'Burst write differs')
            transfer((0x53, 0xa5, 0xff))
            require(read(0x53, 4) == [0xa5, 3, 10, 0xc6], 'Pointer wrap differs')
            transfer((0x4a, 0xff))
            require(read(0x4a) == [0x3f], 'Write fabricated interrupt status')
            for reg in (0x44, 0x49, 0x92, 0x3f, 0x55, 0xff):
                transfer((reg, 0xff), accepted=False)
            require(read(0x44, 6) == [0] * 6, 'Writes changed optical samples')
            require(read(0x92) == [0xe0], 'Write changed manufacturer ID')
            transfer((0x40, 0x80))
            require(read(0x40, 4) == [10, 0, 2, 1], 'Software reset failed')
            require(read(0x4b, 10) == [255, 15, 0, 0, 255, 255, 0, 0, 0, 0],
                    'Threshold or offset reset differs')
            transfer((0x41, 0xc6))
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'System reset failed')
            transfer(count=1, accepted=False)
            require(read(0x40, 4) == [10, 0, 2, 1], 'System reset retained state')
    print('PASS eye sensor: ID, bursts, wrap, read-only data, NACK and both resets')


def check_proximity(qemu):
    with tempfile.TemporaryDirectory() as folder:
        disk = Path(folder) / 'scratch.raw'
        disk.write_bytes(bytes(512))
        check_proximity_state(qemu, disk)


def check_proximity_state(qemu, disk):
    bus = 0x2c01a000
    port = free_port()
    with subprocess.Popen([qemu, '-M', 'nikon-z72-lab', '-accel', 'qtest',
                           '-drive', f'if=none,id=scratch,file={disk},format=raw,snapshot=on',
                           '-qmp', f'tcp:127.0.0.1:{port},server=on,wait=off',
                           '-serial', 'none', '-display', 'none',
                           '-qtest', 'stdio', '-qtest-log', '/dev/null', '-device',
                           'nikon-z72-eye,bus=master-i2c2,address=56,proximity=2748'],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as process:
        def command(line):
            process.stdin.write(line + '\n')
            process.stdin.flush()
            reply = process.stdout.readline().split()
            require(reply and reply[0] == 'OK', f'Failed qtest command {line}: {reply}')
            return int(reply[1], 0) if len(reply) > 1 else None

        def transfer(payload=(), count=0, hold=False):
            command(f'writel {bus} {0x63 if count else 0x62}')
            for byte in payload:
                command(f'writel {bus + 12} {byte}')
            if count:
                command(f'writel {bus + 20} {count}')
            control = 0x2b if count else 0x2a
            command(f'writel {bus} {control | (0x10 if hold else 0)}')
            command(f'writel {bus + 8} 0x38')
            command('clock_step 1000')
            require(command(f'readl {bus + 16}') == 3, 'Eye transaction did not complete')
            return [command(f'readl {bus + 12}') for _ in range(count)]

        def sample():
            transfer((0x44,))
            return transfer(count=6)

        try:
            transfer((0x41, 0x41))
            command('clock_step 9997999')
            require(sample() == [0] * 6, 'Early proximity conversion')
            command('clock_step 1')
            require(sample() == [0xbc, 0x0a, 0, 0, 0, 0], 'PS or ALS data differs')
            transfer((0x41, 0))
            require(sample()[:2] == [0xbc, 0x0a], 'Standby lost the last result')
            transfer((0x40, 0x80))
            transfer((0x41, 0x41))
            transfer((0x41, 0x01))
            command('clock_step 10000000')
            require(sample() == [0] * 6, 'Standby kept an interrupted conversion')
            monitor = QmpClient(port)
            try:
                def snapshot(action):
                    reply = monitor.command('human-monitor-command', {'command-line': action})
                    require(not reply, f'{action}: {reply}')

                transfer((0x41, 0x41))
                command('clock_step 6000000')
                transfer((0x53,), hold=True)
                command(f'writel {bus + 16} 3')
                command(f'writel {bus + 12} 0xa5')
                require(command(f'readl {bus + 20}') == 1, 'Write already left the TX FIFO')
                snapshot('savevm eye')
                transfer((0x40, 0x80))
                snapshot('loadvm eye')
                require(command(f'readl {bus + 4}') & 0x100, 'Restored controller lost its held peer')
                command('clock_step 1000')
                require(command(f'readl {bus + 16}') == 3, 'Restored I2C transfer did not complete')
                transfer((0x53,))
                require(transfer(count=1) == [0xa5], 'Restored byte did not reach the selected register')
                require(sample()[:2] == [0, 0], 'Pending sample was published early')
                command('clock_step 4100000')
                require(sample()[:2] == [0xbc, 0x0a], 'Restored conversion lost its deadline')
            finally:
                monitor.close()
        finally:
            process.terminate()
    print('PASS eye proximity: conversion deadline, standby, ALS isolation, reset and state restore')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    qemu = parser.parse_args().qemu
    check(qemu)
    check_proximity(qemu)
