# SPDX-License-Identifier: GPL-2.0-or-later
"""Check DMA roots, actual bytes, IRQ acknowledgement, cancellation and errors."""
import argparse
import json
import re
import socket
import struct
import subprocess
import time


def run(qemu, machine='nikon-z72-dual-lab,controller-link=off', role='master'):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        wire_port = listener.getsockname()[1]
    source, destination = 0x2c080000, 0x2c080100
    slave = bytes(range(32, 48))
    dual = machine.startswith('nikon-z72-dual-lab')
    # Seed private RAM, rather than MMIO which device reset can clear later.
    slave_setup = [(source, int.from_bytes(slave[:8], 'little'), 8),
                   (source + 8, int.from_bytes(slave[8:], 'little'), 8),
                   (destination, 0x5c5c5c5c5c5c5c5c, 8),
                   (destination + 8, 0x5c5c5c5c5c5c5c5c, 8)] if dual else []
    loaders = [part for address, value, size in slave_setup for part in
               ('-device', f'loader,addr={address:#x},data={value:#x},'
                f'data-len={size},cpu-num=2')]
    process = subprocess.Popen([qemu, '-M', machine,
        '-accel', 'qtest', '-display', 'none', '-serial', 'none', '-monitor', 'none',
        '-qmp', 'stdio', '-global', 'nikon-z72-boot-config.peripheral-dma=on',
        '-qtest', f'tcp:127.0.0.1:{wire_port},server=on,wait=off',
        '-qtest-log', '/dev/null', *loaders],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wire = stream = None
    passed = False
    try:
        deadline = time.monotonic() + 15
        while wire is None:
            try:
                wire = socket.create_connection(('127.0.0.1', wire_port), timeout=3)
            except OSError:
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read().decode())
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.05)
        stream = wire.makefile('rwb')
        assert 'QMP' in json.loads(process.stdout.readline())
        irq = {}

        def command(line):
            stream.write(line.encode() + b'\n')
            stream.flush()
            while True:
                reply = stream.readline().decode().split()
                if reply and reply[0] == 'IRQ':
                    irq[int(reply[2])] = reply[1] == 'raise'
                    continue
                assert reply and reply[0] == 'OK', reply
                return int(reply[1], 0) if len(reply) > 1 else None

        def monitor(name, **arguments):
            process.stdin.write(json.dumps(dict(execute=name, arguments=arguments)).encode() + b'\n')
            process.stdin.flush()
            while True:
                reply = json.loads(process.stdout.readline())
                if 'event' not in reply:
                    assert 'return' in reply, reply
                    return reply['return']

        def read(address):
            return command(f'readl {address:#x}')

        def write(address, value):
            command(f'writel {address:#x} {value:#x}')

        def put(address, data):
            stream.write(f'write {address:#x} {len(data):#x} 0x{data.hex()}\n'.encode())
            stream.flush()
            assert stream.readline().strip() == b'OK'

        def get(address, length, cpu=0):
            text = monitor('human-monitor-command', **{
                'command-line': f'x /{length}bx {address:#x}', 'cpu-index': cpu})
            return bytes(int(value, 16) for line in text.splitlines() if ':' in line
                         for value in re.findall(r'0x[0-9a-fA-F]+', line.split(':', 1)[1]))

        base = 0x2c020000
        ca, cb = base + 0x10, base + 0x14

        def transfer(start=source, end=destination, count=4, width=2,
                     selection=0, fixed=False):
            write(base, 0x90000000)
            write(cb, (width << 26) | 0x180000 | ((1 << 25) if fixed else 0))
            write(base + 0x18, start)
            write(base + 0x1c, end)
            write(ca, 0x80000000 | ((selection << 24) if selection else 0x20000000) |
                  (count - 1))

        monitor('qmp_capabilities')
        command(f'irq_intercept_out /machine/{role}-hdmac0 sysbus-irq')
        master = bytes(range(16))
        put(source, master)
        put(destination, bytes([0xa5] * 32))
        transfer()
        command('clock_step 1000')
        assert read(cb) >> 16 & 7 == 5, monitor('qom-get',
            path=f'/machine/{role}-hdmac0', property='runtime')
        assert irq.get(0), irq
        assert get(destination, 16) == master
        write(cb, read(cb) & ~0x1f0000)
        command('clock_step 1')
        assert not irq[0]
        if dual:
            assert get(source, 16, cpu=2) == slave
            assert get(destination, 16, cpu=2) == bytes([0x5c] * 16)
            cpus = monitor('query-cpus-fast')
            slave_cpu = next(cpu for cpu in cpus if cpu['cpu-index'] == 2)
            assert monitor('qom-get', path='/machine/slave-hdmac0', property='memory') == monitor(
                'qom-get', path=slave_cpu['qom-path'], property='memory')
        assert get(destination, 16) == master

        for width in (0, 1, 2):
            transfer(count=4, width=width, fixed=True)
            command('clock_step 1000')
            assert read(cb) >> 16 & 7 == 5
            assert get(destination, 4 << width) == master[:1 << width] * 4
            write(cb, read(cb) & ~0x1f0000)

        # An unconnected external request cannot touch its destination.
        put(destination, bytes([0x5a] * 16))
        transfer(selection=31)
        command('clock_step 1000000')
        assert read(ca) & 0x80000000 and not read(cb) & 0x70000
        assert get(destination, 16) == bytes([0x5a] * 16)
        write(base, 0)
        assert read(cb) >> 16 & 7 == 2 and not read(ca) & 0x80000000

        for start, end, expected in ((0x08000000, destination, 3),
                                     (source, 0x08000000, 4)):
            write(cb, read(cb) & ~0x1f0000)
            transfer(start=start, end=end)
            command('clock_step 1000')
            assert read(cb) >> 16 & 7 == expected, monitor('qom-get',
                path=f'/machine/{role}-hdmac0', property='runtime')

        # A genuine MMIO write that cancels this transfer must retain cancellation.
        write(cb, read(cb) & ~0x1f0000)
        put(source, struct.pack('<2I', 0, 0x90000000))
        transfer(end=base, count=2)
        command('clock_step 1000')
        assert read(base) == 0 and read(cb) >> 16 & 7 == 2

        # Draining via bank 0 must leave bank 1 seeing RX empty as well.
        spi, bank1 = 0x2c0a0000, 0x2c030000
        write(spi + 0x10, 15 << 8)
        write(spi + 0x0c, 0x420)
        write(spi + 0x3c, 1)
        write(base, 0x90000000)

        def receive(bank, channel, target):
            address = bank + 0x10 + channel * 16
            write(bank, 0x90000000)
            write(address + 4, 0x06180000)
            write(address + 8, spi + 4)
            write(address + 12, target)
            write(address, 0x84000000)
            return address

        first = receive(base, 1, destination + 16)
        write(spi, 0x1234)
        command('clock_step 100001')
        assert read(first + 4) >> 16 & 7 == 5
        assert read(spi + 0x14) & 0x20
        second = receive(bank1, 0, destination + 18)
        command('clock_step 1')
        assert read(second) & 0x80000000 and not read(second + 4) & 0x70000, monitor(
            'qom-get', path=f'/machine/{role}-hdmac1', property='runtime')
        write(spi, 0x5678)
        command('clock_step 100001')
        assert read(second + 4) >> 16 & 7 == 5
        assert get(destination + 16, 4) == b'\xff' * 4

        write(cb, read(cb) & ~0x1f0000)
        transfer(selection=31)
        monitor('system_reset')
        command('clock_step 1000000')
        assert read(base) == read(ca) == read(cb) == 0
        assert get(destination, 16) == bytes([0x5a] * 16)
        passed = True
    finally:
        if stream is not None:
            stream.close()
        if wire is not None:
            wire.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        process.stdin.close()
        process.stdout.close()
        if not passed:
            print(process.stderr.read().decode(), flush=True)
        process.stderr.close()
    print(f'PASS {role} DMA: bytes/widths, IRQ ack, demand, faults, self-cancel and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    qemu = parser.parse_args().qemu
    run(qemu)
    run(qemu, 'nikon-z72-slave-lab', 'slave')
