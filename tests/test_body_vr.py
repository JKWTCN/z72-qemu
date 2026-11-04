# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise body VR memory traffic through physical CS, SPI and HDMAC."""
import argparse
import json
import socket
import struct
import subprocess
import time


def request(code=0xd0, flag=0, data=b'', address=0, size=None, key=0xaa55):
    result = bytearray(276 if (size or len(data)) > 128 else 152)
    struct.pack_into('<BBH', result, 0, code, flag, (len(data) if size is None else size) + 16)
    if code in (0xf1, 0xf2) and flag == 0:
        struct.pack_into('<HH', result, 4, key, address)
    result[20:20 + len(data)] = data
    if code == 0xf1:
        result[8] = -sum(result[4:]) & 255
    return result


def run(qemu):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen([qemu, '-M', 'nikon-z72-lab', '-accel', 'qtest',
        '-display', 'none', '-serial', 'none', '-monitor', 'none', '-qmp', 'stdio',
        '-global', 'nikon-z72-boot-config.virtual-body-vr=on',
        '-global', 'nikon-z72-body-vr.work-delay-ns=1000000',
        '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off', '-qtest-log', '/dev/null'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wire = stream = None
    try:
        deadline = time.monotonic() + 15
        while wire is None:
            try:
                wire = socket.create_connection(('127.0.0.1', port), timeout=3)
            except OSError:
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read().decode())
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.05)
        stream = wire.makefile('rwb')
        assert 'QMP' in json.loads(process.stdout.readline())

        def monitor(name, **arguments):
            process.stdin.write(json.dumps(dict(execute=name, arguments=arguments)).encode() + b'\n')
            process.stdin.flush()
            while True:
                reply = json.loads(process.stdout.readline())
                if 'event' not in reply:
                    assert 'return' in reply, reply
                    return reply['return']

        def command(line):
            stream.write(line.encode() + b'\n')
            stream.flush()
            reply = stream.readline().decode().split()
            assert reply and reply[0] == 'OK', reply
            return reply[1] if len(reply) > 1 else None

        def read(address):
            return int(command(f'readl {address:#x}'), 0)

        def write(address, value):
            command(f'writel {address:#x} {value:#x}')

        def advance(ns):
            command(f'clock_step {ns}')

        def diagnostic(name):
            return monitor('qom-get', path='/machine/master-body-vr', property=name)

        base, cs = 0x2c0a0400, 0x0428202c

        def exchange(data, dma=False):
            write(cs, 0x20000)
            write(base + 0x10, (15 if dma else 7) << 8)
            write(base + 0x0c, 0x420 if dma else 0x20)
            write(base + 0x3c, 1)
            if dma:
                source, target = 0xb7c10000, 0xb7c14000
                command(f'write {source:#x} {len(data):#x} 0x{data.hex()}')
                write(0x2c020000, 0x90000000)
                for channel, start, end, selection, control in (
                        (5, base + 4, target, 12, 0x26180000),
                        (4, source, base, 11, 0x25180000)):
                    reg = 0x2c020010 + 16 * channel
                    write(reg + 4, control)
                    write(reg + 8, start)
                    write(reg + 12, end)
                    write(reg, 0x80000000 | selection << 24 | (len(data) // 2 - 1))
                for _ in range(len(data) + 64):
                    advance(4000)
                    if not (read(0x2c020050) | read(0x2c020060)) & 0x80000000:
                        break
                assert read(0x2c020054) >> 16 & 7 == 5
                assert read(0x2c020064) >> 16 & 7 == 5
                result = bytes.fromhex(command(f'read {target:#x} {len(data):#x}').removeprefix('0x'))
                write(0x2c020054, 0x25000000)
                write(0x2c020064, 0x26000000)
            else:
                result = bytearray()
                for value in data:
                    write(base, value)
                    advance(2000)
                    result.append(read(base + 4))
            write(base + 0x3c, 0)
            write(cs, 0x20002)
            return bytes(result)

        def read_memory(address, size, dma=False):
            exchange(request(0xf2, address=address, size=size), dma=dma)
            advance(2000000)
            result = exchange(request(0xf2, flag=1), dma=dma)
            assert struct.unpack_from('<H', result, 2)[0] == size + 16
            assert struct.unpack_from('<HH', result, 4) == (0xaa55, address)
            assert (sum(result[4:9]) + sum(result[20:20 + size])) & 255 == 0
            assert not any(result[9:20])
            return result[20:20 + size]

        monitor('qmp_capabilities')
        write(cs, 0x20002)
        write(cs, 0)
        assert read(cs) & 2
        write(cs, 0x10001)
        assert read(cs) & 3 == 3
        assert diagnostic('frames') == 0
        assert 'sensor-connected=0 actuator-connected=0' in diagnostic('runtime')
        assert not any(exchange(request())[8:])

        data = bytes((i * 31 + 7) & 255 for i in range(128))
        exchange(request(0xf1, data=data, address=0x120), dma=True)
        assert diagnostic('writes') == 0 and 'busy=1' in diagnostic('runtime')
        busy = exchange(request())
        assert busy[1] & 1
        advance(2000000)
        assert diagnostic('writes') == 1 and 'busy=0' in diagnostic('runtime')
        assert read_memory(0x120, 128, dma=True) == data
        assert not any(exchange(request())[8:])

        malformed = request(0xf1, data=b'changed', address=0x120)
        malformed[8] ^= 1
        exchange(malformed)
        advance(2000000)
        assert diagnostic('rejected') == 1 and diagnostic('writes') == 1
        assert read_memory(0x120, 7) == data[:7]
        exchange(request(0xf1, data=b'bad', address=0x3fff))
        exchange(request(0xf2, address=0, size=1, key=0x55aa))
        exchange(request(0xfa))
        assert diagnostic('rejected') == 4

        exchange(request(0xf1, data=b'new', address=0x220)[:4])
        advance(2000000)
        assert diagnostic('truncated') == 1 and diagnostic('writes') == 1
        assert read_memory(0x220, 3) == b'\0' * 3

        exchange(request(0xf1, flag=4, data=bytes(range(66))))
        advance(2000000)
        assert diagnostic('configuration-generation') == 1
        assert read_memory(0x120, 7) == data[:7]
        long_data = bytes(range(256))
        exchange(request(0xf1, data=long_data, address=0x300), dma=True)
        advance(2000000)
        # The long reply needs the full transfer window to be consumed.
        exchange(request(0xf2, address=0x300, size=256)[:152], dma=True)
        advance(2000000)
        response = exchange(request(0xf2, flag=1, size=256), dma=True)
        assert response[20:276] == long_data and not any(response[9:20])

        exchange(request(0xf2, address=0x300, size=128), dma=True)
        advance(2000000)
        exchange(request(0xf2, flag=1)[:8])
        assert 'reply-pending=1' in diagnostic('runtime')
        response = exchange(request(0xf2, flag=1), dma=True)
        assert response[20:148] == long_data[:128]
        assert 'reply-pending=0' in diagnostic('runtime')

        exchange(request(0xf1, data=b'first', address=0x600))
        exchange(request(0xf1, data=b'later', address=0x600))
        advance(2000000)
        assert read_memory(0x600, 5) == b'first'
        rejected = diagnostic('rejected')
        exchange(bytes(278))
        invalid = request(0xf1)
        struct.pack_into('<H', invalid, 2, 15)
        exchange(invalid)
        assert diagnostic('rejected') == rejected + 2
        assert diagnostic('truncated') == 4
        control = request(0xd2)
        struct.pack_into('<H', control, 2, 1)
        exchange(control)
        assert diagnostic('rejected') == rejected + 3
        assert diagnostic('truncated') == 4
        exchange(request(0xf2, address=0x3000, size=1))
        exchange(request(0xf2, address=0x2fff, size=2))
        assert diagnostic('rejected') == rejected + 5
        assert diagnostic('truncated') == 4

        exchange(request(0xf1, data=b'cancelled', address=0x300))
        assert 'busy=1' in diagnostic('runtime')
        monitor('system_reset')
        advance(2000000)
        assert diagnostic('frames') == diagnostic('writes') == 0
        assert diagnostic('configuration-generation') == 0
        assert read_memory(0x300, 9) == bytes(9)
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
        process.stderr.close()
    print('PASS body VR: physical CS, DMA readback, deferred writes, checksums, bounds, rejection and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    run(parser.parse_args().qemu)
