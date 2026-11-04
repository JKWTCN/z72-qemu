# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the finite lens through real SPI FIFOs, phase GPIO and history RX."""
import argparse
import json
import socket
import struct
import subprocess
import time


def packet(size, data=b''):
    result = bytearray(size)
    result[0] = 0x55
    result[1:1 + len(data)] = data
    result[-1] = -sum(result[:-1]) & 255
    return result


def run(qemu):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen([qemu, '-M', 'nikon-z72-lab', '-accel', 'qtest',
        '-display', 'none', '-serial', 'none', '-monitor', 'none', '-qmp', 'stdio',
        '-global', 'nikon-z72-boot-config.virtual-lens=on',
        '-global', 'nikon-z72-spi.peer-low-byte-first=on',
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
            return int(reply[1], 0) if len(reply) > 1 else None

        def read(address):
            return command(f'readl {address:#x}')

        def write(address, value):
            command(f'writel {address:#x} {value:#x}')

        def advance(ns):
            command(f'clock_step {ns}')

        def diagnostic(name):
            return monitor('qom-get', path='/machine/master-lens', property=name)

        base = 0x2c0a0300
        receiver = 0x2c0a0200

        def setup():
            write(base + 0x10, 7 << 8)
            write(base + 0x0c, 0x20)
            write(base + 0x3c, 1)
            write(receiver + 0x10, 15 << 8)
            write(receiver + 0x4c, 1)
            write(receiver + 0x3c, 1)

        def exchange(data):
            result = bytearray()
            for value in data:
                write(base, value)
                advance(2000)
                assert not read(base + 0x14) & 0x20
                result.append(read(base + 4))
            return result

        def dma_exchange(data):
            source, target = 0xb7c10000, 0xb7c14000
            stream.write(f'write {source:#x} {len(data):#x} 0x{data.hex()}\n'.encode())
            stream.flush()
            assert stream.readline().strip() == b'OK'
            write(base + 0x10, 15 << 8)
            write(base + 0x0c, 0x420)
            write(0x2c020000, 0x90000000)
            for channel, start, end, selection, control in (
                    (1, base + 4, target, 10, 0x26180000),
                    (0, source, base, 9, 0x25180000)):
                address = 0x2c020010 + 16 * channel
                write(address + 4, control)
                write(address + 8, start)
                write(address + 12, end)
                write(address, 0x80000000 | (selection << 24) | (len(data) // 2 - 1))
            for _ in range(len(data) + 64):
                advance(4000)
                if not (read(0x2c020010) | read(0x2c020020)) & 0x80000000:
                    break
            assert read(0x2c020014) >> 16 & 7 == 5
            assert read(0x2c020024) >> 16 & 7 == 5
            write(0x2c020014, 0x25000000)
            write(0x2c020024, 0x26000000)
            stream.write(f'read {target:#x} {len(data):#x}\n'.encode())
            stream.flush()
            reply = stream.readline().decode().split()
            assert reply[0] == 'OK'
            result = bytes.fromhex(reply[1].removeprefix('0x'))
            write(base + 0x0c, 0x20)
            write(base + 0x10, 7 << 8)
            return result

        sequence = 0

        def request(code, size, data=b'', sub=0, mode=0, dma=False):
            nonlocal sequence
            header = bytearray([0x55, sequence, mode, code, sub, 0, 0, 0])
            struct.pack_into('<H', header, 5, (size - 2) // 2)
            header[-1] = -sum(header[:-1]) & 255
            sequence = (sequence + 1) & 255
            write(0x0426f010, 1 << 9)
            assert not read(0x0426f008) & (1 << 9)
            exchange(header)
            assert read(0x04282018) & 1
            advance(1000000)
            assert not read(0x04282018) & 1
            assert read(0x0426f008) & (1 << 9)
            write(0x0426f010, 1 << 9)
            assert not read(0x0426f008) & (1 << 9)
            result = (dma_exchange if dma else exchange)(packet(size, data))
            advance(1000000)
            assert len(result) == size and result[0] == 0x55 and sum(result) & 255 == 0
            return result

        monitor('qmp_capabilities')
        setup()
        assert diagnostic('completed') == 0
        response = request(0x1f, 4, b'\1', mode=0xff)
        assert response[1] == 0 and response[2] == 1
        response = request(0x10, 28)
        assert struct.unpack_from('<H', response, 1)[0] == 0x7ffe
        request(0x11, 74)
        response = request(0x12, 66)
        assert struct.unpack_from('<2H', response, 1) == (960, 960)
        assert struct.unpack_from('<H', response, 7)[0] == 50
        assert struct.unpack_from('<H', response, 11)[0] == 50
        for sub, size in ((0, 7426), (0x10, 3468)):
            response = request(0x24, size, sub=sub, dma=True)
            assert response[7385 if not sub else 1] == (1 if not sub else 0)
        assert request(0x15, 6)[2] == 1
        request(0x13, 14)
        # Replies snapshot pending state at header acceptance, before its timer ends.
        assert request(0x15, 6)[1] == 1
        assert request(0x15, 6)[1:3] == bytes([0, 0])
        assert diagnostic('configuration-generation') == 1
        request(0x21, 6, struct.pack('<I', 0x12345678))
        assert struct.unpack_from('<I', request(0x27, 6), 1)[0] == 0x12345678
        request(0x50, 4, b'\2')
        assert request(0x51, 4)[1] == 0x80
        assert request(0x51, 4)[1] == 0
        request(0xa3, 4, struct.pack('<H', 192))
        response = request(0x20, 258)
        assert response[203] & 0x18 and response[216] == 3
        assert 0 < diagnostic('aperture-position') < 192
        advance(20000000)
        assert diagnostic('aperture-position') == 192
        assert diagnostic('aperture-generation') == 1
        response = request(0x20, 258)
        assert struct.unpack_from('<H', response, 9)[0] == 1152
        assert struct.unpack_from('<H', response, 197)[0] == 192
        assert not response[203] & 0x18
        request(0x70, 14, b'\0' + struct.pack('<i', 100))
        advance(10000000)
        response = request(0x71, 14)
        assert response[1] == 0 and struct.unpack_from('<i', response, 2)[0] == 100

        request(0x16, 4, b'\1')
        history = bytearray()
        for _ in range(1000):
            advance(4000)
            if not read(receiver + 0x14) & 0x20:
                history += struct.pack('<H', read(receiver + 4))
                if len(history) == 42:
                    break
        assert len(history) == 42 and history[0] == 0x55 and sum(history) & 255 == 0
        assert struct.unpack_from('<i', history, 2)[0] == 100
        assert diagnostic('stream-frames') >= 1
        request(0x16, 4, b'\0')
        before = diagnostic('stream-frames')
        advance(100000000)
        assert diagnostic('stream-frames') == before
        assert diagnostic('rejected') == 0

        # Reject an invalid full packet without committing a new motor target.
        request(0xa3, 4, struct.pack('<H', 1153))
        assert diagnostic('rejected') == 1
        assert diagnostic('aperture-target') == 192
        monitor('system_reset')
        advance(1)
        assert diagnostic('completed') == diagnostic('rejected') == 0
        assert diagnostic('aperture-position') == diagnostic('focus-position') == 0
        assert not diagnostic('aperture-pending') and not diagnostic('focus-pending')
        setup()
        # A complete packet with a bad checksum cannot finish negotiation.
        header = bytearray([0x55, 0, 0xff, 0x1f, 0, 1, 0, 0])
        header[-1] = -sum(header[:-1]) & 255
        exchange(header)
        advance(1000000)
        write(0x0426f010, 1 << 9)
        exchange(bytes([0x55, 1, 0, 0]))
        advance(2000000)
        assert diagnostic('rejected') == 1 and diagnostic('completed') == 0
        assert read(0x04282018) & 1 and not read(0x0426f008) & (1 << 9)
        monitor('system_reset')
        advance(1)
        setup()
        # Unknown commands never publish a phase completion.
        header = bytearray([0x55, 0, 0, 0xfe, 0, 1, 0, 0])
        header[-1] = -sum(header[:-1]) & 255
        exchange(header)
        advance(2000000)
        assert diagnostic('rejected') == 1 and read(0x04282018) & 1
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
    print('PASS virtual lens: complete pages, causal GPIO, configuration, iris, focus, history and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    run(parser.parse_args().qemu)
