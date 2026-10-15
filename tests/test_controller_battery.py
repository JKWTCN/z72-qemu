# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the synthetic battery peer protocol with synthetic controller loads.

The reply values come from an independent model of the recovered field
arithmetic; the peer must reproduce them from the controller nonce, stay
silent on a mismatched challenge, and answer the follow-up queries.
"""
import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from analyze.qemu_display import Remote

NONCE_ADDRESS = 0x2001F446
PUBLISHED_ADDRESS = 0x2001F458
UART = 0x40011000
BATTERY_ID = b'LAB00001'

# nonce / published challenge / internal value triples from the model.
VECTORS = [
    dict(nonce=b'\x9dy\xb1\xa3\x7f1\x80\x1c\xd1\x1ag\x06\xfb@\xd6\xbd\x00\x00',
         pub=b"\xe3\xb1CA\x00\x86\x0c}\xdd\xab'\xb7\xbeg\xca$\x06\x00",
         internal=b'\xaa$\x1d?\xea\xe5[W,\xde\x7fW\xc7|r\x08\x07\x00'),
    dict(nonce=b'WRhF\x90;\xb1>\xdeV$9\xe9\xc1\xb8#\x00\x00',
         pub=b'\xfd\xb0\x12\xa4w\xb2 \r\xa3W\xa7/<@\x92\xb2\x02\x00',
         internal=b'\xd6>7v\xfd2\x06\xf4\xcc&\x8c*\xfe\xe7\xa4\xc9\x06\x00'),
    dict(nonce=b")\xbaO\x7fy)'\xf3\xfb+\xdcvn{\xe1\x95\x00\x00",
         pub=b'\x07nr\xbe\xe2\xd20\x91F]\xdce\xb9ma\xc4\x07\x00',
         internal=b'\x8dD\x06\x00\x85\xba\xa5;\xbdu\rg\xe4\xe8\xdeX\x05\x00'),
]


def xor_checksum(data):
    value = 0
    for byte in data:
        value ^= byte
    return value


def harness(qemu, machine, checks):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        image = bytearray(0x200)
        struct.pack_into('<2I', image, 0, 0x20001000, 0x08000101)
        for vector in (3, 4, 5, 6):
            struct.pack_into('<I', image, vector * 4, 0x08000121)
        for offset, opcode in ((0x100, 0x6001), (0x104, 0x6802),
                               (0x108, 0x7001), (0x10c, 0x8001), (0x120, 0xe7fe)):
            struct.pack_into('<H', image, offset, opcode)
        (root / 'synthetic.bin').write_bytes(image)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        remote = process = None
        try:
            with (root / 'qemu.log').open('wb') as log:
                process = subprocess.Popen(
                    [qemu, '-M', machine, '-kernel', str(root / 'synthetic.bin'),
                     '-display', 'none', '-serial', 'none', '-monitor', 'none',
                     '-nic', 'none', '-S', '-gdb', f'tcp:127.0.0.1:{port}'],
                    stdout=subprocess.DEVNULL, stderr=log,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            deadline = time.monotonic() + 10
            while remote is None:
                try:
                    remote = Remote(port)
                except ConnectionRefusedError:
                    require(process.poll() is None and time.monotonic() < deadline,
                            'Synthetic controller startup failed')
                    time.sleep(.05)

            def access(address, value=0, opcode=0x100):
                remote.set(r0=address, r1=value, pc=0x08000000 + opcode)
                remote.command('s')
                regs = remote.regs()
                require(remote.get(regs, 'pc') == 0x08000002 + opcode,
                        'Synthetic uart access faulted')
                return remote.get(regs, 'r2')

            checks(remote, access)
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


def receive(remote, access, count, limit=400):
    data = bytearray()
    for _ in range(limit):
        status = access(UART, opcode=0x104)
        if status & 0x20:
            data.append(access(UART + 4, opcode=0x104) & 0xff)
            if len(data) == count:
                return bytes(data)
            continue
        # Run an idle instruction loop so virtual line timing can advance.
        remote.set(pc=0x08000120)
        timeout = remote.sock.gettimeout()
        remote.sock.settimeout(.003)
        try:
            remote.command('c')
        except TimeoutError:
            remote.interrupt()
        finally:
            remote.sock.settimeout(timeout)
    return bytes(data)


def check(remote, access):
    access(UART + 12, 0x200c)
    for vector in VECTORS:
        remote.write(NONCE_ADDRESS, vector['nonce'])
        remote.write(PUBLISHED_ADDRESS, vector['pub'])
        request = bytes((2, 1, 0x11)) + vector['pub'][:17]
        request += bytes((xor_checksum(request),))
        for byte in b'\x00' + request:
            access(UART + 4, byte)
        reply = receive(remote, access, 29)
        expected = bytearray(29)
        expected[0] = 2
        expected[1] = 6
        expected[3:11] = vector['internal'][:8]
        expected[11] = 1
        expected[28] = xor_checksum(expected[:28])
        require(reply == bytes(expected),
                'Authentication reply differs from the model value')

    # A request whose challenge does not match the stored round stays
    # unanswered and the original receive path observes no data.
    vector = VECTORS[0]
    remote.write(NONCE_ADDRESS, vector['nonce'])
    remote.write(PUBLISHED_ADDRESS, vector['pub'])
    altered = bytes((2, 1, 0x11)) + bytes([vector['pub'][0] ^ 1]) + vector['pub'][1:17]
    altered += bytes((xor_checksum(altered),))
    for byte in altered:
        access(UART + 4, byte)
    require(receive(remote, access, 1, limit=60) == b'',
            'Peer answered a request with a mismatched challenge')

    # Follow-up status query.
    request = bytes((2, 0x0c, 0, xor_checksum(bytes((2, 0x0c, 0)))))
    for byte in request:
        access(UART + 4, byte)
    reply = receive(remote, access, 16)
    expected = bytearray(16)
    expected[0] = 2
    expected[1] = 6
    expected[3:11] = BATTERY_ID
    expected[11] = 1
    expected[13] = 0x28
    expected[15] = xor_checksum(expected[:15])
    require(reply == bytes(expected), 'Status reply differs from the record form')

    # Acknowledgement query.
    request = bytes((2, 0x0e, 1, 0, xor_checksum(bytes((2, 0x0e, 1, 0)))))
    for byte in request:
        access(UART + 4, byte)
    reply = receive(remote, access, 5)
    expected = bytearray(5)
    expected[0] = 2
    expected[1] = 6
    expected[4] = xor_checksum(expected[:4])
    require(reply == bytes(expected), 'Acknowledgement reply differs')

    def exchange(command, payload, size):
        request = bytes((2, command, len(payload))) + payload
        request += bytes((xor_checksum(request),))
        for byte in request:
            access(UART + 4, byte)
        reply = receive(remote, access, size)
        require(len(reply) == size and reply[:2] == b'\x02\x06' and
                xor_checksum(reply) == 0, 'Query reply framing differs')
        return reply

    metadata = exchange(0x0a, b'', 35)
    require(struct.unpack_from('<2H', metadata, 12) == (2000, 2000),
            'Experimental capacity fields differ')
    measurement = exchange(0x0b, b'', 14)
    require(measurement[3] == 80 and
            struct.unpack_from('<H', measurement, 6)[0] == 8000 and
            measurement[12] == 25, 'Experimental measurement fields differ')
    for command, payload in ((2, b'\x00\x00'), (7, b''), (0x89, bytes(14))):
        exchange(command, payload, 4)
    for request in (b'\x02\x0c\x00\x00', b'\x02\x77\x00\x75'):
        for byte in request:
            access(UART + 4, byte)
        require(receive(remote, access, 1, limit=20) == b'',
                'Invalid or unsupported request received a reply')
    exchange(0x0c, b'', 16)
    # A reset must discard a partial request and queued response bytes.
    for byte in b'\x02\x0c\x00\x0e':
        access(UART + 4, byte)
    for byte in b'\x02\x01\x11':
        access(UART + 4, byte)
    require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
            'Battery peer reset failed')
    access(UART + 12, 0x200c)
    require(receive(remote, access, 1, limit=20) == b'',
            'Reset retained a pending battery response')
    exchange(0x0c, b'', 16)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    harness(args.qemu, 'nikon-z72-controller-lab,battery-peer=on', check)
    print('PASS controller battery peer: authentication replies match the '
          'model, mismatches stay silent, follow-up queries answered')
