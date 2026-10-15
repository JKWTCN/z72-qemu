# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise supply records, checksums and bounded writes through the controller."""
import argparse
from pathlib import Path
import tempfile
from test_controller_gpio import run
from analyze.decode_z72 import require


def check_supply(remote, access):
    base = 0x40005800

    def read(offset):
        return access(base + offset, opcode=0x104)

    def start(receiving=False):
        access(base, 0x501)
        require(read(20) & 1, 'Supply START did not complete')
        access(base + 16, 0x70 | receiving)
        require(read(20) & 2, 'Supply address was not acknowledged')
        read(24)

    def send(value, accepted=True):
        access(base + 20, 0xfffffbff)
        access(base + 16, value)
        require(bool(read(20) & 0x400) != accepted,
                'Supply command or payload acknowledgement differs')

    def stop():
        access(base, 0x201)

    access(base + 4, 25)
    sizes = (9, 1, 1, 2, 1, 3, 0, 2, 1, 16, 2)
    for command, size in enumerate(sizes):
        start()
        send(command, bool(size))
        if not size:
            stop()
            continue
        start(True)
        values = []
        for _ in range(size + 1):
            values.append(read(16))
        stop()
        expected = [(command * 16 + i) & 0xff for i in range(size)]
        require(values == expected + [sum(expected) & 0xff],
                'Supply response payload or additive checksum differs')
    for command in range(0xa0, 0xa9):
        length = 2 if command == 0xa6 else 1
        start()
        send(command)
        payload = [0xfe, 5][:length]
        for value in payload:
            send(value)
        send(sum(payload) & 0xff)
        send(0, False)
        stop()
        start()
        send(command)
        for value in payload:
            send(value)
        send((sum(payload) + 1) & 0xff, False)
        # A malformed transaction must stay rejected without index wraparound.
        for _ in range(260 if command == 0xa0 else 1):
            send(0, False)
        stop()
    for command in (0x0b, 0x9f, 0xa9, 0xff):
        start()
        send(command, False)
        stop()
    # The original supply path receives on DMA1 stream 2, channel 7.
    target = 0x20003004
    remote.write(target - 4, b'HEAD' + bytes(3) + b'TAIL')
    stream = 0x40026040
    access(stream + 4, 3)
    access(stream + 8, base + 16)
    access(stream + 12, target)
    access(stream, 0x0e000401)
    start()
    send(7)
    start(True)
    require(access(stream + 4, opcode=0x104) == 3,
            'Receive DMA ran before its peripheral request was enabled')
    access(base + 4, 0x1832)
    for _ in range(1000):
        if access(0x40026000, opcode=0x104) & (0x20 << 16):
            break
    require(access(stream + 4, opcode=0x104) == 0 and
            remote.read(target - 4, 11) == b'HEAD\x70\x71\xe1TAIL',
            'Supply receive DMA payload, checksum or buffer guards differ')
    stop()
    access(base + 4, 25)
    # Transmit uses stream 7 on the same channel; include the checksum byte.
    stream = 0x400260b8
    remote.write(target, b'\xfe\x05\x03')
    access(stream + 4, 3)
    access(stream + 8, base + 16)
    access(stream + 12, target)
    access(stream, 0x0e000441)
    start()
    send(0xa6)
    access(base + 4, 0x0832)
    for _ in range(1000):
        if access(0x40026004, opcode=0x104) & (0x20 << 22):
            break
    require(access(stream + 4, opcode=0x104) == 0 and not read(20) & 0x400,
            'Supply transmit DMA did not finish a valid checksummed request')
    stop()
    access(base + 4, 25)
    print('PASS supply interface: records, checksums, unsupported commands and bounded writes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        state = Path(directory) / 'supply.bin'
        state.write_bytes(bytes(range(176)))
        run(args.qemu, check_supply, ('-device',
            f'nikon-z72-controller-supply,bus=controller-i2c1,address=56,initial-state={state}'))
