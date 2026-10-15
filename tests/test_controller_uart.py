# SPDX-License-Identifier: GPL-2.0-or-later
"""Check controller UART routing, bidirectional bytes and interrupt masking."""
import argparse
from pathlib import Path
import socket
import tempfile
import time
from test_controller_gpio import run
from analyze.decode_z72 import require


def check_port(remote, access, base, irq):
    irq_bit = 1 << (irq - 32)
    def read(address):
        return access(address, opcode=0x104)
    require(read(base) == 0xc0 and read(base + 12) == 0, 'Controller UART reset differs')
    access(base + 8, 0x1b2)
    require(read(base + 8) == 0x1b2, 'Controller UART baud configuration differs')
    access(base + 12, 0x2088)
    require(read(0xe000e204) & irq_bit, 'Controller UART TXE interrupt was not routed')
    access(base + 12, 0x2008)
    access(0xe000e284, irq_bit)
    require(not read(0xe000e204) & irq_bit, 'Masked controller UART interrupt remained pending')
    access(base, 0)
    require(read(base) == 0x80, 'UART status write cleared the hardware TXE flag')
    for byte in b'Z72':
        access(base + 4, byte)
    require(read(base) == 0xc0, 'Controller UART did not retain transmit completion')
    access(base + 12, 0x2048)
    require(read(0xe000e204) & irq_bit, 'Controller UART TC interrupt was not routed')
    access(base, 0)
    access(0xe000e284, irq_bit)
    require(not read(0xe000e204) & irq_bit, 'UART completion acknowledgement failed')
    require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK', 'Controller UART reset failed')
    require(read(base) == 0xc0 and read(base + 8) == 0 and read(base + 12) == 0,
            'Reset retained controller UART configuration')


def check(remote, access, peer):
    for base, irq in ((0x40004400, 38), (0x40011000, 37)):
        check_port(remote, access, base, irq)
    require(b''.join(peer.recv(1) for _ in range(3)) == b'Z72',
            'Battery UART output did not reach its own backend')
    base = 0x40011000
    irq_bit = 1 << 5
    access(base + 12, 0x200c)
    access(0xe000e284, irq_bit)
    peer.sendall(b'\xa5')
    for _ in range(20):
        if access(base, opcode=0x104) & 0x20:
            break
        time.sleep(0.01)
    require(access(base, opcode=0x104) & 0x20, 'Battery UART did not receive its peer byte')
    require(not access(0x40004400, opcode=0x104) & 0x20,
            'Battery input reached the console UART')
    require(not access(0xe000e204, opcode=0x104) & irq_bit,
            'Masked battery receive interrupt became pending')
    access(base + 12, 0x202c)
    require(access(0xe000e204, opcode=0x104) & irq_bit,
            'Battery receive interrupt was not routed to IRQ37')
    require(access(base + 4, opcode=0x104) == 0xa5, 'Battery UART received a different byte')
    access(0xe000e284, irq_bit)
    require(not access(base, opcode=0x104) & 0x20 and
            not access(0xe000e204, opcode=0x104) & irq_bit,
            'Reading battery data did not acknowledge reception')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
        output = Path(directory) / 'console.txt'
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        def connected_check(remote, access):
            with listener.accept()[0] as peer:
                peer.settimeout(3)
                check(remote, access, peer)
        run(args.qemu, connected_check,
            ('-chardev', 'file,id=controller-console,path=' + str(output),
             '-chardev', f'socket,id=controller-battery,host=127.0.0.1,port={listener.getsockname()[1]}'))
        require(output.read_bytes() == b'Z72', 'Controller UART did not emit the submitted bytes')
    print('PASS controller UARTs: separate backends, receive bytes, status, IRQ37/38, masks and reset')
