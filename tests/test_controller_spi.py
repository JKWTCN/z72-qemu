# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise controller serial words, peer clocks, interrupts and routed DMA."""
import argparse
from test_controller_gpio import run
from analyze.decode_z72 import require


PEER = ('-device', 'nikon-z72-controller-spi-peer,bus=controller-spi0,controller=/machine/spi1')


def check(remote, access):
    master, slave = 0x40013000, 0x40013400
    def read(address):
        return access(address, opcode=0x104)
    def wait(address, mask, value):
        for _ in range(1000):
            if read(address) & mask == value:
                return
        raise ValueError('Serial status or routed DMA did not progress')
    for base in (master, slave):
        require(read(base + 8) == 2 and read(base + 16) == 7 and read(base + 32) == 2,
                'Serial reset values differ')
    for auxiliary, bit in ((0x40003c00, 19), (0x40003800, 4)):
        require(read(auxiliary + 8) == 2, 'Additional serial port reset differs')
        access(auxiliary, 0x344)
        access(auxiliary + 4, 0x40)
        access(auxiliary + 12, 0x72)
        wait(auxiliary + 8, 0x83, 3)
        require(read(0xe000e204) & (1 << bit), 'Additional serial receive interrupt was not routed')
        require(read(auxiliary + 12) == 0, 'Disconnected serial bus response differs')
        access(0xe000e284, 1 << bit)
        require(not read(0xe000e204) & (1 << bit), 'Additional serial receive acknowledgement failed')
        access(auxiliary, 0)
        access(auxiliary + 4, 0)
    # A queued slave word cannot complete without a clock from its peer.
    access(slave, 0x240)
    access(slave + 12, 0x59)
    for _ in range(32):
        require(read(slave + 8) == 0, 'Slave word completed without a peer clock')
    access(master, 0x344)
    access(master + 12, 0xa7)
    wait(master + 8, 0x83, 3)
    require(read(master + 12) == 0x59 and read(slave + 12) == 0xa7 and
            read(slave + 8) == 2, 'Eight-bit peer exchange differs')
    access(master, 0)
    access(slave, 0)
    access(master, 0xb44)
    access(slave, 0xa40)
    access(slave + 12, 0x52ab, opcode=0x10c)
    access(master + 12, 0xc139, opcode=0x10c)
    wait(master + 8, 0x83, 3)
    require(read(master + 12) == 0x52ab and read(slave + 12) == 0xc139,
            'Sixteen-bit peer exchange differs')
    # Unread receive data is retained; DR then SR acknowledges overrun.
    access(master, 0)
    access(slave, 0)
    access(master, 0x344)
    access(slave, 0x240)
    for value in (0x35, 0x46):
        access(master + 12, value)
        wait(master + 8, 0x82, 2)
    require(read(slave + 8) & 0x41 == 0x41 and read(slave + 12) == 0x35,
            'Serial overrun replaced unread data')
    require(read(slave + 8) & 0x40 and not read(slave + 8) & 0x40,
            'Serial overrun acknowledgement sequence differs')
    read(master + 12)
    read(master + 8)
    access(slave + 4, 0x80)
    require(read(0xe000e208) & (1 << 20), 'SPI4 TXE interrupt was not routed')
    access(slave + 4, 0)
    access(0xe000e288, 1 << 20)
    require(not read(0xe000e208) & (1 << 20), 'Masked serial interrupt remained asserted')
    # SPI4 transmit channel 4/stream 1 and SPI1 receive channel 3/stream 0.
    dma = 0x40026400
    tx, rx = 0x20002200, 0x20002400
    payload = bytes((0x31, 0x62, 0x93, 0xc4, 0x15, 0x46, 0x77, 0xa8))
    for index, value in enumerate(payload):
        access(tx + index, value, opcode=0x108)
    for stream, channel, direction, peripheral, memory in (
            (0, 3, 0, master + 12, rx), (1, 4, 1, slave + 12, tx)):
        base = dma + 0x10 + stream * 24
        access(base + 4, len(payload))
        access(base + 8, peripheral)
        access(base + 12, memory)
        access(base, (channel << 25) | (direction << 6) | 0x411)
    access(master + 4, 1)
    access(slave + 4, 2)
    for index in range(len(payload)):
        wait(slave + 8, 2, 0)
        access(master + 12, 0x80 + index)
        wait(master + 8, 0x82, 2)
        require(read(slave + 12) == 0x80 + index, 'Slave did not receive the master word')
    wait(dma, 0x820, 0x820)
    require(remote.read(rx, len(payload)) == payload and read(dma + 0x14) == 0 and
            read(dma + 0x2c) == 0, 'Routed serial DMA data or transfer counts differ')
    access(master + 4, 0)
    access(slave + 4, 0)
    require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
            'Serial reset failed')
    for base in (master, slave):
        require(read(base) == 0 and read(base + 4) == 0 and read(base + 8) == 2,
                'Reset retained serial configuration or status')
    for address, value, opcode in ((master, 0x2040, 0x100),
                                    (master + 4, 0x10, 0x100),
                                    (master + 8, 0, 0x100),
                                    (master + 24, 1, 0x100),
                                    (master + 28, 0x800, 0x100),
                                    (master + 36, 0, 0x104),
                                    (master, 0, 0x108)):
        access(address, value, opcode, fault=True)
        require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                'Serial reset after access fault failed')
    print('PASS controller serial: peer clocks, word widths, overrun, IRQ masks, routed DMA and reset')


def check_disabled(remote, access):
    base = 0x40013000
    access(base, 0x344)
    access(base + 12, 0x71)
    for _ in range(32):
        require(access(base + 8, opcode=0x104) & 0x83 == 0x80,
                'Disabled serial completion published data or ready status')
    access(base, 0)
    require(access(base + 8, opcode=0x104) == 2,
            'Disabling serial port did not cancel the pending word')
    print('PASS disabled controller serial completion')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    run(args.qemu, check, PEER)
    run(args.qemu, check_disabled, PEER + ('-global', 'nikon-z72-controller-spi.completion=off'))
