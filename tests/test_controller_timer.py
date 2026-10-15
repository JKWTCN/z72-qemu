# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise counter events and shared timer interrupts with synthetic code."""
import argparse
from test_controller_gpio import run
from analyze.decode_z72 import require


def checks(completion):
    def check(remote, access):
        advanced, compare, link, update = 0x40010000, 0x40014800, 0x40001800, 0x40014400
        def read(address):
            return access(address, opcode=0x104)
        def pending():
            return read(0xe000e200)
        def acknowledge():
            access(0xe000e280, 0xffffffff)
        for base in (advanced, compare, link, update):
            require(read(base + 0x2c) == 0xffff and read(base) == 0,
                    'Timer reset state differs')
        capture = 0x40000400
        access(capture + 0x18, 0x101)
        access(capture + 0x1c, 0x101)
        access(capture + 0xc, 0x1f)
        access(capture + 0x2c, 100)
        access(capture, 9)
        for _ in range(1000):
            if not read(capture) & 1:
                break
        require(not read(capture) & 1 and read(capture + 0x10) == (1 if completion else 0),
                'Input capture configuration fabricated capture events')
        require(bool(pending() & (1 << 29)) == completion, 'TIM3 update IRQ routing differs')
        access(capture + 0x10, 0)
        acknowledge()
        wide = 0x40000000
        require(read(wide + 0x2c) == 0xffffffff, 'Wide timer reset period differs')
        access(wide + 0x24, 0xffffffd0)
        access(wide + 0x34, 0xfffffff0)
        require(read(wide + 0x24) == 0xffffffd0 and read(wide + 0x34) == 0xfffffff0,
                'Wide timer truncated counter or compare values')
        access(wide + 0x18, 0x100)
        access(wide + 0x1c, 0x101)
        access(wide + 0xc, 3)
        access(wide, 9)
        for _ in range(1000):
            if not read(wide) & 1:
                break
        require(not read(wide) & 1 and read(wide + 0x24) == 0 and
                read(wide + 0x10) == (3 if completion else 0),
                'Wide timer compare or full-width rollover differs')
        require(bool(pending() & (1 << 28)) == completion, 'TIM2 update/compare IRQ differs')
        access(wide + 0x10, 0)
        acknowledge()
        auxiliary = 0x40000800
        access(auxiliary + 0xc, 0x1f)
        access(auxiliary + 0x14, 0x1f)
        require(read(auxiliary + 0x10) == 0x1f and pending() & (1 << 30),
                'TIM4 channel events or combined IRQ routing differs')
        access(auxiliary + 0x10, 0)
        acknowledge()
        require(not pending() & (1 << 30), 'TIM4 interrupt acknowledgement failed')
        access(auxiliary + 0x2c, 0x12345678)
        require(read(auxiliary + 0x2c) == 0x5678, 'Sixteen-bit timer accepted a wide period')
        # Both sources must hold IRQ26 until their own flags are acknowledged.
        access(advanced + 0x14, 0x20)
        access(compare + 0x14, 2)
        require(not pending() & (1 << 26), 'Masked timer event raised an IRQ')
        access(advanced + 0xc, 0x20)
        access(compare + 0xc, 2)
        require(pending() & (1 << 26), 'Shared timer interrupt was not raised')
        access(advanced + 0x10, 0xffffffdf)
        acknowledge()
        require(pending() & (1 << 26), 'Clearing one source dropped the other source')
        access(compare + 0x10, 0xfffffffd)
        acknowledge()
        require(not pending() & (1 << 26), 'Acknowledged timer IRQ remained asserted')
        # Other advanced events use independent interrupt groups.
        access(advanced + 0xc, 0x83)
        access(advanced + 0x14, 0x83)
        require(pending() & 0x0b000000 == 0x0b000000,
                'Advanced update, compare or break IRQ routing differs')
        access(advanced + 0x10, 0)
        acknowledge()
        require(not pending() & 0x0f000000, 'Advanced IRQ acknowledgement failed')
        access(advanced + 0xc, 1)
        access(update + 0xc, 2)
        access(advanced + 0x14, 1)
        access(update + 0x14, 2)
        require(pending() & (1 << 25), 'Shared update timer interrupt was not raised')
        access(advanced + 0x10, 0)
        acknowledge()
        require(pending() & (1 << 25), 'Clearing advanced update lost the other timer IRQ')
        access(update + 0x10, 0)
        acknowledge()
        require(not pending() & (1 << 25), 'Shared update timer acknowledgement failed')
        # The link timer combines update and both compare channels on IRQ43.
        access(link + 0xc, 7)
        access(link + 0x14, 7)
        require(read(0xe000e204) & (1 << 11), 'Link timer event did not reach IRQ43')
        secondary = 0x40010400
        access(secondary + 0xc, 0x80)
        access(secondary + 0x14, 0x80)
        access(link + 0x10, 0xfffffffe)
        access(0xe000e284, 1 << 11)
        require(read(0xe000e204) & (1 << 11), 'Update acknowledgement lost link compare IRQ')
        access(link + 0x10, 0)
        access(0xe000e284, 1 << 11)
        require(read(0xe000e204) & (1 << 11), 'Link timer acknowledgement lost shared break IRQ')
        access(secondary + 0x10, 0)
        access(0xe000e284, 1 << 11)
        require(not read(0xe000e204) & (1 << 11), 'Link timer acknowledgement failed')
        access(secondary + 0xc, 0x23)
        access(secondary + 0x14, 0x23)
        require(read(0xe000e204) & 0x7000 == 0x7000,
                'Secondary advanced update, trigger or compare IRQ routing differs')
        access(secondary + 0x10, 0)
        access(0xe000e284, 0x7000)
        access(link + 0x28, 499)
        access(link + 0x2c, 20)
        access(link + 0x34, 5)
        access(link + 0x38, 10)
        access(link, 9)
        for _ in range(10000):
            if not read(link) & 1:
                break
        require(not read(link) & 1 and read(link + 0x10) == (7 if completion else 0),
                'Link timer did not count through both compare channels and update')
        access(link + 0x10, 0)
        access(0xe000e284, 1 << 11)
        # One pulse bounds the hardware run and prevents recurring test IRQs.
        access(compare + 0xc, 3)
        access(compare + 0x28, 0)
        access(compare + 0x2c, 100)
        access(compare + 0x34, 50)
        access(compare + 0x24, 0)
        access(compare + 0x10, 0)
        access(compare, 9)
        for _ in range(1000):
            if not read(compare) & 1:
                break
        require(not read(compare) & 1 and read(compare + 0x24) == 0,
                'One-pulse counter did not stop at rollover')
        require(read(compare + 0x10) == (3 if completion else 0),
                'Hardware compare/update flags or completion switch differ')
        require(bool(pending() & (1 << 26)) == completion,
                'Hardware timer interrupt differs from completion setting')
        access(compare + 0x10, 0xfffffffe)
        require(read(compare + 0x10) == (2 if completion else 0),
                'Status write cleared an unrelated compare flag')
        access(compare + 0x10, 0)
        acknowledge()
        # An output compare above ARR raises CC1IF at overflow, independently of UIF.
        for value in (101, 0xffff):
            access(compare + 0xc, 2)
            access(compare + 0x2c, 100)
            access(compare + 0x34, value)
            access(compare + 0x24, 0)
            access(compare, 11)
            for _ in range(1000):
                if not read(compare) & 1:
                    break
            require(not read(compare) & 1 and read(compare + 0x10) == (2 if completion else 0),
                    'Output compare above reload did not complete on overflow')
            require(bool(pending() & (1 << 26)) == completion,
                    'Compare overflow did not reach its enabled interrupt')
            access(compare + 0x10, 0)
            acknowledge()
        require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                'Timer reset failed')
        require(read(wide + 0x2c) == 0xffffffff and read(wide + 0x24) == 0,
                'Reset did not restore wide timer period and count')
        for base in (advanced, compare, link, update, capture, auxiliary, secondary):
            require(read(base + 0x2c) == 0xffff and
                    all(read(base + offset) == 0 for offset in (0, 12, 16, 36, 40, 52)),
                    'Timer reset retained configuration or events')
        for address, value, opcode in ((compare, 0x10, 0x100),
                                      (compare + 8, 1, 0x100),
                                      (compare + 0x30, 1, 0x100),
                                      (compare + 0x14, 4, 0x100),
                                      (compare + 0x4c, 0, 0x100),
                                      (compare + 0x50, 0, 0x104),
                                      (compare, 0, 0x108)):
            access(address, value, opcode, fault=True)
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Timer reset after access fault failed')
        print('PASS controller timers: events, shared IRQ, one-pulse count, reset and faults',
              'completion=' + str(completion))
    return check


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    run(args.qemu, checks(True))
    run(args.qemu, checks(False), ('-global', 'nikon-z72-controller-timer.completion=off'))
