# SPDX-License-Identifier: GPL-2.0-or-later
"""Check controller pin routing, edges and grouped interrupt delivery."""
import argparse
from test_controller_gpio import run
from analyze.decode_z72 import require


def check_routing(remote, access):
    route, exti = 0x40013800, 0x40013c00
    for index in range(4):
        value = 0x76543210 ^ index
        access(route + 8 + index * 4, value)
        require(access(route + 8 + index * 4, opcode=0x104) == value,
                'Pin route configuration was not independent')
    access(exti, 0x400041)
    access(exti + 8, 0x400041)
    access(exti + 0x10, 0x400041)
    require(access(exti + 0x14, opcode=0x104) == 0x400041,
            'Software request did not latch local pending bits')
    access(exti + 0x14, 1)
    require(access(exti + 0x14, opcode=0x104) == 0x400040 and
            access(exti + 0x10, opcode=0x104) == 0x400040,
            'Pending acknowledgement did not clear only the selected request')
    require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
            'Controller reset failed')
    require(all(access(route + offset, opcode=0x104) == 0
                for offset in (0, 4, 8, 12, 16, 20, 32)) and
            all(access(exti + offset, opcode=0x104) == 0 for offset in range(0, 24, 4)),
            'Reset retained routing or pending state')
    def read(address):
        return access(address, opcode=0x104)
    def pending(irq):
        return bool(read(0xe000e200 + 4 * (irq // 32)) & (1 << (irq % 32)))
    def clear(irq):
        access(exti + 20, 0xffffffff)
        access(0xe000e280 + 4 * (irq // 32), 1 << (irq % 32))
    for pin in range(16):
        port, bit = pin % 8, 1 << pin
        base = 0x40020000 + port * 0x400
        irq = 6 + pin if pin < 5 else 23 if pin < 10 else 40
        access(route + 8 + 4 * (pin // 4), port << (4 * (pin % 4)))
        access(base, 1 << (pin * 2))
        access(base + 20, 0)
        clear(irq)
        access(exti, 0)
        access(exti + 8, bit)
        access(exti + 12, 0)
        access(base + 20, bit)
        require(read(exti + 20) == bit and not pending(irq),
                'Masked rising edge did not retain its status independently')
        access(exti, bit)
        require(pending(irq), 'Unmasking a pending edge did not assert its group')
        clear(irq)
        access(base + 20, bit)
        require(read(exti + 20) == 0 and not pending(irq),
                'Unchanged pin level retriggered an edge')
        access(base + 20, 0)
        require(read(exti + 20) == 0, 'Disabled falling edge was latched')
        access(exti + 12, bit)
        access(base + 20, bit)
        clear(irq)
        access(base + 20, 0)
        require(read(exti + 20) == bit and pending(irq),
                'Falling edge did not reach its mapped interrupt')
        clear(irq)
        # Selecting another port must reject edges from this port.
        access(route + 8 + 4 * (pin // 4), ((port + 1) % 8) << (4 * (pin % 4)))
        access(base + 20, bit)
        require(read(exti + 20) == 0 and not pending(irq),
                'An unselected port raised an interrupt')
        access(base + 20, 0)
    # Two pending sources in the same group retain the line independently.
    access(exti, 0x60)
    access(exti + 16, 0x20)
    access(exti + 16, 0x40)
    require(read(exti + 16) == 0x60 and pending(23),
            'Software requests did not accumulate in their interrupt group')
    access(exti + 20, 0x20)
    access(0xe000e280, 1 << 23)
    require(read(exti + 20) == 0x40 and pending(23),
            'Acknowledging one source dropped its shared group')
    clear(23)
    # Drive the external switch through its physical pad signal.
    access(route + 12, 6 << 4)
    access(0x40021800, 0)
    access(exti, 32)
    access(exti + 8, 32)
    access(exti + 12, 0)
    require(remote.command('qRcmd,' + 'qom-set /machine power-switch true'.encode().hex()) == 'OK',
            'External switch update failed')
    require(read(exti + 20) == 32 and pending(23),
            'External switch rising edge did not reach the controller interrupt')
    clear(23)
    require(remote.command('qRcmd,' + 'qom-set /machine power-switch false'.encode().hex()) == 'OK',
            'External switch restore failed')
    for address, opcode in ((route + 0x18, 0x104), (route + 0x24, 0x100),
                             (exti + 0x18, 0x104), (exti, 0x108)):
        access(address, 0, opcode, fault=True)
        require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                'Controller reset after routing fault failed')
    print('PASS controller routing: sixteen edges, eight ports, grouped IRQ, switch, reset and faults')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    run(parser.parse_args().qemu, check_routing)
