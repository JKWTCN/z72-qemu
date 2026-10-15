# SPDX-License-Identifier: GPL-2.0-or-later
"""Check actual GIC IRQ delivery and secure physical timer wiring without firmware."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from tools.boot_probe import reset_machine


def run(args):
    args.destination.mkdir(parents=True, exist_ok=False)
    obj, binary = args.destination/'interrupt.o', args.destination/'interrupt.bin'
    subprocess.run([args.clang, '--target=arm-none-eabi', '-mcpu=cortex-a7', '-c',
                    str(ROOT/'tests/interrupt_harness.S'), '-o', str(obj)], check=True)
    subprocess.run([args.linker, '-Ttext=0x40100000', '--oformat=binary', str(obj), '-o', str(binary)], check=True)
    contexts = []
    for role in ('master', 'slave'):
        # The loader starts at the stock base; a synthetic branch enters the
        # test vector block. No stock image or stock startup contract is used.
        # Use an absolute jump to the separately loaded test vector block.
        image = struct.pack('<2I', 0xE51FF004, 0x40100000)
        with reset_machine(args.qemu, args.destination/role, image, role,
                           ram_images=[(binary, 0x40100000)]) as remote:
            idle = 0x40100080
            def until(address):
                remote.breakpoint(address)
                try:
                    require(remote.command('c').startswith('T05') and
                            remote.get(remote.regs(), 'pc') == address, 'Interrupt execution failed')
                finally:
                    remote.breakpoint(address, False)
            until(idle)
            require(remote.get(remote.regs(), 'r0') == 0x04000000, 'Laboratory CBAR mismatch')
            def store(address, value):
                remote.write(address, struct.pack('<I', value))
            require(struct.unpack('<I', remote.read(0x04001004, 4))[0] & 31 == 7,
                    'GIC does not expose 256 interrupt slots')
            store(0x04001000, 1)
            store(0x04002004, 0xFF)
            store(0x04002000, 1)
            store(0x04001F00, 0x02000001)
            until(0x40100100)
            until(idle)
            require(remote.read(0x40100300, 8) == struct.pack('<2I', 1, 1),
                    'SGI delivery, acknowledge or handler mismatch')
            store(0x04001100, 1 << 29)
            remote.set(pc=0x40100180)
            until(0x40100100)
            until(idle)
            require(remote.read(0x40100300, 8) == struct.pack('<2I', 2, 29),
                    'Secure physical timer IRQ delivery mismatch')
            require(remote.get(remote.regs(), 'sp') == 0x04008E00 and
                    remote.get(remote.regs(), 'cpsr') & 0x1F == 0x13,
                    'IRQ handler failed to restore SVC state')
            require(struct.unpack('<I', remote.read(0x0400200C, 4))[0] == 1023,
                    'Interrupt acknowledgement retained a pending source')
            contexts.append(dict(role=role, cbar=0x04000000, interrupts=256,
                                 delivered_ids=[1, 29], passed=True))
        print('PASS', role, 'GIC SGI and physical timer IRQ delivery', flush=True)
    report = dict(format=1, contexts=contexts, passed=True, stock_irq_handler_verified=False)
    (args.destination/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--clang', default='clang')
    parser.add_argument('--linker', default='ld.lld')
    parser.add_argument('--destination', type=Path, required=True)
    try:
        run(parser.parse_args())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Error: {error}\n')
