# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise serial FIFO bounds, asynchronous completion and access faults."""
import argparse
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from tools.boot_probe import reset_machine
from tools.smp_boot_probe import reach


def run(args):
    args.destination.mkdir(parents=True, exist_ok=False)
    # STR, LDR, STRB; a bounded SUBS/BNE loop advances virtual time.
    image = struct.pack('<11I', 0xE5810000, 0xE5912000, 0xE5C10000,
                        0, 0, 0, 0, 0, 0xE2500001, 0x1AFFFFFD, 0xEAFFFFFE)
    contexts = []
    for role in ('master', 'slave'):
        with reset_machine(args.qemu, args.destination/role, image, role,
                           icount='shift=4,sleep=off') as remote:
            def access(address, value=0, read=False, byte=False, fault=False):
                instruction = 2 if byte else 1 if read else 0
                remote.set(pc=BASE + instruction * 4, cpsr=0xD3,
                           r0=value, r1=address)
                remote.command('s')
                regs = remote.regs()
                if fault:
                    require(remote.get(regs, 'pc') == 16 and
                            remote.get(regs, 'cpsr') & 31 == 0x17,
                            'Unsupported serial access did not abort')
                    return
                require(remote.get(regs, 'pc') == BASE + instruction * 4 + 4,
                        'Serial access failed')
                return remote.get(regs, 'r2') if read else None

            def advance():
                remote.set(pc=BASE + 32, cpsr=0xD3, r0=16384)
                reach(remote, BASE + 40)

            for channel in (0, 1, 6, 8, 9, 10):
                bus = 0x2C0A0000 + channel * 0x100
                require(access(bus + 0x48, read=True) == 64,
                        'Serial capacity differs')
                require(access(bus + 0x14, read=True) == 0x24,
                        'Serial reset status differs')
                access(bus, 1, fault=True)
                access(bus + 0x10, 15 << 8)
                access(bus + 0x4c, 32)
                access(bus + 0x20, 7)
                access(bus + 0x3c, 1)
                for value in range(64):
                    access(bus, value)
                require(access(bus + 0x14, read=True) == 0x30,
                        'Queued serial FIFO status differs')
                access(bus, 0x1234, fault=True)
                advance()
                require(access(bus + 0x24, read=True) == 7,
                        'Serial completion causes differ')
                first_irq = 192 + channel * 2
                pending = access(0x04001200 + (first_irq // 32) * 4, read=True)
                require(pending & (3 << (first_irq % 32)) == 3 << (first_irq % 32),
                        'Serial completion did not reach both interrupt lines')
                require(access(bus + 0x14, read=True) == 0x14,
                        'Completed serial FIFO status differs')
                for _ in range(64):
                    require(access(bus + 4, read=True) == 0xffff,
                            'Disconnected input did not sample high')
                require(access(bus + 0x14, read=True) == 0x24,
                        'Drained serial FIFO status differs')
                require(access(bus + 0x24, read=True) == 3,
                        'RX cause stayed asserted after draining')
                access(bus + 0x28, 3)
                require(access(bus + 0x24, read=True) == 0,
                        'Serial acknowledgement did not clear causes')
                access(bus + 4, read=True, fault=True)
                access(bus + 0x48, 1, fault=True)
                access(bus, 0, byte=True, fault=True)
                access(bus + 0x10, 7 << 8)
                access(bus, 0x12)
                advance()
                require(access(bus + 4, read=True) == 0xff,
                        'Serial input did not respect word width')
                access(bus, 0x34)
                access(bus + 0x3c, 0)
                advance()
                require(access(bus + 0x24, read=True) == 0 and
                        access(bus + 0x14, read=True) == 0x24,
                        'Disabled channel retained a queued completion')
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Serial reset failed')
            for channel in range(11):
                bus = 0x2C0A0000 + channel * 0x100
                require(access(bus + 0x10, read=True) == 0 and
                        access(bus + 0x24, read=True) == 0,
                        'Reset retained serial configuration or causes')
            contexts.append(dict(role=role, channels=[0, 1, 6, 8, 9, 10],
                                 fifo_bounds=True, completion=True,
                                 access_faults=True, reset=True, passed=True))
        print('PASS ' + role + ' serial FIFO and completion', flush=True)
    (args.destination/'report.json').write_text(json.dumps(dict(
        format=1, contexts=contexts, passed=True, controller_reply_verified=False,
        panel_verified=False, menu_verified=False), indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    run(parser.parse_args())
