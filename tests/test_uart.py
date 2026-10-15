# SPDX-License-Identifier: GPL-2.0-or-later
"""Check console TX bytes, mixed register widths, reset and unsupported accesses."""
import argparse
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from tools.boot_probe import reset_machine

UART = 0x2C090000


def run(args):
    args.destination.mkdir(parents=True, exist_ok=False)
    # STRB, STRH, STR, LDRB, LDRH: synthetic instructions only.
    image = struct.pack('<5I', 0xE5C10000, 0xE1C100B0, 0xE5810000,
                        0xE5D12000, 0xE1D120B0)
    contexts = []
    for role in ('master', 'slave'):
        console = args.destination/f'{role}-console.txt'
        with reset_machine(args.qemu, args.destination/role, image, role, console=console) as remote:
            def access(offset, value=0, size=1, read=False, fault=False):
                instruction = (3 if size == 1 else 4) if read else {1:0, 2:1, 4:2}[size]
                remote.set(pc=BASE+instruction*4, cpsr=0xD3, r0=value, r1=UART+offset)
                remote.command('s')
                regs = remote.regs()
                if fault:
                    require(remote.get(regs, 'pc') == 16 and remote.get(regs, 'cpsr') & 31 == 0x17,
                            'Unsupported UART access did not abort')
                    return None
                require(remote.get(regs, 'pc') == BASE+instruction*4+4, 'UART access failed')
                return remote.get(regs, 'r2') if read else None
            for offset, size in ((0,1), (1,1), (2,1), (3,1), (4,2), (6,2), (12,2)):
                require(access(offset, size=size, read=True) == (2 if offset == 3 else 0),
                        'UART reset register mismatch')
            for offset, size, value in ((0,1,1), (1,1,0x81), (2,1,0), (3,1,0x80),
                                       (6,2,0x363), (12,2,0x405)):
                access(offset, value, size)
                require(access(offset, size=size, read=True) == (value | 2 if offset == 3 else value),
                        'UART configuration readback mismatch')
            # Software cannot clear device-owned TX-ready in the synchronous model.
            access(3, 0)
            require(access(3, read=True) == 2, 'Software cleared TX-ready')
            require(access(12, read=True) == 5 and access(13, read=True) == 4,
                    'Format bytes do not alias the halfword')
            access(12, 2)
            access(13, 8)
            require(access(12, size=2, read=True) == 0x802,
                    'Format byte writes did not preserve the other half')
            access(15, 2)
            require(access(15, read=True) == 2, 'Auxiliary control readback mismatch')
            for value in (0x15A, 0x37, 0x32, 0x0D, 0x0A):
                access(4, value, 2)
                require(access(4, size=2, read=True) == value, 'TX data latch mismatch')
            rejected = [(0,2), (1,2), (4,1), (6,1), (8,2), (14,1), (14,2), (16,1), (4,4), (5,2)]
            for offset, size in rejected:
                access(offset, size=size, fault=True)
            require(console.read_bytes() == b'Z72\r\n', 'Rejected accesses emitted console bytes')
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK', 'UART reset failed')
            for offset, size in ((0,1), (1,1), (2,1), (3,1), (4,2), (6,2), (12,2), (13,1), (15,1)):
                require(access(offset, size=size, read=True) == (2 if offset == 3 else 0),
                        'Reset retained UART configuration')
            contexts.append(dict(role=role, tx_hex='5a37320d0a', tx_verified=True,
                mixed_widths_verified=True, ninth_bit_latch_verified=True,
                reset_verified=True, rejected_accesses=rejected, passed=True))
        print('PASS', role, 'console TX, register widths, reset and access faults', flush=True)
    (args.destination/'report.json').write_text(json.dumps(dict(format=1, contexts=contexts,
        passed=True, receive_verified=False, uart_irq_verified=False), indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    try:
        run(parser.parse_args())
    except (OSError, ValueError) as error:
        parser.exit(1, f'Error: {error}\n')
