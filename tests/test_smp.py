# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify CPU identity, targeted SGIs and per-core timer IRQ wiring without firmware."""
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
from tools.smp_boot_probe import reach


def run(args):
    args.destination.mkdir(parents=True, exist_ok=False)
    obj, binary = args.destination/'smp.o', args.destination/'smp.bin'
    subprocess.run([args.clang, '--target=arm-none-eabi', '-mcpu=cortex-a7', '-c',
                    str(ROOT/'tests/smp_harness.S'), '-o', str(obj)], check=True)
    subprocess.run([args.linker, '-Ttext=0x40100000', '--oformat=binary', str(obj), '-o', str(binary)], check=True)
    contexts = []
    for role in ('master', 'slave'):
        image = struct.pack('<2I', 0xE51FF004, 0x40100000)
        with reset_machine(args.qemu, args.destination/role, image, role, cpus=2,
                           ram_images=[(binary, 0x40100000)]) as remote:
            idle, handler = 0x401000C0, 0x40100100
            def until(address, thread):
                stopped, regs = reach(remote, address, f'vCont;c:{thread:x}')
                require(stopped == thread, 'Wrong core received interrupt')
                return regs
            def record(core):
                return list(struct.unpack('<3I', remote.read(0x40100400+core*16, 12)))
            def guest_call(thread, address, **registers):
                remote.select_thread(thread)
                remote.set(pc=address, **registers)  # Synthetic harness only.
                return until(idle, thread)
            for thread in (1, 2):
                regs = until(idle, thread)
                require(remote.get(regs, 'r4') == thread-1 and
                        remote.get(regs, 'sp') == 0x04008E00-(thread-1)*0x100 and
                        record(thread-1) == [thread-1, 0, 0], 'Core identity or banked stack mismatch')
            # Banked GIC accesses require a running guest CPU context. Use ARM
            # loads/stores rather than debugger MMIO, including shared words.
            regs = guest_call(1, 0x401001B0)
            require((remote.get(regs, 'r0') >> 5) & 7 == 1,
                    'GIC does not expose two CPU interfaces')
            # Send SGI 1 to CPU 1, with CPU 0 explicitly excluded.
            guest_call(1, 0x401001A0, r0=0x00020001)
            until(handler, 2)
            until(idle, 2)
            require(record(0) == [0, 0, 0] and record(1) == [1, 1, 1],
                    'Targeted SGI reached the wrong CPU or failed acknowledgement')
            # Reverse direction; IAR includes source CPU 1 in bits 12:10.
            guest_call(2, 0x401001A0, r0=0x00010001)
            until(handler, 1)
            until(idle, 1)
            require(record(0) == [0, 1, 0x401] and record(1) == [1, 1, 1],
                    'Reverse SGI source or target mismatch')
            for thread in (1, 2):
                remote.select_thread(thread)
                remote.set(pc=0x40100180)  # Synthetic harness only.
                until(handler, thread)
                regs = until(idle, thread)
                require(record(thread-1) == [thread-1, 2, 29] and
                        remote.get(regs, 'sp') == 0x04008E00-(thread-1)*0x100 and
                        remote.get(regs, 'cpsr') & 0x1F == 0x13,
                        'Private timer routing or IRQ state restoration mismatch')
                regs = guest_call(thread, 0x401001C0)
                require(remote.get(regs, 'r0') == 1023,
                        'CPU interface retained a pending interrupt')
            contexts.append(dict(role=role, cpu_affinities=[0, 1],
                sgi_acknowledgements=[1, 0x401], local_timer_ids=[29, 29],
                directed_sgis_verified=True, private_timers_verified=True, passed=True))
        print('PASS', role, 'targeted SGIs and per-core physical timers', flush=True)
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
