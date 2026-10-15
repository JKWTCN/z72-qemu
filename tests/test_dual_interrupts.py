# SPDX-License-Identifier: GPL-2.0-or-later
"""Check engine-local GIC banking and interrupt isolation with synthetic code."""
import argparse
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from tools.dual_boot_probe import dual_machine
from tools.smp_boot_probe import reach


def run(args):
    args.destination.mkdir(parents=True, exist_ok=False)
    obj = args.destination/'smp.o'
    binary = args.destination/'smp.bin'
    subprocess.run([args.clang, '--target=arm-none-eabi', '-mcpu=cortex-a7', '-c',
                    str(ROOT/'tests/smp_harness.S'), '-o', str(obj)], check=True)
    subprocess.run([args.linker, '-Ttext=0x40100000', '--oformat=binary',
                    str(obj), '-o', str(binary)], check=True)
    stub = struct.pack('<2I', 0xe51ff004, 0x40100000)
    process = remote = None
    try:
        process, remote = dual_machine(args.qemu, args.destination, stub, stub,
                                       args.destination/'console.txt', icount=None)
        for thread in (1, 3):
            remote.select_thread(thread)
            remote.write(0x40100000, binary.read_bytes())

        def until(address, thread):
            stopped, regs = reach(remote, address, f'vCont;c:{thread:x}')
            require(stopped == thread, 'Interrupt reached the wrong engine or core')
            return regs

        def record(thread):
            remote.select_thread(thread)
            core = (thread-1) % 2
            return list(struct.unpack('<3I', remote.read(0x40100400+core*16, 12)))

        def call(thread, address, **registers):
            remote.select_thread(thread)
            remote.set(pc=address, **registers)  # Synthetic instructions only.
            return until(0x401000c0, thread)

        for thread in (1, 2, 3, 4):
            regs = until(0x401000c0, thread)
            require(remote.get(regs, 'r4') == (thread-1) % 2,
                    'Engine-local CPU affinity differs')
        for sender, receiver, acknowledgement in ((1, 2, 1), (2, 1, 0x401),
                                                   (3, 4, 1), (4, 3, 0x401)):
            before = {thread: record(thread) for thread in (1, 2, 3, 4)}
            target = 1 << ((receiver-1) % 2)
            call(sender, 0x401001a0, r0=(target << 16) | 1)
            until(0x40100100, receiver)
            until(0x401000c0, receiver)
            for thread in (1, 2, 3, 4):
                observed = record(thread)
                expected = before[thread]
                if thread == receiver:
                    expected = [expected[0], expected[1]+1, acknowledgement]
                require(observed == expected, 'SGI banking, acknowledgement or isolation failed')
        for thread in (1, 2, 3, 4):
            before = {core: record(core) for core in (1, 2, 3, 4)}
            remote.select_thread(thread)
            remote.set(pc=0x40100180)  # Synthetic timer programming only.
            until(0x40100100, thread)
            until(0x401000c0, thread)
            for core in (1, 2, 3, 4):
                expected = before[core]
                if core == thread:
                    expected = [expected[0], expected[1]+1, 29]
                require(record(core) == expected, 'Private timer crossed a core or engine')
            regs = call(thread, 0x401001c0)
            require(remote.get(regs, 'r0') == 1023, 'Pending interrupt retained after EOI')
        report = dict(format=1, engine_cpu_affinities=[[0, 1], [0, 1]],
                      directed_sgis_verified=True, private_timers_verified=True,
                      interrupt_isolation_verified=True, passed=True)
        (args.destination/'report.json').write_text(
            json.dumps(report, indent=2)+'\n', encoding='utf-8')
        print('PASS dual-engine GIC banking and interrupt isolation', flush=True)
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--clang', default='clang')
    parser.add_argument('--linker', default='ld.lld')
    parser.add_argument('--destination', type=Path, required=True)
    run(parser.parse_args())
