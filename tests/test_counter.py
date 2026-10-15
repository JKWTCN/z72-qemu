# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise counter progression, freeze, carry, reset and rejected CPU accesses."""
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

COUNTER = 0x04266000


def run(args):
    args.destination.mkdir(parents=True, exist_ok=False)
    obj, binary = args.destination/'counter.o', args.destination/'counter.bin'
    subprocess.run([args.clang, '--target=arm-none-eabi', '-mcpu=cortex-a7', '-c',
                    str(ROOT/'tests/counter_harness.S'), '-o', str(obj)], check=True)
    subprocess.run([args.linker, '-Ttext=0x40100000', '--oformat=binary', str(obj), '-o', str(binary)], check=True)
    contexts = []
    for role in ('master', 'slave'):
        image = struct.pack('<2I', 0xE51FF004, 0x40100000)
        with reset_machine(args.qemu, args.destination/role, image, role,
                           ram_images=[(binary, 0x40100000)]) as remote:
            def sample():
                remote.set(pc=0x40100040, cpsr=0xD3)
                remote.breakpoint(0x40100080)
                try:
                    require(remote.command('c').startswith('T05') and
                            remote.get(remote.regs(), 'pc') == 0x40100080, 'Counter sample failed')
                finally:
                    remote.breakpoint(0x40100080, False)
                frequency, _, physical, mmio = struct.unpack('<IIQQ', remote.read(0x40100500, 24))
                require(frequency == 48000000, 'CPU counter frequency mismatch')
                return dict(physical=physical, mmio=mmio)
            def store(offset, value):
                remote.set(pc=0x40100100, cpsr=0xD3, r0=value, r1=COUNTER+offset)
                remote.command('s')
                require(remote.get(remote.regs(), 'pc') == 0x40100104, 'Counter store failed')
            require(remote.read(COUNTER, 4) == remote.read(COUNTER+8, 12)[:4] == bytes(4),
                    'Counter reset control or low word mismatch')
            samples = [sample(), sample()]
            require(samples[-1]['mmio'] == samples[-2]['mmio'] == 0 and
                    samples[-1]['physical'] > samples[-2]['physical'], 'Disabled counter did not freeze')
            store(16, 48000000)
            store(8, 0xFFFFFFFE)
            store(12, 0)
            store(0, 3)
            samples.extend([sample(), sample()])
            require(samples[-1]['mmio'] > samples[-2]['mmio'] > 0xFFFFFFFF,
                    'Enabled counter did not advance or carry into high word')
            store(0, 0)
            frozen = sample()
            require(sample()['mmio'] == frozen['mmio'], 'Stopped counter changed')
            store(8, 0x89ABCDEF)
            store(12, 0x01234567)
            require(sample()['mmio'] == 0x0123456789ABCDEF, 'Split counter programming mismatch')
            store(0, 3)
            require(sample()['mmio'] > 0x0123456789ABCDEF, 'Counter resume failed')
            faults = []
            for offset, pc, value in ((4, 0x104, 0), (20, 0x104, 0),
                (0, 0x108, 0), (0, 0x10C, 0), (1, 0x104, 0),
                (8, 0x100, 0), (0, 0x100, 4), (16, 0x100, 48000000)):
                remote.set(pc=0x40100000+pc, cpsr=0xD3, r0=value, r1=COUNTER+offset)
                remote.command('s')
                require(remote.get(remote.regs(), 'pc') == 0x10 and
                        remote.get(remote.regs(), 'cpsr') & 0x1F == 0x17,
                        'Unsupported counter access did not abort')
                faults.append(dict(offset=offset, instruction_offset=pc, value=value))
            store(0, 0)
            remote.set(pc=0x40100100, cpsr=0xD3, r0=1, r1=COUNTER+16)
            remote.command('s')
            require(remote.get(remote.regs(), 'pc') == 0x10, 'Unknown frequency did not abort')
            require(remote.read(COUNTER+16, 4) == struct.pack('<I', 48000000),
                    'Rejected frequency changed device state')
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK', 'Counter reset failed')
            require(remote.read(COUNTER, 4) == bytes(4) and
                    remote.read(COUNTER+8, 12) == bytes(12), 'Reset retained counter state')
            contexts.append(dict(role=role, frequency=48000000, samples=samples,
                carry_verified=True, freeze_resume_verified=True, reset_verified=True,
                rejected_accesses=faults, invalid_frequency_rejected=True, passed=True))
        print('PASS', role, 'counter clock, freeze/resume, carry, reset and access faults', flush=True)
    report = dict(format=1, contexts=contexts, passed=True,
                  cpu_counter_gating_verified=False, hardware_timing_verified=False)
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
