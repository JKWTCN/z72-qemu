# SPDX-License-Identifier: GPL-2.0-or-later
"""Check whether the slave comm receive path ever runs in the dual machine."""
import argparse, json, subprocess, sys, time
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from tools.smp_boot_probe import stop_registers
sys.path.insert(0, str(ROOT/'tools'))
from tools.dual_boot_probe import dual_machine, sample_cores


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    qemu, destination = args.qemu, args.destination
    master, slave = args.master.read_bytes(), args.slave.read_bytes()
    from analyze.firmware_structure import analyze_eg
    for role, image in [('master', master), ('slave', slave)]:
        analyze_eg(image, role)
    destination.mkdir(parents=True, exist_ok=False)
    process = remote = None
    try:
        process, remote = dual_machine(qemu, destination, master, slave,
                                       destination/'console.txt')
        # Free boot window first.
        remote.sock.settimeout(30)
        try:
            stop_registers(remote, remote.command('vCont;c'))
        except TimeoutError:
            try:
                remote.interrupt()
            except TimeoutError:
                pass
        # Break on the slave receive entry and the master receive entry.
        sites = ((0x10060E3C, 'slave-receive'), (0x10387F84, 'master-receive'))
        for address, _ in sites:
            remote.breakpoint(address)
        hits = Counter()
        try:
            for _ in range(10):
                remote.sock.settimeout(10)
                thread, regs = stop_registers(remote, remote.command('vCont;c'))
                pc = remote.get(regs, 'pc')
                label = next(n for a, n in sites if a == pc)
                hits[(label, thread)] += 1
                remote.breakpoint(pc, False)
                remote.command('s')
                remote.breakpoint(pc)
        except TimeoutError:
            try:
                remote.interrupt()
            except TimeoutError:
                pass
        finally:
            for address, _ in sites:
                remote.breakpoint(address, False)
        print('receive hits:', dict(hits))
        for core in sample_cores(remote):
            print('core', core)
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
    main()
