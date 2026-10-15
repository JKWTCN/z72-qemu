# SPDX-License-Identifier: GPL-2.0-or-later
"""Check firmware-driven readiness between the two engine GPIO interfaces."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from tools.dual_boot_probe import dual_machine
from tools.smp_boot_probe import reach, stop_registers


def scenario(qemu, directory, images, enabled):
    directory.mkdir()
    process = remote = None
    result = dict(link_enabled=enabled)
    try:
        process, remote = dual_machine(qemu, directory, images['master'],
            images['slave'], directory/'console.txt', globals_=(
                'nikon-z72-boot-config.peer-gpio=' + ('on' if enabled else 'off'),))
        remote.sock.settimeout(30)
        thread, regs = reach(remote, BASE + 0x40d3e)
        require(thread in (3, 4) and remote.get(regs, 'r1') == 1,
                'Slave did not set its original readiness output')
        descriptor = remote.read(remote.get(regs, 'r0'), 16)
        require(int.from_bytes(descriptor[:4], 'little') == 0x87 and
                descriptor[4] == 10 and
                int.from_bytes(descriptor[8:12], 'little') == 0x04282020,
                'Slave readiness pin descriptor differs')
        result['output_thread'] = thread
        thread, regs = reach(remote, BASE + 0x367e76)
        require(thread in (1, 2), 'Readiness consumer is outside master engine')
        descriptor = remote.read(remote.get(regs, 'r5'), 16)
        require(int.from_bytes(descriptor[:4], 'little') == 0x60 and
                descriptor[4] == 3 and
                int.from_bytes(descriptor[8:12], 'little') == 0x04282018,
                'Master readiness pin descriptor differs')
        require(bool(int.from_bytes(remote.read(0x04282018, 4), 'little') & 8)
                == enabled, 'Master input differs from connected slave output')
        resumed = BASE + 0x367e8a
        if enabled:
            result['continued_thread'], _ = reach(remote, resumed)
        else:
            remote.breakpoint(resumed)
            try:
                remote.sock.settimeout(3)
                try:
                    stop_registers(remote, remote.command('vCont;c'))
                    raise ValueError('Disconnected readiness resumed communication initialization')
                except TimeoutError:
                    remote.interrupt()
            finally:
                remote.breakpoint(resumed, False)
            remote.select_thread(1)
            require(int.from_bytes(remote.read(0x04282018, 4), 'little') & 8 == 0,
                    'Disconnected input became ready')
        result.update(passed=True, wait_resumed=enabled)
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
    log = (directory/'qemu.log').read_text(errors='replace')
    require(not re.search(r'with (?:DFSR|IFSR)', log), 'Readiness wait encountered a memory fault')
    print('PASS ' + directory.name, flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    images = dict(master=args.master.read_bytes(), slave=args.slave.read_bytes())
    structures = {role: analyze_eg(data, role) for role, data in images.items()}
    args.destination.mkdir(parents=True, exist_ok=False)
    report = dict(format=1, firmware={role: data['sha256'] for role, data in structures.items()},
        full_boot_verified=False, menu_verified=False,
        assumptions=['Board readiness wiring inferred from complementary firmware paths.',
                     'Original reset and pin writes; no debugger state writes.'], scenarios={})
    for enabled in (True, False):
        name = 'connected' if enabled else 'disconnected'
        report['scenarios'][name] = scenario(args.qemu, args.destination/name, images, enabled)
    (args.destination/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
