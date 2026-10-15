# SPDX-License-Identifier: GPL-2.0-or-later
"""Sample the communication ring indices in the dual machine over time."""
import argparse, json, struct, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.smp_boot_probe import stop_registers
sys.path.insert(0, str(ROOT/'tools'))
from tools.dual_boot_probe import dual_machine


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
        for round_index in range(3):
            remote.sock.settimeout(20)
            try:
                stop_registers(remote, remote.command('vCont;c'))
            except TimeoutError:
                try:
                    remote.interrupt()
                except TimeoutError:
                    pass
            for thread, role, base in [(1, 'master', 0xB7CF0000),
                                       (3, 'slave', 0xC60F0000)]:
                remote.select_thread(thread)
                for bank in range(2):
                    header = base + bank * 0xC618
                    indices = [struct.unpack('<I', remote.read(header + offset, 4))[0]
                               for offset in (8, 0x10)]
                    print(json.dumps(dict(round=round_index, role=role, bank=bank,
                        write_index=indices[0], read_index=indices[1])), flush=True)
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
