# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe original serial setup and the disconnected controller boundary."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from tools.dual_boot_probe import dual_machine
from tools.smp_boot_probe import reach


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    images = dict(master=args.master.read_bytes(), slave=args.slave.read_bytes())
    profiles = {role: analyze_eg(image, role) for role, image in images.items()}
    args.destination.mkdir(parents=True, exist_ok=False)
    process = remote = None
    try:
        process, remote = dual_machine(args.qemu, args.destination, images['master'],
            images['slave'], args.destination/'console.txt', trace=None,
            icount='shift=4,sleep=off')
        remote.sock.settimeout(30)
        thread, regs = reach(remote, BASE + 0x1eb846)
        require(thread in (1, 2) and remote.get(regs, 'r0') == 0,
                'Disconnected controller unexpectedly became ready')
        remote.select_thread(thread)
        require(remote.read(0xB1808958, 1) == b'\x01',
                'Original transmitter did not prepare a request')
        require(int.from_bytes(remote.read(0xB18020B0, 4), 'little') == 64,
                'Original serial driver did not retain the modeled capacity')
        require(int.from_bytes(remote.read(0x2C0A0010, 4), 'little') == 0xf00,
                'Original serial configuration differs')
        packet = remote.read(0xB1D1A8C4, 256)
        length = int.from_bytes(packet[2:4], 'little')
        require(packet[0] == 1 and packet[1] == 1 and length == 28 and
                packet[252:254] == b'\x01\x01' and sum(packet) & 255 == 255,
                'Original queued controller frame failed its framing checks')
        faults = []
        for core in (1, 2, 3, 4):
            remote.select_thread(core)
            status = {name: remote.read_register(name)
                      for name in remote.register_numbers
                      if any(field in name for field in ('DFSR', 'IFSR'))}
            require(status and not any(status.values()),
                    'Original serial initialization recorded a processor fault')
            faults.append(dict(thread=core, status=status))
        report = dict(format=1, passed=True,
            firmware={role: p['sha256'] for role, p in profiles.items()},
            observer_thread=thread, original_capacity=64, serial_word_bits=16,
            queued_frame=dict(channel=1, route=1, length=length, checksum_verified=True),
            controller_ready=False, fault_status=faults,
            full_boot_verified=False, menu_verified=False,
            assumptions=['Disconnected bus input high; controller responses are unmodeled.',
                         'FIFO capacity 64 and completion latency 100 us are laboratory choices.',
                         'Original reset and task execution; no debugger state writes.'])
        (args.destination/'report.json').write_text(json.dumps(report, indent=2)+'\n',
                                                  encoding='utf-8')
        print('PASS original serial setup and queued controller request', flush=True)
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
