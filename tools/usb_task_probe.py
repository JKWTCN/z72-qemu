# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover live USB-related task entries from the running original board.

Boots the stock master and slave through the verified transport-startup
checkpoints until the main task settles, then reads the runtime task array
and the scheduler neighborhoods to recover the task control blocks whose
static-table entries carry no function pointers. Read-only: no debugger
state writes, no firmware bytes exported.
"""
import argparse
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from tools.dual_boot_probe import dual_machine
from tools.smp_boot_probe import reach, stop_registers

TASK_ARRAY_STRUCT = 0xB1800028
WANTED_NAMES = (b'EXSUSB', b'LSPTP', b'DBGCMD', b'DBGUART', b'PTPSIC',
                b'PTPPOS', b'PTPPIP', b'IAPONUSB', b'POSTLOG')
WANTED_INDICES = (58, 59, 60, 61, 86, 144, 145, 146, 147, 149, 150, 177,
                  187, 188, 189, 190)


def scenario(qemu, directory, master, slave):
    directory.mkdir()
    process = remote = None
    try:
        process, remote = dual_machine(qemu, directory, master, slave,
            directory / 'console.txt', icount='shift=4,sleep=off', trace=None,
            globals_=('nikon-z72-boot-config.transport-link=on',))
        remote.sock.settimeout(60)
        # Verified startup checkpoints from the transport exchange.
        thread, regs = reach(remote, BASE + 0x2be346)
        require(remote.get(regs, 'r4') == 0x2013c90c, 'Initiator command differs')
        thread, _ = reach(remote, BASE + 0x2be352)
        thread, _ = reach(remote, BASE + 0x2be6c8)
        thread, _ = reach(remote, BASE + 0x1e0c52)
        thread, regs = reach(remote, BASE + 0x40e3c)
        require(thread in (3, 4), 'Receiver on wrong engine')
        reach(remote, BASE + 0x40f7e)
        thread, _ = reach(remote, BASE + 0x1e0196)
        result = dict(settled_thread=thread)
        remote.select_thread(1)

        words = struct.unpack('<4I', remote.read(TASK_ARRAY_STRUCT, 16))
        result['task_struct'] = [hex(word) for word in words]
        records = {}
        for base_index, base in enumerate(words):
            if not 0xB0000000 <= base < 0xC0000000:
                continue
            table = {}
            for index in WANTED_INDICES:
                entry = {}
                for stride in (28, 12, 4):
                    record = remote.read(base + index * stride, max(stride, 16))
                    words_in = struct.unpack('<%dI' % (len(record) // 4), record)
                    entry['stride%d' % stride] = record.hex()
                    blocks = []
                    for word in words_in:
                        if (0x10020000 <= word < 0x12700000) or (0xB1800000 <= word < 0xBFF00000):
                            try:
                                blocks.append(dict(at=hex(word),
                                                   data=remote.read(word, 64).hex()))
                            except Exception:
                                pass
                    if blocks:
                        entry['followed_stride%d' % stride] = blocks
                if entry:
                    table[index] = entry
            records['array%d' % base_index] = table
        result['records'] = records

        hits = []
        for start, length in ((0xB2B40000, 0x20000), (0xB1800000, 0x40000)):
            blob = remote.read(start, length)
            for key in WANTED_NAMES:
                position = blob.find(key)
                seen = 0
                while position >= 0 and seen < 2:
                    context = blob[max(0, position - 96):position + 64]
                    hits.append(dict(name=key.decode(), address=hex(start + position),
                                     context=context.hex()))
                    seen += 1
                    position = blob.find(key, position + 1)
        result['name_hits'] = hits

        faults = []
        for core in (1, 2, 3, 4):
            remote.select_thread(core)
            state = {name: remote.read_register(name)
                     for name in remote.register_numbers
                     if any(field in name for field in ('DFSR', 'IFSR'))}
            require(not any(state.values()), 'Processor fault during run')
            faults.append(state)
        result['passed'] = True
        return result
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    images = dict(master=args.master.read_bytes(), slave=args.slave.read_bytes())
    structures = {role: analyze_eg(data, role) for role, data in images.items()}
    report = dict(format=1,
                  firmware={role: data['sha256'] for role, data in structures.items()},
                  full_boot_verified=False, menu_verified=False,
                  assumptions=['Live read-only recovery of task records; '
                              'entry semantics still need per-task decoding.'],
                  scenario=scenario(args.qemu, args.destination, images['master'],
                                    images['slave']))
    (args.destination / 'report.json').write_text(
        json.dumps(report, indent=2, default=str) + '\n', encoding='utf-8')
    print('PASS live task records recovered:', args.destination)


if __name__ == '__main__':
    main()
