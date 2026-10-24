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
CURRENT_TASK_TABLE = 0xB2B41604
TCB_POOL_SCAN = (0xB2C30000, 0x30000)
WANTED_NAMES = (b'EXSUSB', b'LSPTP', b'DBGCMD', b'DBGUART', b'PTPSIC',
                b'PTPPOS', b'PTPPIP', b'IAPONUSB', b'POSTLOG')
WANTED_INDICES = (58, 59, 60, 61, 86, 144, 145, 146, 147, 149, 150, 177,
                  187, 188, 189, 190)
WANTED_KERNEL_IDS = {0x2F, 0x30, 0x31, 0x32, 0xB9, 0xE7}


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

        # Control-block hunt: the running-task pointers fix the layout, the
        # pool scan collects entry candidates keyed by nearby kernel ids.
        current = {}
        for core in range(4):
            pointer = struct.unpack('<I', remote.read(
                CURRENT_TASK_TABLE + core * 4, 4))[0]
            if 0xB0000000 <= pointer < 0xC0000000:
                current[core] = dict(at=hex(pointer),
                                     data=remote.read(pointer, 0x60).hex())
        result['current_tasks'] = current

        entries = []
        start, length = TCB_POOL_SCAN
        blob = b''.join(remote.read(start + chunk, min(0x1000, length - chunk))
                        for chunk in range(0, length, 0x1000))
        total_blocks = 0
        for offset in range(0, len(blob) - 0x18, 4):
            flags = struct.unpack_from('<I', blob, offset + 8)[0]
            entry = struct.unpack_from('<I', blob, offset + 0x14)[0]
            if not 0x10020000 <= entry < 0x10700000:
                continue
            if flags >> 16 not in (0x0000, 0x0100, 0x0101, 0x0001):
                continue
            total_blocks += 1
            kernel_id = flags & 0xFFFF
            context = blob[max(0, offset - 0x10):offset + 0x28]
            record = dict(pool=hex(start + offset), id=kernel_id,
                          entry=hex(entry), context=context.hex(),
                          wanted=kernel_id in WANTED_KERNEL_IDS)
            entries.append(record)
            if record['wanted']:
                # One window per task anchored at its deepest stack pointer;
                # the task's own loop frame lies at the highest addresses.
                head = blob[offset:offset + 0x60]
                pointers = [word for word in struct.unpack(
                    '<%dI' % (len(head) // 4), head)
                    if 0xB5000000 <= word < 0xB6000000]
                if pointers:
                    anchor = min(pointers)
                    try:
                        frame = remote.read(anchor, 0x600)
                        code = [hex(value) for value in
                                struct.unpack('<%dI' % (len(frame) // 4), frame)
                                if 0x10020000 <= value < 0x10700000]
                        record['stacks'] = [dict(stack=hex(anchor), code=code)]
                    except Exception:
                        record['stacks'] = []
                # The dispatcher loop calls the handler stored at its
                # control object +0x24; the wait object (context word seven)
                # sits at object +0x20.
                context_words = struct.unpack(
                    '<%dI' % (len(record['context']) // 8), 
                    bytes.fromhex(record['context']))
                wait_object = context_words[7]
                record['wait_object'] = hex(wait_object)
                if 0xB0000000 <= wait_object < 0xC0000000:
                    try:
                        obj = remote.read(wait_object - 0x20, 0x28)
                        fields = struct.unpack('<10I', obj)
                        record['dispatcher'] = dict(
                            base=hex(wait_object - 0x20),
                            handler=hex(fields[9]),
                            words=[hex(word) for word in fields])
                    except Exception:
                        pass
        result['pool_blocks_with_entries'] = total_blocks
        result['pool_entry_candidates'] = entries

        # Follow the USB task event blocks into their wait queues.
        event_follow = []
        for block in (0x1206F7C0, 0x1206F840, 0x1206F8C0, 0x1206F9C0,
                      0x12070440):
            window = remote.read(block, 0x120)
            event_follow.append(dict(block=hex(block), data=window.hex()))
            for word in struct.unpack('<%dI' % (len(window) // 4), window):
                if 0xB2B00000 <= word < 0xB2D00000:
                    try:
                        event_follow.append(dict(
                            block=hex(word),
                            data=remote.read(word, 0x60).hex()))
                    except Exception:
                        pass
                    break
        result['event_follow'] = event_follow

        # Walk the scheduler queues to sample blocked-task control blocks.
        samples = []
        for head in (0xB2B4171C, 0xB2B4174C):
            node = struct.unpack('<I', remote.read(head, 4))[0]
            for _ in range(6):
                if not 0xB0000000 <= node < 0xC0000000 or node == head:
                    break
                samples.append(dict(at=hex(node),
                                    data=remote.read(node, 0x60).hex()))
                node = struct.unpack('<I', remote.read(node, 4))[0]
        result['queue_samples'] = samples
        result['passed'] = True

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
