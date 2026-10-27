# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe native display registers and buffers after console startup.

This reads the configured surfaces, not the graphics console's probe image.
It neither supplies pixels nor completes hardware transfers.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.web_console import Machine

OUTPUT_BASE = 0x20140000


def snapshot(machine):
    """Stop all cores while correlating register fields and buffer samples."""
    with machine.io:
        machine.qmp.command('stop')
        try:
            words = machine._words(OUTPUT_BASE, 0xf000 // 4)
            registers = {hex(OUTPUT_BASE + i * 4): hex(value)
                         for i, value in enumerate(words) if value}
            pipelines = []
            # Driver objects b1801250/b180126c use offsets 0/4000.
            for offset in (0, 0x4000):
                def word(address):
                    return words[(address + offset) // 4]

                size = word(0x204)
                buffers = []
                # 1046e250 selects these four address arrays; this does not
                # establish their current index or their pixel format.
                for bank in (0x210, 0x220, 0x2440, 0x3440):
                    for index in range(4):
                        address = word(bank + index * 4)
                        if not address:
                            continue
                        sample = None
                        # Do not dereference an unconfigured peripheral or a
                        # corrupt pointer as though it were a pixel surface.
                        if 0xb0000000 <= address <= 0xe0000000 - 256:
                            data = machine._bytes(address, 256)
                            sample = dict(length=len(data),
                                          sha256=hashlib.sha256(data).hexdigest())
                        buffers.append(dict(register=hex(OUTPUT_BASE + offset + bank + index * 4),
                                            address=hex(address), sample=sample))
                pipelines.append(dict(
                    offset=hex(offset), input_control=hex(word(0x200)),
                    width=size & 0xffff, height=(size >> 16) & 0x3fff,
                    stride_fields=[word(0x240), word(0x250)],
                    output_control=hex(word(0x1200)),
                    interrupt_mask=hex(word(0x1210)),
                    interrupt_status=hex(word(0x1214)), buffers=buffers))
            input_state = dict(
                format=hex(machine._words(0x20068500, 1)[0]),
                geometry=[hex(x) for x in machine._words(0x20069500, 13)],
                channels=[dict(base=hex(base), buffers=[hex(x) for x in
                    machine._words(base + 0x50, 8)])
                    for base in range(0x20069800, 0x20069c00, 0x100)])
            capture = machine._bytes(0xb23f6a7c, 0x20)
            return dict(registers=registers, pipelines=pipelines, input=input_state,
                        capture=dict(state=capture[4], substate=capture[5],
                                     pending=hex(int.from_bytes(capture[0x1c:0x20], 'little'))),
                        operation3=hex(machine._words(0xb23f6ff0, 1)[0]),
                        operation14=hex(machine._words(0xb23f701c, 1)[0]),
                        output_notification_index=machine._words(0xb180854c + 0x2c, 1)[0],
                        display_state=machine._bytes(0xb202be70 + 0x19e, 1).hex())
        finally:
            machine.qmp.command('cont')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--wsl', action='store_true')
    parser.add_argument('--sd-card', type=Path)
    parser.add_argument('--samples', type=int, default=2)
    parser.add_argument('--interval', type=float, default=2)
    parser.add_argument('--events', type=int, nargs='+', default=[],
                        help='Pulse physical output-event lines once after the first snapshot')
    parser.add_argument('--display-complete', action='store_true',
                        help='Arm the periodic completion source on both '
                             'recovered lines for the whole run')
    args = parser.parse_args()
    if not 1 <= args.samples <= 20 or not 0 <= args.interval <= 30:
        parser.error('samples must be 1..20 and interval 0..30 seconds')
    if any(not 0 <= event < 64 for event in args.events) or (args.events and args.samples < 2):
        parser.error('events must be 0..63 and require at least two snapshots')
    args.realtime = args.auto_menu = False
    args.sd_card = None
    args.update_store = ROOT / '.local' / 'display-probe-store'
    args.update_image = None
    machine = Machine(args)
    report = dict(observation='native-display-registers-and-256-byte-samples',
                  events=args.events, samples=[])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        machine.restart()
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            state = machine.status()
            if state['phase'] == 'failed':
                raise RuntimeError(state['error'])
            if state.get('ready') and state.get('index') == 3 and state.get('input_ready'):
                break
            time.sleep(1)
        else:
            raise TimeoutError('Shooting application did not become ready')
        report['boot'] = state
        for index in range(args.samples):
            if index:
                if index == 1:
                    with machine.io:
                        for event in args.events:
                            for level in (1, 0):
                                machine._qtest('set_irq_in /machine/master-display '
                                               f'output-event {event} {level}')
                time.sleep(args.interval)
            report['samples'].append(snapshot(machine))
            args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
            print(f'Native display snapshot {index + 1}/{args.samples}', flush=True)
    finally:
        machine.close()


if __name__ == '__main__':
    main()
