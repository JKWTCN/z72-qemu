# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe the inter-engine communication areas after startup.

Service requests are ring entries in the master's communication area
(0xB7CF0000, header magic 0xAA550001 at +0x2c/+0x28) and the peer answers
through its own area. This probe boots the combined machine, stops all
cores and samples both areas twice: header, ring indices and the first
queue entries, without writing anything.
"""
import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.web_console import Machine

MASTER_AREA = 0xb7cf0000
# The slave's own area (0xC60F0000 local) is visible in the master's
# view through the translated 0x46000000 message window.
SLAVE_AREA = 0x460f0000
ENTRY_STRIDE = 0x108


def sample(machine):
    areas = {}
    for name, base in (('master', MASTER_AREA), ('slave', SLAVE_AREA)):
        words = machine._words(base, 0x40 // 4)
        # Ring geometry: index at +8, depth at +0x10; the submit code
        # places entries at base + index*0x108 with the argument at
        # entry +0x18 and the service byte at entry +0x1c.
        areas[name] = dict(
            header=[hex(word) for word in words],
            index=words[2], depth=words[4],
            magic_valid=bool(words[1] == 0xaa550001),
            entries=[[hex(word) for word in
                      machine._words(base + 0x18 + entry * ENTRY_STRIDE, 2)]
                     for entry in range(2)])
    return areas


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--wsl', action='store_true')
    parser.add_argument('--interval', type=float, default=3.0)
    args = parser.parse_args()
    require(1 <= args.interval <= 30, 'Interval out of bounds')
    args.realtime = args.auto_menu = False
    args.sd_card = None
    args.update_store = ROOT / '.local' / 'comm-area-store'
    args.update_image = None
    args.display_complete = False
    machine = Machine(args)
    report = dict(observation='communication-areas', samples=[])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        machine.restart()
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            state = machine.status()
            if state['phase'] == 'failed':
                raise RuntimeError(state['error'])
            if state.get('ready') and state.get('index') == 3 and state.get('input_ready'):
                break
            time.sleep(1)
        else:
            raise TimeoutError('Shooting application did not become ready')
        for index in range(2):
            with machine.io:
                machine.qmp.command('stop')
                try:
                    report['samples'].append(sample(machine))
                finally:
                    machine.qmp.command('cont')
            if index == 0:
                time.sleep(args.interval)
        args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        first, second = report['samples']
        for name in ('master', 'slave'):
            print(name,
                  'index', first[name]['index'], '->', second[name]['index'],
                  'depth', first[name]['depth'], '->', second[name]['depth'],
                  'magic_valid', first[name]['magic_valid'], second[name]['magic_valid'])
    finally:
        machine.close()


def require(condition, message):
    if not condition:
        raise ValueError(message)


if __name__ == '__main__':
    main()
