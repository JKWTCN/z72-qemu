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
# Transport control blocks: the magic pair at +0x28/+0x2c gates both the
# submit and the consumer paths. Both engines address one base through
# two literals ten bytes apart (master 0xB1808928/0xB1808938 minus 0x10,
# slave 0xC1006F68/0xC1006F78 minus 0x10); the slave's base is read
# through the master's bus window.
CONTROL_BLOCKS = ((0xb1808928, 'master'), (0x41006f68, 'slave'))
# Slave-side transport counters and the five event-handler slots the
# consumer callback dispatches through (slave RAM via the bus window).
SLAVE_COUNTERS = 0x4144f3ac
SLAVE_HANDLERS = 0x4144f570
# The slave's 11-slot service table (service ids 0..0xa) and the
# master's counterpart, read through each owner's own view.
SLAVE_SERVICES = 0x4144f380
MASTER_SERVICES = 0xb1d19e48
# The slave's per-service local ring pointers (cursor at +0x30) that
# the generic handler enqueues consumed requests into.
SLAVE_SERVICE_RINGS = 0x4144f584


def service_rings(machine):
    pointers = machine._words(SLAVE_SERVICE_RINGS, 11)
    rings = {}
    for index, pointer in enumerate(pointers):
        if not 0xc0000000 <= pointer < 0xc2000000:
            rings[index] = None
            continue
        window = 0x40000000 + (pointer & 0x0fffffff)
        rings[index] = dict(pointer=hex(pointer),
                            cursor=machine._words(window + 0x30, 1)[0])
    return dict(pointers=[hex(p) for p in pointers], rings=rings)


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
    controls = {}
    for base, name in CONTROL_BLOCKS:
        words = machine._words(base, 0x34 // 4)
        controls[name] = dict(
            base=hex(base), words=[hex(word) for word in words],
            magic_pair=[hex(words[0xa]), hex(words[0xb])],
            magic_ok=bool(words[0xa] == 0xc00108 and words[0xb] == 0xaa550001))
    counters = machine._words(SLAVE_COUNTERS, 2)
    handlers = machine._words(SLAVE_HANDLERS, 5)
    services = {'slave': [hex(word) for word in machine._words(SLAVE_SERVICES, 11)],
                'master': [hex(word) for word in machine._words(MASTER_SERVICES, 11)]}
    return dict(areas=areas, controls=controls,
                slave_counters=[hex(word) for word in counters],
                slave_handlers=[hex(word) for word in handlers],
                services=services,
                slave_service_rings=service_rings(machine))


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
            a, b = first['areas'][name], second['areas'][name]
            print(name,
                  'index', a['index'], '->', b['index'],
                  'depth', a['depth'], '->', b['depth'],
                  'magic_valid', a['magic_valid'], b['magic_valid'])
        for name in ('master', 'slave'):
            control = first['controls'][name]
            print('control', name, 'pair', control['magic_pair'],
                  'ok', control['magic_ok'])
        print('slave counters', first['slave_counters'], '->',
              second['slave_counters'])
        print('slave handlers', first['slave_handlers'])
        for engine in ('master', 'slave'):
            print(engine, 'service table', first['services'][engine])
        print('slave service rings', first['slave_service_rings']['pointers'])
        for index, ring in first['slave_service_rings']['rings'].items():
            if ring:
                print(' service', index, 'ring', ring['pointer'],
                      'cursor', ring['cursor'], '->',
                      second['slave_service_rings']['rings'][index]['cursor'])
    finally:
        machine.close()


def require(condition, message):
    if not condition:
        raise ValueError(message)


if __name__ == '__main__':
    main()
