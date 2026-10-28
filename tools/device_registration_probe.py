# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe the local device-registration worker from reset, without patching it.

Addresses are for C 1.70. The registration callback is distinct from the
later service-state router. Only the normal synchronization input is driven.
"""
import argparse
import json
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from tools.comm_area_probe import sample
from tools.web_console import Machine, SYNC_WAIT

POINTS = {
    0x103b21aa: 'registration-gate-result',
    0x103b21b6: 'registration-gate-passed',
    0x102638a2: 'registration-callback-bit8',
    0x10264972: 'device-request',
    0x10264a72: 'device-reservation-result',
    0x10264de0: 'device-service-creation',
    0x103ce6ac: 'device-construction',
}


class RegistrationMachine(Machine):
    def _boot_dance(self):
        remote = self.remote
        armed = dict(POINTS)
        armed[SYNC_WAIT] = 'synchronization-wait'
        self.registration_stops = []
        for address in armed:
            remote.breakpoint(address)
        deadline = time.monotonic() + self.args.watch
        synchronized = False
        try:
            while time.monotonic() < deadline and armed:
                remote.sock.settimeout(min(5, max(0.2, deadline - time.monotonic())))
                try:
                    reply = remote.command('vCont;c')
                except TimeoutError:
                    remote.sock.settimeout(15)
                    remote.interrupt()
                    require(not self.shutdown.is_set(), 'Probe stopped')
                    continue
                match = re.search(r'thread:([0-9a-f]+);', reply)
                require(match is not None, 'Missing stop thread')
                thread = int(match[1], 16)
                remote.select_thread(thread)
                registers = remote.regs()
                pc = remote.get(registers, 'pc')
                # Both engine images use the same base. Slave hits are not
                # evidence about the master's local registration worker.
                if thread > 2 or pc not in armed:
                    continue
                record = dict(
                    entry=armed[pc], pc=hex(pc), thread=thread,
                    registers={name: hex(remote.get(registers, name))
                               for name in ('r0', 'r1', 'r2', 'r5', 'r6', 'lr')},
                    pending=int.from_bytes(remote.read(0xb1d52228, 2), 'little'))
                if pc == 0x10264972:
                    descriptor = remote.get(registers, 'r0')
                    context = int.from_bytes(remote.read(descriptor + 0xc, 4), 'little')
                    record['request'] = dict(descriptor=hex(descriptor), context=hex(context),
                        category=remote.read(context + 0xd, 1)[0],
                        service_flag=int.from_bytes(remote.read(context + 0xac, 4), 'little'),
                        resource=int.from_bytes(remote.read(context + 0x12c, 4), 'little'))
                self.registration_stops.append(record)
                if pc == SYNC_WAIT:
                    require(all(remote.get(registers, name) == value
                                for name, value in
                                (('r0', 0xb18a764c), ('r1', 8), ('r3', 50))),
                            'Unexpected synchronization wait')
                    require(int.from_bytes(remote.read(0x20060040, 4), 'little') & 0x10,
                            'Synchronization input is masked')
                    for level in (1, 0):
                        self._qtest(f'set_irq_in /machine/unattached/{self.config_names[0]} '
                                    f'sync-event 15 {level}')
                    for level in (0, 1):
                        self._qtest(f'set_irq_in /machine/unattached/{self.config_names[0]} '
                                    f'frame-sync-enable 0 {level}')
                    synchronized = True
                remote.breakpoint(pc, False)
                del armed[pc]
        finally:
            remote.sock.settimeout(15)
            for address in armed:
                remote.breakpoint(address, False)
            require(remote.command('D') == 'OK', 'Could not detach')
            remote.sock.close()
            self.remote = None
        self.registration_unseen = list(armed.values())
        require(synchronized, 'Synchronization wait was not observed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--wsl', action='store_true')
    parser.add_argument('--sd-card', type=Path)
    parser.add_argument('--display-complete', action='store_true')
    parser.add_argument('--watch', type=int, default=120)
    args = parser.parse_args()
    require(30 <= args.watch <= 180, 'Watch time out of bounds')
    args.realtime = args.auto_menu = False
    args.update_store = ROOT / '.local' / 'registration-probe-store'
    args.update_image = None
    machine = RegistrationMachine(args)
    report = dict(observation='local-device-registration-from-reset',
                  watch_seconds=args.watch, sd_attached=args.sd_card is not None,
                  display_complete=args.display_complete)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        machine.restart()
        deadline = time.monotonic() + args.watch + 240
        while time.monotonic() < deadline:
            state = machine.status()
            if state['phase'] == 'failed':
                raise RuntimeError(state['error'])
            if state.get('ready') and state.get('index') == 3 and state.get('input_ready'):
                break
            time.sleep(1)
        else:
            raise TimeoutError('Shooting application did not become ready')
        report.update(boot=state, stops=machine.registration_stops,
                      unseen=machine.registration_unseen)
        with machine.io:
            machine.qmp.command('stop')
            try:
                communication = sample(machine)
                # Publish decoded fields only, without RAM excerpts.
                report['communication'] = dict(
                    areas={name: {key: area[key] for key in
                                  ('index', 'depth', 'magic_valid', 'messages')}
                           for name, area in communication['areas'].items()},
                    service_rings={name: {key: value for key, value in ring.items()
                                          if key != 'head'}
                                   for name, ring in
                                   communication['slave_service_rings']['rings'].items()
                                   if ring is not None})
                report['module_wait_mask'] = hex(machine._words(0xb1864854, 1)[0])
                report['input_format'] = hex(machine._words(0x20068500, 1)[0])
                report['device_worker_state'] = dict(
                    state=machine._bytes(0xb1864d49, 1)[0],
                    category=machine._bytes(0xb1864d4a, 1)[0])
            finally:
                machine.qmp.command('cont')
        args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({key: value for key, value in report.items()
                          if key != 'communication'}, indent=2))
    finally:
        machine.close()


if __name__ == '__main__':
    main()
