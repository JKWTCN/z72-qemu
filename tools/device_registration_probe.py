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
    0x102323ec: 'session-report-gate',
}
CAPTURE_OPERATION_POINTS = {
    0x103f2540: 'operation14-api',
    0x103f2550: 'operation14-precheck-result',
    0x103f255c: 'operation14-admission-result',
    0x103f258a: 'operation14-api-result',
    0x103ef318: 'operation14-task-request',
    0x1020ea1c: 'operation14-callback-result',
    0x10247dea: 'operation14-ui-completion',
}
RELEASE_EVENT_POINTS = {
    0x103f24e4: 'operation13-api',
    0x103ef2bc: 'operation13-task-request',
    0x1020e9c0: 'operation13-callback-result',
    0x104be91e: 'release-notification-map',
    0x1053e62c: 'release-gate-clear-path',
    0x1036096a: 'public-request-entry-96a',
    0x1036096e: 'public-request-entry-96e',
    0x10360972: 'public-request-entry-972',
    0x10247960: 'public-request-96a-result',
    0x103edd08: 'operation13-state-update',
    0x103f22ca: 'capture-status-callback-registration',
    0x10247e38: 'initialization-success-dispatch',
    0x103f25bc: 'operation16-api',
    0x103f25d4: 'operation17-api',
    0x103ef366: 'operation16-task-request',
    0x103ef376: 'operation17-task-request',
    0x10323676: 'operation16-mode-request',
    0x1032375a: 'operation17-mode-request',
    0x10632f56: 'operation16-completion',
    0x10632fae: 'operation17-completion',
    0x102097fa: 'input-format-setter',
    0x10209848: 'input-format-write',
    0x1020905a: 'input-geometry-setter',
}
INITIALIZATION_FOLLOWUP_POINTS = {
    0x10204c02: 'initialization-parent-state-check',
    0x10204c14: 'initialization-parent-continuation',
    0x10204c38: 'initialization-interface-predicate-result',
    0x10204c4a: 'initialization-parent-predicate-result',
    0x10204c6a: 'initialization-followup-call',
    0x1020dad2: 'initialization-main-state-forward',
    0x1020dc5c: 'initialization-select-state4',
    0x102470ae: 'initialization-state4-entry',
    0x102470d6: 'initialization-state4-parent-report',
    0x1020dc72: 'initialization-state4-ready-path',
}
MODE_REQUEST_POINTS = {address: label for address, label in RELEASE_EVENT_POINTS.items()
                       if label.startswith(('operation16-', 'operation17-'))}
INPUT_CONFIG_POINTS = {
    0x1023abaa: 'input-configuration-request',
    0x1023aed8: 'input-configuration-update',
    0x1023ad12: 'input-geometry-request-selected',
    0x1023afd4: 'input-geometry-update-selected',
    0x1023c8ae: 'input-geometry-full-configuration',
    0x10239c34: 'input-geometry-frame-configuration',
    0x10239bcc: 'input-geometry-conditional-configuration',
    0x1020905a: 'input-geometry-setter',
}
RESOURCE_READ_POINTS = {
    0x103c048a: ('resource-read-entry', None),
    0x103c05f4: ('resource-reload-entry', None),
    0x103c04e0: ('resource-alternate-result', 'r5'),
    0x103c04f2: ('resource-primary-result', 'r5'),
    0x103c0652: ('resource-reload-alternate-result', 'r8'),
    0x103c0664: ('resource-reload-primary-result', 'r8'),
}


class RegistrationMachine(Machine):
    def _boot_dance(self):
        remote = self.remote
        armed = dict(POINTS)
        if self.args.capture_operations:
            armed.update(CAPTURE_OPERATION_POINTS)
        if self.args.watch_release:
            armed.update(RELEASE_EVENT_POINTS)
        if self.args.watch_input_config:
            armed.update(INPUT_CONFIG_POINTS)
        if self.args.watch_resources:
            armed.update({address: value[0] for address, value in RESOURCE_READ_POINTS.items()})
        resource_hits = {}
        input_hits = {}
        armed[SYNC_WAIT] = 'synchronization-wait'
        self.registration_stops = []
        self.session_stops = []
        self.operation14_stops = []
        self.release_event_stops = []
        self.release_gate_stops = []
        self.system_mode_stops = []
        self.mode_callback_stops = {16: [], 17: []}
        watchers = {}
        if self.args.watch_session:
            watchers[0xb3c78081] = (1, self.session_stops)
        if self.args.capture_operations:
            watchers[0xb23f701c] = (4, self.operation14_stops)
        if self.args.watch_release:
            watchers[0xb201bdd4] = (4, self.release_event_stops)
            watchers[0xb1821e84] = (4, self.release_gate_stops)
            watchers[0xb1818d28] = (2, self.system_mode_stops)
        for address, (size, _) in watchers.items():
            require(remote.command(f'Z2,{address:x},{size:x}') == 'OK',
                    'Write watchpoint rejected')
        for address in armed:
            remote.breakpoint(address)
        deadline = time.monotonic() + self.args.watch
        synchronized = False
        try:
            while time.monotonic() < deadline and (armed or watchers):
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
                watch = re.search(r'watch:([0-9a-f]+);', reply)
                if watch and int(watch[1], 16) in watchers:
                    address = int(watch[1], 16)
                    size, records = watchers[address]
                    write = dict(
                        pc=hex(pc), thread=thread,
                        value_before=int.from_bytes(remote.read(address, size), 'little'),
                        registers={name: hex(remote.get(registers, name))
                                   for name in ('r0', 'r1', 'r2', 'r3', 'r4', 'r5',
                                                'r6', 'r7', 'lr')})
                    if pc == 0x10357fba:
                        write['parameter_copy'] = dict(
                            source=hex(remote.get(registers, 'r5') + 0x204),
                            destination=hex(remote.get(registers, 'r4') + 1),
                            value=remote.get(registers, 'r0') & 255)
                    records.append(write)
                    # QEMU stops before the watched store. Advance it with
                    # the watchpoint removed; otherwise every resume reports
                    # the same instruction again without executing the store.
                    require(remote.command(f'z2,{address:x},{size:x}') == 'OK',
                            'Write watchpoint removal failed')
                    del watchers[address]
                    remote.sock.settimeout(15)
                    remote.command(f'vCont;s:{thread:x}')
                    remote.select_thread(thread)
                    write['value_after'] = int.from_bytes(remote.read(address, size), 'little')
                    if self.args.watch_release and address == 0xb1821e84 and write['value_after'] == 1:
                        write['registered_mode_callbacks'] = {}
                        for operation, slot in ((16, 0xb23f7024), (17, 0xb23f7028)):
                            write['registered_mode_callbacks'][str(operation)] = hex(int.from_bytes(
                                remote.read(slot, 4), 'little'))
                            require(remote.command(f'Z2,{slot:x},4') == 'OK',
                                    'Mode callback watchpoint rejected')
                            watchers[slot] = (4, self.mode_callback_stops[operation])
                        for point, label in MODE_REQUEST_POINTS.items():
                            if point not in armed:
                                remote.breakpoint(point)
                            armed[point] = 'post-gate-' + label
                    if len(records) < 8:
                        require(remote.command(f'Z2,{address:x},{size:x}') == 'OK',
                                'Write watchpoint re-arm failed')
                        watchers[address] = (size, records)
                    continue
                # Both engine images use the same base. Slave hits are not
                # evidence about the master's local registration worker.
                if thread > 2 or pc not in armed:
                    if pc in armed:
                        remote.breakpoint(pc, False)
                        remote.sock.settimeout(15)
                        remote.command(f'vCont;s:{thread:x}')
                        remote.breakpoint(pc)
                    continue
                resource = None
                if self.args.watch_resources and pc in RESOURCE_READ_POINTS:
                    pointer_register = RESOURCE_READ_POINTS[pc][1]
                    resource = (remote.read(remote.get(registers, pointer_register), 1)[0]
                                if pointer_register else remote.get(registers, 'r0'))
                    key = (pc, resource)
                    if resource not in (11, 71, 80) or resource_hits.get(key, 0) >= 8:
                        remote.breakpoint(pc, False)
                        remote.sock.settimeout(15)
                        remote.command(f'vCont;s:{thread:x}')
                        remote.breakpoint(pc)
                        continue
                    resource_hits[key] = resource_hits.get(key, 0) + 1
                if pc == 0x104be91e and remote.get(registers, 'r0') != 1:
                    remote.breakpoint(pc, False)
                    remote.sock.settimeout(15)
                    remote.command(f'vCont;s:{thread:x}')
                    remote.breakpoint(pc)
                    continue
                record = dict(
                    entry=armed[pc], pc=hex(pc), thread=thread,
                    registers={name: hex(remote.get(registers, name))
                               for name in ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'lr')},
                    pending=int.from_bytes(remote.read(0xb1d52228, 2), 'little'))
                if resource is not None:
                    record['resource'] = resource
                    record['hit'] = resource_hits[(pc, resource)]
                if self.args.watch_input_config and pc in INPUT_CONFIG_POINTS:
                    input_hits[pc] = input_hits.get(pc, 0) + 1
                    record['hit'] = input_hits[pc]
                    if pc in (0x1023abaa, 0x1023aed8, 0x1023ad12, 0x1023afd4):
                        if pc == 0x1023abaa:
                            mask, table = remote.get(registers, 'r0'), remote.get(registers, 'r2')
                        elif pc == 0x1023aed8:
                            mask, table = remote.get(registers, 'r0'), remote.get(registers, 'r1')
                        elif pc == 0x1023ad12:
                            mask, table = remote.get(registers, 'r5'), remote.get(registers, 'r6')
                        else:
                            mask, table = remote.get(registers, 'r6'), remote.get(registers, 'r7')
                        geometry = int.from_bytes(remote.read(table + 0x18, 4), 'little')
                        record['configuration'] = dict(mask=hex(mask), table=hex(table),
                            geometry_selected=bool(mask & 0x100), geometry_descriptor=hex(geometry))
                if record['entry'].startswith('initialization-'):
                    parent = 0xb1818bd0
                    mode = remote.read(parent + 0x158, 2)
                    interface = int.from_bytes(remote.read(parent + 0x154, 4), 'little')
                    record['parent_state'] = dict(current=mode[0], previous=mode[1],
                        interface=hex(interface))
                    if pc == 0x102470ae:
                        record['state4_object'] = hex(remote.get(registers, 'r0'))
                    if record['entry'] == 'initialization-parent-handler':
                        for address, label in INITIALIZATION_FOLLOWUP_POINTS.items():
                            remote.breakpoint(address)
                            armed[address] = label
                    if pc == 0x10204c6a:
                        target = remote.get(registers, 'r2')
                        record['followup_target'] = hex(target)
                        address = target & ~1
                        remote.breakpoint(address)
                        armed[address] = 'initialization-followup-handler'
                if pc == 0x10264972:
                    descriptor = remote.get(registers, 'r0')
                    context = int.from_bytes(remote.read(descriptor + 0xc, 4), 'little')
                    record['request'] = dict(descriptor=hex(descriptor), context=hex(context),
                        category=remote.read(context + 0xd, 1)[0],
                        service_flag=int.from_bytes(remote.read(context + 0xac, 4), 'little'),
                        resource=int.from_bytes(remote.read(context + 0x12c, 4), 'little'))
                if pc == 0x102323ec:
                    context = remote.get(registers, 'r0')
                    record['session'] = dict(context=hex(context),
                        state=remote.read(context, 1)[0],
                        gate=remote.read(context + 0x41, 1)[0])
                if pc in CAPTURE_OPERATION_POINTS:
                    record['capture_state'] = list(remote.read(0xb23f6a80, 2))
                    record['operation14_callback'] = hex(int.from_bytes(
                        remote.read(0xb23f701c, 4), 'little'))
                if pc in (0x1020ea1c, 0x10247dea):
                    payload = remote.get(registers, 'r4' if pc == 0x1020ea1c else 'r1')
                    record['completion_result'] = int.from_bytes(remote.read(payload, 4), 'little')
                if pc in RELEASE_EVENT_POINTS:
                    record['release_gate'] = int.from_bytes(remote.read(0xb1821e84, 4), 'little')
                    record['event1_pending'] = int.from_bytes(remote.read(0xb201bdd4, 4), 'little')
                    if pc == 0x103f24e4:
                        record['asynchronous'] = remote.get(registers, 'r0') != 0
                    if pc in (0x103f25bc, 0x103f25d4):
                        record['request_flags'] = hex(int.from_bytes(remote.read(
                            remote.get(registers, 'r0'), 4), 'little'))
                        record['callback'] = hex(remote.get(registers, 'r1'))
                    if pc in (0x10632f56, 0x10632fae):
                        record['notification'] = hex(remote.get(registers, 'r0'))
                        payload = remote.get(registers, 'r1')
                        record['completed_flags'] = hex(int.from_bytes(
                            remote.read(payload, 4), 'little')) if payload else None
                    if pc == 0x102097fa:
                        pointer = remote.get(registers, 'r1')
                        record['format_flag_inputs'] = [int.from_bytes(
                            remote.read(pointer + i * 4, 4), 'little') for i in range(14)]
                    if pc == 0x10209848:
                        record['packed_format'] = hex(remote.get(registers, 'r0'))
                    if pc == 0x1020e9c0:
                        record['notification'] = hex(remote.get(registers, 'r6'))
                        record['completion_result'] = int.from_bytes(remote.read(
                            remote.get(registers, 'r4'), 4), 'little')
                    if pc == 0x104be91e:
                        record['notification'] = hex(remote.get(registers, 'r9'))
                    if pc == 0x10247e38:
                        parent = remote.get(registers, 'r0')
                        target = int.from_bytes(remote.read(parent + 0x88, 4), 'little')
                        record['dispatch'] = dict(parent=hex(parent), target=hex(target),
                            event=remote.get(registers, 'r1'),
                            mode=remote.get(registers, 'r2'),
                            argument=hex(remote.get(registers, 'r3')))
                        if target:
                            address = target & ~1
                            remote.breakpoint(address)
                            armed[address] = 'initialization-parent-handler'
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
                if ((self.args.watch_input_config and pc in INPUT_CONFIG_POINTS and input_hits[pc] < 8)
                        or (self.args.watch_resources and pc in RESOURCE_READ_POINTS)):
                    remote.sock.settimeout(15)
                    remote.command(f'vCont;s:{thread:x}')
                    remote.breakpoint(pc)
                else:
                    del armed[pc]
        finally:
            remote.sock.settimeout(15)
            for address in armed:
                remote.breakpoint(address, False)
            for address, (size, _) in watchers.items():
                require(remote.command(f'z2,{address:x},{size:x}') == 'OK',
                        'Write watchpoint cleanup failed')
            require(remote.command('D') == 'OK', 'Could not detach')
            remote.sock.close()
            self.remote = None
        self.registration_unseen = [label for address, label in armed.items()
                                    if address not in input_hits and
                                    address not in {key[0] for key in resource_hits}]
        self.input_configuration_counts = {label: input_hits.get(address, 0)
                                           for address, label in INPUT_CONFIG_POINTS.items()}
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
    parser.add_argument('--watch-session', action='store_true',
                        help='Record up to eight writes to session root byte +0x41')
    parser.add_argument('--capture-operations', action='store_true',
                        help='Observe operation 14 admission and task submission from reset')
    parser.add_argument('--watch-release', action='store_true',
                        help='Observe operation 13, application event 1 and release-gate writes')
    parser.add_argument('--watch-input-config', action='store_true',
                        help='Observe up to eight hits per input configuration and geometry entry')
    parser.add_argument('--watch-resources', action='store_true',
                        help='Observe up to eight reads per entry and resource 11, 71 or 80 from reset')
    args = parser.parse_args()
    require(30 <= args.watch <= 180, 'Watch time out of bounds')
    args.realtime = args.auto_menu = False
    args.update_store = ROOT / '.local' / 'registration-probe-store'
    args.update_image = None
    machine = RegistrationMachine(args)
    report = dict(observation='local-device-registration-from-reset',
                  watch_seconds=args.watch, sd_attached=args.sd_card is not None,
                  display_complete=args.display_complete,
                  watch_session=args.watch_session,
                  capture_operations=args.capture_operations)
    report['watch_release'] = args.watch_release
    report['watch_input_config'] = args.watch_input_config
    report['watch_resources'] = args.watch_resources
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
                      unseen=machine.registration_unseen,
                      session_stops=machine.session_stops,
                      operation14_stops=machine.operation14_stops)
        if args.watch_input_config:
            report['input_configuration_counts'] = machine.input_configuration_counts
        if args.watch_release:
            report.update(release_event_stops=machine.release_event_stops,
                          release_gate_stops=machine.release_gate_stops,
                          system_mode_stops=machine.system_mode_stops,
                          mode_callback_stops=machine.mode_callback_stops)
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
                report['capture_state'] = list(machine._bytes(0xb23f6a80, 2))
                report['operation14_callback'] = hex(machine._words(0xb23f701c, 1)[0])
                if args.watch_resources:
                    report['resources'] = {}
                    for index in (11, 71, 80):
                        row = machine._words(0xb185eb70 + index * 28, 6)
                        mask, count = machine._words(0xb20a3288 + index * 48 + 40, 2)
                        report['resources'][str(index)] = dict(
                            buffer=hex(row[2]), length=row[3], region=row[5],
                            notification_mask=hex(mask), subscriber_count=count & 0xffff)
                if args.watch_input_config or args.watch_release:
                    ticks_low, ticks_high, frequency = machine._words(0x04266008, 3)
                    report['counter_ticks'] = ticks_low | ticks_high << 32
                    report['counter_frequency'] = frequency
                    report['system_modes'] = list(machine._bytes(0xb1818d28, 2))
                    report['input_geometry'] = [hex(value) for value in
                                                machine._words(0x20069500, 3)]
                if args.watch_release:
                    image = args.master.read_bytes()
                    entries = {}
                    for address, value in ((0x1036096a, 0), (0x1036096e, 0),
                                           (0x10360972, 0), (0x10360976, 1)):
                        code = machine._bytes(address, 4)
                        offset = address - 0x10020000
                        entries[hex(address)] = dict(
                            matches_supplied_image=code == image[offset:offset + 4],
                            returns_constant=code == (0x47702000 | value).to_bytes(4, 'little'),
                            constant=value)
                    report['public_request_entries'] = entries
                    report['operation13_pending'] = machine._words(0xb23f6a7c, 1)[0]
                    report['operation13_callback'] = hex(machine._words(0xb23f7018, 1)[0])
                    report['capture_status_callback'] = hex(machine._words(0xb18695ac, 1)[0])
                    report['release_gate'] = machine._words(0xb1821e84, 1)[0]
                    report['event1_pending'] = machine._words(0xb201bdd4, 1)[0]
                    report['operation16_callback'] = hex(machine._words(0xb23f7024, 1)[0])
                    report['operation17_callback'] = hex(machine._words(0xb23f7028, 1)[0])
                report['device_worker_state'] = dict(
                    state=machine._bytes(0xb1864d49, 1)[0],
                    category=machine._bytes(0xb1864d4a, 1)[0])
                root = machine._words(0xb1887dac, 1)[0]
                report['session_root'] = hex(root)
                report['session_root_field_41'] = machine._bytes(root + 0x41, 1)[0]
            finally:
                machine.qmp.command('cont')
        args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({key: value for key, value in report.items()
                          if key != 'communication'}, indent=2))
    finally:
        machine.close()


if __name__ == '__main__':
    main()
