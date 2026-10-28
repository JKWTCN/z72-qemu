# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe original full-release gating or playback capture-stop requests (C 1.70)."""
import argparse
import json
from pathlib import Path
import re
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from analyze.qemu_display import Remote
from tools.web_console import Machine

ACTION = 0x1053ba0e
AFTER_ACTION = {
    0x10542038: 'action-check-result',
    0x104e6c28: 'release-gate-result',
    0x104e6c66: 'past-release-gate',
    0x1053e598: 'event1-check-result',
    0x1053e62c: 'release-gate-clear-path',
}
AFTER_PLAYBACK = {
    0x103f25ec: 'operation18-api',
    0x103ef386: 'operation18-task-request',
    0x103e7312: 'capture-mode-request',
    0x103e6e94: 'capture-state-transition',
    0x103237d4: 'capture-stop-driver-request',
    0x10323198: 'capture-driver-state-request',
    0x103237ec: 'capture-stop-driver-return',
    0x103e6c0a: 'operation18-completion-producer',
    0x1020e228: 'operation18-ui-dispatch',
    0x10323392: 'capture-stop-driver-branch',
    0x10322e3e: 'capture-stop-subsystem-request',
    0x103233d2: 'capture-stop-mode0-result',
    0x103233fc: 'capture-stop-mode1-result',
    0x1032340a: 'capture-stop-other-mode',
    0x10323430: 'capture-stop-other-mode-result',
    0x10322e64: 'capture-stop-queue-check',
    0x10322e84: 'capture-stop-parameter-result',
    0x10322eb0: 'capture-stop-prepare-result',
    0x10322ede: 'capture-stop-local-stop-result',
    0x10322f30: 'capture-stop-worker-result',
    0x103c5342: 'capture-stop-prepare-request',
    0x1023333e: 'capture-stop-local-stop',
    0x10233394: 'capture-stop-worker-request',
    0x10398726: 'processing-stop-command',
    0x10321a4c: 'capture-driver-notification',
    0x10397260: 'processing-stop-worker',
    0x1026e204: 'processing-stop-delegate',
    0x1026e230: 'processing-stop-link-return',
    0x1026e242: 'processing-stop-sync-request',
    0x1026e246: 'processing-stop-sync-return',
    0x1026e24a: 'processing-stop-callback-return',
    0x1026e254: 'processing-stop-delegate-return',
    0x1039722c: 'processing-stop-finalize',
    0x102ea05a: 'processing-stop-event-request',
    0x102ea06e: 'processing-stop-event-wait',
    0x1026c91a: 'delegate-stop-command',
    0x1026c9a0: 'delegate-stop-wait',
    0x1026c9a4: 'delegate-stop-wait-return',
    0x1026c37c: 'delegate-wait-failure-notification',
    0x1026c9c4: 'delegate-stop-completion-notification',
    0x102e961c: 'link-stop-completion-first',
    0x102e9692: 'link-stop-completion-second',
    0x1026c174: 'delegate-diagnostic-configured',
    0x1026c220: 'delegate-diagnostic-stored-error',
    0x1026c25e: 'delegate-diagnostic-current-error',
    0x102d987c: 'local-stop-frame-wait',
    0x102d9880: 'local-stop-frame-wait-return',
    0x102d98c4: 'local-stop-control20-wait',
    0x102d98c8: 'local-stop-control20-wait-return',
    0x102d9902: 'local-stop-control10-wait',
    0x102d9906: 'local-stop-control10-wait-return',
    0x10296352: 'sampling-control-command',
    0x10296360: 'sampling-control-submit',
}


def snapshot(remote):
    remote.select_thread(1)
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    mode = remote.read(0xb1818d28, 2)
    state = remote.read(0xb1821b18, 1)[0]
    handler_object = word(0xb202f728 + state * 4)
    size, pointer = struct.unpack('<II', remote.read(0xb187556c, 8))
    codes = None
    if size == 0x118 and pointer:
        count = word(pointer + 0x110)
        if count <= 68:
            codes = [hex(x) for x in struct.unpack('<' + 'I' * count,
                                                 remote.read(pointer, count * 4))]
    notifications = remote.read(0x1094559c, 44 * 8)
    engines = {}
    for name, thread in (('master', 1), ('slave', 3)):
        remote.select_thread(thread)
        engines[name] = dict(
            input_format=hex(word(0x20068500)),
            input_geometry=[hex(word(0x20069500 + i * 4)) for i in range(3)])
    remote.select_thread(1)
    return dict(system_mode=mode[0], previous_mode=mode[1],
        engine_inputs=engines,
        action_state=state, handler_object=hex(handler_object),
        action_handler=hex(word(handler_object + 0x14)),
        release_gate=word(0xb1821e84), event1_pending=word(0xb201bdd4),
        event1_notifications=[hex(notification) for notification, event in
                              struct.iter_unpack('<II', notifications) if event == 1],
        capture_state=list(remote.read(0xb23f6a80, 2)),
        operation14_callback=hex(word(0xb23f701c)), status_codes=codes,
        operation15_callback=hex(word(0xb23f7020)),
        operation18_callback=hex(word(0xb23f702c)),
        capture_field_14=hex(word(0xb23f6a90)),
        capture_driver_state=remote.read(0xb1868af1, 1)[0],
        capture_driver_pending_state=remote.read(0xb1868afa, 1)[0],
        capture_driver_mode=remote.read(0xb1868af7, 1)[0],
        stop_queue_count=word(0xb23ef3d0),
        processing_command=remote.read(0xb1868310, 1)[0],
        processing_state=remote.read(0xb1868311, 1)[0],
        delegate_state=remote.read(0xb1868510, 1)[0],
        sampling_control=[hex(word(0x200632e0 + i * 4)) for i in range(2)],
        counter_ticks=int.from_bytes(remote.read(0x04266008, 8), 'little'),
        counter_frequency=word(0x04266010),
        input_format=hex(word(0x20068500)),
        input_geometry=[hex(word(0x20069500 + i * 4)) for i in range(3)],
        switch_words=[hex(word(0xb25eaeac + i * 4)) for i in range(3)])


def observe(machine, seconds, playback=False, local_stop_events=False):
    with machine.io:
        machine.qmp.command('stop')
    remote = Remote(machine.gdb_port)
    armed = {ACTION: 'application-action'}
    if playback:
        armed.update(AFTER_PLAYBACK)
    records = []
    callback_hits = 0
    started = time.monotonic()
    try:
        before = snapshot(remote)
        for address in armed:
            remote.breakpoint(address)
        machine.set_key(8 if playback else 25, 0)
        deadline = started + seconds
        while time.monotonic() < deadline and armed:
            machine.heartbeat()
            remote.sock.settimeout(min(1, max(0.2, deadline - time.monotonic())))
            try:
                reply = remote.command('vCont;c')
            except TimeoutError:
                remote.sock.settimeout(15)
                remote.interrupt()
                continue
            match = re.search(r'thread:([0-9a-f]+);', reply)
            require(match is not None, 'Missing stop thread')
            thread = int(match[1], 16)
            remote.select_thread(thread)
            registers = remote.regs()
            pc = remote.get(registers, 'pc')
            require(pc in armed, f'Unexpected stop at {pc:#x}')
            repeat = thread > 2
            if thread <= 2:
                record = dict(entry=armed[pc], pc=hex(pc), thread=thread,
                    registers={name: hex(remote.get(registers, name)) for name in
                               ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'lr')})
                if playback:
                    record['capture_state'] = list(remote.read(0xb23f6a80, 2))
                    record['driver_state'] = remote.read(0xb1868af1, 1)[0]
                    record['driver_pending_state'] = remote.read(0xb1868afa, 1)[0]
                    record['driver_mode'] = remote.read(0xb1868af7, 1)[0]
                    record['counter_ticks'] = int.from_bytes(remote.read(0x04266008, 8), 'little')
                    if pc == 0x10321a4c:
                        callback_hits += 1
                        record['notification'] = hex(remote.get(registers, 'r0'))
                        if remote.get(registers, 'r0') == 0x041a000d:
                            record['result_bytes'] = list(remote.read(
                                remote.get(registers, 'r1'), 2))
                        repeat = callback_hits < 8
                    if pc == 0x10397260:
                        record['stop_command'] = list(struct.unpack('<4I', remote.read(0xb23ed1a0, 16)))
                    if pc in (0x1026c37c, 0x1026c174, 0x1026c220, 0x1026c25e):
                        record['failure_details'] = list(struct.unpack(
                            '<3I', remote.read(remote.get(registers, 'r1'), 12)))
                    if local_stop_events and pc in (0x102d987c, 0x102d98c4, 0x102d9902):
                        bit = {0x102d987c: 7, 0x102d98c4: 10, 0x102d9902: 18}[pc]
                        mask = int.from_bytes(remote.read(0x20060040, 4), 'little')
                        record['external_sync_event'] = dict(bank=2, bit=bit, mask=hex(mask))
                        require(mask & (1 << bit), 'Requested synchronization event is masked')
                        for level in (0, 1, 0):
                            machine._qtest(f'set_irq_in /machine/unattached/{machine.config_names[0]} '
                                           f'sync-event {11 + bit} {level}')
                if pc == ACTION:
                    action = int.from_bytes(remote.read(
                        remote.get(registers, 'sp') + 0xc, 4), 'little')
                    full = bool(remote.get(registers, 'r5') & 0x40000000)
                    record.update(action=hex(action), full_press=full)
                    repeat = action != 0x1a if playback else not (full and action == 0x14)
                    if not repeat:
                        record['switch_words'] = [hex(x) for x in struct.unpack(
                            '<III', remote.read(0xb25eaeac, 12))]
                        for address, label in ({} if playback else AFTER_ACTION).items():
                            remote.breakpoint(address)
                            armed[address] = label
                if pc == 0x104e6c28:
                    record['release_gate'] = remote.get(registers, 'r0')
                    record['action'] = hex(remote.get(registers, 'r6'))
                records.append(record)
            remote.breakpoint(pc, False)
            if repeat:
                remote.sock.settimeout(15)
                remote.command(f'vCont;s:{thread:x}')
                remote.breakpoint(pc)
            else:
                del armed[pc]
        after = snapshot(remote)
        return dict(before=before, records=records, after=after,
                    observed_seconds=round(time.monotonic() - started, 3),
                    observed_counter_seconds=round((after['counter_ticks'] - before['counter_ticks']) /
                                                   before['counter_frequency'], 6),
                    driver_notification_hits=callback_hits,
                    unseen=[label for address, label in armed.items()
                            if address != 0x10321a4c or callback_hits == 0])
    finally:
        remote.sock.settimeout(15)
        for address in armed:
            remote.breakpoint(address, False)
        remote.command('D')
        remote.sock.close()
        if playback:
            machine.set_key(8, 1)
        machine.set_key(25, 1)
        machine.set_key(24, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--wsl', action='store_true')
    parser.add_argument('--sd-card', type=Path)
    parser.add_argument('--display-complete', action='store_true')
    parser.add_argument('--playback', action='store_true',
                        help='Observe the native playback capture-stop request instead of full release')
    parser.add_argument('--local-stop-events', action='store_true',
                        help='Laboratory input: pulse the enabled synchronization line at each local stop wait')
    parser.add_argument('--round-trip', action='store_true',
                        help='After playback, half-press to return to shooting and observe full release')
    parser.add_argument('--watch', type=int, default=30)
    args = parser.parse_args()
    require(10 <= args.watch <= 300, 'Watch time out of bounds')
    require(not args.local_stop_events or args.playback, 'Local stop events require playback')
    require(not args.round_trip or args.playback, 'Round trip requires playback')
    args.realtime = args.auto_menu = False
    args.update_store = ROOT / '.local/body-shutter-gate-store'
    args.update_image = None
    machine = Machine(args)
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
            raise TimeoutError('Shooting foreground did not become ready')
        report = dict(observation=('native-playback-capture-stop' if args.playback else
                                  'native-full-release-application-gate'), boot=state,
                      sd_attached=args.sd_card is not None,
                      display_complete=args.display_complete, watch_seconds=args.watch,
                      local_stop_events=args.local_stop_events,
                      round_trip=args.round_trip,
                      trace=observe(machine, args.watch, args.playback, args.local_stop_events))
        report['final_application'] = machine.status()
        if args.round_trip and report['final_application']['index'] == 2:
            transitions = []
            started = time.monotonic()
            machine.set_key(24, 0)
            try:
                while time.monotonic() - started < 120:
                    machine.heartbeat()
                    state = machine.status()
                    if not transitions or state['index'] != transitions[-1]['index']:
                        transitions.append(dict(seconds=round(time.monotonic() - started, 3),
                                                index=state['index']))
                    if state['index'] == 3 and state['input_ready']:
                        break
                    time.sleep(1)
            finally:
                machine.set_key(24, 1)
            report['return_liveview'] = dict(application=state, transitions=transitions,
                                             observed_seconds=round(time.monotonic() - started, 3))
            if state['index'] == 3 and state['input_ready']:
                report['shutter_after_return'] = observe(machine, 30)
                report['post_shutter_application'] = machine.status()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
    finally:
        machine.close()


if __name__ == '__main__':
    main()
