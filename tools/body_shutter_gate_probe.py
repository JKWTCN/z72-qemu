# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe original full-release gating or playback capture-stop requests (C 1.70)."""
import argparse
import hashlib
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
RETURN_POINTS = {
    0x1043898e: 'idle-shooting-request',
    0x1062e474: 'application-request-dispatch',
    0x106ddc1e: 'application-start-notification',
    0x10540770: 'shooting-render-entry',
    0x1053cfb8: 'shooting-application-entry',
    0x103f2540: 'operation14-api',
    0x103f258e: 'operation15-api',
    0x103f24e4: 'operation13-api',
    0x103f25bc: 'operation16-api',
    0x103f25d4: 'operation17-api',
    0x103f261a: 'operation19-api',
    0x103ef390: 'operation19-task-request',
    0x10247dea: 'operation14-ui-completion',
    0x10247e38: 'initialization-success-dispatch',
    0x1020dad2: 'initialization-main-state-forward',
    0x102470ae: 'initialization-state4-entry',
    0x102470d6: 'initialization-state4-parent-report',
    0x1020dc72: 'initialization-state4-ready-path',
    0x103e7312: 'capture-mode-request',
    0x10323198: 'capture-driver-state-request',
    0x10322886: 'capture-device-initialization',
    0x1023abaa: 'input-configuration-request',
    0x1023aed8: 'input-configuration-update',
    0x1020905a: 'input-geometry-setter',
    0x1036096a: 'public-request-entry-96a',
    0x1036096e: 'public-request-entry-96e',
    0x10360972: 'public-request-entry-972',
    0x1026c25e: 'delegate-diagnostic-current-error',
    0x103234b2: 'capture-device-initialization-return',
    0x10397c16: 'processing-start-command',
    0x10397526: 'processing-start-report',
    0x1026c6cc: 'delegate-start-command',
    0x1026c26a: 'sampling-start-request',
    0x102d7238: 'sampling-start-configuration',
    0x1026c704: 'delegate-start-wait4',
    0x1026c708: 'delegate-start-wait4-return',
    0x1026c71a: 'delegate-start-control-wait',
    0x1026c71e: 'delegate-start-control-wait-return',
    0x1026c37c: 'delegate-wait-failure-notification',
    0x10321a4c: 'capture-driver-notification',
    0x102d9780: 'sampling-run-request',
    0x102d93a2: 'sampling-run-sequence',
    0x102d949e: 'sampling-run-sync-wait',
    0x102d94a6: 'sampling-run-sync-wait-return',
    0x102d950c: 'sampling-run-delay1-wait',
    0x102d9510: 'sampling-run-delay1-wait-return',
    0x102d954c: 'sampling-run-delay2-wait',
    0x102d9550: 'sampling-run-delay2-wait-return',
    0x1026d534: 'resource-completion-notification',
    0x102d97fc: 'sampling-run-return',
    0x1026c732: 'delegate-sampling-run-return',
    0x1026c758: 'delegate-start-final-wait',
    0x1026c75c: 'delegate-start-final-join',
    0x1026c766: 'delegate-start-completion',
    0x1026d30e: 'delegate-start-final-confirmation',
    0x10394762: 'processing-notification',
    0x10394a12: 'processing-event-set',
    0x103949fc: 'processing-start-completion-event',
    0x10397562: 'processing-start-report-return',
    0x1039a006: 'processing-start-handler-continuation',
    0x1039a010: 'processing-start-parameters-return',
    0x10397064: 'processing-input-start-request',
    0x1039706a: 'processing-input-start-return',
    0x1039707a: 'processing-input-start-wait',
    0x1039707e: 'processing-input-start-wait-return',
    0x1039a018: 'processing-start-input-continuation',
    0x10395a88: 'processing-start-previous-input-wait',
    0x10395a8c: 'processing-start-previous-input-continuation',
    0x1039a01e: 'processing-start-output-continuation',
    0x10395158: 'processing-output-prepare',
    0x1039517c: 'processing-output-prepare-return',
    0x10395052: 'processing-output-parameters',
    0x1039508a: 'processing-output-parameters-return',
    0x1039a036: 'processing-output-parameters-continuation',
    0x1039a03c: 'processing-output-request-continuation',
    0x10394ec8: 'processing-output-timer-request',
    0x10394ef8: 'processing-output-timer-config-return',
    0x10394f08: 'processing-output-timer-start-return',
    0x1037160a: 'delay-timer-open',
    0x10371614: 'delay-timer-open-lock-return',
    0x10371704: 'delay-timer-configure',
    0x10371820: 'delay-timer-configure-return',
    0x10371a28: 'delay-timer-start',
    0x10371a38: 'delay-timer-start-return',
    0x10395116: 'processing-start-output-wait',
    0x1039511a: 'processing-start-output-wait-return',
    0x102422c2: 'input-handshake-start-submitted',
    0x102422ea: 'input-handshake-stop-submitted',
    0x1039a060: 'processing-start-handler-return',
    0x103c048a: 'resource-read-request',
    0x103c0664: 'resource-read-result',
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
    manager = remote.read(0xb1811e40, 28)
    engines = {}
    for name, thread in (('master', 1), ('slave', 3)):
        remote.select_thread(thread)
        engines[name] = dict(
            input_format=hex(word(0x20068500)),
            input_geometry=[hex(word(0x20069500 + i * 4)) for i in range(3)])
    remote.select_thread(1)
    resources = {}
    for index in (11, 71, 80):
        row = 0xb185eb70 + index * 28
        callbacks = 0xb20a3288 + index * 48
        resources[str(index)] = dict(buffer=hex(word(row + 8)), length=word(row + 12),
            region=word(row + 20), notification_mask=hex(word(callbacks + 40)),
            subscriber_count=int.from_bytes(remote.read(callbacks + 44, 2), 'little'))
    delay_channels = []
    for channel in range(12):
        base = 0x2c010100 + channel * 0x100
        divider, terminal, count = struct.unpack('<3I', remote.read(base + 0x1004, 12))
        limit = None
        if channel < 5:
            enable, target, observed = struct.unpack('<3I', remote.read(base + 0x1038, 12))
            limit = dict(enabled=enable, target=target, observed=observed)
        delay_channels.append(dict(channel=channel, events=hex(word(base)),
            pending=hex(word(base + 16)), divider=divider,
            terminal=hex(terminal), count=hex(count), repetition_limit=limit))
    cores = []
    for thread in (1, 2, 3, 4):
        remote.select_thread(thread)
        registers = remote.regs()
        cores.append(dict(thread=thread, pc=hex(remote.get(registers, 'pc')),
            faults={name: hex(remote.read_register(name)) for name in
                    ('DFAR_S', 'IFAR_S', 'DFSR_S', 'IFSR_S')}))
    remote.select_thread(1)
    return dict(system_mode=mode[0], previous_mode=mode[1],
        application=dict(initialized=int.from_bytes(manager[:4], 'little'),
                         current=manager[16], requested=manager[17], state=manager[24]),
        engine_inputs=engines,
        resources=resources, cores=cores,
        delay_enable=hex(word(0x2c011000)), delay_channels=delay_channels,
        action_state=state, handler_object=hex(handler_object),
        action_handler=hex(word(handler_object + 0x14)),
        release_gate=word(0xb1821e84), event1_pending=word(0xb201bdd4),
        event1_notifications=[hex(notification) for notification, event in
                              struct.iter_unpack('<II', notifications) if event == 1],
        capture_state=list(remote.read(0xb23f6a80, 2)),
        operation14_callback=hex(word(0xb23f701c)), status_codes=codes,
        operation15_callback=hex(word(0xb23f7020)),
        operation18_callback=hex(word(0xb23f702c)),
        operation19_callback=hex(word(0xb23f7030)),
        capture_field_14=hex(word(0xb23f6a90)),
        capture_driver_state=remote.read(0xb1868af1, 1)[0],
        capture_driver_pending_state=remote.read(0xb1868afa, 1)[0],
        capture_driver_mode=remote.read(0xb1868af7, 1)[0],
        stop_queue_count=word(0xb23ef3d0),
        processing_command=remote.read(0xb1868310, 1)[0],
        processing_state=remote.read(0xb1868311, 1)[0],
        processing_field_24=word(0xb1868334),
        processing_output_kind=remote.read(0xb23ed190, 1)[0],
        processing_output_mode=remote.read(0xb23ed184, 1)[0],
        gpio_adapter=dict(mode=remote.read(0xb18a7920, 1)[0],
                          timer_active=word(0xb18a7924),
                          output_descriptor=hex(word(0xb18a7928)),
                          input_descriptor=hex(word(0xb18a792c))),
        gpio_irq=dict(mask=hex(word(0x0426f000)), pending=hex(word(0x0426f008)),
                      polarity=hex(word(0x0426f014))),
        delegate_state=remote.read(0xb1868510, 1)[0],
        delegate_kind=remote.read(0xb1868511, 1)[0],
        sampling_control=[hex(word(0x200632e0 + i * 4)) for i in range(2)],
        counter_ticks=int.from_bytes(remote.read(0x04266008, 8), 'little'),
        counter_frequency=word(0x04266010),
        input_format=hex(word(0x20068500)),
        input_geometry=[hex(word(0x20069500 + i * 4)) for i in range(3)],
        switch_words=[hex(word(0xb25eaeac + i * 4)) for i in range(3)])


def lcd_snapshot(machine):
    """Summarize the native LCD plane without exporting its pixel payload."""
    with machine.io:
        machine.qmp.command('stop')
        try:
            size = machine._words(0x20144204, 1)[0]
            width, height = size & 0xffff, (size >> 16) & 0x3fff
            planes = machine._words(0x20144210, 2)
            result = dict(width=width, height=height, planes=[hex(value) for value in planes])
            if not (0 < width <= 4096 and 0 < height <= 4096):
                return dict(result, configured=False)
            for plane in planes:
                if 0xb0000000 <= plane <= 0xf0000000 - width * height:
                    data = machine._bytes(plane, width * height)
                    return dict(result, configured=True, sampled_plane=hex(plane),
                        byte_count=len(data), sha256=hashlib.sha256(data).hexdigest(),
                        unique_bytes=len(set(data)), minimum=min(data), maximum=max(data))
            return dict(result, configured=False)
        finally:
            machine.qmp.command('cont')


def observe(machine, seconds, playback=False, local_stop_events=False, returning=False,
            gpio_handshake_events=False):
    with machine.io:
        machine.qmp.command('stop')
    remote = Remote(machine.gdb_port)
    armed = {ACTION: 'application-action'}
    if playback:
        armed.update(AFTER_PLAYBACK)
    if returning:
        armed = dict(RETURN_POINTS)
    records = []
    hits = {}
    callback_hits = 0
    started = time.monotonic()
    try:
        before = snapshot(remote)
        for address in armed:
            remote.breakpoint(address)
        machine.set_key(24 if returning else 8 if playback else 25, 0)
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
                if playback or returning:
                    record['capture_state'] = list(remote.read(0xb23f6a80, 2))
                    record['driver_state'] = remote.read(0xb1868af1, 1)[0]
                    record['driver_pending_state'] = remote.read(0xb1868afa, 1)[0]
                    record['driver_mode'] = remote.read(0xb1868af7, 1)[0]
                    record['counter_ticks'] = int.from_bytes(remote.read(0x04266008, 8), 'little')
                    if returning:
                        hits[pc] = hits.get(pc, 0) + 1
                        repeat = hits[pc] < 8
                        record['application_index'] = remote.read(0xb1811e50, 1)[0]
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
                    if returning and gpio_handshake_events and pc in (
                            0x10395a88, 0x102422c2, 0x102422ea):
                        mask = int.from_bytes(remote.read(0x0426f000, 4), 'little')
                        polarity = int.from_bytes(remote.read(0x0426f014, 4), 'little')
                        record['external_gpio_event'] = dict(
                            input=0, resource=84, intid=65, mask=hex(mask),
                            polarity=hex(polarity), injected=not bool(mask & 1))
                        if not mask & 1:
                            for level in (0, 1, 0):
                                machine._qtest(f'set_irq_in /machine/unattached/{machine.config_names[0]} '
                                               f'gpio-input 0 {level}')
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
                            if address not in hits and
                            (address != 0x10321a4c or callback_hits == 0)])
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
    parser.add_argument('--input-handshake', action='store_true',
                        help='Enable the optional output-triggered laboratory GPIO handshake response')
    parser.add_argument('--playback', action='store_true',
                        help='Observe the native playback capture-stop request instead of full release')
    parser.add_argument('--local-stop-events', action='store_true',
                        help='Laboratory input: pulse the enabled synchronization line at each local stop wait')
    parser.add_argument('--round-trip', action='store_true',
                        help='After playback, half-press to return to shooting and observe full release')
    parser.add_argument('--gpio-handshake-events', action='store_true',
                        help='Laboratory input: pulse GPIO input 0 at armed return-path handshake waits/submissions')
    parser.add_argument('--return-watch', type=int, default=120,
                        help='Host seconds to trace the return from playback (30..900)')
    parser.add_argument('--watch', type=int, default=30)
    args = parser.parse_args()
    require(10 <= args.watch <= 300, 'Watch time out of bounds')
    require(30 <= args.return_watch <= 900, 'Return watch time out of bounds')
    require(not args.local_stop_events or args.playback, 'Local stop events require playback')
    require(not args.round_trip or args.playback, 'Round trip requires playback')
    require(not args.gpio_handshake_events or args.round_trip,
            'GPIO handshake events require a round trip')
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
        initial_lcd = lcd_snapshot(machine)
        report = dict(observation=('native-playback-capture-stop' if args.playback else
                                  'native-full-release-application-gate'), boot=state,
                      sd_attached=args.sd_card is not None,
                      display_complete=args.display_complete, watch_seconds=args.watch,
                      input_handshake=args.input_handshake,
                      local_stop_events=args.local_stop_events,
                      gpio_handshake_events=args.gpio_handshake_events,
                      round_trip=args.round_trip,
                      return_watch_seconds=args.return_watch,
                      trace=observe(machine, args.watch, args.playback, args.local_stop_events))
        report['native_lcd_before'] = initial_lcd
        report['final_application'] = machine.status()
        if args.round_trip and report['final_application']['index'] == 2:
            trace = observe(machine, args.return_watch, returning=True,
                            gpio_handshake_events=args.gpio_handshake_events)
            state = machine.status()
            report['return_liveview'] = dict(application=state, trace=trace)
            if state['index'] == 3 and state['input_ready']:
                report['shutter_after_return'] = observe(machine, 30)
                report['post_shutter_application'] = machine.status()
        report['native_lcd_after'] = lcd_snapshot(machine)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
    finally:
        machine.close()


if __name__ == '__main__':
    main()
