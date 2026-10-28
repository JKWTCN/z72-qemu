# SPDX-License-Identifier: GPL-2.0-or-later
"""Dump the runtime notification subscription records copied from the tables.

The sender of notification 0x041b0080 is a registered callback. Static tables
hold the handler addresses; the notification codes are only present in the
runtime copies. This probe boots the combined machine to the shooting
foreground, stops all cores and reads the record blocks without writing.
"""
import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from tools.web_console import Machine

# File tables 0x2441668/0x24481d4/0x2448f58/0x2449cdc carry destination
# pointers in their headers; the runtime blocks below hold the live records.
BLOCKS = ((0xb18649f8, 0x60, 'table-1'), (0xb1864a60, 0x60, 'table-2'))
LINKED = ((0xb2bc87f8, 0x40, 'link-1'), (0xb2bcf364, 0x40, 'link-2'))
# The capture module block (slots +0x14/+0x18/+0x20/+0x50/+0x54/+0x58 hold
# the router callbacks and device object) and the service-manager block's
# service-3 descriptors (+0x3dc/+0x438).
BLOCKS += ((0xb1864834, 0x80, 'module'), (0xb238af30, 0x40, 'service-manager'),
           (0xb238b30c, 0x60, 'service-3-a'), (0xb238b368, 0x60, 'service-3-b'))
CALLBACK = 0x10269f0d
NOTIFICATION = 0x041b0080
# The linked handler blocks (0xb2bc87f8/0xb2bcf364) live in the state-stack
# window; the scatter window holds the module blocks themselves.
SCAN_BASE, SCAN_SIZE = 0xb2000000, 0xc00000
# Runtime entries of the device-state sender and the capture dispatcher.
SENDER = 0x10269f0c
DISPATCHER = 0x103cd162
# The communication-ring consumer (both engines share the image base).
RING_CONSUMER = 0x10387f84
# Positive controls: the whole-word sync handler (IRQ 87, fed by the
# sample source) and the 10 ms timer handler (IRQ 237).
CONTROLS = (0x102dc5c0, 0x105165d4)


def observe_notifications(machine, seconds, limit=24, poll_ready=False):
    """Record breakpoint hits at the sender and the capture dispatcher.

    The dispatcher's r0 is the delivered notification code; the sender's lr
    identifies the notification infrastructure that invoked it. Nothing is
    written to guest memory or registers.
    """
    import re
    from analyze.qemu_display import Remote
    with machine.io:
        # A deterministic handshake: halt through the monitor first, then
        # attach. Breakpoints arm on a stopped target and vCont;c resumes it;
        # \x03 is only sent while the target runs (vCont;c timed out).
        machine.qmp.command('stop')
    remote = Remote(machine.gdb_port)
    remote.sock.settimeout(15)
    armed = {address: name for address, name in
             ((SENDER, 'sender'), (DISPATCHER, 'dispatcher'),
              (RING_CONSUMER, 'ring-consumer'),
              *zip(CONTROLS, ('control-sync87', 'control-timer237')))}
    for address in armed:
        require(remote.command(f'Z1,{address:x},2') == 'OK',
                'Notification breakpoint rejected')
    records = []
    ready = False
    try:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and len(records) < limit:
            remote.sock.settimeout(1 if poll_ready else
                                   min(6, max(0.2, deadline - time.monotonic())))
            try:
                reply = remote.command('vCont;c')
            except TimeoutError:
                if poll_ready:
                    # Short segments let the readiness poll run between
                    # resumes while boot proceeds. status() takes the
                    # machine lock itself; do not wrap it again.
                    remote.sock.settimeout(15)
                    remote.interrupt()
                    state = machine.status()
                    if state.get('ready') and state.get('index') == 3 \
                            and state.get('input_ready'):
                        ready = True
                        break
                    continue
                # A stop request returns the stop reply; the next loop
                # iteration resumes the machine again.
                remote.sock.settimeout(15)
                remote.interrupt()
                continue
            match = re.search(r'thread:([0-9a-f]+);', reply or '')
            if not match:
                break
            thread = int(match[1], 16)
            remote.select_thread(thread)
            registers = remote.regs()
            pc = remote.get(registers, 'pc')
            entry = armed.get(pc, 'other')
            records.append(dict(
                pc=hex(pc), entry=entry, thread=thread,
                code=hex(remote.get(registers, 'r0')),
                payload=hex(remote.get(registers, 'r1')),
                caller=hex(remote.get(registers, 'lr'))))
            if entry.startswith('control'):
                # One control hit proves the observation window works;
                # removing it keeps later ticks from re-stopping here.
                require(remote.command(f'z1,{pc:x},2') == 'OK',
                        'Control breakpoint removal failed')
                del armed[pc]
    finally:
        remote.sock.settimeout(15)
        for address in armed:
            require(remote.command(f'z1,{address:x},2') == 'OK',
                    'Notification breakpoint cleanup failed')
        remote.command('D')
        remote.sock.close()
        with machine.io:
            machine.qmp.command('cont')
    return records, ready


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--wsl', action='store_true')
    parser.add_argument('--watch', type=int, default=20,
                        help='Seconds of steady-state breakpoint observation')
    parser.add_argument('--watch-boot', type=int, default=0,
                        help='Observe from the post-handshake boot window '
                             'until the shooting foreground is ready')
    parser.add_argument('--skip-scan', action='store_true',
                        help='Skip the RAM scan; still dump the fixed blocks')
    args = parser.parse_args()
    require(5 <= args.watch <= 120, 'Watch seconds out of bounds')
    require(0 <= args.watch_boot <= 600, 'Boot watch seconds out of bounds')
    args.realtime = args.auto_menu = False
    args.sd_card = None
    args.update_store = ROOT / '.local' / 'subscription-probe-store'
    args.update_image = None
    machine = Machine(args)
    report = dict(observation='runtime-subscription-records', blocks={},
                  linked={}, send_callback=None, matches=[])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        machine.restart()
        if args.watch_boot:
            # The boot dance owns the debug connection until the machine
            # reaches the running phase; observe from there through the
            # application startup window.
            deadline = time.monotonic() + 240
            while machine.phase == 'starting':
                require(time.monotonic() < deadline, 'Machine startup timed out')
                if machine.phase == 'failed':
                    raise RuntimeError(machine.error)
                time.sleep(0.5)
            require(machine.phase == 'running', machine.error or machine.phase)
            stops, ready = observe_notifications(machine, args.watch_boot,
                                                 poll_ready=True)
            report['boot_notification_stops'] = stops
            report['boot_watch_ready'] = ready
        deadline = time.monotonic() + 300
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
        with machine.io:
            machine.qmp.command('stop')
            try:
                for address, size, name in BLOCKS + LINKED:
                    words = machine._words(address, size // 4)
                    report['blocks' if name.startswith('table') else 'linked'][name] = dict(
                        base=hex(address),
                        words=[hex(word) for word in words])
                    for index, word in enumerate(words):
                        if word == CALLBACK:
                            report['matches'].append(dict(
                                block=name, base=hex(address), index=index,
                                offset=hex(index * 4),
                                context=[hex(w) for w in words[max(0, index - 3):index + 3]]))
                report['send_callback'] = hex(machine._words(0xb1864834 + 0x58, 1)[0])
                # Locate the live records holding the callback or the
                # notification code across the initialized-data window.
                report['scan'] = dict(base=hex(SCAN_BASE), size=SCAN_SIZE,
                                      skipped=args.skip_scan,
                                      callback_hits=[], code_hits=[])
                chunk = 0x2000
                for offset in (range(0, SCAN_SIZE, chunk)
                               if not args.skip_scan else ()):
                    words = machine._words(SCAN_BASE + offset, chunk // 4)
                    for index, word in enumerate(words):
                        if word not in (CALLBACK, NOTIFICATION):
                            continue
                        entry = dict(address=hex(SCAN_BASE + offset + index * 4),
                                     context=[hex(w) for w in
                                              words[max(0, index - 3):index + 3]])
                        (report['scan']['callback_hits'] if word == CALLBACK
                         else report['scan']['code_hits']).append(entry)
            finally:
                machine.qmp.command('cont')
        report['notification_stops'], _ = observe_notifications(machine, args.watch)
        args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(dict(send_callback=report['send_callback'],
                              boot_notification_stops=report.get('boot_notification_stops'),
                              notification_stops=report['notification_stops']),
                         indent=2))
    finally:
        machine.close()


if __name__ == '__main__':
    main()
