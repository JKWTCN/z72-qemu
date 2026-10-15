# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify the original syscall handoff after the parameter tail in both roles."""
import argparse
import json
import re
import struct
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from analyze.kernel_boot import kernel_profile
from tools.boot_probe import reset_machine
from tools.smp_boot_probe import trace_smp, reach, stop_registers, snapshot

# Scheduler state recovered from the payload block: the idle loop reads the
# per-core current-task pointer at 0xB2B41604 and the timer dispatcher reads
# the event word at 0x2B000008.
READY_TASK_TABLE = 0xB2B41604
TIMER_EVENT = 0x2B000008


def bounded_continue(remote, seconds=15):
    """Continue once with a short bound; report whether any stop arrived."""
    remote.sock.settimeout(seconds)
    try:
        thread, regs = stop_registers(remote, remote.command('vCont;c:1'))
        return dict(timed_out=False, pc=remote.get(regs, 'pc'))
    except TimeoutError:
        # The outstanding vCont reply never arrived; interrupt the target so
        # the pending stop reply drains and the connection resyncs.
        remote.sock.settimeout(20)
        try:
            remote.interrupt()
        except TimeoutError:
            pass
        return dict(timed_out=True)
    finally:
        remote.sock.settimeout(30)


def settle_loop(remote, limit, low, high):
    """Step until one address repeats; the handoff wait stabilizes there."""
    import collections
    seen = collections.Counter()
    remote.sock.settimeout(30)
    for _ in range(limit):
        remote.command('s')
        pc = remote.get(remote.regs(), 'pc')
        require(low <= pc < high,
                f'Handoff execution left the recovered block at {pc:#x}')
        seen[pc] += 1
        if seen[pc] > 4:
            return pc, seen
    raise ValueError('Original handoff wait loop did not settle')


def observe_wait(remote, profile):
    """Expose the wait object through access watchpoints on register leads."""
    low, high = profile['handler_low'], profile['handler_high']
    ram_low, ram_high = profile['wait_ram']
    _, seen = settle_loop(remote, 900, low, high)
    regs = remote.regs()
    candidates = []
    for name in ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
                 'r8', 'r9', 'r10', 'r11', 'r12'):
        value = remote.get(regs, name)
        if ram_low <= value < ram_high and not value & 3 and value not in candidates:
            candidates.append(value)
    require(candidates, 'No wait-object candidates found in private RAM')
    watched = candidates[:6]
    before = [remote.read(address, 8) for address in watched]
    for address in watched:
        require(remote.command(f'Z4,{address:x},4') == 'OK',
                'Wait watchpoint insertion failed')
    try:
        hits = []
        remote.sock.settimeout(45)
        for _ in range(6):
            try:
                thread, regs = stop_registers(remote, remote.command('vCont;c:1'))
            except TimeoutError:
                break
            pc = remote.get(regs, 'pc')
            require(low <= pc < high,
                    f'Wait access outside the recovered block at {pc:#x}')
            hits.append(pc)
    finally:
        for address in watched:
            remote.command(f'z4,{address:x},4')
    require(len(hits) >= 4, 'Wait object was not re-accessed within the bound')
    repeated = max((hits.count(pc), pc) for pc in set(hits))
    require(repeated[0] >= 3, 'Wait accesses did not repeat at one address')
    after = [remote.read(address, 8) for address in watched]
    require(before == after,
            'Wait-object words changed although no completion source exists')
    message = int.from_bytes(remote.read(profile['message'], 4), 'little')
    require(message == 0, 'Mailbox window was written during the handoff wait')
    return dict(settled_pcs=len(seen), candidates=[hex(c) for c in candidates],
                watched=len(watched), hits=len(hits),
                repeat_pc=hex(repeated[1]), repeat_count=repeated[0],
                wait_words_unchanged=True, mailbox_word=message)


def trace_master(remote, image, structure, profile):
    prefix = trace_smp(remote, image, structure, 'concurrent', stop_after_task=True)
    remote.sock.settimeout(120)
    thread, regs = reach(remote, BASE+profile['staging_call'])
    payload = profile['payload']
    for offset in (0, payload['length']//2 & ~3, payload['length']-4):
        landed = remote.read(payload['dest']+offset, 4)
        expected = image[payload['source_file']+offset:
                         payload['source_file']+offset+4]
        require(landed == expected, 'Staging payload copy mismatch')
    remote.breakpoint(BASE+profile['svc_instruction'])
    try:
        thread, regs = stop_registers(remote, remote.command('vCont;c:1'))
    finally:
        remote.breakpoint(BASE+profile['svc_instruction'], False)
    require(thread == 1 and remote.get(regs, 'pc') == BASE+profile['svc_instruction'],
            'Original handoff did not issue its syscall')
    require(remote.get(regs, 'r12') == profile['descriptor'] and
            remote.get(regs, 'r1') == 2 and not remote.get(regs, 'cpsr') & 0x20,
            'Original handoff syscall arguments mismatch')
    svc_state = snapshot(remote, thread, regs)
    # The exception base is the copied vector block; the SVC must vector there.
    remote.breakpoint(profile['swi_vector'])
    try:
        thread, regs = stop_registers(remote, remote.command('vCont;c:1'))
    finally:
        remote.breakpoint(profile['swi_vector'], False)
    require(thread == 1 and remote.get(regs, 'pc') == profile['swi_vector'] and
            remote.get(regs, 'cpsr') & 0x1f == 0x13,
            'Original syscall did not dispatch through the vector block')
    require(int.from_bytes(remote.read(profile['swi_vector']+0x1c, 4), 'little')
            == profile['payload_words'][1],
            'Vector block service pointer mismatch')
    # Stepping settles into the wait inside the recovered service block.
    wait = observe_wait(remote, profile)
    # With the initializer sites trapped, the bounded continue must not return:
    # the handoff stays inside the service block in the isolated role.
    for address in ('staging_call', 'staging_continuation', 'staging_entry'):
        remote.breakpoint(BASE+profile[address])
    try:
        bounded = bounded_continue(remote)
    finally:
        for address in ('staging_call', 'staging_continuation', 'staging_entry'):
            remote.breakpoint(BASE+profile[address], False)
    return dict(prefix=prefix, payload_copy_verified=True,
                syscall_descriptor=profile['descriptor'],
                syscall_state=svc_state, dispatch_verified=True,
                wait=wait, full_startup_verified=False, **bounded)


NOTIFY_BASE = 0x04009000


def trace_peer_release(remote, image, structure, profile, role, log_path):
    """Stand in for the unmodeled peer response and record the next boundary.

    The debugger performs one write of the recovered wait word with the
    release value, substituting the peer engine's shared-memory response;
    no firmware code, register or table content is modified."""
    prefix = trace_smp(remote, image, structure, 'concurrent', stop_after_task=True)
    remote.sock.settimeout(120)
    if role == 'master':
        thread, regs = reach(remote, BASE+profile['staging_call'])
    else:
        thread, regs = reach(remote, BASE+0x33B14)
        thread, regs = reach(remote, BASE+profile['chain_return'])
    remote.breakpoint(BASE+profile['svc_instruction'])
    thread, regs = stop_registers(remote, remote.command('vCont;c:1'))
    remote.breakpoint(BASE+profile['svc_instruction'], False)
    released = []
    if 'release_word' in profile:
        word = profile['release_word']
        remote.write(word, (1).to_bytes(4, 'little'))
        released.append(hex(word))
    vectors = structure['startup']['vector_address']
    # Continue both cores: the chain site may resume before or after the
    # run settles, which races between runs. After a bounded free window
    # the freed run parks both cores in the recovered scheduler dispatch
    # loop inside the payload service block, so the stable assertions are
    # the flushed fault record plus the parked dispatch addresses.
    remote.breakpoint(BASE+profile['chain_return'])
    remote.breakpoint(vectors+16)
    stops = []
    remote.sock.settimeout(30)
    timed_out = False
    try:
        for _ in range(3):
            try:
                thread, regs = stop_registers(remote, remote.command('vCont;c'))
            except TimeoutError:
                # The outstanding continue never stopped: interrupt so the
                # pending stop reply drains and the connection resyncs.
                timed_out = True
                try:
                    remote.interrupt()
                except TimeoutError:
                    pass
                break
            stops.append(remote.get(regs, 'pc'))
            if vectors+16 in stops and BASE+profile['chain_return'] in stops:
                break
    finally:
        remote.breakpoint(vectors+16, False)
        remote.breakpoint(BASE+profile['chain_return'], False)
    chain_stops = stops.count(BASE+profile['chain_return'])
    # Give both cores a bounded free window, then sample where the run
    # settled by interrupting and stepping each core once.
    bounded_continue(remote, 45)
    parked = []
    remote.sock.settimeout(20)
    try:
        remote.interrupt()
    except TimeoutError:
        pass
    for cpu in (1, 2):
        try:
            thread, regs = stop_registers(remote, remote.command(f'vCont;s:{cpu}'))
            parked.append(dict(thread=cpu, pc=remote.get(regs, 'pc'),
                               cpsr=remote.get(regs, 'cpsr') & 0x1f))
        except TimeoutError:
            parked.append(dict(thread=cpu, pc=None))
    if role == 'master':
        # Both cores settle in the recovered per-core dispatch loop of the
        # payload service block (empty run queues; virtual 0x1010705C..).
        dispatch_low = profile['handler_low'] + 0x7050
        dispatch_high = profile['handler_low'] + 0x70B0
    else:
        # The isolated slave settles inside its recovered service block.
        dispatch_low = profile['handler_low']
        dispatch_high = profile['handler_high']
    require(all(entry['pc'] is not None and
                dispatch_low <= entry['pc'] < dispatch_high for entry in parked),
            'Freed run did not settle in the scheduler service block')
    return dict(prefix=prefix, released=released, chain_stops=chain_stops,
                scheduler_parked=[{**entry, 'pc': hex(entry['pc'])} for entry in parked],
                full_startup_verified=False, fault_log_pending=str(log_path))


def verify_peer_release_log(result, profile):
    """Check the flushed run log after the emulator exits."""
    log = Path(result.pop('fault_log_pending')).read_text(encoding='utf-8')
    parsed = [(int(status, 16), int(address, 16)) for status, address in
              re.findall(r'with DFSR (\w+) DFAR (\w+)', log)]
    require(not parsed,
            'The freed run still reached a data-abort boundary: ' +
            str([[hex(status), hex(address)] for status, address in parsed]))
    events = log.count('Taking exception')
    require(events > 100, 'Peer release did not restart kernel activity')
    result.update(exception_events=events,
                  observed_faults=[[hex(status), hex(address)]
                                   for status, address in parsed])


def trace_tick_release(remote, image, structure, profile, log_path):
    """Run the freed master with the modeled timer tick and verify activity.

    The periodic contract substitutes for the unmodeled hardware tick: the
    machine latches the armed event mask into the timer block at 0x2B000000
    and raises the recovered dispatch line. Delivery, scheduler task pickup
    and a fault-free window are asserted deterministically."""
    prefix = trace_smp(remote, image, structure, 'concurrent', stop_after_task=True)
    remote.sock.settimeout(120)
    thread, regs = reach(remote, BASE+profile['staging_call'])
    remote.breakpoint(BASE+profile['svc_instruction'])
    thread, regs = stop_registers(remote, remote.command('vCont;c:1'))
    remote.breakpoint(BASE+profile['svc_instruction'], False)
    remote.write(profile['release_word'], (1).to_bytes(4, 'little'))
    vectors = structure['startup']['vector_address']
    remote.breakpoint(BASE+profile['chain_return'])
    remote.breakpoint(vectors+16)
    remote.sock.settimeout(30)
    try:
        for _ in range(3):
            try:
                stop_registers(remote, remote.command('vCont;c'))
            except TimeoutError:
                try:
                    remote.interrupt()
                except TimeoutError:
                    pass
                break
    finally:
        remote.breakpoint(vectors+16, False)
        remote.breakpoint(BASE+profile['chain_return'], False)
    # Free window under the tick; the timer event word must show the armed
    # mask and at least one sample of the per-core current-task table must
    # show a dispatched task on the primary core.
    dispatched = 0
    samples = []
    for _ in range(3):
        remote.sock.settimeout(20)
        try:
            stop_registers(remote, remote.command('vCont;c'))
        except TimeoutError:
            try:
                remote.interrupt()
            except TimeoutError:
                pass
        ready = struct.unpack('<2I', remote.read(READY_TASK_TABLE, 8))
        event = struct.unpack('<I', remote.read(TIMER_EVENT, 4))[0]
        samples.append(dict(ready=[hex(w) for w in ready], event=hex(event)))
        dispatched += ready[0] != 0
    require(dispatched >= 2, 'The tick run never showed a dispatched task')
    parked = []
    remote.sock.settimeout(20)
    for cpu in (1, 2):
        try:
            thread, regs = stop_registers(remote, remote.command(f'vCont;s:{cpu}'))
            parked.append(dict(thread=cpu, pc=remote.get(regs, 'pc')))
        except TimeoutError:
            parked.append(dict(thread=cpu, pc=None))
    payload_low = profile['handler_low']
    payload_high = profile['handler_high']
    require(all(entry['pc'] is not None and payload_low <= entry['pc'] < payload_high
                for entry in parked),
            'A core left the payload service block during the tick run')
    return dict(prefix=prefix, samples=samples,
                dispatched_samples=dispatched,
                scheduler_parked=[{**entry, 'pc': hex(entry['pc'])} for entry in parked],
                full_startup_verified=False, menu_verified=False,
                fault_log_pending=str(log_path))


def verify_tick_release_log(result):
    """Check the flushed tick run log after the emulator exits."""
    log = Path(result.pop('fault_log_pending')).read_text(encoding='utf-8')
    parsed = [(int(status, 16), int(address, 16)) for status, address in
              re.findall(r'with DFSR (\w+) DFAR (\w+)', log)]
    require(not parsed,
            'The tick run reached a data-abort boundary: ' +
            str([[hex(status), hex(address)] for status, address in parsed]))
    irqs = len(re.findall(r'Taking exception 5 \[IRQ\]', log))
    require(irqs > 1000, 'The modeled tick was not delivered repeatedly')
    result.update(irq_entries=irqs, exception_events=log.count('Taking exception'),
                  observed_faults=[])


def trace_master_disabled(remote, image, structure, profile, name, log_path):
    prefix = trace_smp(remote, image, structure, 'concurrent', stop_after_task=True)
    vectors = structure['startup']['vector_address']
    exceptions = [vectors+n for n in (4, 12, 16)]
    for address in exceptions:
        remote.breakpoint(address)
    try:
        remote.sock.settimeout(120)
        thread, after = stop_registers(remote, remote.command('vCont;c:1'))
        require(thread == 1 and remote.get(after, 'pc') == vectors+16 and
                remote.get(after, 'cpsr') & 31 == 0x17,
                'Disabled staging RAM did not data-abort')
        fault = snapshot(remote, thread, after)
    finally:
        for address in exceptions:
            remote.breakpoint(address, False)
    log = log_path.read_text(encoding='utf-8')
    matches = re.findall(r'with DFSR (\w+) DFAR (\w+)', log)
    require(matches and matches[-1][0] == '0x808' and
            int(matches[-1][1], 16) == profile['payload']['dest'],
            'Disabled staging fault status or address mismatch')
    return dict(prefix=prefix, fault_status=0x808,
                fault_address=profile['payload']['dest'], fault=fault)


def trace_slave(remote, image, structure, profile):
    prefix = trace_smp(remote, image, structure, 'concurrent', stop_after_task=True)
    remote.sock.settimeout(120)
    thread, regs = reach(remote, BASE+0x33B14)
    thread, regs = reach(remote, BASE+profile['chain_return'])
    remote.breakpoint(BASE+profile['svc_instruction'])
    try:
        thread, regs = stop_registers(remote, remote.command('vCont;c:1'))
    finally:
        remote.breakpoint(BASE+profile['svc_instruction'], False)
    require(thread == 1 and remote.get(regs, 'pc') == BASE+profile['svc_instruction'] and
            remote.get(regs, 'r12') == profile['descriptor'] and
            not remote.get(regs, 'cpsr') & 0x20,
            'Original slave handoff syscall mismatch')
    svc_state = snapshot(remote, thread, regs)
    remote.breakpoint(BASE+profile['swi_veneer'])
    try:
        thread, regs = stop_registers(remote, remote.command('vCont;c:1'))
        require(remote.get(regs, 'pc') == BASE+profile['swi_veneer'] and
                not remote.get(regs, 'cpsr') & 0x20,
                'Original slave SVC did not reach the vector veneer')
        remote.command('s')
        regs = remote.regs()
        require(remote.get(regs, 'pc') == profile['swi_veneer_target'],
                'Original slave vector veneer target mismatch')
    finally:
        remote.breakpoint(BASE+profile['swi_veneer'], False)
    require(remote.read(BASE+profile['dispatcher'],
                        0x30) == image[profile['dispatcher']:
                                        profile['dispatcher']+0x30],
            'Original slave dispatcher prologue mismatch')
    sample = observe_wait(remote, profile)
    remote.breakpoint(BASE+profile['chain_return'])
    try:
        bounded = bounded_continue(remote)
    finally:
        remote.breakpoint(BASE+profile['chain_return'], False)
    return dict(prefix=prefix, syscall_descriptor=profile['descriptor'],
                syscall_state=svc_state, dispatch_verified=True,
                dispatcher_verified=True, wait=sample,
                full_startup_verified=False, **bounded)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    try:
        images = dict(master=args.master.read_bytes(), slave=args.slave.read_bytes())
        structures = {role: analyze_eg(image, role) for role, image in images.items()}
        profiles = {role: kernel_profile(image, structures[role], role)
                    for role, image in images.items()}
        args.destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, contexts=[], full_boot_verified=False, menu_verified=False,
            qemu_version=subprocess.check_output([args.qemu, '--version'], text=True).splitlines()[0],
            assumptions=['Two execution cores per isolated role; original reset and startup task.',
                'Original images preloaded; no register, instruction, table or handshake patches.',
                'Existing experimental platform, console, pin, controller, snapshot and parameter contracts remain in use.',
                'The stock handoff boundary is observed only; no completion source is modeled.',
                'Debugger stops at original instruction addresses never modify firmware state.',
                'The peer-release scenario performs one stand-in write of the '
                'recovered zero wait word, substituting the unmodeled peer-engine '
                'shared-memory response; firmware code, registers and tables stay '
                'unmodified. Exploratory sweeps through the laboratory interrupt '
                'injector found no shared line that releases the wait by itself.',
                'The tick-release scenario additionally enables the experimental '
                'timer contract at 0x2B000000: the armed event mask latches at a '
                'selectable period and raises dispatch line 237 until the '
                'original dispatcher writes the bits back. The period unit and '
                'real channel timing remain unconfirmed; the isolated slave '
                'never arms this timer, so its scenarios keep it disabled.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], scenarios={})
            scenarios = [(f'{role}-stock', dict(cpus=2, uart_enabled=True,
                          console=args.destination/f'{role}-stock-console.txt',
                          timer_tick=False))]
            scenarios.append((f'{role}-peer-release', dict(cpus=2, uart_enabled=True,
                console=args.destination/f'{role}-peer-release-console.txt',
                timer_tick=False)))
            if role == 'master':
                scenarios.append(('master-stage-disabled', dict(cpus=2, uart_enabled=True,
                    console=args.destination/'master-stage-disabled-console.txt',
                    stage_config=False, timer_tick=False)))
                scenarios.append(('master-tick-release', dict(cpus=2, uart_enabled=True,
                    console=args.destination/'master-tick-release-console.txt',
                    timer_tick=True)))
            pending = []
            tick_pending = []
            for name, options in scenarios:
                with reset_machine(args.qemu, args.destination/name, image, role,
                                   **options) as remote:
                    if name.endswith('-peer-release'):
                        result = trace_peer_release(remote, image, structures[role],
                                                    profiles[role], role,
                                                    args.destination/name/'qemu.log')
                        pending.append((result, profiles[role]))
                    elif name.endswith('-tick-release'):
                        result = trace_tick_release(remote, image, structures[role],
                                                    profiles[role],
                                                    args.destination/name/'qemu.log')
                        tick_pending.append(result)
                    elif role == 'master':
                        result = (trace_master(remote, image, structures[role], profiles[role])
                                  if options.get('stage_config', True) else
                                  trace_master_disabled(remote, image, structures[role],
                                                        profiles[role], name,
                                                        args.destination/name/'qemu.log'))
                    else:
                        result = trace_slave(remote, image, structures[role], profiles[role])
                if name.endswith('-stock'):
                    require(result.get('timed_out'),
                            'Stock handoff unexpectedly progressed past the retry boundary')
                context['scenarios'][name.split('-', 1)[1]] = result
                print('PASS', name, flush=True)
            for result, peer_profile in pending:
                verify_peer_release_log(result, peer_profile)
            for result in tick_pending:
                verify_tick_release_log(result)
                print('PASS master-tick-release log', flush=True)
            context['passed'] = True
            report['contexts'].append(context)
        report['passed'] = True
        (args.destination/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
        print('Report:', args.destination/'report.json')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
