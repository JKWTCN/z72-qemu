# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe native controller startup action with explicitly supplied input edges."""
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
from tools.body_shutter_gate_probe import snapshot, lcd_snapshot, input_dma_snapshot

POINTS = {
    0x0803661c: 'step-trigger', 0x08034ff0: 'step-request',
    0x0803c070: 'actuator-request', 0x0803c5c8: 'actuator-task',
    0x080359c4: 'c6-configure', 0x08035a4c: 'c7-configure',
    0x0803c22c: 'c6-callback', 0x0803c2a8: 'c7-callback',
    0x0803c5a8: 'actuator-notification', 0x0803c5b8: 'actuator-data',
    0x080369a0: 'channel9-data', 0x08036c60: 'channel9-result',
    0x080369d0: 'channel9-command', 0x08035030: 'backend-configure',
    0x08036748: 'channel9-task', 0x08034de0: 'backend-task',
    0x08035eec: 'motor-drive-request',
}


def controller_state(remote):
    remote.select_thread(5)
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    descriptors = {}
    for offset in (0x34, 0x38, 0x3c, 0x40):
        pointer = word(0x20018718 + offset)
        if 0x20000000 <= pointer <= 0x2003fff0:
            descriptors[hex(offset)] = dict(pointer=hex(pointer),
                words=[hex(x) for x in struct.unpack('<4I', remote.read(pointer, 16))])
    return dict(header=list(remote.read(0x2001887c, 0x30)),
        words={hex(x): hex(word(0x2001887c + x)) for x in range(0x30, 0x5c, 4)},
        backend_header=list(remote.read(0x2001756c, 24)),
        channel9_header=list(remote.read(0x2001359c, 6)),
        gpio_c={hex(x): hex(word(0x40020800 + x)) for x in (0, 0x0c, 0x10, 0x20)},
        capture_timer={hex(x): hex(word(0x40000400 + x)) for x in
            (0, 0x0c, 0x10, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x2c)},
        drive_timer={hex(x): hex(word(0x40000000 + x)) for x in
            (0, 0x18, 0x1c, 0x20, 0x28, 0x2c, 0x34, 0x3c)},
        timer_descriptors=descriptors,
        faults=[hex(word(0xe000ed28)), hex(word(0xe000ed2c))])


def observe(machine, seconds, supply_step, supply_positions):
    machine.qmp.command('stop')
    remote = Remote(machine.gdb_port)
    active, counts, returns = dict(POINTS), {}, {}
    records, supplied = [], []
    result = dict(records=records, supplied_inputs=supplied,
                  host_step_requested=supply_step, host_positions_requested=supply_positions)
    try:
        before = snapshot(remote)
        actuator_before = controller_state(remote)
        result.update(before=before, actuator_before=actuator_before)
        for address in active:
            remote.breakpoint(address)
        if supply_step:
            def word(address):
                return int.from_bytes(remote.read(address, 4), 'little')
            remote.select_thread(5)
            require(word(0x40013810) & 15 == 6 and word(0x40013c00) & 0x100 and
                    word(0x40013c08) & 0x100 and not word(0x40013c14) & 0x100,
                    'Native G8 rising input was not armed')
            original = int(bool(word(0x40021810) & 0x100))
            for level in (original, 1 - original, original):
                machine._qtest(f'set_irq_in /machine/controller/keys-gpio unnamed-gpio-in 8 {level}')
            supplied.append(dict(input='G8', levels=[original, 1 - original, original]))
        started, deadline = time.monotonic(), time.monotonic() + seconds
        while time.monotonic() < deadline and active:
            machine.heartbeat()
            remote.sock.settimeout(1)
            try:
                reply = remote.command('vCont;c')
            except TimeoutError:
                remote.sock.settimeout(15)
                remote.interrupt()
                continue
            match = re.search(r'thread:([0-9a-f]+);', reply)
            require(match is not None, 'Missing actuator stop thread')
            thread = int(match[1], 16)
            remote.select_thread(thread)
            registers = remote.regs()
            pc = remote.get(registers, 'pc')
            require(thread == 5 and pc in active, 'Unexpected actuator observation stop')
            record = dict(entry=active[pc], pc=hex(pc),
                registers={name: hex(remote.get(registers, name)) for name in
                    ('r0', 'r1', 'r2', 'r3', 'sp', 'lr')}, state=controller_state(remote))
            if pc in (0x0803c5b8, 0x080369a0):
                pointer = remote.get(registers, 'r1')
                if 0x20000000 <= pointer <= 0x2003ffec:
                    record['payload'] = list(remote.read(pointer, 20))
            if pc == 0x080369d0:
                descriptor = remote.get(registers, 'r0')
                if 0x20000000 <= descriptor <= 0x2003fff8:
                    length = int.from_bytes(remote.read(descriptor, 2), 'little')
                    pointer = int.from_bytes(remote.read(descriptor + 4, 4), 'little')
                    record['command_length'] = length
                    if 0 < length <= 32 and 0x20000000 <= pointer <= 0x20040000 - length:
                        record['command_payload'] = list(remote.read(pointer, length))
            if pc in (0x080359c4, 0x08035a4c):
                control = remote.get(registers, 'r1')
                if supply_positions and control in (0x20, 0x21):
                    target = remote.get(registers, 'lr') & ~1
                    require(target not in active, 'Overlapping actuator return observation')
                    returns[target] = (6 if pc == 0x080359c4 else 7, control & 1)
                    active[target] = 'position-armed-return'
                    remote.breakpoint(target)
            if pc in returns:
                pin, level = returns.pop(pc)
                state = record['state']
                require((int(state['gpio_c']['0x0'], 16) >> (2 * pin)) & 3 == 2 and
                        (int(state['gpio_c']['0x20'], 16) >> (4 * pin)) & 15 == 2,
                        'Position pin was not configured for alternate function 2')
                require(int(state['capture_timer']['0x0'], 16) & 1,
                        'Native input capture timer was not running')
                old = (int(state['gpio_c']['0x10'], 16) >> pin) & 1
                require(old != level, 'Requested feedback would not change the input level')
                machine._qtest(f'set_irq_in /machine/controller/position-gpio unnamed-gpio-in {pin} {level}')
                edge = dict(input='C' + str(pin), previous=old, level=level,
                            gpio_only=True, host_supplied=True)
                supplied.append(edge)
                record['supplied_feedback'] = edge
            records.append(record)
            remote.breakpoint(pc, False)
            counts[pc] = counts.get(pc, 0) + 1
            if pc in POINTS and counts[pc] < 12:
                remote.command(f'vCont;s:{thread:x}')
                remote.breakpoint(pc)
            else:
                del active[pc]
        result.update(after=snapshot(remote), actuator_after=controller_state(remote),
                      observed_host_seconds=round(time.monotonic() - started, 3))
        result['observed_counter_seconds'] = round(
            (result['after']['counter_ticks'] - before['counter_ticks']) /
            before['counter_frequency'], 9)
        return result
    except Exception as error:
        result.update(error=str(error), actuator_at_error=controller_state(remote))
        return result
    finally:
        remote.sock.settimeout(15)
        for address in active:
            remote.breakpoint(address, False)
        remote.command('D')
        remote.sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--sd-card', type=Path)
    parser.add_argument('--wsl', action='store_true')
    parser.add_argument('--step-input', action='store_true')
    parser.add_argument('--position-inputs', action='store_true')
    parser.add_argument('--watch', type=int, default=120)
    args = parser.parse_args()
    require(10 <= args.watch <= 600, 'Watch time out of bounds')
    require(not args.position_inputs or args.step_input, 'Position experiment requires the step input')
    args.realtime = args.auto_menu = False
    args.update_store, args.update_image = ROOT / '.local/controller-actuator-store', None
    for name in ('display_complete', 'input_handshake', 'frame_phase', 'input_stop_complete',
                 'frame_generate', 'frame_notify', 'frame_process', 'aux_image_process',
                 'processing_resource_header'):
        setattr(args, name, True)
    machine = Machine(args)
    try:
        machine.restart()
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            state = machine.status()
            require(state['phase'] != 'failed', str(state.get('error')))
            if state.get('ready') and state.get('index') == 3 and state.get('input_ready'):
                break
            time.sleep(1)
        else:
            raise TimeoutError('Shooting foreground did not become ready')
        dma_before = input_dma_snapshot(machine)
        result = dict(observation='native-controller-startup-actuator-input-experiment',
            boot=state, trace=observe(machine, args.watch, args.step_input, args.position_inputs),
            input_dma_before=dma_before, input_dma_after=input_dma_snapshot(machine),
            native_lcd=lcd_snapshot(machine), firmware_included=False,
            limitations=['Host input experiment, not a physical motor model',
                         'Does not establish natural startup or photo completion'])
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
        require('error' not in result['trace'], str(result['trace'].get('error')))
        print('Recorded native actuator input experiment:', args.out)
    finally:
        machine.close()


if __name__ == '__main__':
    main()
