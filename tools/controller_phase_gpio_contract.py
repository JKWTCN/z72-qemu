# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original controller phase outputs and their deferred pulse clearing."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from tools.controller_actuator_contract import ActuatorProbe
from tools.controller_core_probe import CONTROLLER_SHA256


class PhaseProbe(ActuatorProbe):
    def __init__(self, image):
        super().__init__(image)
        self.u.mem_map(0x40020000, 0x2000)
        self.writes, self.pulse_timers, self.history = [], [], []
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write, begin=0x40020000, end=0x40021fff)
        # Synthetic descriptors reflect the port and masks independently
        # observed during original execution. No external wiring is inferred.
        for slot, address, mask in ((0x20018738, 0x20030000, 1),
                                    (0x2001873c, 0x20030020, 0x80)):
            self.u.mem_write(slot, struct.pack('<I', address))
            self.u.mem_write(address, struct.pack('<4I', 0, 0, 0x40020c00, mask))

    def write(self, u, access, address, size, value, unused):
        self.writes.append(dict(address=hex(address), size=size, value=hex(value)))

    def boundary(self, u, address, size, unused):
        args = [u.reg_read(register) for register in self.REGISTERS]
        if address == 0x08035b8c:
            self.pulse_timers.append(dict(callback=hex(args[0]), control=hex(args[1]),
                                          interval=args[2]))
        elif address == 0x08037034:
            self.history.append(args[:2])
        else:
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_R0, 0)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def check(image):
    require(hashlib.sha256(image).hexdigest() == CONTROLLER_SHA256,
            'Unsupported controller image')
    native = PhaseProbe(image)
    d0 = []
    for minimum in (1, 2):
        native.u.mem_write(0x2001756c, bytes(0x30))
        native.u.mem_write(0x20017571, bytes([minimum]))
        native.writes.clear(); native.hardware.clear(); native.other_events.clear()
        native.call(0x08035204)
        require(native.writes == [dict(address='0x40020c18', size=4, value='0x1')] and
                native.u.mem_read(0x2001757e, 1) == b'\x01', 'D0 phase start differs')
        start_hardware = list(native.hardware)
        start_events = list(native.other_events)
        native.writes.clear()
        native.call(0x08034fa4, 1)
        require(not native.writes and native.u.mem_read(0x2001757e, 1) == b'\x01',
                'A nonzero stop result changed D0 or its active field')
        native.call(0x08034fa4, 0)
        require(native.writes == [dict(address='0x40020c18', size=4, value='0x10000')] and
                native.u.mem_read(0x2001757e, 1) == b'\x00', 'D0 phase stop differs')
        d0.append(dict(minimum=minimum, start_hardware=start_hardware, start_events=start_events,
                       nonzero_stop_preserved=True, zero_stop_cleared=True))
    native.writes.clear(); native.pulse_timers.clear(); native.other_events.clear()
    native.call(0x08036748, 0)
    require(not native.writes and not native.pulse_timers, 'Empty task input produced a pulse')
    native.call(0x08036748, 0x4000)
    require(native.writes == [dict(address='0x40020c18', size=4, value='0x80')],
            'D7 task did not set its own output')
    require(native.pulse_timers == [dict(callback='0x80366f5', control='0x640', interval=100)],
            'D7 pulse timer request differs')
    arm = dict(native.pulse_timers[-1])
    native.writes.clear(); native.pulse_timers.clear(); native.other_events.clear()
    native.call(0x080366f4)
    require(not native.writes and native.other_events ==
            [dict(object=hex(0x200135f0), event=hex(0x8000))],
            'D7 timer callback changed GPIO directly or posted a different task event')
    require(len(native.pulse_timers) == 1 and
            native.pulse_timers[0]['callback'] == '0x0' and
            native.pulse_timers[0]['control'] == '0x60', 'D7 timer did not cancel itself')
    native.call(0x08036748, 0x8000)
    require(native.writes == [dict(address='0x40020c18', size=4, value='0x800000')],
            'D7 deferred task did not clear its output')
    return dict(format=1, result='passed', firmware_included=False,
        controller_sha256=CONTROLLER_SHA256,
        d0=dict(resource='0x30', slot='0x20018738', start='0x08035204', stop='0x08034fa4',
                active_field='0x2001757e', cases=d0),
        d7=dict(resource='0x37', slot='0x2001873c', task='0x08036748', high_event='0x4000',
                timer_request=arm, callback='0x080366f4', clear_event='0x8000',
                callback_posts_task_only=True),
        boundaries=['Synthetic GPIO descriptors and MMIO storage',
                    'Timer scheduling, event posts and history recording are intercepted',
                    'Original phase, GPIO writer, timer callback and task branch instructions execute'],
        limitations=['Task inputs and timer callback are explicitly invoked in this isolated fixture',
                     'No elapsed-time, physical mechanism or cross-processor wiring is verified'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--controller', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.controller.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original controller phase outputs: D0 active gating and D7 deferred pulse clear')
