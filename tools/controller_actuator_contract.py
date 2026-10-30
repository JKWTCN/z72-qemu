# SPDX-License-Identifier: GPL-2.0-or-later
"""Bounded original-controller actuator checks with explicit synthetic inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_M4, UC_ARM_REG_R0,
    UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
    UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from tools.controller_core_probe import CONTROLLER_SHA256


class ActuatorProbe:
    BASE = 0x2001887c
    STOP = 0x09000000
    REGISTERS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)

    def __init__(self, image):
        self.u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)
        self.u.mem_map(0x08000000, 0x100000)
        self.u.mem_write(0x08000000, image)
        self.u.mem_map(0x20000000, 0x40000)
        self.u.mem_map(self.STOP, 0x1000)
        self.u.reg_write(UC_ARM_REG_SP, 0x2003bf00)
        self.u.emu_start(0x08003805, 0x08020084, count=5000000)
        require(self.u.reg_read(UC_ARM_REG_PC) == 0x08020084,
                'Controller scatter initialization did not reach main')
        self.inputs = [0, 0]
        self.armed = {}
        self.events, self.notifications, self.hardware = [], [], []
        self.other_events = []
        self.ticks = 0
        self.u.hook_add(UC_HOOK_CODE, self.boundary)

    def boundary(self, u, address, size, unused):
        args = [u.reg_read(r) for r in self.REGISTERS]
        result = 0
        if address in (0x08035324, 0x08035338):
            result = self.inputs[address == 0x08035338]
        elif address in (0x080359c4, 0x08035a4c):
            pin = 7 if address == 0x08035a4c else 6
            if args[1] == 0x60:
                self.armed.pop(pin, None)
            else:
                require(args[1] in (0x20, 0x21), 'Unexpected feedback edge control')
                self.armed[pin] = (args[0], args[1])
            self.hardware.append(dict(entry=hex(address), pin=pin,
                                      callback=hex(args[0]), control=hex(args[1])))
        elif address in (0x08035ad4, 0x08035c44, 0x08035cfc,
                         0x08035d70, 0x08035e28, 0x08035eec):
            self.hardware.append(dict(entry=hex(address), args=[hex(x) for x in args[:3]]))
        elif address == 0x080214fe:
            if args[0] == self.BASE + 0x5c:
                self.events.append(args[1])
            else:
                self.other_events.append(dict(object=hex(args[0]), event=hex(args[1])))
        elif address in (0x0803c5a8, 0x0803c5b8):
            self.notifications.append(dict(entry=hex(address), code=hex(args[0]),
                payload=list(u.mem_read(args[1], 20)) if args[1] else None))
        elif address in (0x080354e8, 0x080354f8):
            self.ticks += 100
            result = self.ticks
        elif address in (0x08036fc0, 0x080354ac, 0x080354b0):
            pass
        else:
            return
        u.reg_write(UC_ARM_REG_R0, result)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))

    def call(self, address, *args):
        for register, value in zip(self.REGISTERS, args):
            self.u.reg_write(register, value)
        self.u.reg_write(UC_ARM_REG_SP, 0x2003bf00)
        self.u.reg_write(UC_ARM_REG_LR, self.STOP | 1)
        self.u.emu_start(address | 1, self.STOP, count=1000000)
        require(self.u.reg_read(UC_ARM_REG_PC) == self.STOP,
                f'Original actuator call {address:#x} did not return')
        return self.u.reg_read(UC_ARM_REG_R0)

    def header(self):
        return list(self.u.mem_read(self.BASE, 0x18))

    def drain(self):
        count = 0
        while self.events:
            event = self.events.pop(0)
            self.call(0x0803c5c8, event)
            count += 1
            require(count < 32, 'Synthetic actuator task did not settle')


def probe(image):
    native = ActuatorProbe(image)
    predicates = []
    for mode in range(4):
        for c6, c7 in ((0, 0), (1, 0), (0, 1), (1, 1)):
            native.inputs = [c6, c7]
            actual = native.call(0x0803c324, mode)
            expected = int((mode in (0, 1) and c6 == c7 == 1) or
                           (mode == 2 and c6 == c7 == 0))
            require(actual == expected, 'Original position predicate differs')
            predicates.append(dict(mode=mode, c6=c6, c7=c7, result=actual))

    native.inputs = [0, 0]
    native.call(0x0803c070, 0xa)
    require(native.events == [2], 'Action request did not post task event 2')
    native.drain()
    start = native.header()
    require(start[4:10] == [1, 2, 4, 0, 3, 10], 'Original action plan differs')
    steps = []
    for pin in (6, 7):
        require(pin in native.armed, 'Expected feedback line was not armed')
        callback, control = native.armed[pin]
        require(control == 0x21, 'Expected rising feedback edge differs')
        native.inputs[pin - 6] = 1
        native.call(callback)
        native.drain()
        steps.append(dict(pin=pin, callback=hex(callback), inputs=list(native.inputs),
                          header=native.header()))
    require(any(n['code'] == '0x2060021' for n in native.notifications),
            'Two feedback transitions did not produce an actuator result')
    require(not any(n['code'] == '0x206001f' for n in native.notifications),
            'Feedback case emitted the position failure notification')
    require(native.header()[0] == 1 and native.header()[5:7] == [4, 4],
            'Feedback case did not reach the original final position')
    opening_notifications, opening_hardware = list(native.notifications), list(native.hardware)
    native.notifications.clear()
    native.hardware.clear()
    native.call(0x0803c070, 3)
    native.drain()
    closing_start = native.header()
    require(closing_start[5:7] == [4, 0], 'Second-step actuator target differs')
    closing_steps = []
    for pin, value, position in ((6, 0, 5), (7, 0, 6), (6, 1, 7), (7, 1, 0)):
        require(pin in native.armed, 'Second-step feedback line was not armed')
        callback, control = native.armed[pin]
        require(control == (0x21 if value else 0x20), 'Second-step feedback polarity differs')
        native.inputs[pin - 6] = value
        native.call(callback)
        native.drain()
        require(native.header()[5] == position, 'Second-step position sequence differs')
        closing_steps.append(dict(pin=pin, value=value, callback=hex(callback),
                                  header=native.header()))
    require(native.header()[0] == 1 and native.header()[5:7] == [0, 0] and
            any(row['code'] == '0x2060021' and row['payload'][0] == 0
                for row in native.notifications), 'Second-step actuator result differs')
    closing = dict(action=3, start_header=closing_start, feedback_steps=closing_steps,
                   notifications=list(native.notifications), hardware_calls=list(native.hardware))

    stalled = ActuatorProbe(image)
    stalled.call(0x0803c070, 0xa)
    stalled.drain()
    require(not stalled.notifications, 'Action completed before receiving feedback')
    stalled.call(0x0803c5c8, 0x80)
    stalled.drain()
    failures = [n for n in stalled.notifications if n['code'] == '0x206001f']
    require(len(failures) == 1 and failures[0]['payload'][0] == 3,
            'Original timeout path did not report position status 3')
    stalled.call(0x08034cf8)
    stalled.call(0x08034fdc, 0x080369a1)
    stalled.u.mem_write(0x20030000, bytes(failures[0]['payload']))
    stalled.call(0x08035480, 0x0206001f, 0x20030000)
    require(list(stalled.u.mem_read(0x2001756e, 1)) == [3] and
            stalled.other_events == [dict(object='0x20017598', event='0x20')],
            'Position failure did not reach the backend task')
    stalled.call(0x08034de0, 0x20)
    require(list(stalled.u.mem_read(0x200135a0, 1)) == [3] and
            stalled.other_events[-1] == dict(object='0x200135f0', event='0x10000'),
            'Position failure did not reach channel 9 status')
    return dict(format=1, firmware_included=False, controller_sha256=CONTROLLER_SHA256,
        scope='bounded original actuator; synthetic zero configuration and explicit GPIO samples',
        position_predicate='0x0803c324', position_cases=predicates,
        action=hex(0xa), action_entry='0x0803c070', task='0x0803c5c8',
        start_header=start, feedback_steps=steps, notifications=opening_notifications,
        hardware_calls=opening_hardware, second_step_action=closing,
        missing_feedback=dict(host_supplied_timeout_event='0x80',
            final_header=stalled.header(), notifications=stalled.notifications,
            original_failure_route=['0x08035480', '0x08034edc', '0x08034de0', '0x080369a0'],
            channel9_status=3, queued_tasks=stalled.other_events),
        host_boundaries=['record task posts and dispatch them in order',
            'supply explicit C6/C7 logical samples', 'record edge registration and invoke callbacks',
            'record timer and motor requests without physical execution',
            'supply monotonically increasing synthetic timer samples',
            'supply task timeout event 0x80 in the missing-feedback case',
            'record notifications, then pass the recorded failure through original adapters',
            'omit logging and critical sections'],
        limitations=['Not a complete controller boot or motor model',
            'Zero synthetic configuration does not represent camera calibration',
            'Does not establish physical wiring, motor timing, or native photo completion'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--controller', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    image = args.controller.read_bytes()
    require(hashlib.sha256(image).hexdigest() == CONTROLLER_SHA256,
            'Controller image digest differs')
    result = probe(image)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original actuator position predicates and action feedback contract')


if __name__ == '__main__':
    main()
