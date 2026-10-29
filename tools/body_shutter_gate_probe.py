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
    0x104e6c70: 'release-action-qualification-result',
    0x105548e2: 'release-action-context-check',
    0x105548ec: 'release-action-property-check',
    0x10554902: 'release-action-qualification-return',
    0x104e16b4: 'release-action-configuration-entry',
    0x104e1714: 'release-action-configuration-early-return',
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
    0x1023334a: 'capture-stop-local-lock-return',
    0x10233366: 'capture-stop-local-callback-return',
    0x10233370: 'capture-stop-local-join-return',
    0x102301b6: 'capture-stop-input-drain',
    0x1023c50a: 'capture-stop-input-mask-disable',
    0x1020c290: 'capture-stop-input-quiesce',
    0x1020c2c0: 'capture-stop-input-quiesce-return',
    0x1023c526: 'capture-stop-input-channel9-return',
    0x1023c52e: 'capture-stop-input-channel7-return',
    0x1023c53a: 'capture-stop-input-channel6-return',
    0x1023c54c: 'capture-stop-input-channel45-return',
    0x1023c558: 'capture-stop-input-channel3-return',
    0x1023c56c: 'capture-stop-input-channel1-return',
    0x10230212: 'capture-stop-input-disable-return',
    0x10233386: 'capture-stop-input-drain-return',
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

CORE_WORKER_POINTS = {
    0x103b4e1e: 'reconfigure-processing-core-entry',
    0x103b4e60: 'reconfigure-processing-core-configure-begin',
    0x103b4e64: 'reconfigure-processing-core-configure-return',
    0x103b4ef4: 'reconfigure-processing-core-port-enable',
    0x103b4f10: 'reconfigure-processing-core-notify-start',
    0x103b4f26: 'reconfigure-processing-core-notification-wait',
    0x103b4f2a: 'reconfigure-processing-core-notification-return',
    0x103b4fbe: 'reconfigure-processing-core-module-poll',
    0x103b4fd0: 'reconfigure-processing-core-completion',
}

RECONFIGURE_POINTS = {
    **CORE_WORKER_POINTS,
    0x103ba6ea: 'reconfigure-remote-capture-submit',
    0x103ba164: 'reconfigure-release-phase-submit',
    0x103f36fa: 'reconfigure-operation59-api',
    0x103f19c0: 'reconfigure-operation59-task',
    0x1022827c: 'reconfigure-capture-callback-registration',
    0x103e7312: 'reconfigure-capture-mode-request',
    0x10528afe: 'reconfigure-release-settings-build',
    0x1052273e: 'reconfigure-release-settings-dispatch',
    0x1031dd62: 'reconfigure-driver-ready-bit1',
    0x10326700: 'reconfigure-driver-ready-bit2',
    0x10322666: 'reconfigure-backend-ready-notification',
    0x103ed7ac: 'reconfigure-global-release-ready',
    0x1038e7b8: 'reconfigure-backend-mode-request',
    0x1038dfec: 'reconfigure-backend-initialize',
    0x1038e092: 'reconfigure-backend-initialize-wait20',
    0x1038e2d6: 'reconfigure-backend-initialize-wait40',
    0x103191c6: 'reconfigure-driver-job-return',
    0x102290b0: 'reconfigure-readiness-state-compare',
    0x102295f6: 'reconfigure-readiness-notification',
    0x103eddb8: 'reconfigure-readiness-consumer',
    0x103edd08: 'reconfigure-operation13-state-update',
    0x10389b56: 'reconfigure-processing-address-bindings',
    0x10389b90: 'reconfigure-processing-port-configure',
    0x103b4b1e: 'reconfigure-processing-worker-configure-begin',
    0x103b4b26: 'reconfigure-processing-worker-configure-return',
    0x103b4b2e: 'reconfigure-processing-worker-controls-return',
    0x103b4b3e: 'reconfigure-processing-worker-notification-wait',
    0x103b4b42: 'reconfigure-processing-worker-notification-return',
    0x103bdb9e: 'reconfigure-processing-dma-configure',
    0x103bd03a: 'reconfigure-processing-controller-control4',
    0x103bded0: 'reconfigure-processing-module-configure',
    0x103bd07c: 'reconfigure-processing-module-start',
    0x102692ca: 'reconfigure-capture-display-surface',
    0x103e1d30: 'reconfigure-display-frame-selected',
    0x103e1dea: 'reconfigure-display-frame-submit',
    0x1046c3c2: 'reconfigure-display-format',
    0x1023c57a: 'reconfigure-mode1-output-complete',
    0x1023c5dc: 'reconfigure-mode1-output-return',
    0x10238d16: 'reconfigure-frame-count-check',
    0x10238d3e: 'reconfigure-frame-count-complete',
    0x1022e600: 'reconfigure-input-event8-check',
    0x10230368: 'reconfigure-finite-input-worker',
    0x102303e8: 'reconfigure-finite-input-notification',
    0x103204f2: 'reconfigure-driver-state5-producer',
    0x102301b6: 'reconfigure-input-drain',
    0x10230212: 'reconfigure-input-drain-return',
    0x1023c50a: 'reconfigure-input-disable',
    0x1020c290: 'reconfigure-raw-stop',
    0x1020c2c0: 'reconfigure-raw-stop-return',
    0x10233cf6: 'reconfigure-context-queue',
    0x103259cc: 'reconfigure-context-request',
    0x10326264: 'reconfigure-context-request-return',
}


def processing_worker_snapshot(remote, task):
    descriptor = int.from_bytes(remote.read(task + 0x3c, 4), 'little')
    result = dict(task=hex(task), descriptor=hex(descriptor),
                  state=remote.read(task + 0x40, 1)[0], event_object=hex(task + 0x2c))
    if 0xb1800000 <= descriptor < 0xb5efffe8:
        nodes = int.from_bytes(remote.read(descriptor, 4), 'little')
        count = remote.read(descriptor + 4, 1)[0]
        if count <= 64 and 0xb1800000 <= nodes < 0xb5effc00:
            data = remote.read(nodes, count * 16)
            result['nodes'] = [dict(index=index, tags=list(data[index * 16:index * 16 + 8]),
                word_8=hex(struct.unpack_from('<I', data, index * 16 + 8)[0]),
                word_c=hex(struct.unpack_from('<I', data, index * 16 + 12)[0]))
                for index in range(count)]
    return result


def task_wait_snapshot(remote, task):
    handle = int.from_bytes(remote.read(task, 4), 'little')
    kernel_id = handle & 0xffff
    result = dict(object=hex(task), handle=hex(handle), kernel_id=hex(kernel_id))
    if not 0 < kernel_id < 512:
        return result
    tcb = 0xb2c32f30 + kernel_id * 0xd8
    fields = struct.unpack('<48I', remote.read(tcb, 192))
    if fields[2] & 0xffff != kernel_id:
        return result
    # Original scheduler 0x10107040/0x1010709c stores/restores SP at +0xbc.
    # +0x40 is the syscall wait stack; +0x44 holds a wait argument.
    stack = fields[47]
    result.update(tcb=hex(tcb), flags=hex(fields[2]), entry=hex(fields[5]),
                  saved_sp=hex(stack), syscall_sp=hex(fields[16]), stack_code_candidates=[])
    if 0xb5000000 <= stack <= 0xb5effc00:
        values = struct.unpack('<256I', remote.read(stack, 1024))
        result['stack_code_candidates'] = [dict(offset=hex(index * 4), value=hex(value))
            for index, value in enumerate(values) if 0x10020000 <= value < 0x107a0000]
    return result


def image_work_snapshot(remote):
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    result = []
    for address in (0xb238e774, 0xb238e794, 0xb238e7b4):
        node, count = word(address), word(address + 8)
        row = dict(address=hex(address), count=count, jobs=[])
        for unused in range(min(count, 8)):
            if not 0xb2c00000 <= node <= 0xb5effff4:
                break
            request = word(node + 8)
            if 0xb2c00000 <= request <= 0xb5effffc:
                parameters = word(request)
                if 0xb2c00000 <= parameters <= 0xb5efc1cf:
                    row['jobs'].append(dict(request=hex(request), parameters=hex(parameters),
                        owner=hex(word(parameters + 0xc)),
                        pending=hex(word(parameters + 0x6c)),
                        busy=remote.read(parameters + 0x3e30, 1)[0]))
            node = word(node + 4)
        result.append(row)
    return result


def input_context_snapshot(remote):
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    result = []
    # These four queues are traversed as contexts by 0x102300b0.
    for address in (0xb25eeba4, 0xb25eebc4, 0xb25eebe4, 0xb25eec04):
        node, count = word(address), word(address + 8)
        row = dict(address=hex(address), count=count, head=hex(node), contexts=[])
        for unused in range(min(count, 8)):
            if not 0xb2c00000 <= node <= 0xb5effff4:
                break
            context = word(node + 8)
            if 0xb2c00000 <= context <= 0xb5effeaf:
                row['contexts'].append(dict(address=hex(context),
                    consumers=remote.read(context + 0xc, 1)[0],
                    parameters=hex(word(context + 0x144)),
                    pending=hex(word(context + 0x14c))))
            node = word(node + 4)
        result.append(row)
    return result


def auxiliary_image_snapshot(remote):
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    def register(offset):
        response = remote.command(f'm{0x20201000 + offset:x},4')
        # Unsupported device words may be unassigned in the current profile.
        return None if response.startswith('E') else hex(int.from_bytes(bytes.fromhex(response), 'little'))
    current = word(0xb1809630)
    result = dict(task=task_wait_snapshot(remote, 0xb1d52be0), current=hex(current),
        runtime=hex(word(0xb1801ef8)),
        registers={hex(offset): register(offset) for offset in
            (0, 4, 0x14, 0x20, 0x2c, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x5c, 0x60,
             0xa0, 0xa4, 0xa8, 0xac, 0xb0, 0xb4, 0xb8, 0xbc, 0xc0, 0xc4, 0xc8, 0xcc,
             0x100, 0x104, 0x108, 0x10c, 0x110, 0x118, 0x11c, 0x120, 0x124,
             0x128, 0x12c, 0x130, 0x140, 0x160, 0x164, 0x168, 0x16c, 0x170,
             0x178, 0x188, 0x1a0)})
    if 0xb1800000 <= current <= 0xb5efff27:
        result['configuration'] = {hex(offset): hex(word(current + offset)) for offset in
            (0, 4, 0xc, 0x10, 0x14, 0x18, 0x20, 0x24, 0x28,
             0x2c, 0x3c, 0x4c, 0x5c, 0x6c, 0x70, 0x74, 0x78,
             0x80, 0x88, 0x8c, 0x90, 0x94, 0xa4, 0xac, 0xb4, 0xc0, 0xcc, 0xd0)}
    return result


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
    remote.select_thread(5)
    lens_descriptor = word(0x2000EE10 + 96 * 4)
    lens_detection = dict(controller_g0_level=word(0x40021810) & 1,
        descriptor=hex(lens_descriptor),
        debounced_samples=list(remote.read(0x2000E92C, 2)),
        reported_connection=remote.read(0x2000E778, 1)[0])
    if 0x20000000 <= lens_descriptor <= 0x2001FFF0:
        lens_detection['descriptor_fields'] = [hex(value) for value in
            struct.unpack('<4I', remote.read(lens_descriptor, 16))]
    remote.select_thread(1)
    lens_detection['master_connection'] = remote.read(0xB188A27A, 1)[0]
    resources = {}
    for index in (11, 71, 80):
        row = 0xb185eb70 + index * 28
        callbacks = 0xb20a3288 + index * 48
        resources[str(index)] = dict(buffer=hex(word(row + 8)), length=word(row + 12),
            region=word(row + 20), notification_mask=hex(word(callbacks + 40)),
            subscriber_count=int.from_bytes(remote.read(callbacks + 44, 2), 'little'))
    readiness = dict(state=remote.read(0xb18697e0, 1)[0],
        driver_flags=hex(word(0xb1868b68)),
        driver_subscriber=hex(word(0xb1868b38)),
        global_subscriber=hex(word(0xb18695ac)),
        backend_state=list(remote.read(0xb21e26b5, 2)),
        callback=hex(word(0xb18697e4)), enabled_notifications=hex(word(0xb18697e8)),
        operation13_pending=word(0xb23f6a7c), operation13_callback=hex(word(0xb23f7018)),
        bitmaps=[])
    for address in (0xb1869818, 0xb1869820):
        capacity, pointer = struct.unpack('<2I', remote.read(address, 8))
        row = dict(descriptor=hex(address), capacity=capacity, pointer=hex(pointer))
        if 0 < capacity <= 128 and 0xb1800000 <= pointer <= 0xb5effff0:
            values = struct.unpack('<' + 'I' * ((capacity + 31) // 32),
                                   remote.read(pointer, ((capacity + 31) // 32) * 4))
            row['set_bits'] = [index for index in range(capacity)
                               if values[index // 32] & 1 << (index % 32)]
        readiness['bitmaps'].append(row)
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
    geometry = list(struct.unpack('<13I', remote.read(0x20069500, 13 * 4)))
    input_channels = []
    for base, count in ((0x20069800, 4), (0x2006a400, 10), (0x2006b400, 10)):
        for channel in range(count):
            address = base + channel * 0x100
            values = {}

            def capture_words(offset, words=1):
                data = remote.read(address + offset, words * 4)
                for index, (value,) in enumerate(struct.iter_unpack('<I', data)):
                    values[hex(offset + index * 4)] = hex(value)

            if count == 4:
                capture_words(8)
                capture_words(0x50, 8)
                if not channel & 1:
                    capture_words(0x14, 2)
                    capture_words(0x3c, 5)
                if channel == 2:
                    capture_words(0x24)
                if channel >= 2:
                    capture_words(0x80)
            else:
                capture_words(0x14, 2)
                capture_words(0x24)
                capture_words(0x3c, 6)
                capture_words(0x60)
                capture_words(0x74)
                capture_words(0x80)
                if channel in (2, 3, 4, 9):
                    capture_words(0x54, 3)
                    capture_words(0x64, 3)
            if any(int(value, 16) for value in values.values()):
                input_channels.append(dict(base=hex(address), fields=values))
    driver_queue = struct.unpack('<5I', remote.read(0xb23ede14, 20))
    driver_pending = None
    base, stride, capacity, count, head = driver_queue
    if base == 0xb23ede2c and stride == 0x5c and capacity == 60 and count <= capacity and head < capacity:
        data = remote.read(base, stride * capacity)
        driver_pending = [hex(struct.unpack_from('<I', data, ((head + index) % capacity) * stride)[0])
                          for index in range(count)]
    completed_heads = []
    for index in range(4):
        node = word(0xb26b3924 + index * 32)
        item = dict(node=hex(node))
        if 0xb2c00000 <= node < 0xb5effff4:
            value = word(node + 8)
            item['value'] = hex(value)
            if 0xb2c00000 <= value < 0xb5effeb0:
                item['raw_fields'] = {hex(offset): hex(word(value + offset))
                                      for offset in (0x144, 0x14c)}
        completed_heads.append(item)
    output_config = remote.read(0xb26b44cc, 0x44)
    output_registers = {}
    if output_config[0] < 10:
        for offset in range(0, 0x348, 0x28):
            address = word(0xb18069d4 + output_config[0] * 4 + offset)
            if 0x20068000 <= address < 0x20070000:
                item = dict(address=hex(address))
                if (address & 0xff) in (0x14, 0x18, 0x24, 0x3c, 0x40, 0x44,
                                       0x48, 0x4c, 0x50, 0x60, 0x74, 0x80):
                    item['value'] = hex(word(address))
                output_registers[hex(offset)] = item
    return dict(system_mode=mode[0], previous_mode=mode[1],
        processing_controller={hex(index * 4): hex(value) for index, value in enumerate(
            struct.unpack('<17I', remote.read(0x20100000, 68)))},
        processing_address_table={hex(index * 4): hex(value) for index, value in enumerate(
            struct.unpack('<32I', remote.read(0x20102880, 128)))},
        processing_ports=[[hex(value) for value in struct.unpack('<16I', remote.read(
            0x20102000 + index * 0x100, 64))] for index in range(2)],
        processing_address_banks=[[hex(value) for value in struct.unpack('<64I', remote.read(
            0x20102200 + index * 0x100, 256))] for index in range(2)],
        processing_sequence=[hex(value) for value in struct.unpack('<37I', remote.read(0x20102600, 148))],
        processing_dma=[dict(channel=channel, words=[hex(value) for value in struct.unpack(
            '<13I', remote.read(0x20100400 + channel * 0x40, 52))]) for channel in range(16)],
        mode1_output=dict(configuration=output_config.hex(), registers=output_registers),
        driver_work_queue=[hex(value) for value in driver_queue],
        driver_pending_functions=driver_pending,
        application=dict(initialized=int.from_bytes(manager[:4], 'little'),
                         current=manager[16], requested=manager[17], state=manager[24]),
        engine_inputs=engines, lens_detection=lens_detection,
        resources=resources, capture_readiness=readiness, cores=cores,
        capture_tasks={name: task_wait_snapshot(remote, task) for name, task in
                       (('driver', 0xb23edde8), ('backend', 0xb21e2654),
                        ('image', 0xb238e654), ('processing', 0xb23ecc80),
                        ('input', 0xb25eeb78))},
        input_context_queues=input_context_snapshot(remote),
        input_mask8_owner=hex(word(0xb25ef024)),
        auxiliary_image=auxiliary_image_snapshot(remote),
        image_work_queues=image_work_snapshot(remote),
        release_control=dict(header=list(remote.read(0xb186935c, 16)),
            words={hex(offset): hex(word(0xb186935c + offset))
                   for offset in (0x24, 0x28, 0x34, 0x38, 0x3c, 0x40, 0x44)}),
        input_channel_scan_count=24, input_channels=input_channels,
        input_completed_queues=[word(0xb26b3924 + index * 32 + 8) for index in range(4)],
        input_completed_heads=completed_heads,
        input_interrupts=dict(
            controls={hex(offset): hex(word(0x20068000 + offset))
                      for offset in (0, 4, 8, 0x10, 0x14, 0x18)},
            banks=[dict(mask=hex(word(0x20068200 + index * 32)),
                        status=hex(word(0x20068210 + index * 32))) for index in range(8)],
            callbacks={hex(index * 4): hex(value) for index, value in enumerate(
                struct.unpack('<12I', remote.read(0xb18067e4, 48)))}),
        input_state=dict(state_5=remote.read(0xb1887d75, 1)[0],
                         state_6=remote.read(0xb1887d76, 1)[0],
                         finite_frames=list(remote.read(0xb1888146, 2)),
                         processing_flags=hex(word(0xb26b38cc)),
                         finite_request=hex(word(0xb1887dd8)),
                         finite_queue_count=word(0xb25eebcc),
                         mode1_output_latches=[word(0xb26b38d8 + index * 4) for index in range(2)],
                         configured_mask=hex(word(0xb1887dcc)),
                         required_mask=hex(word(0xb1887dd0)),
                         processing_masks=[hex(word(0xb26b38b4 + index * 4)) for index in range(4)]),
        delay_enable=hex(word(0x2c011000)), delay_channels=delay_channels,
        action_state=state, handler_object=hex(handler_object),
        action_handler=hex(word(handler_object + 0x14)),
        release_gate=word(0xb1821e84), event1_pending=word(0xb201bdd4),
        release_action_context=dict(byte_b202c017=remote.read(0xb202c017, 1)[0],
                                    byte_b202c97a=remote.read(0xb202c97a, 1)[0],
                                    option41=word(0xb202bcd0), option42=word(0xb202bcd4)),
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
        capture_driver_context_count=word(0xb1868b58),
        capture_driver_finish_comparison_word=hex(word(0xb1868c34)),
        capture_stop_ready_flags=hex(word(0xb1868b64)),
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
        input_geometry=[hex(value) for value in geometry[:3]],
        input_geometry_registers={hex(0x20069500 + index * 4): hex(value)
                                  for index, value in enumerate(geometry)},
        switch_words=[hex(word(0xb25eaeac + i * 4)) for i in range(3)])


def lcd_snapshot(machine):
    """Summarize the native LCD plane without exporting its pixel payload."""
    with machine.io:
        machine.qmp.command('stop')
        try:
            size = machine._words(0x20144204, 1)[0]
            width, height = size & 0xffff, (size >> 16) & 0x3fff
            planes = [machine._words(address, 1)[0] for address in (0x20144210, 0x20144220)]
            result = dict(width=width, height=height, planes=[hex(value) for value in planes],
                          registers={hex(offset): hex(machine._words(0x20144000 + offset, 1)[0])
                                     for offset in (0x200, 0x204, 0x240, 0x250,
                                                    0x410, 0x414, 0x418, 0x41c, 0x420, 0x424,
                                                    0x600, 0x604)})
            candidates = {}
            for offset in (0x210, 0x220, 0x2440, 0x24c0, 0x3440, 0x34c0):
                addresses = machine._words(0x20144000 + offset, 4)
                for index, address in enumerate(addresses):
                    if 0xb0000000 <= address <= 0xf0000000 - 4096:
                        key = hex(address)
                        if key not in candidates:
                            data = machine._bytes(address, 4096)
                            candidates[key] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                                   unique_bytes=len(set(data)), minimum=min(data), maximum=max(data),
                                                   slots=[])
                        candidates[key]['slots'].append(hex(offset + index * 4))
            result['candidate_buffer_heads'] = candidates
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


def input_dma_snapshot(machine):
    with machine.io:
        machine.qmp.command('stop')
        try:
            paths = ['/machine/unattached/' + name for name in machine.config_names]
            path = next(path for path in paths if machine.qmp.command(
                'qom-get', dict(path=path, property='master-role')))
            count = machine.qmp.command('qom-get', dict(path=path, property='input-dma-count'))
            address = machine.qmp.command('qom-get', dict(path=path, property='input-dma-address'))
            stride = machine._words(0x20069a08, 1)[0]
            result = dict(frames=count, address=hex(address), stride=stride)
            result['processing_frames'] = machine.qmp.command('qom-get',
                dict(path=path, property='processing-dma-count'))
            if count and address and 0 < stride <= 16384:
                data = machine._bytes(address, stride)
                result['first_row'] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                           unique_bytes=len(set(data)), minimum=min(data), maximum=max(data))
            return result
        finally:
            machine.qmp.command('cont')


def observe(machine, seconds, playback=False, local_stop_events=False, returning=False,
            gpio_handshake_events=False, watch_read=None, watch_write=None, frame_notify=False,
            reconfigure=False, tail_frame_events=False, mode1_frame_events=False,
            watch_bytes=4, watch_count=1, shutter_on_preview=False, half_before_full=False,
            input_boundary_events=False, shutter_on_ready=False, capture_submit_on_ready=False,
            capture_wait_idle=False):
    with machine.io:
        machine.qmp.command('stop')
    remote = Remote(machine.gdb_port)
    armed = {ACTION: 'application-action'}
    if playback:
        armed.update(AFTER_PLAYBACK)
    if returning:
        armed = dict(RETURN_POINTS)
    if reconfigure:
        armed.update(RECONFIGURE_POINTS)
    if input_boundary_events:
        armed.update({0x102389c2: 'input-boundary-wait',
                      0x102389c6: 'input-boundary-wait-return'})
    if frame_notify:
        armed.update({0x10238d4a: 'input-frame-task',
                      0x10238c40: 'input-frame-dequeue',
                      0x1023c960: 'input-completed-enqueue',
                      0x1023beec: 'input-frame-context-enqueue',
                      0x1022e2e0: 'input-frame-notification',
                      0x1022e0ae: 'input-context-wait-update',
                      0x1022e154: 'input-context-wait-stored',
                      0x1022e1aa: 'input-context-all-waits-complete',
                      0x10321d80: 'input-context-driver-complete',
                      0x10321d94: 'input-context-output-check',
                      0x10321dbe: 'input-context-output-enqueue',
                      0x1032206e: 'input-context-special-job-check',
                      0x10322126: 'input-context-special-job-found',
                      0x10322250: 'input-context-special-job-submit',
                      0x10325304: 'input-context-header-construction',
                      0x10233570: 'input-context-frame-prepare',
                      0x10398206: 'processing-frame-parameters',
                      0x10233b9c: 'processing-frame-parameters-return',
                      0x10232154: 'input-context-frame-configure',
                      0x102313ea: 'input-ready-worker',
                      0x10231472: 'input-ready-context-selected',
                      0x10231486: 'input-ready-normal-branch',
                      0x102314e6: 'input-ready-state-check',
                      0x102315c2: 'input-ready-notification',
                      0x102315c4: 'input-ready-notification-call',
                      0x103279c0: 'input-ready-notification-decision',
                      0x10327c88: 'input-ready-queue-submit',
                      0x10319d88: 'input-driver-queue-result',
                      0x103191c4: 'input-ready-queue-dispatch',
                      0x10326676: 'input-ready-driver-producer',
                      0x103231b2: 'input-driver-state-transition',
                      0x1032a792: 'input-context-consumer-release',
                      0x10321e22: 'input-context-consumer-return',
                      0x10321e24: 'input-context-driver-output-return'})
    records = []
    hits = {}
    callback_hits = 0
    watch_address = watch_read if watch_read is not None else watch_write
    watch_type = 3 if watch_read is not None else 2
    memory_watch_armed = False
    watched_count = 0
    started = time.monotonic()
    breakpoints_installed = False
    capture_caller = None
    try:
        before = snapshot(remote)
        if capture_submit_on_ready:
            from tools.native_capture_caller import NativeCaptureCaller
            capture_caller = NativeCaptureCaller(remote)
            armed.update(capture_caller.points)
        for address in armed:
            remote.breakpoint(address)
        breakpoints_installed = True
        tail_events = []
        mode1_events = []
        def pulse_mode1():
            for level in (1, 0):
                machine._qtest(f'set_irq_in /machine/unattached/{machine.config_names[0]} '
                               f'input-event 103 {level}')
            mode1_events.append(103)
        if mode1_frame_events:
            require(before['capture_driver_state'] == 4 and
                    before['input_state']['finite_frames'][1] == 1 and
                    int(before['input_state']['processing_flags'], 16) & 4,
                    'Mode 1 event experiment requires the observed finite input request')
            pulse_mode1()
        if tail_frame_events:
            require(before['capture_driver_state'] == 4 and
                    before['input_interrupts']['controls']['0x8'] == '0x10',
                    'Tail event experiment requires the observed reconfiguration state')
            for line in (0, 6):
                for level in (1, 0):
                    machine._qtest(f'set_irq_in /machine/unattached/{machine.config_names[0]} '
                                   f'input-event {line} {level}')
                tail_events.append(line)
        if watch_address is not None:
            require(remote.command(f'Z{watch_type},{watch_address:x},{watch_bytes:x}') == 'OK',
                    'Memory watchpoint rejected')
            memory_watch_armed = True
        if not (shutter_on_preview or shutter_on_ready or capture_submit_on_ready):
            machine.set_key(24 if returning else 8 if playback else 25, 0)
        preview_press_sent = False
        idle_preview_seen = False
        preview_half_tick = None
        boundary_frame = 0
        boundary_path = None
        if input_boundary_events:
            paths = ['/machine/unattached/' + name for name in machine.config_names]
            boundary_path = next(path for path in paths if machine.qmp.command(
                'qom-get', dict(path=path, property='master-role')))
            boundary_frame = machine.qmp.command('qom-get',
                dict(path=boundary_path, property='input-dma-count'))
        deadline = started + seconds
        while time.monotonic() < deadline and (armed or memory_watch_armed):
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
            watched = re.search(r'(?:rwatch|watch):([0-9a-f]+);', reply)
            watched_address = int(watched[1], 16) if watched else None
            if watched_address is not None and watch_address <= watched_address < watch_address + watch_bytes:
                record = dict(entry='watched-read' if watch_type == 3 else 'watched-write',
                    pc=hex(pc), thread=thread,
                    address=hex(watched_address), registers={name: hex(remote.get(registers, name))
                        for name in ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
                                     'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'cpsr')})
                record['address_kind'] = 'reported-watch-window'
                window_before = None
                if watch_type == 2 and watch_bytes > 4 and 0x20100000 <= watch_address < 0x20110000 - watch_bytes:
                    window_before = remote.read(watch_address, watch_bytes)
                if pc == 0x10361044:
                    record['saved_return'] = hex(int.from_bytes(remote.read(
                        remote.get(registers, 'sp'), 4), 'little'))
                if 0x20100000 <= watched_address < 0x2014f000:
                    record['stack_words'] = [hex(value) for value in struct.unpack(
                        '<32I', remote.read(remote.get(registers, 'sp'), 128))]
                read_watched_word = watch_type == 2 and (
                    0xb2c00000 <= watched_address <= 0xb5effffc or
                    0x20100000 <= watched_address <= 0x2010fffc)
                if read_watched_word:
                    record['previous_window_word' if watch_bytes > 4 else 'previous_word'] = hex(
                        int.from_bytes(remote.read(watched_address, 4), 'little'))
                if pc in (0x1024ffb4, 0x1024ffda):
                    descriptor = remote.get(registers, 'r5') - 0x14
                    columns, rows = struct.unpack('<HH', remote.read(descriptor + 0x1e, 4))
                    record['grid_buffer'] = dict(descriptor=hex(descriptor),
                        columns=columns, rows=rows, sample_bytes=2,
                        row_bytes=(columns * 2 + 15) & ~15,
                        sample_address=hex(int.from_bytes(remote.read(descriptor + 0x2c, 4), 'little')),
                        field_28=hex(int.from_bytes(remote.read(descriptor + 0x28, 4), 'little')),
                        field_30=hex(int.from_bytes(remote.read(descriptor + 0x30, 4), 'little')))
                if 'TTBR0_S' in remote.register_numbers:
                    ttbr = remote.read_register('TTBR0_S')
                    section_address = (ttbr & 0xffffc000) + (watched_address >> 20) * 4
                    section = int.from_bytes(remote.read(section_address, 4), 'little')
                    record['translation'] = dict(ttbr0=hex(ttbr),
                        section_address=hex(section_address), section=hex(section))
                    if section & 3 == 2:
                        record['translation']['section_physical_address'] = hex(
                            (section & 0xfff00000) | (watched_address & 0xfffff))
                records.append(record)
                require(remote.command(f'z{watch_type},{watch_address:x},{watch_bytes:x}') == 'OK',
                        'Memory watchpoint removal failed')
                memory_watch_armed = False
                remote.sock.settimeout(15)
                remote.command(f'vCont;s:{thread:x}')
                if read_watched_word:
                    record['current_window_word' if watch_bytes > 4 else 'current_word'] = hex(
                        int.from_bytes(remote.read(watched_address, 4), 'little'))
                if window_before is not None:
                    window_after = remote.read(watch_address, watch_bytes)
                    record['changed_window_words'] = [dict(address=hex(watch_address + index * 4),
                        previous=hex(previous), current=hex(current))
                        for index, (previous, current) in enumerate(zip(
                            struct.unpack('<' + 'I' * (watch_bytes // 4), window_before),
                            struct.unpack('<' + 'I' * (watch_bytes // 4), window_after))) if previous != current]
                watched_count += 1
                if watched_count >= watch_count:
                    break
                require(remote.command(f'Z{watch_type},{watch_address:x},{watch_bytes:x}') == 'OK',
                        'Memory watchpoint rearm failed')
                memory_watch_armed = True
                continue
            require(pc in armed, f'Unexpected stop at {pc:#x}')
            repeat = thread > 2
            if thread <= 2:
                record = dict(entry=armed[pc], pc=hex(pc), thread=thread,
                    registers={name: hex(remote.get(registers, name)) for name in
                               ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'lr')})
                if capture_caller:
                    return_pc = capture_caller.observe(pc, registers)
                    if return_pc is not None:
                        require(return_pc not in armed, 'Capture return observation overlaps a breakpoint')
                        armed[return_pc] = 'diagnostic-capture-task-return'
                        remote.breakpoint(return_pc)
                keep = not (pc == 0x10319d88 and remote.get(registers, 'r4') != 0x10326677 or
                            pc == 0x103191c4 and not reconfigure and remote.get(registers, 'r1') != 0x10326677 or
                            pc == 0x103231b2 and remote.get(registers, 'r0') == remote.get(registers, 'r7'))
                if capture_caller and pc in capture_caller.ui_points:
                    record['ui_capture'], keep, repeat = capture_caller.ui_observation(pc, registers)
                    if (capture_wait_idle and idle_preview_seen and not preview_press_sent and
                            pc == 0x1020f8dc and keep and
                            not record['ui_capture']['blocking_resources'] and
                            int.from_bytes(remote.read(0xb1821e84, 4), 'little') == 0):
                        capture_caller.trigger()
                        preview_press_sent = True
                        record['diagnostic_capture_after_idle_event'] = True
                if keep and pc == 0x103231b2:
                    record['state_transition'] = dict(previous=remote.get(registers, 'r7'),
                        next=remote.get(registers, 'r0'), request=remote.get(registers, 'r10'))
                if pc == 0x1046c3c2:
                    record['display_configuration'] = remote.read(remote.get(registers, 'r1'), 24).hex()
                if input_boundary_events and pc == 0x102389c2:
                    requested = remote.get(registers, 'r1')
                    routes = ((0x100000, 0, 3), (0x200000, 0, 4),
                              (0x800000, 3, 5), (0x1000000, 3, 0), (0x4000000, 4, 7))
                    frames = machine.qmp.command('qom-get',
                        dict(path=boundary_path, property='input-dma-count'))
                    lines = []
                    if requested and not requested & ~0x5b00000 and frames > boundary_frame:
                        selected = [(bank, bit) for mask, bank, bit in routes if requested & mask]
                        enabled = all(int.from_bytes(remote.read(0x20068200 + bank * 32, 4),
                                                     'little') & 1 << bit for bank, bit in selected)
                        if enabled:
                            for bank, bit in selected:
                                line = bank * 32 + bit
                                for level in (1, 0):
                                    machine._qtest(f'set_irq_in /machine/unattached/{machine.config_names[0]} '
                                                   f'input-event {line} {level}')
                                lines.append(line)
                            boundary_frame = frames
                    record['input_boundary'] = dict(requested=hex(requested), raw_frames=frames,
                                                     injected_lines=lines)
                if input_boundary_events and pc in (0x102389c2, 0x102389c6):
                    hits[pc] = hits.get(pc, 0) + 1
                    repeat = hits[pc] < 64
                if pc == 0x103e1d30:
                    pointer = remote.get(registers, 'r5')
                    record['display_frame'] = dict(address=hex(pointer),
                        words={hex(index * 4): hex(value) for index, value in enumerate(
                            struct.unpack('<34I', remote.read(pointer, 0x88)))})
                if pc == 0x102692ca:
                    surface = remote.get(registers, 'r3')
                    record['capture_surface'] = dict(address=hex(surface),
                        words={hex(index * 4): hex(value) for index, value in enumerate(
                            struct.unpack('<7I', remote.read(surface, 0x1c)))})
                    context = remote.get(registers, 'r4')
                    if 0xb2c00000 <= context < 0xb5effeb0:
                        record['capture_context'] = dict(address=hex(context),
                            words={hex(offset): hex(int.from_bytes(remote.read(context + offset, 4), 'little'))
                                   for offset in (0, 4, 8, 0xc, 0x10, 0x30, 0x68, 0x6c, 0x70,
                                                  0x74, 0x90, 0x94, 0x98, 0x9c, 0xa0, 0xa4, 0x144, 0x148)})
                        objects = {}
                        for offset in (0x68, 0x6c, 0x70, 0x74, 0x9c, 0xa0, 0xa4):
                            pointer = int.from_bytes(remote.read(context + offset, 4), 'little')
                            if 0xb2c00000 <= pointer < 0xb5efffbc:
                                objects[hex(offset)] = dict(address=hex(pointer),
                                    words={hex(index * 4): hex(value) for index, value in enumerate(
                                        struct.unpack('<17I', remote.read(pointer, 0x44)))})
                        record['capture_buffer_objects'] = objects
                if pc in (0x103bded0, 0x103bd07c):
                    module = remote.get(registers, 'r0' if pc == 0x103bded0 else 'r1')
                    if module < 128:
                        base, callback = struct.unpack('<2I', remote.read(0x1078a2a0 + module * 8, 8))
                        record['processing_module'] = dict(index=module, base=hex(base), callback=hex(callback))
                        if 0x20100100 <= base < 0x20110000:
                            values = struct.unpack('<8I', remote.read(base, 32))
                            record['processing_module']['registers'] = [hex(value) for value in values]
                            pointer = remote.get(registers, 'r1') if pc == 0x103bded0 else values[4]
                            record['processing_module']['parameters'] = hex(pointer)
                            if 0xb1800000 <= pointer < 0xb5efff00 or 0xb0100000 <= pointer < 0xb08fff00:
                                data = remote.read(pointer, 256)
                                record['processing_module']['parameter_summary'] = dict(
                                    bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                if pc == 0x103bdb9e:
                    node = remote.get(registers, 'r4')
                    channel = remote.read(node + 1, 1)[0]
                    record['processing_dma_channel'] = channel
                    if channel < 16:
                        record['processing_dma_words'] = [hex(value) for value in struct.unpack(
                            '<13I', remote.read(0x20100400 + channel * 0x40, 52))]
                if pc == 0x103bd03a:
                    record['processing_controller'] = [hex(value) for value in struct.unpack(
                        '<17I', remote.read(0x20100000, 68))]
                    record['processing_dma'] = [dict(channel=channel, words=[hex(value) for value in struct.unpack(
                        '<13I', remote.read(0x20100400 + channel * 0x40, 52))]) for channel in range(16)]
                if pc in (0x103b4b1e, 0x103b4b26, 0x103b4b2e, 0x103b4b3e, 0x103b4b42):
                    task = remote.get(registers, 'r4')
                    record['processing_worker'] = processing_worker_snapshot(remote, task)
                    if pc == 0x103b4b3e:
                        record['processing_worker']['wait_flags'] = hex(remote.get(registers, 'r1'))
                    if pc == 0x103b4b42:
                        record['processing_worker']['returned_flags'] = hex(int.from_bytes(remote.read(
                            remote.get(registers, 'sp') + 4, 4), 'little'))
                if pc in CORE_WORKER_POINTS:
                    index = remote.get(registers, 'r5')
                    task = remote.get(registers, 'r0') if pc == 0x103b4e1e else 0xb1d52600 + index * 72
                    if task in (0xb1d52600, 0xb1d52648):
                        record['processing_core'] = processing_worker_snapshot(remote, task)
                        if pc == 0x103b4e1e:
                            record['processing_core']['activation'] = remote.get(registers, 'r1')
                        if pc == 0x103b4f26:
                            record['processing_core']['wait_flags'] = hex(remote.get(registers, 'r1'))
                        if pc == 0x103b4f2a:
                            record['processing_core']['returned_flags'] = hex(int.from_bytes(remote.read(
                                remote.get(registers, 'sp'), 4), 'little'))
                if pc == 0x10389b56:
                    pointer = remote.get(registers, 'r2')
                    values = struct.unpack('<80I', remote.read(pointer, 320))
                    record['processing_address_bindings'] = dict(address=hex(pointer),
                        bank_selector=remote.get(registers, 'r1'),
                        banks=[[hex(value) for value in values[index * 16:(index + 1) * 16]]
                               for index in range(4)], enabled=list(values[64:]))
                if pc == 0x10389b90:
                    pointer = remote.get(registers, 'r1')
                    data = remote.read(pointer, 20)
                    record['processing_port_configuration'] = dict(address=hex(pointer),
                        controls=list(data[:8]), word_8=hex(struct.unpack_from('<I', data, 8)[0]),
                        word_c=hex(struct.unpack_from('<I', data, 12)[0]),
                        halfword_10=struct.unpack_from('<H', data, 16)[0],
                        byte_12=data[18], port=data[19])
                if pc == 0x103e1dea:
                    packet = remote.get(registers, 'r1')
                    record['display_packet'] = dict(address=hex(packet),
                        words={hex(offset): hex(int.from_bytes(remote.read(packet + offset, 4), 'little'))
                               for offset in (0, 4, 8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20,
                                              0xdc, 0xe0, 0xe4, 0xe8, 0xec, 0xf0, 0xf4, 0xf8)})
                    if (shutter_on_preview or shutter_on_ready or capture_submit_on_ready) and not preview_press_sent:
                        paths = ['/machine/unattached/' + name for name in machine.config_names]
                        path = next(path for path in paths if machine.qmp.command(
                            'qom-get', dict(path=path, property='master-role')))
                        completed = machine.qmp.command('qom-get',
                            dict(path=path, property='processing-dma-count'))
                        gate = int.from_bytes(remote.read(0xb1821e84, 4), 'little')
                        if completed and (not (shutter_on_ready or capture_submit_on_ready) or gate == 0):
                            ticks = int.from_bytes(remote.read(0x04266008, 8), 'little')
                            if capture_submit_on_ready:
                                idle_preview_seen = True
                                blocked = capture_caller.blocking_resources() if capture_wait_idle else []
                                record['capture_pending_resources'] = blocked
                                if not blocked:
                                    capture_caller.trigger()
                                    preview_press_sent = True
                                    record['diagnostic_capture_after_processing_frames'] = completed
                                    record['release_gate_before_diagnostic_capture'] = gate
                            elif half_before_full and preview_half_tick is None:
                                machine.set_key(24, 0)
                                preview_half_tick = ticks
                                record['half_press_after_processing_frames'] = completed
                            elif not half_before_full or ticks - preview_half_tick >= before['counter_frequency'] // 2:
                                machine.set_key(25, 0)
                                preview_press_sent = True
                                record['shutter_after_processing_frames'] = completed
                                record['release_gate_before_press'] = gate
                                if half_before_full:
                                    record['half_press_counter_seconds'] = (
                                        ticks - preview_half_tick) / before['counter_frequency']
                if playback or returning or reconfigure:
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
                        callback_hits += int(keep)
                        record['notification'] = hex(remote.get(registers, 'r0'))
                        if remote.get(registers, 'r0') == 0x041a000d:
                            record['result_bytes'] = list(remote.read(
                                remote.get(registers, 'r1'), 2))
                        if not capture_caller:
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
                if frame_notify and pc in (0x10238d4a, 0x10238c40, 0x1023c960, 0x1023beec,
                                           0x1022e2e0, 0x1022e0ae, 0x1022e154, 0x1022e1aa,
                                           0x10321d80, 0x10321d94, 0x10321dbe, 0x10321e22, 0x10321e24,
                                           0x1032206e, 0x10322126, 0x10322250, 0x10325304,
                                           0x10233570, 0x10398206, 0x10233b9c, 0x10232154,
                                           0x102313ea, 0x10231472, 0x10231486, 0x102314e6,
                                           0x102315c2, 0x10326676,
                                           0x102315c4, 0x103279c0, 0x10327c88, 0x10319d88,
                                           0x103191c4, 0x103231b2,
                                           0x1032a792):
                    hits[pc] = hits.get(pc, 0) + int(keep)
                    limit = 32 if capture_caller and pc in capture_caller.ui_points else 8
                    repeat = not keep or hits[pc] < limit
                    pointer = None
                    if pc == 0x1022e2e0:
                        code = remote.get(registers, 'r0')
                        record['notification'] = hex(code)
                        if code == 0x041a0002:
                            pointer = remote.get(registers, 'r1')
                            record['completed_object'] = hex(pointer)
                    elif pc in (0x1022e0ae, 0x1032a792, 0x10232154):
                        pointer = remote.get(registers, 'r0')
                    elif pc == 0x1023beec:
                        pointer = remote.get(registers, 'r1')
                    elif pc in (0x1022e154, 0x1022e1aa, 0x1032206e, 0x10322126,
                                0x10322250, 0x10325304, 0x10398206, 0x10233b9c):
                        pointer = remote.get(registers, 'r4')
                    elif pc in (0x10231472, 0x10231486, 0x102314e6, 0x102315c2, 0x102315c4):
                        pointer = remote.get(registers, 'r4')
                    elif pc == 0x10233570:
                        pointer = int.from_bytes(remote.read(remote.get(registers, 'r0'), 4), 'little')
                    elif pc == 0x10321d80:
                        packet = remote.get(registers, 'r4')
                        pointer = int.from_bytes(remote.read(packet + 8, 4), 'little')
                    elif pc in (0x10321d94, 0x10321dbe, 0x10321e22, 0x10321e24):
                        pointer = remote.get(registers, 'r5')
                    if pointer is not None and 0xb2c00000 <= pointer < 0xb5effe00:
                        record['context'] = dict(address=hex(pointer),
                            parameters=hex(int.from_bytes(remote.read(pointer + 0x144, 4), 'little')),
                            pending=hex(int.from_bytes(remote.read(pointer + 0x14c, 4), 'little')),
                            consumers=hex(remote.read(pointer + 0xc, 1)[0]),
                            output_fields={hex(offset): hex(int.from_bytes(remote.read(pointer + offset, 4), 'little'))
                                           for offset in (0x20, 0x30, 0x34, 0x38, 0x40, 0x68, 0x6c, 0x70)})
                        if pc in (0x1032206e, 0x10322126, 0x10322250, 0x10325304):
                            record['driver_header'] = list(remote.read(0xb1868af0, 0x30))
                    if pc == 0x10398206:
                        record['frame_parameters'] = [hex(value) for value in struct.unpack(
                            '<29I', remote.read(remote.get(registers, 'r0'), 0x74))]
                    if keep and pc in (0x102313ea, 0x10231472, 0x10231486, 0x102314e6,
                              0x102315c2, 0x102315c4, 0x103279c0, 0x10327c88, 0x10319d88,
                              0x10326676):
                        record['input_ready_fields'] = {hex(offset): hex(int.from_bytes(
                            remote.read(0xb1887d70 + offset, 4), 'little'))
                            for offset in (0, 0x40, 0x50, 0x54, 0x58)}
                        record['driver_header'] = list(remote.read(0xb1868af0, 0x30))
                    if keep and pc == 0x10319d88:
                        record['queue_words'] = [hex(value) for value in struct.unpack(
                            '<5I', remote.read(0xb23ede14, 20))]
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
                if keep:
                    records.append(record)
                if mode1_frame_events and pc == 0x1023c5dc and len(mode1_events) == 1:
                    latch = int.from_bytes(remote.read(0xb26b38dc, 4), 'little')
                    record['mode1_output_latch'] = latch
                    if latch == 1:
                        pulse_mode1()
                if reconfigure and pc in RECONFIGURE_POINTS:
                    hits[pc] = hits.get(pc, 0) + 1
                    repeat = hits[pc] < (64 if pc == 0x1022827c or
                                        (shutter_on_ready or capture_submit_on_ready) and not preview_press_sent and
                                        pc == 0x103e1dea else 32 if pc == 0x103bded0 or
                                        half_before_full and pc == 0x103e1dea else 8)
            remote.breakpoint(pc, False)
            if repeat:
                remote.sock.settimeout(15)
                remote.command(f'vCont;s:{thread:x}')
                remote.breakpoint(pc)
            else:
                del armed[pc]
        after = snapshot(remote)
        return dict(before=before, records=records, after=after,
                    diagnostic_capture=capture_caller.report if capture_caller else None,
                    capture_wait_idle=capture_wait_idle,
                    observed_seconds=round(time.monotonic() - started, 3),
                    observed_counter_seconds=round((after['counter_ticks'] - before['counter_ticks']) /
                                                   before['counter_frequency'], 6),
                    driver_notification_hits=callback_hits,
                    tail_frame_events=tail_events,
                    mode1_frame_events=mode1_events,
                    memory_watch=(dict(address=hex(watch_address), bytes=watch_bytes,
                                       limit=watch_count, observed=watched_count)
                                  if watch_address is not None else None),
                    shutter_on_preview=shutter_on_preview,
                    preview_press_sent=preview_press_sent and not capture_submit_on_ready,
                    half_before_full=half_before_full, preview_half_sent=preview_half_tick is not None,
                    input_boundary_events=input_boundary_events,
                    shutter_on_ready=shutter_on_ready,
                    unseen=[label for address, label in armed.items()
                            if not hits.get(address, 0) and
                            not (capture_caller and capture_caller.ui_hits.get(address, 0)) and
                            (address != 0x10321a4c or callback_hits == 0)])
    finally:
        remote.sock.settimeout(15)
        if capture_caller:
            capture_caller.close()
        if memory_watch_armed:
            remote.command(f'z{watch_type},{watch_address:x},{watch_bytes:x}')
        if breakpoints_installed:
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
    parser.add_argument('--frame-phase', action='store_true',
                        help='Enable the optional masked periodic sampling phase source')
    parser.add_argument('--input-stop-complete', action='store_true',
                        help='Enable the optional command-triggered input stop response')
    parser.add_argument('--frame-generate', action='store_true',
                        help='Enable the experimental RAW12 checkerboard input DMA source')
    parser.add_argument('--frame-notify', action='store_true',
                        help='Experimentally latch recovered input timing causes after successful DMA')
    parser.add_argument('--reconfigure-watch', type=int, default=0,
                        help='Wait up to this many host seconds for driver state 4 before tracing (0..900)')
    parser.add_argument('--tail-frame-events', action='store_true',
                        help='Laboratory input: pulse input causes 0/6 once after RAW stops in state 4')
    parser.add_argument('--mode1-frame-events', action='store_true',
                        help='Laboratory input: pulse bank 3 bit 7, then repeat after the first native output latch')
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
    parser.add_argument('--watch', type=int, default=30,
                        help='Host seconds to observe the requested stage (10..900)')
    parser.add_argument('--boot-watch', type=int, default=240,
                        help='Host seconds to wait for the shooting foreground (30..600)')
    parser.add_argument('--watch-read', type=lambda value: int(value, 0),
                        help='Capture and single-step watched reads; the default access limit is one')
    parser.add_argument('--watch-write', type=lambda value: int(value, 0),
                        help='Capture and single-step watched writes; the default access limit is one')
    parser.add_argument('--watch-bytes', type=int, default=4,
                        help='Power-of-two memory watch window size in bytes (4..256)')
    parser.add_argument('--watch-count', type=int, default=1,
                        help='Stop an observed stage after this many watched accesses (1..64)')
    parser.add_argument('--frame-process', action='store_true',
                        help='Enable the functional full-scale RAW12 to monochrome preview path')
    parser.add_argument('--shutter-on-preview', action='store_true',
                        help='Leave shutter contacts released until a display submission follows processed pixels')
    parser.add_argument('--half-before-full', action='store_true',
                        help='After preview starts, hold half-press for at least half a counter second before full-press')
    parser.add_argument('--input-boundary-events', action='store_true',
                        help='Laboratory input: pulse supported masked boundary causes at native waits after RAW DMA advances')
    parser.add_argument('--shutter-on-ready', action='store_true',
                        help='Full-press at a processed display submission after the native release gate clears')
    parser.add_argument('--capture-submit-on-ready', action='store_true',
                        help='Diagnostic native-task capture API call after preview and release readiness')
    parser.add_argument('--trace-capture-resource-boot', action='store_true',
                        help='Observe capture resource bits 37/44 being written from reset')
    parser.add_argument('--processing-resource-header', action='store_true',
                        help='Supply group 23 with a zero experimental body and native storage trailer')
    parser.add_argument('--capture-wait-idle', action='store_true',
                        help='Defer the diagnostic capture until the native filtered resource intersection clears')
    args = parser.parse_args()
    require(10 <= args.watch <= 900, 'Watch time out of bounds')
    require(0 <= args.reconfigure_watch <= 900, 'Reconfiguration watch time out of bounds')
    require(not args.tail_frame_events or args.reconfigure_watch and args.frame_notify,
            'Tail event experiment requires reconfiguration observation and frame notification')
    require(not args.mode1_frame_events or args.reconfigure_watch and args.frame_notify,
            'Mode 1 event experiment requires reconfiguration observation and frame notification')
    require(not (args.tail_frame_events and args.mode1_frame_events),
            'Select one reconfiguration event experiment')
    require(30 <= args.boot_watch <= 600, 'Boot watch time out of bounds')
    require(args.watch_read is None or 0 <= args.watch_read <= 0xfffffffc and
            args.watch_read % 4 == 0, 'Read watch address out of bounds')
    require(args.watch_write is None or 0 <= args.watch_write <= 0xfffffffc and
            args.watch_write % 4 == 0, 'Write watch address out of bounds')
    require(args.watch_read is None or args.watch_write is None, 'Choose one memory watch type')
    require(4 <= args.watch_bytes <= 256 and args.watch_bytes & (args.watch_bytes - 1) == 0,
            'Memory watch window size out of bounds')
    require(1 <= args.watch_count <= 64, 'Memory watch access count out of bounds')
    require(all(address is None or address + args.watch_bytes <= 0x100000000
                for address in (args.watch_read, args.watch_write)), 'Memory watch range wraps')
    require(not args.frame_notify or args.frame_generate, 'Frame notification requires generated input pixels')
    require(not args.frame_process or args.frame_generate, 'Frame processing requires generated input pixels')
    require(not args.shutter_on_preview or args.frame_process and args.reconfigure_watch and
            not args.playback, 'Preview shutter requires processing and a shooting reconfiguration observation')
    require(not args.half_before_full or args.shutter_on_preview or args.shutter_on_ready,
            'Staged shutter requires preview- or readiness-triggered input')
    require(not args.input_boundary_events or args.frame_generate and args.frame_notify and
            args.reconfigure_watch and not args.playback,
            'Input boundary experiment requires RAW DMA and shooting reconfiguration observation')
    require(not args.shutter_on_ready or args.frame_process and args.reconfigure_watch and
            not args.playback and not args.shutter_on_preview,
            'Ready shutter requires processing and shooting observation without preview-triggered input')
    require(not args.capture_submit_on_ready or args.frame_process and args.reconfigure_watch and
            not (args.playback or args.shutter_on_ready or args.shutter_on_preview or args.half_before_full),
            'Diagnostic capture requires processing and shooting observation without body shutter input')
    require(not args.capture_wait_idle or args.capture_submit_on_ready,
            'Idle capture observation requires the diagnostic native capture caller')
    require(30 <= args.return_watch <= 900, 'Return watch time out of bounds')
    require(not args.local_stop_events or args.playback, 'Local stop events require playback')
    require(not args.round_trip or args.playback, 'Round trip requires playback')
    require(not args.gpio_handshake_events or args.round_trip,
            'GPIO handshake events require a round trip')
    args.realtime = args.auto_menu = False
    args.update_store = ROOT / '.local/body-shutter-gate-store'
    args.update_image = None
    if args.trace_capture_resource_boot:
        from tools.capture_resource_boot_trace import CaptureResourceMachine
        machine = CaptureResourceMachine(args)
    else:
        machine = Machine(args)
    try:
        machine.restart()
        deadline = time.monotonic() + args.boot_watch
        while time.monotonic() < deadline:
            state = machine.status()
            if state['phase'] == 'failed':
                raise RuntimeError(state['error'])
            if state.get('ready') and state.get('index') == 3 and state.get('input_ready'):
                break
            time.sleep(1)
        else:
            report = dict(observation='shooting-startup-deadline', boot=state,
                          boot_watch_seconds=args.boot_watch,
                          display_complete=args.display_complete,
                          input_handshake=args.input_handshake, frame_phase=args.frame_phase,
                          input_stop_complete=args.input_stop_complete,
                          frame_generate=args.frame_generate,
                          frame_notify=args.frame_notify,
                          shooting_foreground_ready=False)
            # A running console has detached its startup observer. Preserve
            # the failed foreground's actual state before closing the VM.
            if state['phase'] == 'running':
                with machine.io:
                    machine.qmp.command('stop')
                    remote = Remote(machine.gdb_port)
                    try:
                        report['snapshot'] = snapshot(remote)
                    finally:
                        remote.command('D')
                        remote.sock.close()
                report['native_lcd'] = lcd_snapshot(machine)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
            raise TimeoutError('Shooting foreground did not become ready')
        reconfiguration = None
        if args.reconfigure_watch:
            started = time.monotonic()
            driver_state = None
            reached = False
            while time.monotonic() - started < args.reconfigure_watch:
                machine.heartbeat()
                with machine.io:
                    driver_state = (machine._words(0xb1868af0, 1)[0] >> 8) & 255
                    finite_ready = (not args.mode1_frame_events or
                                    machine._bytes(0xb1888147, 1)[0] == 1 and
                                    machine._words(0xb26b38cc, 1)[0] & 4)
                if driver_state == 4 and finite_ready:
                    reached = True
                    break
                time.sleep(1)
            reconfiguration = dict(driver_state=driver_state, reached=reached,
                                   host_seconds=round(time.monotonic() - started, 3))
            print(json.dumps(dict(reconfiguration_wait=reconfiguration)), flush=True)
        initial_lcd = lcd_snapshot(machine)
        initial_dma = input_dma_snapshot(machine) if args.frame_generate else None
        report = dict(observation=('native-playback-capture-stop' if args.playback else
                                  'native-full-release-application-gate'), boot=state,
                      sd_attached=args.sd_card is not None,
                      display_complete=args.display_complete, watch_seconds=args.watch,
                      input_handshake=args.input_handshake,
                      frame_phase=args.frame_phase,
                      input_stop_complete=args.input_stop_complete,
                      frame_generate=args.frame_generate,
                      frame_notify=args.frame_notify,
                      frame_process=args.frame_process,
                      local_stop_events=args.local_stop_events,
                      gpio_handshake_events=args.gpio_handshake_events,
                      round_trip=args.round_trip,
                      reconfiguration_wait=reconfiguration,
                      return_watch_seconds=args.return_watch,
                      trace=observe(machine, args.watch, args.playback, args.local_stop_events,
                                    watch_read=args.watch_read, watch_write=args.watch_write,
                                    watch_bytes=args.watch_bytes, watch_count=args.watch_count,
                                    shutter_on_preview=args.shutter_on_preview,
                                    half_before_full=args.half_before_full,
                                    input_boundary_events=args.input_boundary_events,
                                    shutter_on_ready=args.shutter_on_ready,
                                    capture_submit_on_ready=args.capture_submit_on_ready,
                                    capture_wait_idle=args.capture_wait_idle,
                                    frame_notify=args.frame_notify,
                                    reconfigure=bool(args.reconfigure_watch),
                                    tail_frame_events=args.tail_frame_events,
                                    mode1_frame_events=args.mode1_frame_events))
        report['native_lcd_before'] = initial_lcd
        report['processing_resource_header'] = args.processing_resource_header
        if args.trace_capture_resource_boot:
            report['capture_resource_boot_writes'] = machine.resource_boot_writes
        if initial_dma is not None:
            report['input_dma_before'] = initial_dma
        report['final_application'] = machine.status()
        if args.round_trip and report['final_application']['index'] == 2:
            trace = observe(machine, args.return_watch, returning=True,
                            gpio_handshake_events=args.gpio_handshake_events,
                            watch_write=args.watch_write, frame_notify=args.frame_notify,
                            watch_bytes=args.watch_bytes, watch_count=args.watch_count)
            state = machine.status()
            report['return_liveview'] = dict(application=state, trace=trace)
            if state['index'] == 3 and state['input_ready']:
                report['shutter_after_return'] = observe(machine, 30, watch_write=args.watch_write,
                    frame_notify=args.frame_notify, watch_bytes=args.watch_bytes, watch_count=args.watch_count)
                report['post_shutter_application'] = machine.status()
        report['native_lcd_after'] = lcd_snapshot(machine)
        if args.frame_generate:
            report['input_dma_after'] = input_dma_snapshot(machine)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
    finally:
        machine.close()


if __name__ == '__main__':
    main()
