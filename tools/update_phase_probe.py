# SPDX-License-Identifier: GPL-2.0-or-later
"""Bound the execute-service transition after a supplied authentication result.

The original execute controller runs against a synthetic selected-package
snapshot and event result. The first update-preparation call is captured and
refused. No programming is executed. This does not establish menu dialog order.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require, validate_master
from tools.native_update_probe import NativeUpdateProbe


def scenario(image, authentication_result):
    probe = NativeUpdateProbe(image, b'')
    events = []

    def fixed(value):
        return lambda *args: probe.result(value)

    def selected(output, *args):
        snapshot = bytearray(0x48)
        struct.pack_into('<I', snapshot, 8, 1)
        snapshot[12] = 4
        probe.u.mem_write(output, bytes(snapshot))
        probe.result(0)

    def post_event(handle, mask, *args):
        events.append(dict(kind='event_post', mask=mask))
        if mask == 0x10:
            probe.u.mem_write(0xB1887D22, struct.pack('<H', authentication_result))
        probe.result(0)

    def wait(handle, mask, output, timeout):
        require(mask == 0x20, 'Unexpected execution event')
        events.append(dict(kind='authentication_result_consumed', result=authentication_result))
        probe.put_word(output, 0x20)
        probe.result(1)

    def preparation(*args):
        events.append(dict(kind='update_preparation_entered', offset='0x37c8fe'))
        probe.result(2)  # Refuse before executing any update-preparation body.

    for offset, callback in {
            0x2D4B1A: fixed(1), 0x37D1F2: selected,
            0x37AD26: fixed(0), 0x3D60CA: fixed(probe.SCRATCH + 0x4000),
            0x3D69A8: fixed(0), 0x3D698C: fixed(0),
            0x3BB2CA: fixed(0), 0x3BB30A: fixed(0),
            0x3410D2: fixed(0), 0x3410CC: post_event,
            0x341116: wait, 0x37C8FE: preparation, 0x3D69C0: fixed(0),
    }.items():
        probe.install_hook(offset, callback)
    returned = probe.call(0x3D6474, 0)
    entered = any(event['kind'] == 'update_preparation_entered' for event in events)
    require(entered == (authentication_result == 0), 'Unexpected post-authentication branch')
    require(returned == (2 if entered else authentication_result), 'Unexpected service result')
    return dict(supplied_authentication_result=authentication_result,
                events=events, execute_controller_returned=returned,
                preparation_entered=entered, preparation_body_executed=False,
                programming_executed=False)


def run(image):
    validate_master(image)
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        scope='Original execute controller after host-supplied worker completion',
        cases=[scenario(image, value) for value in (3, 0)],
        original_controller_entry='0x103f6474',
        authentication_worker_entry='0x103f6938',
        post_authentication_preparation='0x1039c8fe',
        host_boundaries=['synthetic selected whole-package snapshot', 'controller readiness and state',
                         'allocated work buffer', 'event completion and supplied authentication result',
                         'progress callbacks and locks', 'refused preparation and cleanup'],
        original_authentication_executed=False, menu_confirmation_order_verified=False,
        safe_pre_confirmation_checksum_cancel_route_established=False,
        limitations=[
            'This run proves the controller branch, not that a real package authenticates.',
            'The first preparation call is refused before its body; no flash operation is attempted.',
            'The menu caller and the final Yes/No dialog are outside this isolated execution.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run(args.master.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS execute-service authentication failure/success transitions; preparation refused')


if __name__ == '__main__':
    main()
