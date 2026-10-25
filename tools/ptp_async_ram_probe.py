# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare F044 with F032 on two fixed RAM regions of Z7 II C 1.70.

Default prints an offline plan. --execute performs the comparison; it never
requests boot memory, writes RAM or initiates a firmware update.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import digest, require
from analyze.ptp_checksum_context import identity, parameters, response_ok
from tools.ptp_checksum_context_probe import UsbCamera


TARGETS = (('usb_descriptor', 0xB1809888, 32),
           ('text_command_table', 0xB188B7FC, 32))
TIMEOUT_MS = 20000  # Allow additional time for the F044 internal wait.


def plan():
    commands = [dict(opcode='0x1001', purpose='identity'),
                dict(opcode='0x1002', purpose='open own session'),
                dict(opcode='0x94fd', parameters=parameters(0xF001))]
    for name, address, size in TARGETS:
        for command, phase in ((0xF032, 'before'), (0xF044, 'async'), (0xF032, 'after')):
            commands.append(dict(opcode='0x94ff', target=name, phase=phase,
                                 parameters=parameters(command, address, size)))
    commands.extend((dict(opcode='0x94fe', parameters=parameters(0xF002)),
                     dict(opcode='0x1003', purpose='close own session')))
    return dict(format=1, transaction_plan=commands, host_timeout_ms=TIMEOUT_MS,
                camera_read_executed=False, initiates_update=False,
                writes_camera_memory=False, reads_boot_memory=False,
                remote_address_semantics_verified=False)


def observe(camera, report, save):
    report['stage'] = 'identity'
    data, reply = camera.read(0x1001, [])
    require(reply[0] == 0x2001, 'DeviceInfo failed')
    report['identity'] = identity(data)
    report['camera_read_executed'] = True
    error = None
    try:
        report['stage'] = 'enter_service'
        response_ok(camera.send(0x94FD, parameters(0xF001)), allowed=(0x2001, 0x201E))
        for name, address, size in TARGETS:
            result = dict(target=name, address=hex(address), bytes=size, reads=[])
            report['targets'].append(result)
            snapshots = []
            for command, phase in ((0xF032, 'before'), (0xF044, 'async'), (0xF032, 'after')):
                report['stage'] = name + ':' + phase
                data, reply = camera.read(0x94FF, parameters(command, address, size))
                result['reads'].append(dict(phase=phase, outer=hex(reply[0]),
                                           inner=[hex(value) for value in reply[1]],
                                           received_bytes=len(data)))
                response_ok(reply)
                require(len(data) == size, name + ': incomplete ' + phase + ' read')
                data = bytes(data)
                save(name + '-' + phase + '.bin', data)
                snapshots.append(data)
                result['reads'][-1]['sha256'] = digest(data)
                if phase == 'before':
                    require(len(set(data)) >= 4, name + ': reference is too uniform; F044 not sent')
                    if name == 'usb_descriptor':
                        require(data[:2] == b'\x12\x01' and
                                struct.unpack_from('<HH', data, 8) == (0x04B0, 0x044B),
                                'Unexpected USB descriptor; F044 not sent')
            before, asynchronous, after = snapshots
            result.update(reference_stable=before == after,
                          reference_nontrivial=len(set(before)) >= 4,
                          async_matches_reference=before == asynchronous == after)
            result['comparison_passed'] = all(result[key] for key in
                ('reference_stable', 'reference_nontrivial', 'async_matches_reference'))
        report['fixed_ram_comparison_passed'] = all(
            target['comparison_passed'] for target in report['targets'])
    except BaseException as exc:
        error = exc
        raise
    finally:
        if getattr(camera, 'synchronized', True):
            if error is None:
                report['stage'] = 'exit_service'
            try:
                response_ok(camera.send(0x94FE, parameters(0xF002)))
                report['service_exit_completed'] = True
            except Exception as exc:
                if error is None:
                    raise
                error.add_note('Service exit also failed: ' + str(exc))
        else:
            report['service_exit_skipped_unsynchronized'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--destination', type=Path, help='New local output directory; default creates a dated directory')
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps(plan(), indent=2))
        return
    destination = args.destination or ROOT / '.local' / (
        'ptp-async-ram-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))
    require(not destination.exists(), 'Destination already exists; choose a new directory')
    destination.mkdir(parents=True)
    report = dict(format=1, completed=False, stage='connect', targets=[],
                  camera_read_executed=False, initiates_update=False,
                  writes_camera_memory=False, reads_boot_memory=False,
                  fixed_ram_comparison_passed=False, boot_memory_read_verified=False,
                  remote_address_semantics_verified=False)
    try:
        with UsbCamera(timeout_ms=TIMEOUT_MS) as camera:
            observe(camera, report, lambda name, data: (destination / name).write_bytes(data))
            report['stage'] = 'close_session'
        report.update(completed=True, stage='finished')
    except BaseException as exc:
        report['error'] = str(exc)
        report['cleanup_notes'] = getattr(exc, '__notes__', [])
        raise
    finally:
        (destination / 'report.json').write_text(
            json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
        print('Saved:', destination)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, ImportError, OSError) as error:
        print('PTP RAM comparison failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
