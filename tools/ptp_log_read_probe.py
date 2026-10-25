# SPDX-License-Identifier: GPL-2.0-or-later
"""Test the diagnostic log path; optionally read one fixed boot-memory line.

Default prints a plan without USB access. --execute temporarily changes three
fixed RAM gate bytes and restores their saved values. No flash writes, arbitrary
addresses, update requests or automatic command retries are supported.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import struct
import sys
from time import sleep

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import digest, require, validate_master
from analyze.ptp_checksum_context import identity, parameters, response_ok
from analyze.upgrade_signature import appended_key, verify_update
from tools.ptp_checksum_context_probe import UsbCamera

GATES = (('log_retention', 0xB180048C), ('debug_admission', 0xB1800474),
         ('diagnostic_configuration', 0xB20D2D6A))
RAM = 0xB1809880  # Aligned line containing the previously observed USB descriptor.
BOOT = 0x10000080
QUEUE = 0xB1800038
LOG_SEQUENCE = 0xB1800490
OBJECT8_RECORD = 0xB185EC50
OBJECT8_REGION = 0xB185E724
RING = 0xB18B9DA8
RING_COUNT = 4096
WINDOW = 32
COMMANDS = {address: ('debug memdump 0x%08x 16' % address).encode('ascii') + b'\0'
            for address in (RAM, BOOT)}
PACKAGE_SHA = 'fc0e94f57500a1f0e287c6b9a036c81a5ffceccb8432a377d645b3fa35a19b6a'


class LogCamera(UsbCamera):
    def upload(self, opcode, args, data):
        """Send only a fixed diagnostic line or one allowlisted RAM gate byte."""
        gate_write = (opcode == 0x94FE and len(args) == 5 and args[0] == 0xF033 and
                      args[1] in dict(GATES).values() and args[2:] == [1, 0, 0] and
                      data in (b'\0', b'\1'))
        command = opcode == 0x92F0 and not args and data in COMMANDS.values()
        require(gate_write or command, 'Upload outside the fixed diagnostic scope')
        self.start_session()
        require(self.synchronized, 'PTP stream is unsynchronized; no further commands')
        try:
            self.transaction += 1
            transaction = self.transaction
            packet = struct.pack('<IHHI', 12 + 4 * len(args), 1, opcode, transaction)
            packet += struct.pack('<' + str(len(args)) + 'I', *args)
            payload = struct.pack('<IHHI', 12 + len(data), 2, opcode, transaction) + data
            for block in (packet, payload):
                require(self.device.write(self.output, block, timeout=self.timeout_ms) == len(block),
                        'Incomplete PTP upload; no retry')
            kind, code, received, result = self.container()
            require(kind == 3 and received == transaction and len(result) <= 20 and
                    len(result) % 4 == 0, 'Malformed upload response')
            return code, list(struct.unpack('<' + str(len(result) // 4) + 'I', result))
        except BaseException:
            self.synchronized = False
            raise


def read_ram(camera, address, count):
    data, reply = camera.read(0x94FF, parameters(0xF032, address, count))
    try:
        response_ok(reply)
    except ValueError as exc:
        raise ValueError('F032 read rejected at %s (%d bytes): %s' % (hex(address), count, exc)) from exc
    require(len(data) == count, 'Incomplete RAM read at ' + hex(address))
    return bytes(data)


def write_gate(camera, address, value):
    response = camera.upload(0x94FE, parameters(0xF033, address, 1), bytes([value]))
    response_ok(response)
    require(len(response[1]) >= 2 and response[1][1] == 1, 'Gate write count differs')
    require(read_ram(camera, address, 1) == bytes([value]), 'Gate readback differs')


def record_line(record, address):
    require(len(record) == 128, 'Incomplete log record')
    length = struct.unpack_from('<H', record, 12)[0]
    if not 0 < length <= 102 or record[14] != 0:
        return None
    text = record[16:16 + length].decode('ascii', errors='replace')
    match = re.match(r'^\s*\[%08x\]\s+((?:[0-9a-f]{2}\s+){16})\s*\[' % address,
                     text, re.IGNORECASE)
    return bytes.fromhex(match[1]) if match else None


def sequence(camera):
    return struct.unpack('<I', read_ram(camera, LOG_SEQUENCE, 4))[0]


def inspect_guard(camera, report, save):
    """Read two fixed descriptor records; do not read or change any gate byte."""
    report['camera_access_executed'] = True
    data, reply = camera.read(0x1001, [])
    require(reply[0] == 0x2001, 'DeviceInfo failed')
    report['identity'] = identity(data)
    entered = False
    try:
        report['stage'] = 'guard:enter_service'
        response_ok(camera.send(0x94FD, parameters(0xF001)))
        entered = True
        report['stage'] = 'guard:object8_record'
        record = read_ram(camera, OBJECT8_RECORD, 28)
        save('guard-object8.bin', record)
        require(record[0] == 8 and struct.unpack_from('<I', record, 20)[0] == 8,
                'Unexpected object 8 descriptor binding')
        report['stage'] = 'guard:object8_region'
        region = read_ram(camera, OBJECT8_REGION, 36)
        save('guard-object8-region.bin', region)
        base = struct.unpack_from('<I', record, 8)[0]
        size = struct.unpack_from('<I', record, 12)[0]
        end = (base - 1 + size) & 0xFFFFFFFF
        config = dict(GATES)['diagnostic_configuration']
        report['guard_inspection'] = dict(
            descriptor_address=hex(OBJECT8_RECORD), region_address=hex(OBJECT8_REGION),
            cached_base=hex(base), cached_bytes=size,
            region_capacity=struct.unpack_from('<I', region, 8)[0], inclusive_end=hex(end),
            configuration_address=hex(config),
            configuration_overlaps_cached_object=base != 0 and end != 0 and base <= config <= end,
            limitation='Two non-atomic metadata reads; no write permission is tested or granted.')
        report['stage'] = 'guard:observations_complete'
    finally:
        if entered and camera.synchronized:
            try:
                response_ok(camera.send(0x94FE, parameters(0xF002)))
                report['service_exit_completed'] = True
            except Exception as exc:
                report['cleanup_notes'].append('Service exit failed: ' + str(exc))
        elif entered:
            report['cleanup_notes'].append('USB unsynchronized; service exit not sent')


def dump_line(camera, address, report, save, pause):
    """One command, bounded log observation, no resubmission or queue writes."""
    require(struct.unpack('<I', read_ram(camera, QUEUE + 8, 4))[0] == 0,
            'Diagnostic queue is busy; command not submitted')
    start = sequence(camera)
    old = {}
    for index in range(WINDOW):
        slot = ((start + index) & 0xFFFFFFFF) % RING_COUNT
        old[slot] = read_ram(camera, RING + slot * 128, 128)
    require(sequence(camera) == start, 'Logs changed during baseline; command not submitted')
    report['stage'] = 'dump:' + hex(address)
    attempt = dict(address=hex(address), sequence_before=start, command_sent=False)
    report['dumps'].append(attempt)
    save('report.json', report)
    attempt['command_sent'] = True  # Submission may take effect even if the response is lost.
    save('report.json', report)
    response = camera.upload(0x92F0, [], COMMANDS[address])
    require(response[0] == 0x2001, 'Diagnostic command rejected: ' + repr(response))
    for poll in range(8):
        current = sequence(camera)
        count = (current - start) & 0xFFFFFFFF
        attempt.update(sequence_after=current, new_records=count, polls=poll + 1)
        require(count <= WINDOW, 'Log observation window exceeded; no command retry')
        for offset in range(count):
            slot = ((start + offset) & 0xFFFFFFFF) % RING_COUNT
            location = RING + slot * 128
            first = read_ram(camera, location, 128)
            if first == old[slot]:
                continue  # A reserved slot may not have been published yet.
            value = record_line(first, address)
            if value is not None and first == read_ram(camera, location, 128):
                require(struct.unpack('<I', read_ram(camera, QUEUE + 8, 4))[0] == 0,
                        'Matching log observed but command queue remains busy')
                save('dump-%08x-record.bin' % address, first)
                save('dump-%08x.bin' % address, value)
                attempt.update(matching_record_observed=True, sha256=digest(value))
                return value
        pause(0.2)
    queue = struct.unpack('<7I', read_ram(camera, QUEUE, 28))
    attempt['queue_after'] = dict(busy=queue[2], line_length=queue[6])
    raise ValueError('No fresh matching dump record; command consumption remains unverified')


def observe(camera, report, save, read_boot=False, pause=sleep):
    report['camera_access_executed'] = True
    data, response = camera.read(0x1001, [])
    require(response[0] == 0x2001, 'DeviceInfo failed')
    report['identity'] = identity(data)
    entered, dirty = False, []
    try:
        report['stage'] = 'enter_service'
        response_ok(camera.send(0x94FD, parameters(0xF001)))
        entered = True
        report['stage'] = 'baseline'
        baseline = read_ram(camera, RAM, 32)
        descriptor = baseline[8:]
        require(descriptor[:2] == b'\x12\x01' and
                struct.unpack_from('<HH', descriptor, 8) == (0x04B0, 0x044B),
                'Unexpected USB descriptor; gate writes not started')
        require(read_ram(camera, 0xB1800060, 4) == bytes(4),
                'Diagnostic capture state is active; gate writes not started')
        require(read_ram(camera, QUEUE + 8, 4) == bytes(4),
                'Diagnostic queue is busy; gate writes not started')
        save('ram-before.bin', baseline)
        for name, address in GATES:
            report['stage'] = 'read_gate:' + name
            value = read_ram(camera, address, 1)[0]
            require(value in (0, 1), 'Unexpected gate state: ' + name)
            report['original_gates'][name] = dict(address=hex(address), value=value)
        save('report.json', report)
        for name, address in GATES:
            if report['original_gates'][name]['value'] != 1:
                report['stage'] = 'enable:' + name
                dirty.append((name, address))
                report['gates_restored'] = False
                report['gate_writes_attempted'].append(name)
                save('report.json', report)
                write_gate(camera, address, 1)
        actual = dump_line(camera, RAM, report, save, pause)
        after = read_ram(camera, RAM, 32)
        require(after == baseline and actual == baseline[:16], 'RAM log comparison failed')
        report['ram_comparison_passed'] = True
        if read_boot:
            # Reach this only after a fresh, stable RAM comparison in this session.
            report['boot_read_attempted'] = True
            save('report.json', report)
            boot = dump_line(camera, BOOT, report, save, pause)
            save('boot-material.bin', boot[8:16])
            report['boot_material_candidate_saved'] = True
        report['stage'] = 'observations_complete'
    finally:
        for name, address in reversed(dirty):
            entry = dict(name=name, restored=False)
            report['restoration'].append(entry)
            if not camera.synchronized:
                entry['error'] = 'USB unsynchronized; no restoration command sent'
                continue
            try:
                original = report['original_gates'][name]['value']
                current = read_ram(camera, address, 1)[0]
                require(current in (1, original), 'Gate changed externally; restoration stopped')
                if current != original:
                    write_gate(camera, address, original)
                entry['restored'] = True
            except Exception as exc:
                entry['error'] = str(exc)
        report['gates_restored'] = all(item['restored'] for item in report['restoration'])
        if entered and camera.synchronized:
            try:
                response_ok(camera.send(0x94FE, parameters(0xF002)))
                report['service_exit_completed'] = True
            except Exception as exc:
                report['cleanup_notes'].append('Service exit failed: ' + str(exc))
        elif entered:
            report['cleanup_notes'].append('USB unsynchronized; service exit not sent')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--execute', action='store_true')
    source.add_argument('--verify-material', type=Path, help='Verify a local eight-byte candidate; no USB access')
    parser.add_argument('--read-boot', action='store_true',
                        help='After the RAM comparison, read the fixed boot line once')
    parser.add_argument('--inspect-guard', action='store_true',
                        help='Only read fixed object 8 descriptors; no RAM gate writes or dump commands')
    parser.add_argument('--master', type=Path,
                        default=ROOT / '../../Temporary/2610/07/Z_72/eg1840_mas_01700.bin')
    parser.add_argument('--package', type=Path,
                        default=ROOT / '../../Temporary/2610/24/z72/Z7_2_0170.bin')
    args = parser.parse_args()
    require(not (args.inspect_guard and (args.read_boot or args.verify_material is not None)),
            '--inspect-guard cannot be combined with boot reading or material verification')
    require(not (args.execute and not args.inspect_guard),
            'RAM gate and boot experiments are suspended: the configuration byte is protected. '
            'Only --execute --inspect-guard is available for camera access.')
    if not args.execute and args.verify_material is None:
        print(json.dumps(dict(writes_camera_ram=not args.inspect_guard, writes_flash=False, initiates_update=False,
                              inspect_guard=args.inspect_guard,
                              execution_suspended=not args.inspect_guard,
                              temporary_gates={} if args.inspect_guard else {name: hex(address) for name, address in GATES},
                              ram_comparison_address=None if args.inspect_guard else hex(RAM), read_boot=args.read_boot,
                              descriptor_reads=[hex(OBJECT8_RECORD), hex(OBJECT8_REGION)] if args.inspect_guard else [],
                              boot_line_address=hex(BOOT) if args.read_boot else None,
                              restores_original_gates=True, camera_access_executed=False), indent=2))
        return
    require(not (args.read_boot and args.verify_material is not None),
            'Local material verification does not accept --read-boot')
    master = package = None
    if args.read_boot or args.verify_material is not None:
        master, package = args.master.read_bytes(), args.package.read_bytes()
        validate_master(master)
        require(digest(package) == PACKAGE_SHA, 'Requires the original C 1.70 package')
    destination = ROOT / '.local' / ('ptp-log-read-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))
    destination.mkdir(parents=True, exist_ok=False)
    report = dict(format=1, completed=False, stage='identity', original_gates={},
                  gate_writes_attempted=[], restoration=[], dumps=[], cleanup_notes=[],
                  writes_camera_ram=not args.inspect_guard, writes_flash=False, initiates_update=False,
                  inspect_guard=args.inspect_guard,
                  camera_access_executed=False, gates_restored=True, material_recovered=False,
                  ram_comparison_passed=False, boot_read_attempted=False,
                  boot_material_candidate_saved=False, package_digest_verified=False,
                  service_exit_completed=False)

    def save(name, value):
        if name.endswith('.json'):
            value = (json.dumps(value, indent=2) + '\n').encode('utf-8')
        (destination / name).write_bytes(value)

    try:
        if args.verify_material is None:
            with LogCamera() as camera:
                if args.inspect_guard:
                    inspect_guard(camera, report, save)
                else:
                    observe(camera, report, save, args.read_boot)
            require(report['gates_restored'] and report['service_exit_completed'], 'Cleanup incomplete')
        else:
            report.update(stage='offline_verification', writes_camera_ram=False,
                          camera_access_executed=False)
            material = args.verify_material.read_bytes()
            require(len(material) == 8, 'Expected exactly eight material bytes')
            save('boot-material.bin', material)
        if master is not None:
            report['stage'] = 'verify_package'
            material = (destination / 'boot-material.bin').read_bytes()
            verified = verify_update(package, material, master)
            save('verified-material.json', dict(format=1, b8=material.hex(),
                                               k8=appended_key(material, master).hex(),
                                               package_sha256=digest(package),
                                               package_digest=verified['digest']))
            report.update(package_digest_verified=True, material_recovered=True,
                          package_sha256=digest(package), material_sha256=digest(material))
        report['completed'] = True
    except (Exception, KeyboardInterrupt) as exc:
        report['error'] = str(exc) or type(exc).__name__
        report['cleanup_notes'].extend(getattr(exc, '__notes__', ()))
    finally:
        save('report.json', report)
        print(json.dumps(report, indent=2))
        print('Saved:', destination)
    if not report['completed']:
        raise SystemExit(1)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, ImportError) as exc:
        print('PTP log observation failed: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
