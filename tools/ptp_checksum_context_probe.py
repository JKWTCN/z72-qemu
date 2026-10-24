# SPDX-License-Identifier: GPL-2.0-or-later
"""Inspect an existing checksum context; never initiate a firmware update.

Default is an offline transaction plan. --execute uses a USB PTP
interface for one fixed RAM snapshot. --context reads a local snapshot
instead. No menu interaction or checksum-triggering command is sent.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require, validate_master
from analyze.ptp_checksum_context import CONTEXT, CONTEXT_SIZE, capture, identity, inspect_context, parameters


class UsbCamera:
    """Small PTP reader; keep the existing driver and never detach it."""

    def __init__(self):
        import usb.core
        import usb.util
        self.util = usb.util
        self.device = usb.core.find(idVendor=0x04B0, idProduct=0x044B)
        require(self.device is not None, 'Z7 II USB device 04B0:044B not found')
        self.claimed, self.session, self.session_attempted = False, False, False
        self.pending = bytearray()
        self.transaction = 0
        try:
            interfaces = [item for item in self.device.get_active_configuration()
                          if (item.bInterfaceClass, item.bInterfaceSubClass, item.bInterfaceProtocol)
                          == (6, 1, 1) and item.bAlternateSetting == 0]
            require(len(interfaces) == 1, 'Expected one PTP interface')
            interface = interfaces[0]
            self.interface = interface.bInterfaceNumber
            endpoints = [item for item in interface if item.bmAttributes & 3 == 2]
            self.input = next(item.bEndpointAddress for item in endpoints if item.bEndpointAddress & 0x80)
            self.output = next(item.bEndpointAddress for item in endpoints if not item.bEndpointAddress & 0x80)
            if os.name != 'nt':
                require(not self.device.is_kernel_driver_active(self.interface),
                        'PTP interface is owned by a driver; no automatic detachment')
            try:
                self.util.claim_interface(self.device, self.interface)
            except (usb.core.USBError, NotImplementedError) as exc:
                raise RuntimeError('Cannot claim PTP interface. Close other camera programs and '
                                   'check USB permissions; keep the existing camera driver.') from exc
            self.claimed = True
        except BaseException:
            self.util.dispose_resources(self.device)
            raise

    def container(self):
        while len(self.pending) < 12:
            self.pending.extend(self.device.read(self.input, 4096, timeout=5000))
        size, kind, code, transaction = struct.unpack_from('<IHHI', self.pending)
        require(12 <= size <= 2 * 1024 * 1024, 'Invalid PTP container size')
        while len(self.pending) < size:
            self.pending.extend(self.device.read(self.input, 4096, timeout=5000))
        payload = bytes(self.pending[12:size])
        del self.pending[:size]
        return kind, code, transaction, payload

    def transact(self, opcode, args, receive_data):
        if self.session:
            self.transaction += 1
        transaction = self.transaction if self.session else 0
        packet = struct.pack('<IHHI', 12 + 4 * len(args), 1, opcode, transaction)
        packet += struct.pack('<' + str(len(args)) + 'I', *args)
        require(self.device.write(self.output, packet, timeout=5000) == len(packet),
                'Incomplete PTP command write')
        kind, code, received, payload = self.container()
        require(received == transaction, 'PTP transaction mismatch')
        data = b''
        if kind == 2:
            require(receive_data and code == opcode, 'Unexpected PTP data phase')
            data = payload
            kind, code, received, payload = self.container()
        require(kind == 3 and received == transaction and len(payload) <= 20 and len(payload) % 4 == 0,
                'Malformed PTP response')
        values = list(struct.unpack('<' + str(len(payload) // 4) + 'I', payload))
        require(not (receive_data and code == 0x2001 and not data and
                     not (opcode == 0x94FF and values and values[0] != 0x2001)),
                'Successful read omitted its data phase')
        return data, (code, values)

    def start_session(self):
        if self.session:
            return
        require(not self.session_attempted, 'PTP session open already failed; no automatic retry')
        self.session_attempted = True
        _, reply = self.transact(0x1002, [1], False)
        require(reply[0] == 0x2001, 'Cannot open a new PTP session: ' + repr(reply))
        self.session = True

    def read(self, opcode, args):
        if opcode != 0x1001:
            self.start_session()
        return self.transact(opcode, args, True)

    def send(self, opcode, args):
        self.start_session()
        return self.transact(opcode, args, False)[1]

    def __enter__(self):
        return self

    def __exit__(self, kind, error, traceback):
        try:
            if self.session:
                _, reply = self.transact(0x1003, [], False)
                require(reply[0] == 0x2001, 'PTP session close failed: ' + repr(reply))
        except Exception as exc:
            if error is None:
                raise
            error.add_note('PTP session close also failed: ' + str(exc))
        finally:
            try:
                if self.claimed:
                    self.util.release_interface(self.device, self.interface)
            finally:
                self.util.dispose_resources(self.device)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--execute', action='store_true')
    source.add_argument('--context', type=Path)
    parser.add_argument('--backend', choices=('usb',), default='usb')
    parser.add_argument('--info-only', action='store_true', help='Only query DeviceInfo; do not enter service')
    parser.add_argument('--master', type=Path)
    parser.add_argument('--package', type=Path)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--previous', type=Path, help='Compare against an earlier local context.bin')
    args = parser.parse_args()
    if not args.execute and args.context is None:
        plan = dict(context_address=hex(CONTEXT), bytes=CONTEXT_SIZE,
            transaction_plan=[dict(opcode='0x1001', purpose='identity'),
                dict(opcode='0x94fd', parameters=parameters(0xF001)),
                dict(opcode='0x94ff', parameters=parameters(0xF032, CONTEXT, CONTEXT_SIZE)),
                dict(opcode='0x94fe', parameters=parameters(0xF002))],
            initiates_update=False, menu_confirmation_order_verified=False)
        if args.info_only:
            plan['transaction_plan'] = plan['transaction_plan'][:1]
        plan['backend'] = args.backend
        plan['usb_session_operations'] = ['0x1002', '0x1003'] if args.backend == 'usb' and not args.info_only else []
        print(json.dumps(plan, indent=2))
        return
    if args.info_only:
        require(args.execute and args.context is None, '--info-only requires --execute')
        with UsbCamera() as connected:
            data, reply = connected.read(0x1001, [])
            require(reply[0] == 0x2001, 'DeviceInfo failed')
            print(json.dumps(identity(data), indent=2))
        return
    require(args.master is not None and args.package is not None and args.destination is not None,
            'Snapshot inspection needs --master, --package and --destination')
    require(not args.destination.exists(), 'Destination already exists')
    master, package = args.master.read_bytes(), args.package.read_bytes()
    validate_master(master)
    previous = args.previous.read_bytes() if args.previous is not None else None
    require(previous is None or len(previous) == CONTEXT_SIZE,
            'Previous snapshot must contain 52 bytes')
    # Validate the local input before opening a camera.
    inspect_context(bytes(CONTEXT_SIZE), package, master)
    if args.context is not None:
        context, camera_identity = args.context.read_bytes(), None
    else:
        with UsbCamera() as connected:
            context, camera_identity = capture(connected)
    report, material = inspect_context(context, package, master)
    report.update(format=1, firmware_included=False, identity=camera_identity,
                  camera_read_executed=args.execute, initiates_update=False,
                  menu_confirmation_order_verified=False)
    if previous is not None:
        report['context_changed'] = previous != context
        report['changed_offsets'] = [i for i in range(CONTEXT_SIZE) if previous[i] != context[i]]
    args.destination.mkdir(parents=True)
    (args.destination / 'context.bin').write_bytes(context)
    (args.destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    if material is not None:
        (args.destination / 'verified-material.json').write_text(json.dumps(material, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, ImportError, OSError) as error:
        print('PTP observation failed: ' + str(error), file=sys.stderr)
        for note in getattr(error, '__notes__', ()):
            print(note, file=sys.stderr)
        raise SystemExit(1)
