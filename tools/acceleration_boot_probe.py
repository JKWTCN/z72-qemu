# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify C1.70 acceleration resource delivery and the first sample on combined boot."""
import argparse
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from tools.smp_boot_probe import reach, stop_registers
from tools.web_console import LIVE_VIEW_OPTIONS, Machine


class BootProbe(Machine):
    def _boot_dance(self):
        # Observe the first read before the console's later display sync edge.
        remote = self.remote
        remote.sock.settimeout(90)
        _, regs = reach(remote, 0x103d4e90)
        owner = remote.get(regs, 'r4')
        require(remote.get(regs, 'r0') == 1, 'Original sample read failed')
        pointers = struct.unpack('<II', remote.read(owner + 424, 8))
        for ptr, path in zip(pointers, self.args.acceleration_records):
            record = path.read_bytes()
            require(ptr and remote.read(ptr, len(record)) == record,
                    'Installed acceleration record differs from boot storage')
        axes = struct.unpack('<hhh', remote.read(owner + 0x22, 6))
        require(remote.read(0xb1807efc, 1) == b'\x01', 'Firmware selected the other sensor')
        require(axes == self.args.acceleration_sample, f'Unexpected original axes {axes}')
        # Standby and the queued direction callback run on separate paths.
        pending = {0x103d5266, 0x103eeb7a, 0x103eea94, 0x10350dcc}
        for pc in pending:
            remote.breakpoint(pc)
        direction = None
        while pending:
            _, regs = stop_registers(remote, remote.command('vCont;c'))
            pc = remote.get(regs, 'pc')
            require(pc in pending, f'Unexpected execution stop at {pc:#x}')
            pending.remove(pc)
            remote.breakpoint(pc, False)
            if pc == 0x103d5266:
                require(remote.get(regs, 'r4') == 1, 'First sample processing or standby write failed')
            elif pc == 0x103eeb7a:
                frame = remote.get(regs, 'sp')
                event = int.from_bytes(remote.read(frame + 16, 4), 'little')
                require(event in (0x42051200, 0x42051201), f'Unexpected direction event {event:#x}')
                direction = remote.get(regs, 'r0')
            elif pc == 0x103eea94:
                require(remote.get(regs, 'r0') == direction, 'Direction callback value differs')
            else:
                aggregate = int.from_bytes(remote.read(0xb1868170, 4), 'little')
                require(aggregate & 2, 'Direction callback did not contribute its aggregate bit')
        capability = int.from_bytes(remote.read(0xb1807f08, 4), 'little')
        require(capability == 1, 'First sample did not publish capability')
        print(f'PASS combined boot: records={pointers[0]:#x}/{pointers[1]:#x}, '
              f'axes={axes}, capability={capability}, event={event:#x}, '
              f'direction={direction}, aggregate={aggregate:#x}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--acceleration-sample', nargs=3, type=int, metavar=('X', 'Y', 'Z'),
                        default=(-23, 47, 1024))
    args = parser.parse_args()
    if any(not -2048 <= value <= 2047 for value in args.acceleration_sample):
        parser.error('--acceleration-sample requires each axis to be in -2048..2047')
    args.acceleration_sample = tuple(args.acceleration_sample)
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        config, calibration = bytearray(256), bytearray(192)
        for record, kind in ((config, 1), (calibration, 2)):
            record[:6] = b'ACCELE'
            record[16] = kind
        config[32], config[144], config[148] = 81, 0x2d, 2
        struct.pack_into('<3I', calibration, 56, 65536, 65536, 65536)
        args.acceleration_records = root / 'config', root / 'calibration'
        for path, record in zip(args.acceleration_records, (config, calibration)):
            path.write_bytes(record)
        args.update_store = root / 'store'
        args.realtime = args.wsl = False
        for option in LIVE_VIEW_OPTIONS:
            setattr(args, option, True)
        machine = BootProbe(args)
        try:
            machine._start()
        finally:
            machine.close()


if __name__ == '__main__':
    main()
