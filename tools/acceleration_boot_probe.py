# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify C1.70 acceleration resource delivery and the first sample on combined boot."""
import argparse
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from tools.smp_boot_probe import reach
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
        _, regs = reach(remote, 0x103d5266)
        require(remote.get(regs, 'r4') == 1, 'First sample processing or standby write failed')
        capability = int.from_bytes(remote.read(0xb1807f08, 4), 'little')
        require(capability == 1, 'First sample did not publish capability')
        print(f'PASS combined boot: records={pointers[0]:#x}/{pointers[1]:#x}, '
              f'axes={axes}, capability={capability}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
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
        args.acceleration_sample = (-23, 47, 1024)
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
