# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the C1.70 eye proximity getter with measurement enabled by original startup."""
import argparse
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from tools.smp_boot_probe import reach
from tools.web_console import EYE_STATE_C170, LIVE_VIEW_OPTIONS, Machine


class BootProbe(Machine):
    def _boot_dance(self):
        remote = self.remote
        remote.sock.settimeout(90)

        def transfer(regs):
            descriptor = remote.get(regs, 'r1')
            mode, address, tx, rx, size, count = struct.unpack('<BxH4I', remote.read(descriptor, 20))
            require((mode, address) == (1, 0x38), 'Unexpected eye sensor bus descriptor')
            return remote.read(tx, size), rx, count

        _, regs = reach(remote, 0x10400264)
        config = remote.get(regs, 'r1')
        require(remote.read(config + 0x40, 4) == b'\x41\0\0\0', 'Eye configuration missing')
        for expected in ('4000', '41000000', '4a0000000000', '530000', '4100', '4141', '4300'):
            _, regs = reach(remote, 0x103ffb88)
            payload, _, count = transfer(regs)
            require(payload == bytes.fromhex(expected) and count == 0,
                    f'Unexpected boot write {payload.hex()}')
            _, regs = reach(remote, 0x103ffb8c)
            require(remote.get(regs, 'r0') == 0, 'Boot write failed')

        def check_event(level):
            _, regs = reach(remote, 0x103c488e)
            require(remote.get(regs, 'r0') == 0x43190001 and remote.get(regs, 'r1') == 1 - level,
                    f'Unexpected upper eye notification for GPIO level {level}')
            _, regs = reach(remote, 0x10350ef4)
            require(remote.get(regs, 'r0') == 1 - level, 'Eye subscriber received the wrong level')
            _, regs = reach(remote, 0x102c9b22)
            require(remote.get(regs, 'r0') == 0x40000116, 'Unexpected eye state property')
            _, regs = reach(remote, 0x102c9b38)
            address = remote.get(regs, 'r0')
            reach(remote, 0x103c48b4)
            require(remote.read(address, 4) == struct.pack('<I', 1 - level),
                    'Firmware did not store the detected eye state')
            require(address == EYE_STATE_C170, 'Console eye state address differs from the firmware')

        check_event(1)
        reach(remote, 0x103ffc92)
        for level in (0, 1):
            self._drive_eye(level == 0)
            check_event(level)
        # Step out of the last callback before borrowing its caller's stack.
        _, regs = reach(remote, 0x103ffcfa)
        resume = remote.get(regs, 'pc')
        # Reserve scratch space below the current frame for the original reader.
        frame = (remote.get(regs, 'sp') - 32) & ~7
        remote.set(sp=frame)

        def check_sample(expected):
            output = frame + 20
            remote.write(output, b'\xa5' * 4)
            remote.set(pc=0x103ffe40, r0=output, lr=resume | 1)
            _, regs = reach(remote, 0x103ffe86)
            selector, rx, count = transfer(regs)
            require(selector == b'\x44' and count == 2, 'Unexpected proximity read')
            _, regs = reach(remote, 0x103ffe8a)
            require(remote.get(regs, 'r0') == 0 and remote.read(rx, 2) == struct.pack('<H', expected),
                    'Unexpected bus result')
            _, regs = reach(remote, resume)
            require(remote.get(regs, 'r0') == 0 and remote.read(output, 4) == struct.pack('<I', expected),
                    'Unexpected original getter result')

        remote.set(pc=0x103dc538, r0=30, lr=resume | 1)
        reach(remote, resume)
        check_sample(self.args.eye_proximity)
        print(f'PASS firmware-enabled proximity getter: GPIO notifications=0/1/0, sample={self.args.eye_proximity:#x}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    args.eye_proximity = 0xabc
    with tempfile.TemporaryDirectory() as folder:
        args.update_store = Path(folder)
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
