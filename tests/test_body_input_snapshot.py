# SPDX-License-Identifier: GPL-2.0-or-later
"""Keep completed input counters observable after live register reconfiguration."""
from pathlib import Path
import struct
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from tools.body_shutter_gate_probe import input_dma_snapshot


class Machine:
    def __init__(self, layout, peer=0x90000000):
        self.io = threading.RLock()
        self.config_names = ['config']
        self.qmp = self
        self.layout = layout
        self.peer = peer
        self.reads, self.commands = [], []

    def command(self, operation, args=None):
        self.commands.append(operation)
        if operation != 'qom-get':
            return {}
        return {'master-role': True, 'input-dma-count': 1,
                'input-dma-address': 0x51000000, 'primary-input-dma-count': 2,
                'primary-input-dma-address': 0x52000000,
                'preview-scene-aperture': 192, 'preview-scene-factor-q16': 32768,
                'primary-scene-aperture': 576, 'primary-scene-factor-q16': 8192,
                'primary-input-second-dma-address': self.peer}.get(args['property'], 0)

    def _words(self, address, count):
        require((address, count) == (0x20069a08, 1), 'Unexpected preview stride read')
        return [8]

    def _bytes(self, address, length, cpu=0):
        if address in (0x20069808, 0x20069908):
            require(length == 4, 'Unexpected current stride read width')
            return struct.pack('<I', self.layout[address == 0x20069908])
        self.reads.append((address, length, cpu))
        return b'\xa5' * length


def check():
    for layout, peer, supported in (((0, 0), 0x90000000, False), ((4224, 14512), 0x90000000, False),
            ((4224, 12432), 0x90000000, True), ((4928, 14512), 0x90000000, True),
            ((12432, 12432), 0, True), ((14512, 0), 0, True), ((4224, 12432), 0, False)):
        machine = Machine(layout, peer)
        result = input_dma_snapshot(machine)
        require(result['primary_frames'] == 2 and result['first_row']['bytes'] == 8,
                'Reconfiguration lost counters or independent preview observation')
        require(result['preview_scene'] == dict(aperture=192, factor_q16=32768) and
                result['primary_scene'] == dict(aperture=576, factor_q16=8192),
                'Reconfiguration lost completed-frame scene observations')
        require(result['primary_current_row_strides'] == dict(first=layout[0], full=layout[1]),
                'Current row layout was not preserved')
        require(len(result['primary_samples']) == ((2 if peer else 1) if supported else 0),
                'Unknown row layout sampled retained addresses')
        require(('primary_samples_unavailable' in result) != supported,
                'Unknown layout lacks an explicit observation limit')
        expected = [(0x52000000, layout[0], 0)] if supported else []
        if supported and peer:
            expected.append((peer, 5472 * layout[0] // 2816, 2))
        require(machine.reads == expected + [(0x51000000, 8, 0)], 'Wrong owner or sample extent')
        require(machine.commands[0] == 'stop' and machine.commands[-1] == 'cont',
                'Snapshot did not restore execution')
    print('PASS: input snapshot preserves counters and skips unsupported current row layouts')


if __name__ == '__main__':
    check()
