# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe lens state without changing the VM's original execution state."""
from pathlib import Path
import struct
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.body_shutter_gate_probe import lens_snapshot


class Machine:
    def __init__(self, running, fail=False):
        self.io = threading.Lock()
        self.qmp = self
        self.running = running
        self.fail = fail
        self.commands = []
        self.reads = []

    def command(self, name, arguments=None):
        self.commands.append(name)
        if name == 'query-status':
            return {'running': self.running}
        if name in ('stop', 'cont'):
            self.running = name == 'cont'
            return {}
        assert name == 'qom-get' and arguments['path'] == '/machine/master-lens'
        assert not self.running
        if self.fail:
            raise RuntimeError('Device observation failed')
        return 0

    def _bytes(self, address, length):
        assert not self.running
        self.reads.append((address, length))
        if address == 0xb23ed5bc:
            assert length == 1
            return b'\2'
        assert length == 8
        if address == 0xb23ed5c4:
            # Padding is not part of the signed denominator.
            return struct.pack('<hHi', 192, 0xabcd, 640)
        assert address == 0xb1868448
        return struct.pack('<hHi', -1, 0x1234, -192)


class LensSnapshotTests(unittest.TestCase):
    def test_rationals_and_execution_state(self):
        for running in (False, True):
            with self.subTest(running=running):
                machine = Machine(running)
                result = lens_snapshot(machine)
                self.assertEqual(machine.running, running)
                self.assertEqual(machine.commands.count('stop'), int(running))
                self.assertEqual(machine.commands.count('cont'), int(running))
                self.assertEqual(result['policy_state'], 2)
                self.assertEqual(result['policy_target'], dict(numerator=640, denominator=192))
                self.assertEqual(result['last_submitted_target'], dict(numerator=-192, denominator=-1))
                self.assertEqual(machine.reads, [(0xb23ed5bc, 1), (0xb23ed5c4, 8), (0xb1868448, 8)])

    def test_failure_restores_only_a_vm_that_was_running(self):
        for running in (False, True):
            with self.subTest(running=running):
                machine = Machine(running, fail=True)
                with self.assertRaisesRegex(RuntimeError, 'Device observation failed'):
                    lens_snapshot(machine)
                self.assertEqual(machine.running, running)
                self.assertEqual(machine.commands.count('cont'), int(running))


if __name__ == '__main__':
    unittest.main()
