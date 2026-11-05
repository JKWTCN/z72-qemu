# SPDX-License-Identifier: GPL-2.0-or-later
"""LCD observation must preserve a paused VM, including early returns/errors."""
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.body_shutter_gate_probe import lcd_snapshot


class Machine:
    def __init__(self, running, outcome):
        self.io = threading.Lock()
        self.qmp = self
        self.running = running
        self.outcome = outcome
        self.commands = []

    def command(self, name):
        self.commands.append(name)
        if name == 'query-status':
            return {'running': self.running}
        assert name in ('stop', 'cont')
        self.running = name == 'cont'

    def _words(self, address, count):
        assert not self.running
        if self.outcome == 'error':
            raise RuntimeError('Display read failed')
        if address == 0x20144204:
            return [0 if self.outcome == 'unconfigured' else 0x00020002]
        if address == 0x20144210:
            return [0xbd200000] + [0] * (count - 1)
        return [0] * count

    def _bytes(self, address, length):
        assert not self.running and address == 0xbd200000
        return bytes([16]) * length


class LCDSnapshotTests(unittest.TestCase):
    def test_execution_state_on_success_early_return_and_error(self):
        for running in (False, True):
            for outcome in ('configured', 'unconfigured', 'error'):
                with self.subTest(running=running, outcome=outcome):
                    machine = Machine(running, outcome)
                    if outcome == 'error':
                        with self.assertRaisesRegex(RuntimeError, 'Display read failed'):
                            lcd_snapshot(machine)
                    else:
                        result = lcd_snapshot(machine)
                        self.assertEqual(result['configured'], outcome == 'configured')
                    self.assertEqual(machine.running, running)
                    self.assertEqual(machine.commands.count('stop'), int(running))
                    self.assertEqual(machine.commands.count('cont'), int(running))


if __name__ == '__main__':
    unittest.main()
