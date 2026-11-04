# SPDX-License-Identifier: GPL-2.0-or-later
"""Check maintained mode input and timed, bounded dial contacts."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.web_console import Machine, MODE_COUNTS, make_handler


class DialTests(unittest.TestCase):
    def setUp(self):
        self.machine = Machine(None)
        self.machine.shutdown.set()
        self.machine.watchdog.join()
        self.addCleanup(self.machine.close)
        self.machine._ready = lambda: None
        self.machine.gpio_names = [f'gpio{i}' for i in range(8)]
        self.machine.adc_name = 'adc'
        self.commands = []
        self.machine._qtest = self.commands.append
        self.ticks = 0
        self.machine._key_clock = lambda: (self.ticks, 1000)

    def test_both_directions_preserve_every_contact_phase(self):
        for direction, states in ((1, (2, 0, 1, 3)), (-1, (1, 0, 2, 3))):
            with self.subTest(direction=direction):
                self.machine.set_dial(0, direction)
                for state in states:
                    count = len(self.commands)
                    self.ticks += 49
                    self.machine._advance_dials()
                    self.assertEqual(len(self.commands), count)
                    self.ticks += 1
                    self.machine._advance_dials()
                    self.assertEqual(self.commands[-2:], [
                        f'set_irq_in /machine/unattached/gpio5 unnamed-gpio-in 11 {state >> 1}',
                        f'set_irq_in /machine/unattached/gpio5 unnamed-gpio-in 14 {state & 1}'])
                self.assertFalse(self.machine.dial_events[0])

    def test_dials_progress_independently_and_release_cancels(self):
        self.machine.set_dial(0, 1)
        self.machine.set_dial(1, -1)
        self.ticks = 50
        self.machine._advance_dials()
        self.assertEqual(self.commands[-2:], [
            'set_irq_in /machine/unattached/gpio4 unnamed-gpio-in 7 0',
            'set_irq_in /machine/unattached/gpio4 unnamed-gpio-in 13 1'])
        self.machine._release()
        self.assertFalse(any(self.machine.dial_events))
        count = len(self.commands)
        self.ticks += 1000
        self.machine._advance_dials()
        self.assertEqual(len(self.commands), count)
        self.assertTrue(all(command.endswith(' 1') for command in self.commands[-4:]))

    def test_full_queue_rejects_without_changing_admitted_input(self):
        for _ in range(8):
            self.machine.set_dial(0, 1)
        events = list(self.machine.dial_events[0])
        deadline = self.machine.next_dial_ticks[0]
        with self.assertRaisesRegex(ValueError, 'full'):
            self.machine.set_dial(0, -1)
        self.assertEqual(list(self.machine.dial_events[0]), events)
        self.assertEqual(self.machine.next_dial_ticks[0], deadline)
        self.assertFalse(self.commands)

    def test_mode_changes_only_the_analog_input_and_survives_release(self):
        for position, count in enumerate(MODE_COUNTS):
            self.machine.set_mode(position)
            self.assertEqual(self.commands[-1],
                             f'set_irq_in /machine/unattached/adc channel-in 2 {count}')
        self.machine._release()
        self.assertEqual(self.machine.mode_position, 7)
        self.assertEqual(len(self.commands), len(MODE_COUNTS))

    def test_http_validates_inputs_before_delivery(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.machine))
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            cases = [('/mode', {'position': 3}, 200),
                     ('/dial', {'index': 1, 'step': -1}, 200)]
            cases += [('/mode', {'position': value}, 400)
                      for value in (-1, 8, True, '3', None)]
            cases += [('/dial', {'index': index, 'step': step}, 400)
                      for index, step in ((-1, 1), (2, 1), (True, 1), (0, True),
                                          (0, 0), (0, 2), (0, None))]
            for path, body, expected in cases:
                with self.subTest(path=path, body=body):
                    connection = HTTPConnection('127.0.0.1', server.server_port)
                    try:
                        connection.request('POST', path, json.dumps(body),
                                           {'Content-Type': 'application/json'})
                        response = connection.getresponse()
                        response.read()
                        self.assertEqual(response.status, expected)
                    finally:
                        connection.close()
            self.assertEqual(len(self.commands), 1)
            self.assertEqual(self.machine.mode_position, 3)
            self.assertFalse(self.machine.dial_events[0])
            self.assertEqual(len(self.machine.dial_events[1]), 4)
        finally:
            server.shutdown()
            worker.join(timeout=2)
            server.server_close()


if __name__ == '__main__':
    unittest.main()
