# SPDX-License-Identifier: GPL-2.0-or-later
"""Check browser release contacts and queued clicks without booting firmware."""
from collections import deque
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.web_console import Machine, SHUTTER_HALF, SHUTTER_FULL, make_handler


class ShutterTests(unittest.TestCase):
    def setUp(self):
        self.machine = Machine.__new__(Machine)
        self.machine.held = set()
        self.machine.key_events = {}
        self.machine.next_key_ticks = {}
        self.machine.requested_keys = set()
        self.machine.gpio_names = [f'gpio{i}' for i in range(8)]
        self.commands = []
        self.machine._qtest = self.commands.append
        self.ticks = 0
        self.machine._key_clock = lambda: (self.ticks, 1000)

    def edge(self, pin, level):
        self.machine.key_events[pin] = deque([level])
        self.machine._advance_keys()
        self.ticks += 100

    def contacts(self):
        return [tuple(map(int, command.split()[-2:]))
                for command in self.commands[-2:]]

    def test_quick_full_click_preserves_both_edges(self):
        self.machine.key_events[SHUTTER_FULL] = deque([0, 1])
        self.machine._advance_keys()
        self.assertEqual(self.contacts(), [(1, 0), (13, 0)])
        self.ticks = 99
        self.machine._advance_keys()
        self.assertEqual(len(self.commands), 2)
        self.ticks = 100
        self.machine._advance_keys()
        self.assertEqual(self.contacts(), [(13, 1), (1, 1)])
        self.assertFalse(self.machine.held)

    def test_overlapping_half_and_full_controls(self):
        self.edge(SHUTTER_HALF, 0)
        self.edge(SHUTTER_FULL, 0)
        self.edge(SHUTTER_FULL, 1)
        self.assertEqual(self.contacts(), [(13, 1), (1, 0)])
        self.edge(SHUTTER_FULL, 0)
        self.edge(SHUTTER_HALF, 1)
        self.assertEqual(self.contacts(), [(13, 0), (1, 0)])
        self.edge(SHUTTER_FULL, 1)
        self.assertEqual(self.contacts(), [(13, 1), (1, 1)])

    def test_release_all_cancels_pending_press(self):
        self.edge(SHUTTER_FULL, 0)
        self.machine.key_events[SHUTTER_HALF] = deque([0])
        self.machine._release()
        self.assertEqual(self.contacts(), [(13, 1), (1, 1)])
        self.assertFalse(self.machine.held)
        self.assertFalse(self.machine.key_events)
        self.assertFalse(self.machine.next_key_ticks)

    def test_expander_input_still_uses_expander(self):
        self.edge(3, 0)
        self.assertEqual(self.commands, [
            'set_irq_in /machine/peripheral/keys pins 3 0'])

    def test_http_accepts_shutter_and_rejects_invalid_inputs(self):
        events = []
        self.machine.io = threading.Lock()
        self.machine._ready = lambda: None
        self.machine._set_key_locked = lambda pin, level: events.append((pin, level))
        server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.machine))
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for pin, level, status in ((24, 0, 200), (24, 1, 200),
                                       (25, 0, 200), (25, 1, 200),
                                       (26, 0, 400), (True, 0, 400),
                                       (25, True, 400), (25, 2, 400)):
                with self.subTest(pin=pin, level=level):
                    connection = HTTPConnection('127.0.0.1', server.server_port)
                    try:
                        connection.request('POST', '/key',
                                           json.dumps(dict(pin=pin, level=level)),
                                           {'Content-Type': 'application/json'})
                        response = connection.getresponse()
                        response.read()
                        self.assertEqual(response.status, status)
                    finally:
                        connection.close()
            self.assertEqual(events, [(24, 0), (24, 1), (25, 0), (25, 1)])
        finally:
            server.shutdown()
            worker.join(timeout=2)
            server.server_close()


if __name__ == '__main__':
    unittest.main()
