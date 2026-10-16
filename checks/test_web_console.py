# SPDX-License-Identifier: GPL-2.0-or-later
"""Firmware-free checks for browser input and frame transport."""
import http.client
import json
import struct
import threading
import unittest
from unittest.mock import Mock, call
import zlib
from http.server import ThreadingHTTPServer

from tools.web_console import Machine, make_handler, ppm_to_png


class WebConsoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.machine = Mock()
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(cls.machine))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.machine.reset_mock()

    def request(self, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            connection.request('GET' if body is None else 'POST', path,
                               None if body is None else json.dumps(body),
                               headers=headers or {'Content-Type': 'application/json'})
            response = connection.getresponse()
            return response.status, response.read(), response.getheader('Content-Type')
        finally:
            connection.close()

    def test_page_and_assets(self):
        for path, kind in (('/', 'text/html'), ('/console.js', 'text/javascript'),
                           ('/style.css', 'text/css')):
            code, body, content_type = self.request(path)
            self.assertEqual(code, 200)
            self.assertTrue(body)
            self.assertTrue(content_type.startswith(kind))
        self.assertEqual(self.request('/../tools/web_console.py')[0], 404)

    def test_press_release_and_release_all(self):
        for level in (0, 1):
            self.assertEqual(self.request('/key', dict(pin=9, level=level))[0], 200)
        self.assertEqual(self.machine.set_key.call_args_list, [call(9, 0), call(9, 1)])
        self.assertEqual(self.request('/release', {})[0], 200)
        self.machine.release.assert_called_once()

    def test_invalid_input_never_reaches_machine(self):
        for body in (dict(pin=-1, level=0), dict(pin=24, level=0),
                     dict(pin=9, level=2), dict(pin=True, level=0),
                     dict(pin=9, level=False), dict(pin='9', level=0), [], {}):
            self.assertEqual(self.request('/key', body)[0], 400)
        self.machine.set_key.assert_not_called()

    def test_cross_origin_input_rejected(self):
        code, _, _ = self.request('/key', dict(pin=9, level=0),
                                 {'Content-Type': 'application/json', 'Origin': 'https://example.com'})
        self.assertEqual(code, 403)
        self.machine.set_key.assert_not_called()

    def test_restart_conflict(self):
        self.machine.restart.return_value = False
        self.assertEqual(self.request('/restart', {})[0], 409)

    def test_status_error_is_visible(self):
        self.machine.status.side_effect = RuntimeError('monitor disconnected')
        try:
            code, body, _ = self.request('/status')
            self.assertEqual(code, 503)
            self.assertEqual(json.loads(body)['error'], 'monitor disconnected')
        finally:
            self.machine.status.side_effect = None

    def test_png_preserves_rows(self):
        pixels = bytes(range(12))
        png = ppm_to_png(b'P6\n2 2\n255\n' + pixels)
        self.assertEqual(png[:8], b'\x89PNG\r\n\x1a\n')
        offset, rows = 8, b''
        while offset < len(png):
            length = struct.unpack_from('>I', png, offset)[0]
            kind = png[offset + 4:offset + 8]
            payload = png[offset + 8:offset + 8 + length]
            self.assertEqual(struct.unpack_from('>I', png, offset + 8 + length)[0],
                             zlib.crc32(kind + payload))
            if kind == b'IDAT':
                rows += payload
            offset += length + 12
        self.assertEqual(zlib.decompress(rows), b'\0' + pixels[:6] + b'\0' + pixels[6:])
        for bad in (b'P6\n2 2\n255\n', b'P3\n2 2\n255\n' + pixels):
            with self.assertRaises(ValueError):
                ppm_to_png(bad)

    def test_disconnect_releases_held_inputs(self):
        machine = Machine(None)
        released = threading.Event()
        try:
            machine.phase = 'running'
            machine.held = {3, 9}
            machine.requested_keys = {3, 9}
            machine.key_deadline = 0
            commands = []

            def command(line):
                commands.append(line)
                if len(commands) == 2:
                    released.set()

            machine._qtest = command
            self.assertTrue(released.wait(2), 'Disconnected inputs stayed held')
            self.assertEqual(set(commands), {
                'set_irq_in /machine/peripheral/keys pins 3 1',
                'set_irq_in /machine/peripheral/keys pins 9 1'})
            with machine.io:
                self.assertFalse(machine.held)
        finally:
            machine.close()

    def test_short_taps_preserve_both_edges_and_release_gap(self):
        machine = Machine(None)
        machine.shutdown.set()
        machine.watchdog.join()
        ticks = [0]
        commands = []
        machine._ready = lambda: None
        machine._key_clock = lambda: (ticks[0], 1000)
        machine._qtest = commands.append
        try:
            for level in (0, 1, 0, 1):
                machine.set_key(9, level)
            self.assertEqual(commands, ['set_irq_in /machine/peripheral/keys pins 9 0'])
            for value in (99, 100, 199, 200, 299, 300):
                ticks[0] = value
                with machine.io:
                    machine._advance_keys()
                self.assertEqual(len(commands), min(4, value // 100 + 1))
            self.assertEqual([line[-1] for line in commands], ['0', '1', '0', '1'])
            self.assertFalse(machine.held)
            self.assertFalse(machine.key_events)
        finally:
            machine.close()

    def test_release_cancels_pending_tap(self):
        machine = Machine(None)
        machine.shutdown.set()
        machine.watchdog.join()
        commands = []
        machine._ready = lambda: None
        machine._key_clock = lambda: (0, 1000)
        machine._qtest = commands.append
        try:
            machine.set_key(9, 0)
            machine.set_key(9, 1)
            machine.release()
            self.assertEqual([line[-1] for line in commands], ['0', '1'])
            self.assertFalse(machine.held)
            self.assertFalse(machine.key_events)
            self.assertFalse(machine.requested_keys)
        finally:
            machine.close()

    def test_overlapping_restarts_are_rejected(self):
        machine = Machine(None)
        entered, finish = threading.Event(), threading.Event()

        def start():
            entered.set()
            finish.wait(2)

        machine._start = start
        try:
            self.assertTrue(machine.restart())
            self.assertTrue(entered.wait(1))
            self.assertFalse(machine.restart())
        finally:
            finish.set()
            machine.close()

    def test_native_menu_inhibition_is_reported(self):
        machine = Machine(None)
        machine.shutdown.set()
        machine.watchdog.join()
        machine.phase = 'running'
        machine.process = Mock()
        machine.process.poll.return_value = None
        machine.qmp = Mock()
        machine.qmp.command.side_effect = lambda name, *args: (
            {'status': 'running'} if name == 'query-status' else
            0 if args[0]['property'] in ('failed-requests', 'unsupported-commands') else 1)
        codes = [0x3f]

        def words(address, count):
            return {0xb1811e40: [1, 0, 0, 0, 3], 0xb187556c: [0x118, 0xb25d4714],
                    0xb25d4824: [len(codes)], 0xb25d4714: codes}[address]

        machine._words = words
        try:
            self.assertTrue(machine.status()['menu_inhibited'])
            codes.clear()
            self.assertFalse(machine.status()['menu_inhibited'])
        finally:
            machine.process = machine.qmp = None
            machine.close()


if __name__ == '__main__':
    unittest.main()
