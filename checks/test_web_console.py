# SPDX-License-Identifier: GPL-2.0-or-later
"""Firmware-free checks for browser input and frame transport."""
import http.client
import json
from pathlib import Path
import struct
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, call
import zlib
from http.server import ThreadingHTTPServer

from tools.web_console import Machine, make_handler, ppm_to_png
from checks.synthetic_master import build as build_master


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

    def test_update_endpoints_reach_the_machine(self):
        self.assertEqual(self.request('/update/install', {})[0], 200)
        self.machine.install_update.assert_called_once_with()
        self.assertEqual(self.request('/update/remove', {})[0], 200)
        self.machine.remove_update.assert_called_once_with()

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
                    0xb25d4824: [len(codes)], 0xb25d4714: codes,
                    0x10020020: [0x2e726556, 0x372e3130, 0x32302e30]}[address]

        machine._words = words
        try:
            self.assertTrue(machine.status()['menu_inhibited'])
            codes.clear()
            self.assertFalse(machine.status()['menu_inhibited'])
        finally:
            machine.process = machine.qmp = None
            machine.close()

    def test_menu_click_is_held_until_foreground_moves(self):
        machine = Machine(None)
        machine.shutdown.set()
        machine.watchdog.join()
        commands = []
        machine._ready = lambda: None
        machine._key_clock = lambda: (0, 1000)
        machine._qtest = commands.append
        machine.app_index = 3
        try:
            machine.set_key(9, 0)
            machine.set_key(9, 1)
            # The release request is deferred while the foreground is shooting.
            self.assertEqual(commands,
                             ['set_irq_in /machine/peripheral/keys pins 9 0'])
            self.assertIn(9, machine.held)
            self.assertFalse(machine.requested_keys)
            self.assertTrue(machine.menu_release_held)

            def words(address, count):
                return [1, 0, 0, 0, 1 if address == 0xb1811e40 else 3]

            machine._words = words
            machine.menu_poll_ticks = 5
            with machine.io:
                machine._menu_hold_step()
            self.assertEqual([line[-1] for line in commands], ['0', '1'])
            self.assertNotIn(9, machine.held)
            self.assertFalse(machine.menu_release_held)
            self.assertEqual(machine.app_index, 1)
        finally:
            machine.close()

    def test_auto_menu_presses_once_when_shooting_appears(self):
        machine = Machine(None)
        machine.shutdown.set()
        machine.watchdog.join()
        machine.auto_menu = True
        commands = []
        machine._ready = lambda: None
        machine._key_clock = lambda: (0, 1000)
        machine._qtest = commands.append
        try:
            self.assertTrue(machine.auto_menu)
            # Not yet ready: no press even on the polling tick.
            machine._words = lambda address, count: [0, 0, 0, 0, 3]
            machine.auto_menu_ticks = 5
            with machine.io:
                machine._auto_menu_step()
            self.assertEqual(commands, [])
            # Shooting ready: one press and a deferred release.
            machine._words = lambda address, count: [1, 0, 0, 0, 3]
            machine.auto_menu_ticks = 5
            with machine.io:
                machine._auto_menu_step()
            self.assertEqual(commands,
                             ['set_irq_in /machine/peripheral/keys pins 9 0'])
            self.assertTrue(machine.auto_menu_done)
            self.assertTrue(machine.menu_release_held)
            # A later step must not press again.
            with machine.io:
                machine._auto_menu_step()
            self.assertEqual(len(commands), 1)
        finally:
            machine.close()

    def test_auto_menu_can_be_disabled(self):
        machine = Machine(None)
        machine.shutdown.set()
        machine.watchdog.join()
        commands = []
        machine._ready = lambda: None
        machine._key_clock = lambda: (0, 1000)
        machine._qtest = commands.append
        try:
            self.assertFalse(machine.auto_menu)
            machine._words = lambda address, count: [1, 0, 0, 0, 3]
            machine.auto_menu_ticks = 5
            with machine.io:
                machine._auto_menu_step()
            self.assertEqual(commands, [])
        finally:
            machine.close()

    def test_menu_hold_expires_and_release_all_stops_it(self):
        machine = Machine(None)
        machine.shutdown.set()
        machine.watchdog.join()
        commands = []
        machine._ready = lambda: None
        clock = [0]
        machine._key_clock = lambda: (clock[0], 1000)
        machine._qtest = commands.append
        machine.app_index = 3
        try:
            machine.set_key(9, 0)
            machine.set_key(9, 1)
            machine.menu_deadline = time.monotonic() - 1
            machine.menu_poll_ticks = 5
            machine._words = lambda address, count: [1, 0, 0, 0, 3]
            with machine.io:
                machine._menu_hold_step()
            self.assertEqual([line[-1] for line in commands], ['0', '1'])
            self.assertFalse(machine.menu_release_held)

            clock[0] = 200
            machine.set_key(9, 0)
            machine.set_key(9, 1)
            self.assertTrue(machine.menu_release_held)
            machine.release()
            self.assertEqual([line[-1] for line in commands],
                             ['0', '1', '0', '1'])
            self.assertFalse(machine.menu_release_held)
            self.assertFalse(machine.held)
        finally:
            machine.close()

    def update_machine(self):
        """A running machine with a staged signed synthetic update."""
        import shutil
        from analyze.upgrade_signature import assemble_update
        from checks.test_upgrade_signature import table_master
        work = Path(tempfile.mkdtemp(prefix='web-console-update-'))
        self.addCleanup(shutil.rmtree, work, True)
        reference = table_master()
        member = build_master()
        key = bytes.fromhex('0f1e2d3c4b5a6978')
        (work / 'boot-key').write_bytes(key)
        candidate = work / 'candidate.bin'
        from checks.test_update_container import build_container
        payload = build_container([('eg1840_mas_01700', member),
                                   ('_tpj01_v140.bin', b'\0\0')])[0x20:]
        candidate.write_bytes(assemble_update(payload, key, reference))
        machine = Machine(types.SimpleNamespace(
            auto_menu=False, update_image=candidate, boot_key=work / 'boot-key',
            update_store=work / 'store',
            master=types.SimpleNamespace(read_bytes=lambda: reference)))
        self.addCleanup(machine.close)
        machine.shutdown.set()
        machine.watchdog.join()
        machine.phase = 'running'
        machine.process = Mock()
        machine.process.poll.return_value = None
        machine._ready = lambda: None
        machine.reflashes = []
        machine._machine_reflash = lambda image: machine.reflashes.append(image)
        return machine, work, member

    def test_update_installs_from_the_menu_foreground_only(self):
        machine, work, member = self.update_machine()
        machine._words = lambda address, count: [1, 0, 0, 0, 3]
        with self.assertRaisesRegex(ValueError, 'menu'):
                machine.install_update()
        self.assertFalse(machine.store.installed())
        machine._words = lambda address, count: [1, 0, 0, 0, 1]
        manifest = machine.install_update()
        self.assertEqual(machine.reflashes, [member])
        self.assertEqual(manifest['sha256'], machine.staged['sha256'])
        self.assertTrue(manifest['signature']['signed'])
        identity, image = machine.store.load()
        self.assertEqual(image, member)
        self.assertEqual(identity['sha256'], manifest['sha256'])

    def test_update_refuses_the_loaded_firmware(self):
        machine, work, member = self.update_machine()
        machine._words = lambda address, count: [1, 0, 0, 0, 1]
        machine.firmware = dict(machine.staged)
        with self.assertRaisesRegex(ValueError, 'already'):
                machine.install_update()
        self.assertFalse(machine.reflashes)

    def test_update_requires_a_staged_image_and_ready_machine(self):
        machine, work, member = self.update_machine()
        machine.update_image = None
        with self.assertRaisesRegex(ValueError, 'supplied'):
                machine.install_update()
        machine.update_image = work / 'candidate.bin'
        machine._ready = Machine._ready.__get__(machine)
        machine.phase = 'starting'
        with self.assertRaisesRegex(ValueError, '就绪|ready'):
                machine.install_update()

    def test_staged_update_is_signature_checked_at_staging(self):
        import shutil
        from analyze.upgrade_signature import assemble_update
        from checks.test_upgrade_signature import table_master
        work = Path(tempfile.mkdtemp(prefix='web-console-staged-'))
        self.addCleanup(shutil.rmtree, work, True)
        reference = table_master()
        key = bytes.fromhex('0f1e2d3c4b5a6978')
        (work / 'boot-key').write_bytes(key)
        from checks.test_update_container import build_container
        payload = build_container([('eg1840_mas_01700', build_master())])[0x20:]
        signed = assemble_update(payload, key, reference)
        tampered = bytearray(signed)
        tampered[-6] ^= 0x20
        for name, data, failed in (('good', signed, False), ('bad', bytes(tampered), True)):
            candidate = work / f'{name}.bin'
            candidate.write_bytes(data)
            machine = Machine(types.SimpleNamespace(
                auto_menu=False, update_image=candidate, boot_key=work / 'boot-key',
                update_store=work / 'store',
                master=types.SimpleNamespace(read_bytes=lambda: reference)))
            self.addCleanup(machine.close)
            machine.shutdown.set()
            machine.watchdog.join()
            if failed:
                self.assertIn('digest', machine.staged_error)
                self.assertIsNone(machine.staged)
            else:
                self.assertIsNone(machine.staged_error)
                self.assertTrue(machine.staged['signed'])
                self.assertEqual(machine.staged['format'], 'package')
                self.assertIn('digest', machine.staged)

    def test_bare_member_update_takes_the_standalone_path(self):
        machine, work, member = self.update_machine()
        bare = work / 'bare.bin'
        bare.write_bytes(build_master(extra=68))
        machine.update_image = bare
        machine.boot_key = None
        machine.refresh_staged()
        self.assertIsNone(machine.staged_error)
        self.assertFalse(machine.staged['signed'])
        self.assertEqual(machine.staged['format'], 'member')
        self.assertEqual(machine.staged['length'], len(bare.read_bytes()))
        machine._words = lambda address, count: [1, 0, 0, 0, 1]
        manifest = machine.install_update()
        self.assertFalse(manifest['signature']['signed'])
        self.assertEqual(manifest['signature']['format'], 'member')
        self.assertEqual(len(machine.reflashes), 1)

    def test_authenticated_package_still_requires_valid_member_crcs(self):
        from analyze.decode_z72 import crc
        from analyze.upgrade_signature import assemble_update
        from checks.test_update_container import build_container
        machine, work, member = self.update_machine()
        body = bytearray(build_container([('eg1840_mas_01700', member),
                                          ('_tpj01_v140.bin', b'\0\0')])[:-16])
        body[-1] ^= 1
        body += crc(body).to_bytes(2, 'big') + bytes(14)
        machine.update_image.write_bytes(assemble_update(
            body[0x20:], machine.boot_key, machine._reference_master()))
        machine.refresh_staged()
        self.assertIsNone(machine.staged)
        self.assertIn('member CRC', machine.staged_error)

    def test_whole_file_without_a_key_is_rejected_at_start(self):
        import shutil
        from analyze.upgrade_signature import assemble_update
        from checks.test_upgrade_signature import table_master
        work = Path(tempfile.mkdtemp(prefix='web-console-whole-'))
        self.addCleanup(shutil.rmtree, work, True)
        reference = table_master()
        whole = work / 'whole.bin'
        whole.write_bytes(assemble_update(build_master(), b'KEYBYTES', reference))
        with self.assertRaisesRegex(ValueError, 'boot-key'):
            Machine(types.SimpleNamespace(
                auto_menu=False, update_image=whole, boot_key=None,
                update_store=work / 'store',
                master=types.SimpleNamespace(read_bytes=lambda: reference)))

    def test_rollback_removes_the_store_and_reflashes_stock(self):
        import tools.web_console
        machine, work, member = self.update_machine()
        with self.assertRaisesRegex(ValueError, 'No installed'):
                machine.remove_update()
        machine.store.install(member)
        original = tools.web_console.analyze_eg
        try:
            tools.web_console.analyze_eg = lambda data, role: None
            machine.remove_update()
        finally:
            tools.web_console.analyze_eg = original
        self.assertIsNone(machine.store.installed())
        self.assertEqual(len(machine.reflashes), 1)
        self.assertEqual(machine.firmware['source'], 'stock')

    def test_select_master_prefers_the_verified_store(self):
        machine, work, member = self.update_machine()
        image = build_master(extra=68)
        machine.store.install(image, note='rebuild')
        self.assertEqual(machine._select_master(), image)
        self.assertEqual(machine.firmware['source'], 'installed')
        self.assertEqual(machine.firmware['sha256'],
                             __import__('hashlib').sha256(image).hexdigest())
        self.assertIsNone(machine.firmware['store_error'])

    def test_select_master_falls_back_to_stock_when_the_store_is_broken(self):
        machine, work, member = self.update_machine()
        machine.store.install(build_master())
        manifest = json.loads(machine.store.manifest_path.read_text(encoding='utf-8'))
        manifest['sha256'] = '0' * 64
        machine.store.manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        stock = build_master()
        machine.args.master = types.SimpleNamespace(read_bytes=lambda: stock)
        original = __import__('tools.web_console', fromlist=['analyze_eg']).analyze_eg
        try:
            import tools.web_console
            tools.web_console.analyze_eg = lambda data, role: None
            self.assertEqual(machine._select_master(), stock)
            self.assertEqual(machine.firmware['source'], 'stock')
            self.assertIn('manifest', machine.firmware['store_error'])
        finally:
            tools.web_console.analyze_eg = original
            machine.close()

    def test_status_reports_update_state_and_menu_readiness(self):
        machine, work, member = self.update_machine()
        machine.qmp = Mock()
        machine.qmp.command.side_effect = lambda name, *args: (
            {'status': 'running'} if name == 'query-status' else 1)

        def words(address, count):
            if address == 0xb1811e40:
                return [1, 0, 0, 0, 1]
            if address == 0x10020020:
                return [0x2e726556, 0x372e3130, 0x32302e30]
            return [0, 0]

        machine._words = words
        machine.firmware = dict(source='stock', sha256='a' * 64, version='Ver.01.70.02')
        state = machine.status()
        self.assertEqual(state['firmware']['source'], 'stock')
        self.assertEqual(state['staged']['version'], 'Ver.01.70.02')
        self.assertIsNone(state['staged']['error'])
        self.assertTrue(state['update_ready'])
        self.assertFalse(state['update_installed'])
        self.assertEqual(state['booted_version'], 'Ver.01.70.02')

        def shooting(address, count):
            if address == 0xb1811e40:
                return [1, 0, 0, 0, 3]
            if address == 0x10020020:
                return [0x2e726556, 0x372e3130, 0x32302e30]
            return [0, 0]

        machine._words = shooting
        self.assertFalse(machine.status()['update_ready'])


if __name__ == '__main__':
    unittest.main()
