# SPDX-License-Identifier: GPL-2.0-or-later
"""Check color, plane layout and coherent browser LCD snapshots."""
from io import BytesIO
from pathlib import Path
import random
import sys
import threading
import unittest

from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lcd_preview import lcd_rgb
from tools.web_console import Machine


class LCDTests(unittest.TestCase):
    def test_nv16_row_strides_and_uv_order(self):
        rgb = lcd_rgb(2, 2, 0, (bytes([81, 81, 250, 41, 41, 250]), 3),
                      (bytes([90, 240, 250, 250, 240, 110, 250, 250]), 4))
        self.assertEqual(rgb, bytes([255, 0, 0] * 2 + [0, 0, 255] * 2))

    def test_nv12_shares_chroma_between_rows(self):
        self.assertEqual(lcd_rgb(2, 2, 4, (bytes([81] * 4), 2),
                                 (bytes([90, 240, 255]), 3)),
                         bytes([255, 0, 0] * 4))

    def test_overlay_yyuv_and_per_pixel_alpha(self):
        rgb = lcd_rgb(4, 1, 0, (bytes([41] * 4), 4),
                      (bytes([240, 110] * 2), 4),
                      (bytes([81, 81, 90, 240] * 2 + [250, 250]), 10),
                      (bytes([0, 255, 128, 64, 250]), 5))
        self.assertEqual(rgb, bytes([0, 0, 255, 255, 0, 0, 128, 0, 127, 64, 0, 191]))

    def test_independent_float_color_reference(self):
        rng = random.Random(72)
        for _ in range(1000):
            y0, y1, u, v = (rng.randrange(256) for _ in range(4))
            actual = lcd_rgb(2, 1, 0, (bytes([y0, y1]), 2), (bytes([u, v]), 2))
            for at, y in enumerate([y0, y1]):
                luma = max(0, y - 16) * 255 / 219
                expected = [luma + 1.596027 * (v - 128),
                            luma - .391762 * (u - 128) - .812968 * (v - 128),
                            luma + 2.017232 * (u - 128)]
                expected = [max(0, min(255, int(x + .5))) for x in expected]
                self.assertLessEqual(max(abs(a - b) for a, b in
                                         zip(actual[at * 3:at * 3 + 3], expected)), 1)

    def test_packed_alpha_order_levels_and_row_padding(self):
        rgb = lcd_rgb(4, 2, 0, (bytes([41] * 8), 4),
                      (bytes([240, 110] * 4), 4),
                      (bytes([81, 81, 90, 240] * 4), 8),
                      (bytes([0xf0, 0x48, 0xaa, 0x0f, 0x84, 0xbb]), 3), alpha_bits=4)
        self.assertEqual(rgb, bytes([0, 0, 255, 255, 0, 0, 136, 0, 119, 68, 0, 187,
                                     255, 0, 0, 0, 0, 255, 68, 0, 187, 136, 0, 119]))

    def test_invalid_alpha_depth_stride_and_length(self):
        for depth, alpha in ((2, (bytes(2), 2)), (4, (bytes(1), 1)), (4, (bytes(1), 2))):
            with self.subTest(depth=depth, alpha=alpha):
                with self.assertRaises(ValueError):
                    lcd_rgb(4, 1, 0, (bytes(4), 4), (bytes(4), 4),
                            (bytes(8), 8), alpha, alpha_bits=depth)

    def test_neutral_endpoints_and_invalid_planes(self):
        self.assertEqual(lcd_rgb(2, 1, 0, (bytes([16, 235]), 2),
                                 (bytes([128, 128]), 2)), bytes([0, 0, 0, 255, 255, 255]))
        for arguments in [
            (1, 1, 0, (b'\0', 1), (b'\0\0', 2)),
            (2, 1, 4, (b'\0\0', 2), (b'\0\0', 2)),
            (2, 1, 6, (b'\0\0', 2), (b'\0\0', 2)),
            (2, 2, 0, (b'\0' * 4, 2), (b'\0\0', 2)),
            (2, 1, 0, (b'\0', 1), (b'\0\0', 2)),
            (2, 1, 0, (b'\0\0', 2), (b'\0\0', 2), (b'\0' * 4, 4)),
        ]:
            with self.assertRaises(ValueError):
                lcd_rgb(*arguments)

    def machine(self, running=True, broken_uv=False, active_slot=0, overlay_slot=None,
                overlay_format=6, origin=0, scaler=(0, 0, 0)):
        machine = Machine.__new__(Machine)
        machine.io = threading.Lock()
        machine.lcd_cache = (0, b'')
        machine.lcd_interval = 2
        machine._ready = lambda: None
        calls = []

        class Monitor:
            def command(self, name):
                calls.append(name)
                return dict(status='running' if running else 'paused')

        machine.qmp = Monitor()
        registers = {0x20145100: 3, 0x20144204: 0x20002, 0x20144200: 4,
                     0x20144600: 0, 0x20144400: 0, 0x20144404: 0x101, 0x20144408: 0x101,
                     0x20144240: 2, 0x20144250: 2, 0x20146110: 0,
                     0x20144260: active_slot << 16 | ((active_slot + 1) % 4) << 8}
        for slot in range(4):
            registers[0x20144210 + slot * 4] = 0xb1000000 + slot * 0x2000
            registers[0x20144220 + slot * 4] = 0xb1001000 + slot * 0x2000
        if overlay_slot is not None:
            registers.update({0x20146110: 1, 0x20146200: overlay_format, 0x20146400: 0x20002,
                              0x20146204: 0x20002, 0x20146208: origin,
                              0x20146810: scaler[0], 0x20146814: scaler[1], 0x20146818: scaler[2],
                              0x20146214: overlay_slot << 16 | ((overlay_slot + 1) % 4) << 8,
                              0x20146500: 4, 0x20146540: 1 if overlay_format == 5 else 2,
                              0x201464c0: 0xb2100000})
            for slot in range(4):
                registers[0x20146440 + slot * 4] = 0xb2000000 + slot * 0x1000
        registers.update({0x20145328: 3, 0x2014532c: 4})
        machine._words = lambda address, count: [registers[address + i * 4] for i in range(count)]
        reads = []

        def read(address, length):
            reads.append((address, length))
            if address == 0xb2100000:
                return bytes([0xf0, 0x0f]) if overlay_format == 5 else bytes([255, 0, 255, 0])
            if 0xb2000000 <= address < 0xb2004000:
                return bytes([145, 145, 54, 34] * 2)
            if address & 0x1000:
                if broken_uv:
                    raise ValueError('Read failed')
                return bytes([90, 240])
            return bytes([81] * 4)

        machine._bytes = read
        return machine, calls, reads

    def test_snapshot_uses_active_background_slot_not_requested_slot(self):
        for slot in range(4):
            with self.subTest(slot=slot):
                machine, _, reads = self.machine(active_slot=slot)
                image = machine.lcd_png()
                self.assertEqual(reads, [(0xb1000000 + slot * 0x2000, 4),
                                         (0xb1001000 + slot * 0x2000, 2)])
                with Image.open(BytesIO(image)) as frame:
                    self.assertEqual(frame.tobytes(), bytes([255, 0, 0] * 4))

    def test_output_layout_uses_separate_canvas_and_cache(self):
        machine, _, _ = self.machine()
        source = machine.lcd_png()
        png, headers = machine.lcd_frame(output_layout=True)
        self.assertEqual(headers['X-Output-Layout'], '1')
        with Image.open(BytesIO(png)) as frame:
            self.assertEqual(frame.size, (4, 3))
            self.assertEqual(frame.tobytes(), (bytes([255, 0, 0] * 2) + bytes(6)) * 2 + bytes(12))
        self.assertEqual(source, machine.lcd_png())

    def test_background_scale_and_origin_apply_before_overlay(self):
        rgb = lcd_rgb(2, 1, 0, (bytes([16, 235]), 2), (bytes([128, 128]), 2),
                      (bytes([81, 81, 90, 240]), 4), (bytes([255, 0]), 2),
                      background_origin=(1, 1), background_scale=(2, 1, 1, 1),
                      overlay_rect=(3, 1, 2, 1), canvas_size=(5, 2))
        self.assertEqual(rgb, bytes(24) + bytes([255, 0, 0, 255, 255, 255]))

    def test_snapshot_reads_half_height_uv_and_caches_png(self):
        machine, calls, reads = self.machine()
        image = machine.lcd_png()
        self.assertEqual(calls, ['query-status', 'stop', 'cont'])
        self.assertEqual(reads, [(0xb1000000, 4), (0xb1001000, 2)])
        with Image.open(BytesIO(image)) as frame:
            self.assertEqual(frame.size, (2, 2))
            self.assertEqual(frame.tobytes(), bytes([255, 0, 0] * 4))
        self.assertEqual(machine.lcd_png(), image)
        self.assertEqual(machine.lcd_frame(), (image, {
            'X-Display-Route': 3, 'X-Frame-Size': '2x2', 'X-Output-Size': '4x3'}))
        self.assertEqual(calls, ['query-status', 'stop', 'cont'])

    def test_overlay_color_slot_is_independent_with_layout_zero_alpha(self):
        for slot in range(4):
            with self.subTest(slot=slot):
                machine, _, reads = self.machine(active_slot=(slot + 1) % 4, overlay_slot=slot)
                image = machine.lcd_png()
                self.assertEqual(reads[-2:], [(0xb2000000 + slot * 0x1000, 8), (0xb2100000, 4)])
                with Image.open(BytesIO(image)) as frame:
                    self.assertEqual(frame.tobytes(), bytes([0, 255, 1, 255, 0, 0] * 2))

    def test_snapshot_preserves_pause_and_resumes_on_failure(self):
        machine, calls, _ = self.machine(running=False)
        machine.lcd_png()
        self.assertEqual(calls, ['query-status'])
        for running in (False, True):
            machine, calls, _ = self.machine(running, broken_uv=True)
            with self.assertRaisesRegex(ValueError, 'Read failed'):
                machine.lcd_png()
            self.assertEqual(calls, ['query-status', 'stop', 'cont'] if running else ['query-status'])

    def test_snapshot_packed_alpha_plane_size_and_pixels(self):
        machine, calls, reads = self.machine(overlay_slot=2, overlay_format=5)
        image = machine.lcd_png()
        self.assertEqual(reads[-1], (0xb2100000, 2))
        self.assertEqual(calls, ['query-status', 'stop', 'cont'])
        with Image.open(BytesIO(image)) as frame:
            self.assertEqual(frame.tobytes(), bytes([255, 0, 0, 0, 255, 1, 0, 255, 1, 255, 0, 0]))

    def test_positioned_scaled_overlay_clips_and_preserves_source_alpha(self):
        machine, _, _ = self.machine(overlay_slot=2, overlay_format=5, origin=0x1ffff,
                                     scaler=(1, 0x102, 0x101))
        with Image.open(BytesIO(machine.lcd_png())) as frame:
            self.assertEqual(list(frame.getdata()),
                             [(255, 0, 0), (255, 0, 0), (255, 0, 0), (0, 255, 1)])

    def test_invalid_enabled_scaler_resumes_machine(self):
        machine, calls, _ = self.machine(overlay_slot=0, scaler=(1, 2, 0x101))
        with self.assertRaisesRegex(ValueError, 'scale ratio'):
            machine.lcd_png()
        self.assertIn('cont', calls)

    def test_smaller_overlay_at_odd_origin_uses_its_own_y_and_chroma_pair(self):
        rgb = lcd_rgb(4, 1, 0, (bytes([16] * 4), 4), (bytes([128] * 4), 4),
                      (bytes([16, 235, 128, 128]), 4), (bytes([255, 255]), 2),
                      overlay_rect=(1, 0, 2, 1))
        self.assertEqual(rgb, bytes([0] * 6 + [255] * 3 + [0] * 3))


if __name__ == '__main__':
    unittest.main()
