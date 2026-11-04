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

    def machine(self, running=True, broken_uv=False):
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
        registers = {0x20144204: 0x20002, 0x20144200: 4,
                     0x20144210: 0xb1000000, 0x20144240: 2,
                     0x20144220: 0xb1001000, 0x20144250: 2, 0x20146110: 0}
        machine._words = lambda address, count: [registers[address]]
        reads = []

        def read(address, length):
            reads.append((address, length))
            if address == 0xb1001000:
                if broken_uv:
                    raise ValueError('Read failed')
                return bytes([90, 240])
            return bytes([81] * 4)

        machine._bytes = read
        return machine, calls, reads

    def test_snapshot_reads_half_height_uv_and_caches_png(self):
        machine, calls, reads = self.machine()
        image = machine.lcd_png()
        self.assertEqual(calls, ['query-status', 'stop', 'cont'])
        self.assertEqual(reads, [(0xb1000000, 4), (0xb1001000, 2)])
        with Image.open(BytesIO(image)) as frame:
            self.assertEqual(frame.size, (2, 2))
            self.assertEqual(frame.tobytes(), bytes([255, 0, 0] * 4))
        self.assertEqual(machine.lcd_png(), image)
        self.assertEqual(calls, ['query-status', 'stop', 'cont'])

    def test_snapshot_preserves_pause_and_resumes_on_failure(self):
        machine, calls, _ = self.machine(running=False)
        machine.lcd_png()
        self.assertEqual(calls, ['query-status'])
        for running in (False, True):
            machine, calls, _ = self.machine(running, broken_uv=True)
            with self.assertRaisesRegex(ValueError, 'Read failed'):
                machine.lcd_png()
            self.assertEqual(calls, ['query-status', 'stop', 'cont'] if running else ['query-status'])


if __name__ == '__main__':
    unittest.main()
