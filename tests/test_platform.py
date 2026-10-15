# SPDX-License-Identifier: GPL-2.0-or-later
"""Firmware-free checks of memory translations and upstream integration."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.qemu_display import table_for
from analyze.decode_z72 import validate_master, MASTER_SIZE
from qemu.prepare_source import prepare

class Platform(unittest.TestCase):
    def fixture(self):
        stock = bytearray(0x14000)
        for index in range(4096):
            struct.pack_into('<I', stock, 0x10000 + index * 4, (index << 20) | 0xC426)
        return stock

    def test_translations_preserve_attributes(self):
        for backend, regions in (
            ('virt', ((0x100,0x140,0x420),(0xB18,0xB19,0x460),
                      (0xB20,0xB2C,0x480),(0xB2C,0xB5F,0x492))),
            ('nikon-z72-lab', ((0x100,0x140,0x100),(0xB18,0xB19,0xB18),
                               (0xB20,0xB2C,0xB20),(0xB2C,0xB5F,0xB2C))),
        ):
            words = struct.unpack('<4096I', table_for(self.fixture(), backend=backend))
            for first, last, physical in regions:
                for index in range(first, last):
                    self.assertEqual(words[index], ((physical+index-first)<<20) | 0xC426)
            self.assertEqual(words[0x401], 0x40100C02)
            self.assertEqual(words[0x500], 0)

    def test_xn_changes_only_append_section(self):
        for backend in ('virt','nikon-z72-lab'):
            plain = struct.unpack('<4096I', table_for(self.fixture(), backend=backend))
            xn = struct.unpack('<4096I', table_for(self.fixture(), True, backend))
            self.assertEqual([i for i in range(4096) if plain[i] != xn[i]], [0x124])
            self.assertEqual(xn[0x124] ^ plain[0x124], 16)

    def test_nonsection_rejected(self):
        stock = self.fixture()
        struct.pack_into('<I', stock, 0x10400, 0)
        with self.assertRaisesRegex(ValueError, 'section'):
            table_for(stock)

    def test_wrong_same_size_firmware_rejected(self):
        with self.assertRaisesRegex(ValueError, 'stock'):
            validate_master(bytes(MASTER_SIZE))

    def test_overlay_idempotent_and_version_guarded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in ('hw/arm/meson.build','hw/arm/Kconfig','configs/devices/arm-softmmu/default.mak'):
                path = root / name
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text('# upstream\n')
            (root/'VERSION').write_text('10.2.4\n')
            (root/'hw/arm/Kconfig').write_text('# upstream\n\nconfig NIKON_Z72_LAB\n'
                '    bool\n    depends on TCG && ARM\n    select GENERIC_LOADER\n')
            prepare(root)
            config = (root/'hw/arm/Kconfig').read_text()
            self.assertEqual(config.count('config NIKON_Z72_LAB'), 1)
            self.assertIn('    select ARM_GIC\n', config)
            self.assertEqual(config.count('    select ARM_V7M\n'), 1)
            self.assertEqual(config.count('    select STM32F2XX_TIMER\n'), 1)
            self.assertEqual(config.count('    select OR_IRQ\n'), 1)
            self.assertEqual(config.count('    select I2C\n'), 1)
            self.assertEqual(config.count('    select SSI\n'), 1)
            self.assertEqual(config.count('    select STM32F2XX_USART\n'), 1)
            self.assertEqual((root/'hw/arm/meson.build').read_text().count("files('nikon-z72-counter.c')"), 1)
            self.assertEqual((root/'hw/arm/nikon-z72-counter.c').read_bytes(),
                             (ROOT/'qemu/nikon-z72-counter.c').read_bytes())
            before = {p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            prepare(root)
            after = {p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(before, after)
            (root/'VERSION').write_text('10.0.0')
            with self.assertRaisesRegex(ValueError, '10.2.4'):
                prepare(root)

    def test_upgrade_existing_controller_dependencies(self):
        for suffix in ('    select ARM_GIC\n',
                       '    select ARM_GIC\n    select ARM_V7M\n',
                       '    select ARM_GIC\n    select ARM_V7M\n    select STM32F2XX_TIMER\n'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                for name in ('hw/arm/meson.build', 'hw/arm/Kconfig',
                             'configs/devices/arm-softmmu/default.mak'):
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('# upstream\n')
                (root/'VERSION').write_text('10.2.4\n')
                config = root/'hw/arm/Kconfig'
                config.write_text('\nconfig NIKON_Z72_LAB\n    bool\n'
                    '    depends on TCG && ARM\n    select GENERIC_LOADER\n' + suffix)
                prepare(root)
                before = config.read_text()
                for dependency in ('ARM_GIC', 'ARM_V7M', 'STM32F2XX_TIMER', 'OR_IRQ', 'I2C', 'SSI', 'STM32F2XX_USART'):
                    self.assertEqual(before.count('    select ' + dependency + '\n'), 1)
                prepare(root)
                self.assertEqual(config.read_text(), before)

if __name__ == '__main__':
    unittest.main()
