# SPDX-License-Identifier: GPL-2.0-or-later
"""Firmware-free bounds and role-isolation checks for initialization analysis."""
from pathlib import Path
import re
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE
from analyze.firmware_structure import (PROFILES, branch_target, communication_header,
                                        communication_stores, boot_prefix, literal,
                                        scatter_records, section_mapping,
                                        task_records, thumb_literal)
from analyze.qemu_display import table_for


def thumb_ldr_literal(register, immediate):
    """Thumb T1 literal load; the test picks its own pool distances."""
    return 0x4800 | register << 8 | immediate


def thumb_str_imm(rt, rn, word_offset):
    """Thumb T1 immediate store with the given word offset."""
    return 0x6000 | word_offset // 4 << 6 | rn << 3 | rt


class Structure(unittest.TestCase):
    def image(self, records):
        return b''.join(struct.pack('<4I', *r) for r in records) + bytes(18)

    def test_copy_bounds_exclude_crc(self):
        data = self.image([(BASE + 16, 0xB1800000, 16, BASE + 0x6C)])
        self.assertEqual(scatter_records(data, 0)[0]['kind'], 'copy')
        invalid = self.image([(BASE + 20, 0xB1800000, 16, BASE + 0x6C)])
        with self.assertRaisesRegex(ValueError, 'payload'):
            scatter_records(invalid, 0)

    def test_zero_records_do_not_read_source(self):
        data = self.image([(0xDEADBEEF, 0x62700000, 0x49AC5000, BASE + 0x88)])
        self.assertEqual(scatter_records(data, 0)[0]['kind'], 'zero')

    def test_reject_unknown_handler_and_destination_overflow(self):
        for record, error in (
            ((BASE, 0xB1800000, 4, BASE + 0x99), 'handler'),
            ((BASE, 0xFFFFFFFC, 8, BASE + 0x88), 'overflow'),
            ((BASE, 0xB1800001, 4, BASE + 0x88), 'alignment'),
        ):
            with self.assertRaisesRegex(ValueError, error):
                scatter_records(self.image([record]), 0)

    def test_truncation_and_missing_terminator(self):
        with self.assertRaisesRegex(ValueError, 'Truncated'):
            scatter_records(bytes(15), 0)
        record = (BASE, 0xB1800000, 4, BASE + 0x88)
        with self.assertRaisesRegex(ValueError, 'Unterminated'):
            scatter_records(self.image([record, record]), 0, max_records=1)

    def test_arm_branch_sign_extension(self):
        self.assertEqual(branch_target(struct.pack('<I', 0xEAFFFFFE), 0), 0)
        self.assertEqual(branch_target(struct.pack('<I', 0xEA002F20), 0), 0xBC88)
        with self.assertRaisesRegex(ValueError, 'branch'):
            branch_target(bytes(4), 0)

    def test_literal_direction_and_register(self):
        image = struct.pack('<4I', 0xE59F0004, 0xE51F1004, 0xB2BB0000, 0x10030000)
        self.assertEqual(literal(image, 0, 0), 0x10030000)
        self.assertEqual(literal(image, 4, 1), 0xB2BB0000)
        with self.assertRaisesRegex(ValueError, 'literal'):
            literal(image, 0, 1)

    def test_task_record_preserves_unnamed_fields(self):
        data = struct.pack('<12s4I', b'DUALEG', 2, 7, 4096, 0) + bytes(2)
        self.assertEqual(task_records(data, 0, 1)[0]['fields'], [2, 7, 4096, 0])
        with self.assertRaisesRegex(ValueError, 'Truncated'):
            task_records(data, 0, 2)

    def test_thumb_literal_pc_alignment_and_bounds(self):
        data = struct.pack('<4H', 0, 0x4A01, 0, 0) + struct.pack('<I', 0xAA550001)
        self.assertEqual(thumb_literal(data, 2, 2), 0xAA550001)
        with self.assertRaisesRegex(ValueError, 'literal'):
            thumb_literal(data, 2, 1)
        with self.assertRaisesRegex(ValueError, 'Word outside'):
            thumb_literal(data[:10], 2, 2)
        with self.assertRaisesRegex(ValueError, 'instruction outside'):
            thumb_literal(data, -1, 2)

    def test_communication_header_role_and_store_guards(self):
        for role, entry, address in (('master', 0x367E20, 0xB7CF0000),
                                     ('slave', 0x40CD8, 0xC60F0000)):
            data = bytearray(entry + 0x3FC)
            # Original synthetic store sequence built from instruction
            # semantics; the literal-pool distance differs from stock.
            struct.pack_into('<8H', data, entry,
                             thumb_ldr_literal(0, 0xFD), 0x2100,
                             thumb_ldr_literal(2, 0xFA), thumb_ldr_literal(3, 0xFB),
                             thumb_str_imm(2, 0, 0), 0xE9C0, 0x3101,
                             thumb_str_imm(1, 0, 0x10))
            struct.pack_into('<3I', data, entry + 0x3F0, 0x00C00108, 0xAA550001, address)
            records = [dict(kind='zero', destination=address, size=0xC618)]
            header = communication_header(data, role, records)
            self.assertEqual(header['local_address'], address)
            self.assertEqual(header['stop_offset'], entry + 16)
            self.assertEqual(header['untouched_word_offsets'], [0xC, 0x14])
            self.assertEqual([w['value'] for w in header['writes']],
                             [0x00C00108, 0xAA550001, 0, 0])
            with self.assertRaisesRegex(ValueError, 'zero record'):
                communication_header(data, role, [])
            with self.assertRaisesRegex(ValueError, 'zero record'):
                communication_header(data, role, records * 2)
            struct.pack_into('<I', data, entry + 0x3F8, address ^ 0x100000)
            with self.assertRaisesRegex(ValueError, 'literals'):
                communication_header(data, role, records)
            data[entry + 14] = 0
            with self.assertRaisesRegex(ValueError, 'r1, \\[r0'):
                communication_header(data, role, records)

    def test_communication_store_semantics(self):
        entry = 0x40CD8
        data = bytearray(entry + 0x3D8)
        struct.pack_into('<8H', data, entry,
                         thumb_ldr_literal(0, 4), 0x2100,
                         thumb_ldr_literal(2, 8), thumb_ldr_literal(3, 12),
                         thumb_str_imm(2, 0, 0), 0xE9C0, 0x3101,
                         thumb_str_imm(1, 0, 0x10))
        communication_stores(data, entry)
        for index, mutated in ((0, thumb_ldr_literal(4, 4)),   # wrong base register
                               (2, thumb_ldr_literal(3, 8)),   # wrong magic register
                               (4, thumb_str_imm(2, 0, 8)),    # wrong store offset
                               (7, thumb_str_imm(1, 1, 0x10))):  # wrong base register
            original = struct.unpack_from('<8H', data, entry)[index]
            struct.pack_into('<H', data, entry + index * 2, mutated)
            with self.assertRaisesRegex(ValueError, 'Expected'):
                communication_stores(data, entry)
            struct.pack_into('<H', data, entry + index * 2, original)
        struct.pack_into('<H', data, entry + 2, 0x2200)
        with self.assertRaisesRegex(ValueError, 'MOVS'):
            communication_stores(data, entry)

    def test_slave_mmu_isolation(self):
        image = bytearray(0x14000)
        for index in range(4096):
            struct.pack_into('<I', image, 0x10000 + index * 4, index << 20 | 0x14426)
        for backend in ('virt', 'nikon-z72-lab'):
            words = struct.unpack('<4096I', table_for(image, backend=backend, role='slave'))
            for first, last, physical in PROFILES['slave'].windows:
                for index in range(first, last):
                    target = index if backend == 'nikon-z72-lab' else physical + index - first
                    self.assertEqual(words[index], target << 20 | 0x14426)
            self.assertEqual(words[0xB18], 0)
            self.assertEqual(words[0xB20], 0)
            self.assertEqual(words[0xC51], 0)

    def test_stock_section_translation_and_permissions(self):
        image = bytearray(0x14000)
        struct.pack_into('<I', image, 0x10400, 0x4200C436)
        mapping = section_mapping(image, BASE)
        self.assertEqual(mapping['physical_address'], 0x42020000)
        self.assertEqual(mapping['access_permissions'], 5)
        self.assertEqual(mapping['domain'], 1)
        self.assertTrue(mapping['execute_never'])
        for descriptor in (0, 0x10000001, 0x10000003, 0x10040002):
            struct.pack_into('<I', image, 0x10400, descriptor)
            with self.assertRaisesRegex(ValueError, 'ordinary section'):
                section_mapping(image, BASE)
        for address in (-1, 1 << 32):
            with self.assertRaisesRegex(ValueError, '32-bit'):
                section_mapping(image, address)
        with self.assertRaisesRegex(ValueError, 'outside firmware'):
            section_mapping(bytes(0x10400), BASE)

    def test_boot_prefix_role_boundaries_and_mapping_guards(self):
        for role, profile in PROFILES.items():
            image = bytearray(0x14000)
            delta = profile.boot - 0xBC88
            stop = 0xBDA4 + delta
            struct.pack_into('<3I', image, stop - 8, 0xE59F024C, 0xE3A01021, 0xE5801000)
            struct.pack_into('<I', image, stop + 0x24C, 0x04264000)
            stacks = [0xB2BB0000 - i * 0x8000 if role == 'master' else
                      0xC1920000 - i * 0x8000 for i in range(6)]
            struct.pack_into('<6I', image, profile.literals + 16, *stacks)
            for address in (BASE, BASE + 0x10000, *(s - 4 for s in stacks), 0x04264000):
                index = address >> 20
                struct.pack_into('<I', image, 0x10000 + index * 4, index << 20 | 0xC426)
            prefix = boot_prefix(image, profile)
            self.assertEqual(prefix['stop_offset'], stop)
            self.assertEqual([c['stack_top'] for c in prefix['stack_checkpoints']], stacks)
            self.assertEqual(prefix['stack_checkpoints'][-1]['offset'], 0xBD94 + delta)
            self.assertEqual(prefix['first_mmio']['address'], 0x04264000)
            struct.pack_into('<I', image, 0x10400, 0x4200C426)
            with self.assertRaisesRegex(ValueError, 'identity'):
                boot_prefix(image, profile)
            struct.pack_into('<I', image, stop, 0)
            with self.assertRaisesRegex(ValueError, 'store mismatch'):
                boot_prefix(image, profile)

    def test_board_windows_match_translation_profiles(self):
        header = (ROOT / 'qemu/nikon-z72-profile.h').read_text()
        for role, array in (('master', 'nikon_z72_windows'), ('slave', 'nikon_z72_slave_windows')):
            body = re.search(array + r'\[\] = \{(.*?)\n\};', header, re.S)[1]
            actual = {(int(a, 16), int(b, 16)) for a, b in
                      re.findall(r'\{(0x[0-9A-F]+), (0x[0-9A-F]+),', body)}
            expected = {(first << 20, (last - first) << 20)
                        for first, last, _ in PROFILES[role].windows}
            expected.add((0x40100000, 0x100000))
            # Native reset uses a small temporary SRAM stack. It is separate
            # from section-sized windows used by the adapted snippet harness.
            expected.add((0x04008000, 0x1000))
            # The companion serial-adjacent page beside the console interface
            # is written by the kernel after the handoff completes.
            expected.add((0x2C0A0000, 0x1000))
            # Release-path passive blocks: the controller block below the
            # console interface and, for the master role, the large-buffer
            # pool backing the layout-builder destinations. The runtime
            # high-window physical span backs the page-table destinations
            # of the 0x10000000..0x17000000 virtual family, and the
            # peer-alias span receives the section-mapped 0x15xxxxxxx
            # stores observed past the message RAM.
            expected.add((0x2C010000, 0x80000))
            expected.add((0x20100000, 0x6F00000))
            expected.add((0xB6F00000, 0xD00000))
            if role == 'slave':
                # The slave role additionally keeps its post-heap startup
                # storage span that backs peer-memory accesses.
                expected.add((0xC5100000, 0xF00000))
            if role == 'master':
                expected.add((0xB7D00000, 0x2D00000))
                # Native runtime pools and auxiliary load destinations are
                # physical storage; the snippet harness does not map them.
                # The cached-buffer and capture-buffer pools back the
                # runtime address-table bus aliases observed while the
                # original capture path prepares its frame storage.
                expected.update({
                    (0x00000000, 0x100000), (0x50000000, 0x300000),
                    (0x50300000, 0x4C00000), (0x5F900000, 0x2E00000),
                    (0xB1000000, 0x300000), (0xB6000000, 0xF00000),
                    (0xBB300000, 0xDA0000), (0xBC100000, 0x10E0000),
                    (0xBD200000, 0x6BCB400), (0xC3E00000, 0x883B000),
                    (0xCC700000, 0x337E5400),
                })
            self.assertEqual(actual, expected)

    def test_invalid_role_and_backend_rejected(self):
        for kwargs in ({'role': 'unknown'}, {'backend': 'unknown'}):
            with self.assertRaises(ValueError):
                table_for(bytes(0x14000), **kwargs)


if __name__ == '__main__':
    unittest.main()
