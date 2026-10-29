# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the original primary-input builder and its split-DMA descriptors."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class PrimaryProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.u.mem_map(0x20068000, 0x4000)
        self.u.mem_map(0x20130000, 0x10000)
        self.mappings = []

    def boundary(self, u, address, size, unused):
        if address == 0x1038848a:
            self.mappings.append(dict(domain=u.reg_read(UC_ARM_REG_R0),
                address=hex(u.reg_read(UC_ARM_REG_R1)), bytes=u.reg_read(UC_ARM_REG_R2)))
        elif address in (0x10360f18, 0x10360f12):
            # Uncontended locks only; native mapping and register writes run.
            u.reg_write(UC_ARM_REG_R0, 1)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(u, address, size, unused)


def probe(image):
    native = PrimaryProbe(image)
    argument, full, partial, payload = [native.DATA + offset for offset in (0, 0x1000, 0x2000, 0x3000)]
    cases = []
    for split, source_format, packed, bits in (
            (False, 2, 2, 12), (True, 2, 2, 12),
            (True, 3, 0, 16), (True, 0, 1, 14)):
        native.u.mem_write(argument, bytes(0x18))
        native.u.mem_write(argument + 0xc, struct.pack('<2I', full, partial))
        native.u.mem_write(argument + 0x14, struct.pack('<I', int(not split)))
        for descriptor, width, target in ((full, 8288 if split else 2816, 0x68000000),
                                          (partial, 2816, 0x62700000)):
            native.u.mem_write(descriptor, bytes(0x40))
            native.u.mem_write(descriptor + 4, struct.pack('<I', payload))
            native.u.mem_write(descriptor + 0x24, bytes([source_format]))
            native.u.mem_write(descriptor + 0x28, struct.pack('<HH', width, 5520))
            native.u.mem_write(descriptor + 0x34, struct.pack('<I', target))
        native.u.mem_write(payload, struct.pack('<2I', 0x68000000, 0x4800000))
        native.u.mem_write(0xb26b38cc, struct.pack('<I', 1))
        native.u.mem_write(0xb26b48fc, bytes(0x88))
        native.u.mem_write(0x20068000, bytes(0x4000))
        window = native.DATA + 0x5000
        native.u.mem_write(window, struct.pack('<6I', 2, 0x8000000, 0x18000000,
                                               0x68000000, 4, 0))
        native.u.mem_write(0xb180892c, struct.pack('<I', 1))
        require(native.call(0x1038816a - 0x10020000, window, 1) == 1,
                'Original remap window initialization failed')
        native.mappings.clear()
        result = native.call(0x10239c34 - 0x10020000, argument)
        first_stride = ((2816 * bits // 8) + 15) & ~15
        full_stride = ((8288 * bits // 8) + 15) & ~15
        geometry = [native.word(0x20069500 + offset) for offset in range(0, 0x14, 4)]
        require(result == 1 and geometry == [packed, 2816 << 16, 5520 << 16,
                int(split), 5472 if split else 0], 'Primary input geometry differs')
        expected_first = 0x62700000 if split else 0x68000000
        first_addresses = [native.word(0x20069850 + index * 4) for index in range(8)]
        require(first_addresses == [expected_first] + [0] * 7, 'Primary input address groups differ')
        require(native.word(0x20069808) == first_stride and
                native.word(0x20069814) == 1 and native.word(0x20069818) == 1 and
                native.word(0x2006983c) == 0 and native.word(0x20069840) == 1 and
                native.word(0x20069844) == 0 and native.word(0x20069848) == 3,
                'Primary input DMA control differs')
        second_addresses = [native.word(0x20069950 + index * 4) for index in range(8)]
        mappings = [dict(domain=2, address='0x68000000', bytes=0x4800000)] if split else []
        require(native.mappings == mappings, 'Full-buffer mapping request differs')
        require(second_addresses == ([0x18000000 + first_stride] + [0] * 7 if split else [0] * 8),
                'Second input DMA column offset differs')
        require(native.word(0x20069908) == (full_stride if split else 0),
                'Second input DMA row stride differs')
        remap = {name: [native.word(base + index * 4) for index in range(8)]
                 for name, base in (('target', 0x2013d0b0), ('mask', 0x2013d0d0),
                                    ('aperture', 0x2013d0f0))}
        require(remap == dict(target=[0x68000, 0x6a000, 0x6c000, 0x6e000] + [0] * 4,
                             mask=[0xfe000] * 4 + [0] * 4,
                             aperture=[0x18000, 0x1a000, 0x1c000, 0x1e000] + [0] * 4),
                'Original remap register table differs')
        cases.append(dict(split=split, source_format=source_format, bits_per_sample=bits,
            geometry=[hex(value) for value in geometry], first_stride=first_stride,
            first_addresses=[hex(value) for value in first_addresses],
            second_stride=full_stride if split else 0,
            second_addresses=[hex(value) for value in second_addresses],
            mapping_requests=list(native.mappings),
            remap_registers={name: [hex(value) for value in values] for name, values in remap.items()}))
    translations = []
    for source, length in ((0x68000000, 1), (0x69fff000, 0x2000),
                           (0x6c001080, 0x1000), (0x6fffffff, 1), (0x70000000, 1)):
        aperture = native.call(0x103880e4 - 0x10020000, 2, source, length)
        expected = 0x18000000 + source - 0x68000000 if source < 0x70000000 else 0xffffffff
        require(aperture == expected, 'Original mapping lookup range differs')
        if aperture != 0xffffffff:
            for bus, physical in ((aperture, source), (aperture + length - 1, source + length - 1)):
                matches = [(target << 12) | (bus & ~(mask << 12))
                    for target, mask, base in zip(remap['target'], remap['mask'], remap['aperture'])
                    if mask and bus & (mask << 12) == base << 12]
                require(matches == [physical], 'Programmed remap does not invert native lookup')
        translations.append(dict(source=hex(source), bytes=length, aperture=hex(aperture)))
    # Exercise retargeting, not only lookups within the constructor's initial
    # backing. The observed device aperture can name different physical pools.
    native.u.mem_write(window, struct.pack('<6I', 2, 0x8000000, 0x10000000,
                                           0xb8000000, 1, 0))
    require(native.call(0x1038816a - 0x10020000, window, 1) == 1,
            'Original dynamic remap initialization failed')
    dynamic = []
    for source, expected_page in ((0xbad0a000, 0xb8000),
                                  (0x6ad0a000, 0x68000), (0xbad0a000, 0xb8000)):
        aperture = native.call(0x1038848a - 0x10020000, 2, source, 0x4800000)
        require(aperture == 0x12d0a000, 'Original dynamic mapping returned another aperture')
        target, mask, base = [native.word(address) for address in
                             (0x2013d0b0, 0x2013d0d0, 0x2013d0f0)]
        require((target, mask, base) == (expected_page, 0xf8000, 0x10000),
                'Original dynamic remap register update differs')
        require((target << 12) | (aperture & ~(mask << 12)) == source,
                'Dynamic remap inverse differs')
        dynamic.append(dict(source=hex(source), bytes=0x4800000, aperture=hex(aperture),
                            target_page=hex(target), mask_page=hex(mask), aperture_page=hex(base)))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        builder='0x10239c34', descriptor_writer='0x10239900',
        geometry_writer='0x1020905a', cases=cases,
        native_geometry_and_dma_setters=True,
        remap_constructor='0x1038816a', remap_request='0x1038848a', remap_writer='0x102ddc76',
        remap_lookup='0x103880e4', remap_translation_cases=translations,
        dynamic_remap_cases=dynamic,
        native_remap_programming=True, host_boundaries=['Uncontended lock/unlock.'],
        limitations=['Synthetic full/partial buffer headers, addresses, input flags and remap window.',
                    'The synthetic window does not identify the running full-frame backing address.',
                    'Address-group forwarding does not establish ring rotation or completion timing.',
                    'No pixel packing order, DMA transfer, frame completion or photo is supplied.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS original primary input builder and split DMA descriptors')


if __name__ == '__main__':
    main()
