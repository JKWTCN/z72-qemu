# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original resource timing arithmetic and timer-packet construction."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require
from tools.boot_region_probe import RegionProbe
from tools.create_lab_parameters import resource_header_image, resource_timing_image


class TimingProbe(RegionProbe):
    PARAMETERS = 0x51000000
    PACKET = 0xb2b369b8

    def __init__(self, image):
        super().__init__(image)
        self.u.mem_map(self.PARAMETERS, 0x200000)
        self.u.mem_write(0xb18a77a0, struct.pack('<I', self.PARAMETERS))
        self.packet_parts = 0

    def boundary(self, cpu, address, size, unused):
        if address != 0x102ff544:
            return super().boundary(cpu, address, size, unused)
        self.packet_parts += 1
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))


def request(mode, subtype, dynamic=False):
    data = bytearray(0x120)
    data[0], data[0x8c] = mode, subtype
    data[0x5a] = 2
    struct.pack_into('<hHi', data, 0xc, 192, 0, 1134)
    if dynamic:
        data[0x21], data[0x5a], data[0x60] = 1, 7, 60
        struct.pack_into('<i', data, 0x10, 640)
        struct.pack_into('<I', data, 0x64, 1)
    return bytes(data)


def check(image):
    native = TimingProbe(image)
    header, profile = resource_header_image(), resource_timing_image()
    changed = set()
    for group in (1, 7, 10):
        for subtype in range(4):
            row = 0xbe0c0 + group * 64 + subtype * 16
            changed.update(row + at for at in (2, 3, 6, 7, 11, 12, 13))
    require(len(profile) == len(header) == 0x180000 and
            all(a == b for at, (a, b) in enumerate(zip(header, profile)) if at not in changed),
            'Timing profile changes unrelated resource data')
    calculations = []
    for populated, resource in ((False, header), (True, profile)):
        native.u.mem_write(native.PARAMETERS, resource)
        for mode, group, count, duration in ((5, 1, 586, 33336), (11, 7, 292, 16611), (14, 10, 16, 910)):
            require(native.call(0x102fef74 - BASE, mode) == group, 'Original timing group differs')
            for subtype in range(4):
                native.u.mem_write(native.DATA, request(mode, subtype))
                result = native.call(0x10304e3c - BASE, native.DATA)
                output = bytes(native.u.mem_read(native.DATA, 0x120))
                values = (int.from_bytes(output[0x9c:0x9e], 'little'),
                          int.from_bytes(output[0x94:0x98], 'little'),
                          int.from_bytes(output[0xa0:0xa4], 'little'),
                          native.call(0x10304a5e - BASE, native.DATA))
                require(result == 0 and values == ((4096, count, 1000, duration) if populated else (0, 0, 0, 0)),
                        'Original timing arithmetic differs')
                calculations.append(dict(profile=populated, mode=mode, group=group, subtype=subtype,
                    period=values[0], count=values[1], overhead=values[2], duration_us=values[3]))
    native.u.mem_write(native.DATA, request(5, 0, dynamic=True))
    require(native.call(0x10304e3c - BASE, native.DATA) == 0 and
            native.word(native.DATA + 0x94) == 2324 and
            native.call(0x10304a5e - BASE, native.DATA) == 132209,
            'Original duration-dependent count differs')
    packets = []
    record = native.DATA + 0x1000
    native.u.mem_write(record, bytes(0x100))
    for populated, resource in ((False, header), (True, profile)):
        native.u.mem_write(native.PARAMETERS, resource)
        for duration in (None, 0, 7383):
            obj = bytearray(request(11, 0))
            period, count = (4096, 292) if populated else (0, 0)
            struct.pack_into('<H', obj, 0x9c, period)
            struct.pack_into('<I', obj, 0x94, count)
            if duration is not None:
                struct.pack_into('<2I', obj, 0x64, 1, duration)
            native.u.mem_write(native.DATA, bytes(obj))
            native.u.mem_write(native.PACKET, b'\xa5' * 0x160)
            native.packet_parts = 0
            native.call((0x102ffc5a if duration is None else 0x102ffb14) - BASE, record, native.DATA)
            output = bytes(native.u.mem_read(native.PACKET, 0xb0))
            q = 0 if duration is None or not period else (72 * duration + period - 1) // period
            load = (count + q - 1) & 0xffffffff
            require(native.packet_parts == 3 and
                    all(struct.unpack_from('<H', output, at)[0] == (period - 1) & 0xffff
                        for at in (0, 0xa, 0x1c, 0x2c, 0x36, 0x84, 0x8e)) and
                    all(struct.unpack_from('<I', output, at)[0] == load for at in (0x14, 0x40, 0x98)),
                    'Original timer packet load fields differ')
            require(struct.unpack_from('<2I', output, 0xa4) == (q + 3, q + int(populated)),
                    'Original timer metadata or duration increment differs')
            require(bytes(native.u.mem_read(native.DATA, len(obj))) == bytes(obj),
                    'Timer builder modified its source object')
            packets.append(dict(profile=populated, duration_us=duration, period_load=(period - 1) & 0xffff,
                count_load=load, duration_increment=q))
    return dict(schema=1, result='passed-original-resource-timing-contract', master_sha256=MASTER_SHA,
        profile=dict(source='tools/create_lab_parameters.py:resource_timing_image', bytes=len(profile),
            sha256=hashlib.sha256(profile).hexdigest(), groups=[1, 7, 10], subtypes=[0, 1, 2, 3],
            period=4096, fallback_count=586, metadata=1, overhead_parameter=72),
        calculations=calculations, dynamic_count=2324, dynamic_duration_us=132209, packets=packets,
        limitations=['Finite experimental row values, not recovered factory calibration or physical sensor timing.',
            'Original timing and load arithmetic executes; three opaque timer-record consumers are intercepted.',
            'Serial programs remain empty; this contract does not establish integration start, IRQ timing or DMA gating.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS original resource timing rows, duration arithmetic and timer packet loads')


if __name__ == '__main__':
    main()
