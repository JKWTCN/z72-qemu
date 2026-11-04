# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the original master JPEG decode setup and two interrupt phases."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class DecoderProbe(RegionProbe):
    RECORDER = RegionProbe.DATA + 0x4000

    def __init__(self, image):
        super().__init__(image)
        self.u.mem_map(0x24072000, 0x1000)
        self.writes, self.events = [], []
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write)

    def write(self, u, access, address, size, value, unused):
        if 0x24072000 <= address < 0x24072600:
            self.writes.append(dict(address=hex(address), bytes=size, value=hex(value)))

    def boundary(self, u, address, size, unused):
        if address == self.RECORDER:
            descriptor = u.reg_read(UC_ARM_REG_R1)
            self.events.append(dict(notification=hex(u.reg_read(UC_ARM_REG_R0)),
                flags=hex(self.word(descriptor + 0x78)),
                dimensions=list(struct.unpack('<2H', u.mem_read(descriptor + 0x60, 4)))))
            u.reg_write(UC_ARM_REG_R0, 0)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(u, address, size, unused)


def check(image):
    native = DecoderProbe(image)
    descriptor, handle = native.DATA + 0x2000, 0xb1801ec0
    request = bytearray(0x98)
    request[0x3b] = request[0x3c] = 2
    request[0x54] = 2
    for offset, value in {0x48: 0x53000000, 0x4c: 160, 0x50: 160,
            0x58: 0x53100000, 0x5c: 0x53104b00, 0x84: 0x31f,
            0x88: 0xc4d000, 0x94: native.RECORDER | 1}.items():
        struct.pack_into('<I', request, offset, value)
    native.u.mem_write(handle, struct.pack('<3I', 0x113, 0, 0))
    native.u.mem_write(descriptor, bytes(request))
    native.call(0x103be5f0 - BASE, handle, descriptor)
    expected = {0: 0x39, 0x28: 0x31f, 0x400: 8, 0x404: 8, 0x408: 0x10000,
        0x410: 0, 0x414: 0, 0x418: 0, 0x41c: 0, 0x430: 0x53100000,
        0x434: 0x53104b00, 0x440: 0x53000000, 0x458: 0, 0x484: 0xc4d000}
    require(all(native.word(0x24072000 + offset) == value for offset, value in expected.items()),
            'Original decode descriptor-to-register mapping differs')
    native.writes.clear()
    native.call(0x103be756 - BASE, handle)
    require(native.word(0x24072004) == 1 and native.word(0x24072404) == 0x4008 and
            native.word(0x24072400) == 8, 'Original header-only start sequence differs')
    start_writes = list(native.writes)
    for offset, value in {0: 0x3a, 0x18: 120, 0x1c: 160, 0x2c: 0x10,
                           0x480: 0x0a000000}.items():
        native.u.mem_write(0x24072000 + offset, struct.pack('<I', value))
    native.writes.clear()
    native.call(0x103bdfea - BASE)
    geometry = {offset: native.word(0x24072000 + offset) for offset in
                (0x410, 0x414, 0x418, 0x41c, 0x420, 0x424, 0x428)}
    require(geometry == {0x410: 160, 0x414: 160, 0x418: 160, 0x41c: 120,
                         0x420: 0, 0x424: 0, 0x428: 0}, 'Original header geometry differs')
    require(native.word(descriptor + 0x78) == 0x2000 and not native.events and
            native.word(0x24072400) == 0x4008, 'Header did not resume input DMA without completing the request')
    header_writes = list(native.writes)
    native.u.mem_write(0x2407202c, struct.pack('<I', 0x80000000))
    native.u.mem_write(0x24072480, struct.pack('<I', 0x0800c000))
    native.call(0x103bdfea - BASE)
    require(native.events == [dict(notification='0x41051402', flags='0x62001', dimensions=[160, 120])],
            'Original two-phase decode completion differs')
    completion = list(native.events)
    native.u.mem_write(0x24072000, bytes(0x1000))
    request[0x54] = 1
    native.u.mem_write(descriptor, bytes(request))
    native.events.clear()
    native.call(0x103be5f0 - BASE, handle, descriptor)
    native.call(0x103be756 - BASE, handle)
    for offset, value in {0: 0x3a, 0x18: 120, 0x1c: 160, 0x2c: 0x10,
                           0x480: 0x0a000000}.items():
        native.u.mem_write(0x24072000 + offset, struct.pack('<I', value))
    native.call(0x103bdfea - BASE)
    require(native.events == [dict(notification='0x41051402', flags='0x2800', dimensions=[160, 120])] and
            native.word(0x24072400) == 8, 'Original mismatched-format rejection differs')
    return dict(format=1, result='passed', firmware_included=False, master_sha256=MASTER_SHA,
        configure='0x103be5f0', start='0x103be756', handler='0x103bdfea',
        configuration_registers={hex(k): hex(v) for k, v in expected.items()},
        start_writes=start_writes, header_writes=header_writes,
        header_geometry={hex(k): v for k, v in geometry.items()}, completion=completion,
        mismatched_format_rejection=native.events,
        host_boundaries=['Synthetic descriptor, header metadata and completion status; record callback'],
        limitations=['Ordinary MMIO storage does not model status acknowledgement side effects',
                     'No JPEG bytes, pixel DMA, interrupt delivery or LCD output are exercised'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes((json.dumps(result, indent=2) + '\n').encode())
    print('PASS original JPEG header geometry, DMA resume and completion callback')
