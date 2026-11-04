# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original aperture conversion and packet builders with synthetic inputs."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
    UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_LR)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class ApertureProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.packet = self.DATA + 0x1000
        self.max_closure = 1152
        self.packet_selectors = []

    def boundary(self, cpu, address, size, unused):
        a, b, c = (cpu.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
        if address == 0x103466b6:
            require(a == 1 and self.word(b) == 0x1016, 'Unexpected aperture family property')
            cpu.mem_write(c, struct.pack('<I', 0))
            result = 1
        elif address == 0x10346a62:
            require(a == 0x1000300d, 'Unexpected relative closure limit property')
            cpu.mem_write(b, struct.pack('<hHi', 192, 0xa5a5, self.max_closure))
            result = 1
        elif address == 0x1037c3ec:
            self.packet_selectors.append(a)
            result = self.packet
        else:
            return super().boundary(cpu, address, size, unused)
        cpu.reg_write(UC_ARM_REG_R0, result)
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))


def check(image):
    native = ApertureProbe(image)
    source, reference, target = native.DATA, native.DATA + 0x20, native.DATA + 0x40
    biased_cases = []
    for encoded, expected in ((384, 0), (960, 576), (1536, 1152), (2112, 1728)):
        native.u.mem_write(source, bytes(32))
        native.u.mem_write(source + 9, struct.pack('<H', encoded))
        native.u.mem_write(target, b'\xa5' * 8)
        native.call(0x103795cc - BASE, source, target)
        denominator, padding, numerator = struct.unpack('<hHi', native.u.mem_read(target, 8))
        require((denominator,numerator) == (192,expected), 'Biased absolute aperture conversion differs')
        require(padding == 0xa5a5, 'Rational padding was overwritten')
        biased_cases.append(dict(encoded=encoded, denominator=denominator, numerator=numerator))
    closure_cases = []
    for wanted_num, wanted_den, ref_num, ref_den, expected in (
            (6,1,3,1,576), (3,1,3,1,0), (2,1,3,1,0),
            (12,1,3,1,1152), (18,3,6,2,576), (7,2,3,1,96)):
        native.u.mem_write(source, struct.pack('<hHi', wanted_den, 0xa5a5, wanted_num))
        native.u.mem_write(reference, struct.pack('<hHi', ref_den, 0x5a5a, ref_num))
        native.u.mem_write(target, b'\xa5' * 8)
        native.u.reg_write(UC_ARM_REG_R3, target)
        native.call(0x1031086a - BASE, source, 0, reference)
        denominator, padding, numerator = struct.unpack('<hHi', native.u.mem_read(target, 8))
        require((denominator,numerator) == (192,expected), 'Ordinary relative closure differs')
        require(padding == 0xa5a5, 'Closure math consumed rational padding')
        closure_cases.append(dict(request=[wanted_num,wanted_den], reference=[ref_num,ref_den],
            result=[numerator,denominator], maximum=native.max_closure))
    constructors = []
    request = native.DATA + 0x100
    for address, selector, size in ((0x10377dea,0x2c,24), (0x10377e5a,0x36,4)):
        for value in (0,96,576,1152):
            native.u.mem_write(request, bytes(40))
            native.u.mem_write(request + 4, struct.pack('<hHi',192,0xa5a5,value))
            native.u.mem_write(native.packet, b'\xa5' * 26)
            native.call(address - BASE, request, selector)
            output = bytes(native.u.mem_read(native.packet,26))
            require(native.packet_selectors[-1] == selector, 'Original packet buffer selector differs')
            require(output[1:3] == struct.pack('<H',value), 'Relative target packet differs')
            require(output[:1] == b'\xa5' and output[3:] == b'\xa5' * 23,
                    'Packet builder rewrote bytes outside the target')
            constructors.append(dict(constructor=hex(address), packet_bytes=size,
                relative_target=value, target_le_hex=output[1:3].hex()))
    return dict(schema=1,result='passed-original-aperture-coordinate-contract',master_sha256=MASTER_SHA,
        original=dict(biased_getter='0x103795cc',closure='0x1031086a',
            a0_constructor='0x10377dea',a3_constructor='0x10377e5a'),
        biased_cases=biased_cases,closure_cases=closure_cases,constructors=constructors,
        limitations=['Synthetic ordinary-family and maximum-closure properties; no live property discovery.',
            'Only buffer lookup is intercepted for original packet constructors; surrounding framing/checksum is not tested here.',
            'Does not exercise alternate families, native motor timing, electronic exposure or physical optics.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('PASS original aperture bias, ordinary denominator, relative bounds and target packet bytes')


if __name__ == '__main__':
    main()
