# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original two-bit driver readiness and global release notification routing."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from tools.boot_region_probe import RegionProbe
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2


class GlobalReadyProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.notifications = []
        self.queued = []

    def boundary(self, cpu, address, size, unused):
        if address == self.DATA + 0x2000:
            self.notifications.append([cpu.reg_read(UC_ARM_REG_R0), cpu.reg_read(UC_ARM_REG_R1)])
        elif address in (0x10228d3a, 0x10319d56):
            self.queued.append([cpu.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)])
        elif address not in (0x10227b28, 0x1035dea2, 0x1035dea8, 0x10227a2a):
            return super().boundary(cpu, address, size, unused)
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))


def probe(image):
    native = GlobalReadyProbe(image)
    subscriber = native.DATA + 0x2001
    flags = 0xb1868b68
    native.u.mem_write(0xb1868b38, struct.pack('<I', subscriber))
    cases = []
    for entry, added in ((0x1031dd62, 1), (0x10326700, 2)):
        for previous in (0, 1, 2, 3):
            native.notifications.clear()
            native.u.mem_write(flags, struct.pack('<I', previous))
            native.call(entry - 0x10020000)
            actual = native.word(flags)
            require(actual == previous | added, 'Original driver readiness bits differ')
            expected = [[0x04160003, 0]] if actual == 3 else []
            require(native.notifications == expected, 'Original driver notification differs')
            cases.append(dict(entry=hex(entry), previous=previous, result=actual,
                notifications=[dict(code=hex(code), payload=hex(payload))
                               for code, payload in native.notifications]))
    router_cases = []
    for registered in (False, True):
        native.notifications.clear()
        native.queued.clear()
        native.u.mem_write(0xb18695ac, struct.pack('<I', subscriber if registered else 0))
        native.u.mem_write(0xb23f6a7c, bytes(4))
        native.u.mem_write(0xb23f7018, bytes(4))
        native.call(0x3cd470, 0x04160003)
        require(native.notifications == ([[0x0410000d, 0]] if registered else []),
                'Original global release notification differs')
        require(native.queued == [[0x103ecf8d, 0, 0]], 'Original follow-up queue differs')
        require(native.word(0xb23f6a7c) == native.word(0xb23f7018) == 0,
                'Router modified operation 13 request or callback')
        router_cases.append(dict(subscriber_registered=registered, operation13_pending=0,
            operation13_callback=0, notifications=[dict(code=hex(code), payload=hex(payload))
            for code, payload in native.notifications], queued=[hex(x) for x in native.queued[0]]))
    upstream_cases = []
    for entry, code, target in ((0x10321a4c, 0x04190040, 0x1031dd63),
                                (0x10327976, 0x041b0040, 0x10326701)):
        native.queued.clear()
        native.call(entry - 0x10020000, code)
        require(native.queued == [[target, 0, 0]], 'Original upstream readiness queue differs')
        upstream_cases.append(dict(entry=hex(entry), notification=hex(code),
                                   queued=[hex(x) for x in native.queued[0]]))
    return dict(firmware_included=False, master_sha256=hashlib.sha256(image).hexdigest(),
        driver_flags=hex(flags), driver_cases=cases, router='0x103ed470',
        router_input='0x04160003', router_cases=router_cases, upstream_cases=upstream_cases,
        host_boundaries=['notification subscriber', 'follow-up queue',
                         'driver post-notification bookkeeping', 'two local control setters',
                         'upstream local control setter'],
        limitation='Synthetic execution contract; does not establish native production of either readiness bit or completion of a photograph.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS original driver readiness and independent global release routing')
