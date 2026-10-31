# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover C1.70 release GPIO bindings and execute their original edge routing."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class ReleaseProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.bindings, self.events = [], []

    def boundary(self, u, address, size, unused):
        a, b = u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)
        result = 0
        if address in (0x10229b9a, 0x102280ae, 0x10229db0, 0x1022bfea,
                       0x1022bfc2, 0x1021f228):
            pass  # Initialization of unrelated task subscriptions and gates.
        elif address == 0x10368ad2:
            result = a  # Identity resource mapping for this isolated contract.
        elif address == 0x103a047c:
            require(a in (0x58, 0x59, 0x5a, 0x5c), 'Unexpected release resource')
            result = 0xb180249c + a * 56
            require(int.from_bytes(u.mem_read(result, 2), 'little') == a,
                    'Original descriptor resource mismatch')
        elif address == 0x10385ea0:
            configuration = bytes(u.mem_read(b, 8))
            self.bindings.append(dict(resource=int.from_bytes(u.mem_read(a, 2), 'little'),
                descriptor=hex(a), register=hex(self.word(a + 8)),
                pin=u.mem_read(a + 4, 1)[0], input=u.mem_read(a + 0x24, 1)[0],
                intid=self.word(a + 0x28), edge_mode=configuration[0],
                callback=hex(struct.unpack_from('<I', configuration, 4)[0])))
        elif address == 0x10385f5e:
            require(b == 1, 'Original release input not enabled')
        elif address == 0x10228d7a:
            self.events.append(dict(event=a, callback=hex(b)))
        else:
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_R0, result)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def probe(image):
    native = ReleaseProbe(image)
    native.call(0x20c010)
    require([row['resource'] for row in native.bindings] == [0x58, 0x59, 0x5a, 0x5c],
            'Original release binding order changed')
    require([row['intid'] for row in native.bindings] == [69, 70, 71, 73] and
            all(row['edge_mode'] == 2 and row['callback'] == '0x1022aaaf'
                for row in native.bindings), 'Original release interrupt binding differs')
    half, full = [native.word(0xb18698cc + offset) for offset in (4, 8)]
    require((half, full) == (69, 70), 'Original callback identities differ')
    cases = []
    for name, edges, expected in (
            ('half-full-release', [(half, 1), (full, 1), (full, 0), (half, 0)], [0, 1, 2, 3]),
            ('full-without-half', [(full, 1)], []),
            ('full-before-half', [(full, 1), (half, 1)], [0, 1]),
            ('half-released-first', [(half, 1), (full, 1), (half, 0), (full, 0)], [0, 1, 2, 3])):
        native.u.mem_write(0xb18698e4, bytes(28))  # Isolated contact/pending state.
        native.events.clear()
        steps = []
        for irq, level in edges:
            previous = len(native.events)
            native.call(0x20aaae, irq, level)
            steps.append(dict(intid=irq, level=level,
                              events=native.events[previous:]))
        require([row['event'] for row in native.events] == expected,
                'Original half/full edge qualification differs')
        cases.append(dict(name=name, steps=steps))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        initialization='0x1022c010', callback='0x1022aaae', bindings=native.bindings,
        cases=cases, host_boundaries=['identity resource mapping and descriptor lookup',
            'record configuration, interrupt enables and deferred callbacks',
            'skip unrelated initialization subscriptions and gates',
            'supply isolated input edges and clear isolated contact state between cases'],
        limitations=['Does not prove physical board wiring',
            'Does not execute deferred callbacks or prove photo completion'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native release GPIO bindings and four half/full edge sequences')


if __name__ == '__main__':
    main()
