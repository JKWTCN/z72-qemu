# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the original auxiliary result-cell reader and ROI weighting."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R3

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


def probe(image):
    native = RegionProbe(image)
    cells, grid, rectangle, output = [native.DATA + offset
                                      for offset in (0x2000, 0x3000, 0x3100, 0x3200)]
    native.u.mem_write(grid, struct.pack('<hh', 2, 2))
    cases = []
    for x, y, metric, roi, count, area in (
            (32, -64, 100, (0, 0, 64, 64), 4, 1024),
            (32, -64, 10000, (0, 0, 64, 64), 4, 1024),
            (32, -64, 10001, (0, 0, 64, 64), 0, 0),
            (-512, 0, 0, (0, 0, 64, 64), 0, 0),
            (512, 0, 0, (0, 0, 64, 64), 0, 0),
            (0, -512, 0, (0, 0, 64, 64), 0, 0),
            (0, 512, 0, (0, 0, 64, 64), 0, 0),
            (513, -513, 0, (0, 0, 64, 64), 4, 1024),
            (-511, 511, 0, (0, 0, 64, 64), 4, 1024),
            (0, 0, 65535, (0, 0, 64, 64), 0, 0),
            (32, -64, 100, (16, 16, 48, 48), 4, 256),
            (32, -64, 100, (0, 0, 32, 32), 1, 1024)):
        # Extra cells bound the original inclusive ROI boundary reads.
        supplied = (struct.pack('<hhH', x, y, metric) + b'\xa5' * 10) * 9
        native.u.mem_write(cells, supplied)
        native.u.mem_write(rectangle, struct.pack('<4h', *roi))
        native.u.mem_write(output, b'\xa5' * 0x110)
        native.u.reg_write(UC_ARM_REG_R3, output)
        native.call(0x2cbb0c, cells, grid, rectangle)
        observed = native.word(output)
        require(observed == count, 'Original auxiliary cell selection differs')
        records = [list(struct.unpack('<6i', native.u.mem_read(output + 4 + index * 24, 24)))
                   for index in range(observed)]
        require(records == [[x, y, area, metric, x * area, y * area]] * count,
                'Original auxiliary ROI weighting differs')
        require(bytes(native.u.mem_read(cells, len(supplied))) == supplied and
                bytes(native.u.mem_read(output + 0x100, 16)) == b'\xa5' * 16,
                'Auxiliary reader changed its input or output guard')
        cases.append(dict(components=[x, y], metric=metric, roi=list(roi),
                          selected=observed, records=records))
    request, destination = native.DATA + 0x4000, native.DATA + 0x4200
    native.u.mem_write(request, struct.pack('<hhIhhhhI', 32, 32, 0x1357, 64, 64, 2, 2, cells))
    native.u.mem_write(destination, bytes(32))
    native.call(0x2cbcb2, request, destination, output)
    aggregate = dict(entry='0x102ebcb2', origin=[32, 32],
        valid=native.word(destination + 0xc), metric=native.word(destination + 0x10),
        position=list(struct.unpack('<hh', native.u.mem_read(destination + 0x14, 4))),
        tag=native.word(destination + 0x18))
    require((aggregate['valid'], aggregate['metric'], aggregate['position'], aggregate['tag']) ==
            (1, 100, [33, 30], 0x1357), 'Original component scaling or aggregation differs')
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        entry='0x102ebb0c', grid=[2, 2], cell_stride=16,
        signed_component_offsets=[0, 2], metric_offset=4, field_bits=16,
        metric_maximum=10000, rejected_component_values=[-512, 512], cases=cases,
        aggregate=aggregate, component_units_per_coordinate=32,
        limitations=['Synthetic cells and ROI; no image analysis or hardware completion.',
                     'Only this consumer is checked; the remaining cell bytes are not assigned semantics.',
                     'Exact sentinel rejection is not a general component range check.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS 12 original auxiliary result-cell/ROI cases and native coordinate aggregation')
