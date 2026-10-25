# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify diagnostic log retention offline using synthetic memory contents.

Original command dispatch, dump formatting, log records, output selection and
flush logic execute. Console consumption, kernel services and serial output
are supplied. This does not prove that a camera consumes queued PTP text.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import MASTER_SHA, require, validate_master
from tools.usb_debug_probe import Probe


def log_case(master, native_selection):
    probe = Probe(master)
    probe.call(0x39CBCC, 0)
    probe.u.mem_write(probe.SAMPLE, bytes(range(16)))
    probe.u.mem_write(probe.OUTPUT_SELECT, b'\x01')
    probe.u.mem_write(probe.LOG_GATE, b'\x00')
    if native_selection:
        probe.call(0x3BA664, 2)
    del probe.hooks[0x103DA804]  # Execute the original print route and record formatter.
    probe.consume('memdump 0x%08x 8' % probe.SAMPLE)
    written, read_before = (probe.word(probe.LOG_GATE + offset) for offset in (4, 8))
    require(written == 2 and read_before == 0, 'Expected two unread dump records')
    records = [bytes(probe.u.mem_read(0xB18B9DA8 + index * 128, 128))
               for index in range(written)]
    lengths = [int.from_bytes(record[12:14], 'little') for record in records]
    texts = [record[16:16 + size].decode('ascii') for record, size in zip(records, lengths)]
    require('00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f' in texts[1],
            'Original log record omitted the synthetic dump bytes')
    serial = []
    probe.hooks[0x100201EC] = lambda value, *args: serial.append(value & 255) or 0
    probe.call(0x3655F8, 1)
    read_after = probe.word(probe.LOG_GATE + 8)
    require(read_after == (0 if native_selection else 2) and
            bool(serial) == (not native_selection), 'Log flush did not follow its separate gate')
    result = dict(selection='original output-selection function' if native_selection else 'admission byte only',
                  admission_byte=probe.u.mem_read(probe.OUTPUT_SELECT, 1)[0],
                  log_gate=probe.u.mem_read(probe.LOG_GATE, 1)[0],
                  write_sequence=written, read_sequence_before=read_before,
                  read_sequence_after=read_after, serial_output_observed=bool(serial),
                  record_bytes=128, text_offset=16, text_lengths=lengths,
                  synthetic_dump_text=texts[1], records_retained=read_after == 0)
    if native_selection:
        probe.call(0x3BA664, 1)
        probe.call(0x3655F8, 1)
        require(probe.word(probe.LOG_GATE + 8) == written,
                'Restoring serial selection did not drain pending records')
        result['serial_restore_drains_pending_records'] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    master = args.master.read_bytes()
    validate_master(master)
    report = dict(format=1, master_sha256=MASTER_SHA, firmware_included=False,
                  cases=[log_case(master, False), log_case(master, True)],
                  actual_camera_access=False, queued_ptp_line_consumer_verified=False,
                  limitations=['Dump contents are synthetic RAM, not boot material.',
                               'Command-name splitting and invocation of the consumer are supplied.',
                               'Kernel services report success; serial bytes are captured by the host.'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS diagnostic admission, separate log-retention gate and serial restoration')


if __name__ == '__main__':
    main()
