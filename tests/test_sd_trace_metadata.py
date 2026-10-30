# SPDX-License-Identifier: GPL-2.0-or-later
"""Keep SD command metadata bounded and exclude data-port contents."""
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from tools.body_shutter_gate_probe import sd_trace_snapshot


def check():
    with tempfile.TemporaryDirectory(prefix='sd-trace-metadata-') as directory:
        machine = SimpleNamespace(work=Path(directory), args=SimpleNamespace(trace_sd_host=True))
        lines = [
            '123@456:sdhci_access wr32: addr[0x0000] <- 0x14001000 (335548416)',
            '123@456:sdhci_access rd32: addr[0x0020] -> 0xdeadbeef (3735928559)',
            '123@456:sdhci_access wr32: addr[0x0020] <- 0xdeadbeef (3735928559)',
            '123@456:sdhci_send_command CMD24 ARG[0x00000000]',
            '123@456:sdcard_write_block addr 0x0 size 0x200',
            '123@456:sdhci_adma_loop addr=0x15100000, len=512, attr=0x23',
        ]
        trace = machine.work / 'qemu.log'
        trace.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        result = sd_trace_snapshot(machine)
        require(len(result['events']) == 4 and not result['truncated'], 'SD trace selection differs')
        require('deadbeef' not in str(result) and result['events'][0]['value'] == '0x14001000',
                'SD trace exposed data-port contents or lost the DMA address')
        trace.write_text((lines[3] + '\n') * 300, encoding='utf-8')
        result = sd_trace_snapshot(machine)
        require(len(result['events']) == 256 and result['counts']['selected'] == 300 and
                result['truncated'], 'SD trace metadata was not bounded')
        machine.args.trace_sd_host = False
        require(sd_trace_snapshot(machine) is None, 'Disabled trace did not preserve default behavior')
    print('PASS bounded SD metadata, command ordering and data-port exclusion')


if __name__ == '__main__':
    check()
