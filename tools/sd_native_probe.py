# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute captured card workers with MMIO forwarded to the QEMU SD host.

Firmware instructions run in the bounded snapshot environment. Only the
recovered bus/host windows use QEMU; RTOS and other platform fixtures retain
the limitations of card_worker_probe. Card writes use a temporary overlay.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.card_slot_probe import linux
from tools.card_worker_probe import CardWorker, run as run_workers


def run(args):
    from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ
    with tempfile.TemporaryDirectory(prefix='sd-native-', dir=ROOT / '.local') as folder:
        image = args.card_image
        if image is None:
            image = Path(folder) / 'card.raw'
            with image.open('wb') as output:
                output.truncate(1024 * 1024)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        command = [str(args.qemu.resolve()), '-M', 'nikon-z72-lab', '-accel', 'qtest',
                   '-display', 'none', '-serial', 'none', '-monitor', 'none',
                   '-qmp', 'stdio', '-global', 'nikon-z72-boot-config.sd-host=on',
                   '-drive', f'if=none,id=card,file={image.resolve()},format=raw,snapshot=on',
                   '-device', 'sd-card,drive=card', '-qtest',
                   f'tcp:127.0.0.1:{port},server=on,wait=off', '-qtest-log', '/dev/null']
        if os.name == 'nt':
            command = ['wsl.exe', '--exec', *(linux(part) for part in command)]
        process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wire = stream = None
        host_writes = []
        try:
            deadline = time.monotonic() + 10
            while wire is None:
                try:
                    wire = socket.create_connection(('127.0.0.1', port), timeout=5)
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError(process.stderr.read().decode())
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(.05)
            stream = wire.makefile('rwb')

            def qtest(text):
                stream.write(text.encode() + b'\n')
                stream.flush()
                reply = stream.readline().decode().split()
                if not reply or reply[0] != 'OK':
                    raise RuntimeError('Qtest failure: ' + str(reply))
                return int(reply[1], 0) if len(reply) > 1 else None

            class SDHostWorker(CardWorker):
                def __init__(self, *inputs):
                    super().__init__(*inputs)
                    self.u.mem_map(0x2A800000, 0x20000)

                    def access(u, kind, address, size, value, unused):
                        suffix = {1: 'b', 2: 'w', 4: 'l'}[size]
                        if kind == UC_MEM_READ:
                            value = qtest(f'read{suffix} {address:#x}')
                            u.mem_write(address, value.to_bytes(size, 'little'))
                        else:
                            qtest(f'write{suffix} {address:#x} {value:#x}')
                            if 0x2A810000 <= address < 0x2A810100 and len(host_writes) < 256:
                                host_writes.append(dict(address=hex(address), size=size,
                                                        value=hex(value)))
                    for start, end in ((0x2A800000, 0x2A81FFFF),
                                       (0x2A900000, 0x2A900FFF),
                                       (0x2B000000, 0x2B000FFF),
                                       (0x2B200000, 0x2B200FFF)):
                        self.u.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, access,
                                        begin=start, end=end)

            args.capability_all = False
            args.sd_host = True
            args.experiment = ['sd_board_context_init', 'sd_bus_power_on', 'sd_module_op1']
            report = run_workers(args, worker_class=SDHostWorker)
            # Retain per-stage tails and counters without duplicating the
            # startup-heavy first-512 access log in the bridge record.
            report.pop('peripheral_access_total')
            for experiment in report['experiments']:
                experiment.pop('peripheral_access')
            report['peripheral_capture'] = 'Last 64 accesses per stage; total counters retained'
            report['device_backend'] = 'QEMU SDHCI via qtest; bounded firmware execution'
            report['host_register_writes'] = host_writes
            report['host_register_write_limit'] = 256
            report['native_menu_update_verified'] = False
            (args.destination / 'report.json').write_text(
                json.dumps(report, indent=2) + '\n', encoding='utf-8')
            return report
        finally:
            if stream:
                stream.close()
            if wire:
                wire.close()
            if process.poll() is None:
                process.stdin.write(b'{"execute":"qmp_capabilities"}\n{"execute":"quit"}\n')
                process.stdin.flush()
                process.wait(timeout=10)
            for pipe in (process.stdin, process.stdout, process.stderr):
                pipe.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True, type=Path)
    parser.add_argument('--ram-dump', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--card-image', type=Path,
                        help='Optional raw card image; writes stay in a temporary overlay')
    run(parser.parse_args())
