# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute captured card workers with MMIO forwarded to the QEMU SD host.

Firmware instructions run in the bounded snapshot environment. Only the
recovered bus/host windows use QEMU; RTOS and other platform fixtures retain
the limitations of card_worker_probe. Card writes use a temporary overlay.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.card_slot_probe import linux
from tools.card_worker_probe import BASE, CardWorker, run as run_workers


def run(args):
    from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ
    with tempfile.TemporaryDirectory(prefix='sd-native-', dir=ROOT / '.local') as folder:
        image = args.card_image
        if image is None:
            image = Path(folder) / 'card.raw'
            with image.open('wb') as output:
                output.truncate(1024 * 1024)
        with image.open('rb') as source:
            first_sector_sha256 = hashlib.sha256(source.read(512)).hexdigest()
            source.seek(0)
            image_sha256 = hashlib.file_digest(source, 'sha256').hexdigest()
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
        completion_events = []
        card_commands = []
        dma_transfers = []
        unmodeled_services = []
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
                if text.startswith('read '):
                    return bytes.fromhex(reply[1].removeprefix('0x'))
                return int(reply[1], 0) if len(reply) > 1 else None

            class SDHostWorker(CardWorker):
                def install_svc_trap(self):
                    def event_response(service, registers):
                        caller = self.u.reg_read(self.lr)
                        if service != 0x80300500 or (caller & ~1) != BASE + 0x34112C:
                            unmodeled_services.append(dict(service=hex(service), caller=hex(caller)))
                            raise ValueError('Unmodeled RTOS service or event caller')
                        handle, mask, mode, output = registers
                        if mode != 1:
                            raise ValueError('Unsupported card event wait mode')
                        qtest('clock_step 1000000')
                        status = qtest('readl 0x2a810030')
                        if status & 2 and self.pending_dma is not None:
                            transfer = self.pending_dma
                            if transfer['read']:
                                digest = hashlib.sha256()
                                for span in transfer['spans']:
                                    address, length = span['address'], span['length']
                                    data = qtest(f'read {address:#x} {length:#x}')
                                    self.u.mem_write(address, data)
                                    digest.update(data)
                                transfer['data_sha256'] = digest.hexdigest()
                            transfer['completed'] = True
                            self.pending_dma = None
                        matched = status & mask
                        if len(completion_events) < 256:
                            completion_events.append(dict(mask=hex(mask), status=hex(status),
                                                          matched=hex(matched)))
                        if not matched:
                            return 1
                        # Bounded event delivery from device status, standing
                        # in for the original IRQ callback and RTOS event wait.
                        self.u.mem_write(output, struct.pack('<I', status))
                        qtest(f'writel 0x2a810030 {matched:#x}')
                        return 0
                    super().install_svc_trap(response=event_response)

                def __init__(self, *inputs):
                    super().__init__(*inputs)
                    self.u.mem_map(0x2A800000, 0x20000)
                    self.pending_dma = None

                    def prepare_dma(command_word, mode):
                        if not (command_word & 0x20 and mode & 1):
                            return
                        if qtest('readb 0x2a810028') & 0x18 != 0x10:
                            raise ValueError('Only observed ADMA2-32 transfers are supported')
                        cursor = qtest('readl 0x2a810058')
                        remaining = (qtest('readw 0x2a810004') & 0xFFF) * qtest('readw 0x2a810006')
                        transfer = dict(descriptor=hex(cursor), read=bool(mode & 16),
                                        spans=[], completed=False)
                        # QEMU and the snapshot executor have separate RAM.
                        # Mirror actual descriptors before DMA and actual
                        # transferred buffers after device completion.
                        for _ in range(64):
                            raw = bytes(self.u.mem_read(cursor, 8))
                            attributes, length, address = struct.unpack('<HHI', raw)
                            qtest(f'write {cursor:#x} 8 0x{raw.hex()}')
                            if not attributes & 1:
                                break
                            action = attributes & 0x30
                            if action == 0x20:
                                length = min(length or 65536, remaining)
                                if length:
                                    transfer['spans'].append(dict(address=address, length=length))
                                    if not transfer['read']:
                                        data = bytes(self.u.mem_read(address, length))
                                        qtest(f'write {address:#x} {length:#x} 0x{data.hex()}')
                                    remaining -= length
                            elif action not in (0, 0x30):
                                raise ValueError('Unsupported ADMA2 descriptor action')
                            if attributes & 2 or not remaining:
                                break
                            cursor = address if action == 0x30 else cursor + 8
                        else:
                            raise ValueError('ADMA2 descriptor chain exceeds the probe bound')
                        dma_transfers.append(transfer)
                        self.pending_dma = transfer

                    def access(u, kind, address, size, value, unused):
                        suffix = {1: 'b', 2: 'w', 4: 'l'}[size]
                        if kind == UC_MEM_READ:
                            value = qtest(f'read{suffix} {address:#x}')
                            u.mem_write(address, value.to_bytes(size, 'little'))
                        else:
                            is_command = ((address == 0x2A81000C and size == 4) or
                                          (address == 0x2A81000E and size == 2))
                            command_word = value >> 16 if size == 4 else value
                            if is_command:
                                mode = value & 0xFFFF if size == 4 else qtest('readw 0x2a81000c')
                                prepare_dma(command_word, mode)
                            qtest(f'write{suffix} {address:#x} {value:#x}')
                            if is_command and len(card_commands) < 128:
                                card_commands.append(dict(index=(command_word >> 8) & 63,
                                    flags=hex(command_word & 255),
                                    argument=hex(qtest('readl 0x2a810008')),
                                    response0=hex(qtest('readl 0x2a810010'))))
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
            args.experiment = ['sd_board_context_init', 'sd_bus_power_on',
                               'query_local_slot1' if args.slot_query else 'sd_module_op1']
            report = run_workers(args, worker_class=SDHostWorker, quiet=True)
            # Retain per-stage tails and counters without duplicating the
            # startup-heavy first-512 access log in the bridge record.
            report.pop('peripheral_access_total')
            for experiment in report['experiments']:
                experiment.pop('peripheral_access')
            report['peripheral_capture'] = 'Last 64 accesses per stage; total counters retained'
            report['device_backend'] = 'QEMU SDHCI via qtest; bounded firmware execution'
            report['host_register_writes'] = host_writes
            report['host_register_write_limit'] = 256
            report['completion_events'] = completion_events
            report['unmodeled_services'] = unmodeled_services
            report['completion_event_delivery_is_host_modeled'] = True
            report['card_commands'] = card_commands
            report['card_command_log_limit'] = 128
            report['dma_transfers'] = dma_transfers
            report['dma_ram_coherence_is_host_modeled'] = True
            report['card_image'] = dict(size=image.stat().st_size, sha256=image_sha256,
                                       first_sector_sha256=first_sector_sha256)
            result = report['experiments'][-1]
            report['card_open_succeeded'] = (result['result'].get('value') == 0
                                             if not args.slot_query else None)
            report['first_sector_read_verified'] = any(
                transfer['completed'] and transfer.get('data_sha256') == first_sector_sha256
                and sum(span['length'] for span in transfer['spans']) == 512
                for transfer in dma_transfers)
            report['filesystem_mount_verified'] = False
            report['slot_query_succeeded'] = (result['result'].get('value') == 1
                and result.get('query_status') == 0) if args.slot_query else None
            report['passed'] = bool(report['first_sector_read_verified'] and
                (report['slot_query_succeeded'] if args.slot_query else report['card_open_succeeded']))
            report['pass_condition'] = (
                ('Slot query returned one with status zero' if args.slot_query else 'Native SD open returned zero')
                + ' and DMA delivered the image first sector; this does not establish filesystem mounting or menu update acceptance')
            report['native_menu_update_verified'] = False
            (args.destination / 'report.json').write_text(
                json.dumps(report, indent=2) + '\n', encoding='utf-8')
            print(('PASS ' if report['passed'] else 'FAIL ') +
                  ('native slot query' if args.slot_query else 'native SD open') + ' and first-sector read', flush=True)
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
    parser.add_argument('--slot-query', action='store_true',
                        help='Continue through the original slot query toward filesystem attachment')
    run(parser.parse_args())
