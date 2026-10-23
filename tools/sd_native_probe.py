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
        filesystem_dispatches = []
        filesystem_locks = []
        workers = []
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
                def call(self, offset, *arguments, **options):
                    from unicorn.arm_const import UC_ARM_REG_CPSR
                    result = super().call(offset, *arguments, **options)
                    for _ in range(8):
                        if self.pending_worker is None or result.get('fault'):
                            return result
                        target, flags, request = self.pending_worker
                        self.pending_worker = None
                        context = self.u.context_save()
                        self.in_worker = True
                        worker_result = super().call(target, flags, stack=0x50070000)
                        self.in_worker = False
                        filesystem_dispatches.append(dict(entry=hex(target), flags=hex(flags),
                            operation=self.u.mem_read(request + 0xBC, 1)[0],
                            response=struct.unpack('<i', self.u.mem_read(request + 0xC8, 4))[0],
                            result=worker_result))
                        if worker_result.get('fault') or worker_result.get('returned') == 'stopped':
                            return dict(fault='Filesystem worker did not return', worker_result=worker_result)
                        self.u.context_restore(context)
                        start = self.u.reg_read(self.pc)
                        if self.u.reg_read(UC_ARM_REG_CPSR) & 0x20:
                            start |= 1
                        result = self.execute(start, 2000000)
                    return dict(fault='Filesystem dispatch bound exceeded')

                def install_svc_trap(self):
                    def event_handle(address):
                        return struct.unpack('<I', self.u.mem_read(address, 4))[0]
                    def event_set(address, flags, *unused):
                        handle = event_handle(address)
                        self.event_flags[handle] = self.event_flags.get(handle, 0) | flags
                        self.result(0)
                    def event_clear(address, flags, *unused):
                        handle = event_handle(address)
                        self.event_flags[handle] = self.event_flags.get(handle, 0) & ~flags
                        self.result(0)
                    def post_request(address, flags, *unused):
                        target = event_handle(address + 0x24)
                        if self.in_worker or target != BASE + 0x59DD09:
                            raise ValueError('Unsupported filesystem task request')
                        self.pending_worker = ((target & ~1) - BASE, flags, address + 0x58)
                        self.result(0)
                        self.u.emu_stop()
                    if args.slot_query:
                        def mutex_acquire(address, *unused):
                            if address in self.held_mutexes:
                                raise ValueError('Filesystem request mutex is already held')
                            self.held_mutexes.add(address)
                            filesystem_locks.append(dict(object=hex(address), acquire=True))
                            self.result(0)
                        def mutex_release(address, *unused):
                            if address not in self.held_mutexes:
                                raise ValueError('Filesystem request mutex is not held')
                            self.held_mutexes.remove(address)
                            filesystem_locks.append(dict(object=hex(address), acquire=False))
                            self.result(0)
                        self.hook(0x3B5918, mutex_acquire)
                        self.hook(0x3B58FA, mutex_release)
                        self.hook(0x3406E4, post_request)
                        self.hook(0x3410CC, event_set)
                        self.hook(0x3410D2, event_clear)
                    def event_response(service, registers):
                        caller = self.u.reg_read(self.lr)
                        handle, mask, mode, output = registers
                        lock_callers = {0x80250300: 0x39F2FC, 0x80240200: 0x39F2E6}
                        if (self.in_worker and service in lock_callers and
                                (caller & ~1) == BASE + lock_callers[service] and mask == 1):
                            acquire = service == 0x80250300
                            if (handle in self.held_locks) == acquire:
                                raise ValueError('Filesystem serialization lock is not uncontended')
                            if acquire:
                                self.held_locks.add(handle)
                            else:
                                self.held_locks.remove(handle)
                            filesystem_locks.append(dict(handle=hex(handle), acquire=acquire))
                            return 0
                        if (args.slot_query and service == 0x80300500 and
                                (caller & ~1) == BASE + 0x3410F4):
                            available = self.event_flags.get(handle, 0)
                            if not available & mask:
                                raise ValueError('Filesystem worker has not produced a response')
                            self.u.mem_write(output, struct.pack('<I', available))
                            return 0
                        if service != 0x80300500 or (caller & ~1) != BASE + 0x34112C:
                            unmodeled_services.append(dict(service=hex(service), caller=hex(caller)))
                            raise ValueError('Unmodeled RTOS service or event caller')
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
                    workers.append(self)
                    self.u.mem_map(0x2A800000, 0x20000)
                    self.pending_dma = None
                    self.pending_worker = None
                    self.in_worker = False
                    self.event_flags = {}
                    self.held_locks = set()
                    self.held_mutexes = set()

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
            report['filesystem_dispatches'] = filesystem_dispatches
            report['filesystem_task_scheduling_is_host_modeled'] = True
            report['filesystem_lock_operations'] = filesystem_locks
            report['filesystem_lock_fixture'] = 'Single worker; serialization semaphore initially available'
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
            if args.slot_query:
                states = []
                for index in range(4):
                    base = 0xB2B464C0 + index * 0x38
                    try:
                        state = workers[0].u.mem_read(base + 0x3A, 1)[0]
                        words = struct.unpack('<7I', workers[0].u.mem_read(base, 0x1C))
                        states.append(dict(index=index, mount_state=state,
                                           words=[hex(word) for word in words]))
                    except Exception as error:
                        states.append(dict(index=index, error=str(error)))
                report['volume_table_states'] = states
            if args.mount and report['slot_query_succeeded']:
                # The filesystem worker request block is a fixed structure;
                # write an operation number and invoke the worker entry the
                # way the posted event does, then watch the volume states.
                attempts = []
                for operation in (3, 2):
                    context = workers[0].u.context_save()
                    workers[0].held_mutexes.clear()
                    workers[0].held_locks.clear()
                    workers[0].u.mem_write(0xB1D1B0C0 + 0xBC, bytes((operation,)))
                    workers[0].u.mem_write(0xB1D1B0C0 + 0xC8, struct.pack('<I', 0xDEADBEEF))
                    workers[0].in_worker = True
                    result = workers[0].call(0x59DD08, 1)
                    workers[0].in_worker = False
                    states = [workers[0].u.mem_read(0xB2B464C0 + index * 0x38 + 0x3A, 1)[0]
                              for index in range(2)]
                    response = struct.unpack('<I', workers[0].u.mem_read(0xB1D1B0C0 + 0xC8, 4))[0]
                    attempts.append(dict(operation=operation, result=result,
                                         response=response, volume_states=states))
                    if 4 in states:
                        break
                    if result.get('fault'):
                        workers[0].u.context_restore(context)
                report['mount_attempts'] = attempts
                report['mount_verified'] = any(4 in a['volume_states'] for a in attempts)
                states = []
                for index in range(4):
                    base = 0xB2B464C0 + index * 0x38
                    try:
                        state = workers[0].u.mem_read(base + 0x3A, 1)[0]
                        words = struct.unpack('<7I', workers[0].u.mem_read(base, 0x1C))
                        states.append(dict(index=index, mount_state=state,
                                           words=[hex(word) for word in words]))
                    except Exception as error:
                        states.append(dict(index=index, error=str(error)))
                report['volume_table_states_after_mount'] = states

            if args.list_directory is not None and report['slot_query_succeeded']:
                worker = workers[0]
                path, output, record = 0x50006000, 0x50006400, 0x50006800
                worker.u.mem_write(path, args.list_directory.encode('ascii') + bytes(1))
                opened = worker.call(0x47D2E6, path, output)
                directory = dict(path=args.list_directory, open_result=opened, entries=[])
                if opened.get('value') == 0:
                    handle = struct.unpack('<I', worker.u.mem_read(output, 4))[0]
                    for _ in range(64):
                        fetched = worker.call(0x47D3DA, handle, record)
                        if fetched.get('value') != 0:
                            directory['end_result'] = fetched
                            break
                        raw = bytes(worker.u.mem_read(record, 0x220))
                        short = raw[:13].split(bytes(1))[0].decode('ascii', errors='replace')
                        wide = raw[14:526].decode('utf-16-le', errors='replace').split(chr(0))[0]
                        directory['entries'].append(dict(short_name=short, long_name=wide,
                                                        size=struct.unpack_from('<I', raw, 0x218)[0]))
                    directory['close_result'] = worker.call(0x47D3F8, handle)
                report['directory'] = directory
                report['filesystem_mount_verified'] = (
                    opened.get('value') == 0 and directory.get('end_result', {}).get('value') == 1)
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
    parser.add_argument('--mount', action='store_true',
                        help='Drive filesystem worker operations two and three after the slot query')
    parser.add_argument('--list-directory', help='List a camera path after slot query, for example A:\\')
    arguments = parser.parse_args()
    if arguments.list_directory is not None or arguments.mount:
        arguments.slot_query = True
    run(arguments)
