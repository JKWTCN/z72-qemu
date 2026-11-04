# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise native PCI/NVMe queues through the optional engine host windows."""
import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


def run(qemu):
    with tempfile.TemporaryDirectory(prefix='z72-nvme-') as folder:
        image = Path(folder) / 'card.raw'
        original = bytes((i * 13 + 5) & 255 for i in range(512))
        with image.open('wb') as output:
            output.write(original)
            output.truncate(16 * 1024**2)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen([qemu, '-M', 'nikon-z72-lab', '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-monitor', 'none', '-qmp', 'stdio',
            '-global', 'nikon-z72-boot-config.nvme-drive=card',
            '-drive', f'if=none,id=card,file={image},format=raw',
            '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off', '-qtest-log', '/dev/null'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wire = stream = None
        passed = False
        try:
            deadline = time.monotonic() + 15
            while wire is None:
                try:
                    wire = socket.create_connection(('127.0.0.1', port), timeout=3)
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError(process.stderr.read().decode())
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(.05)
            stream = wire.makefile('rwb')
            assert 'QMP' in json.loads(process.stdout.readline())
            irq = {}

            def monitor(name):
                process.stdin.write(json.dumps(dict(execute=name)).encode() + b'\n')
                process.stdin.flush()
                while True:
                    reply = json.loads(process.stdout.readline())
                    if 'event' not in reply:
                        assert 'return' in reply, reply
                        return reply['return']

            def command(line):
                stream.write(line.encode() + b'\n')
                stream.flush()
                while True:
                    reply = stream.readline().decode().split()
                    if reply and reply[0] == 'IRQ':
                        irq[int(reply[2])] = reply[1] == 'raise'
                        continue
                    assert reply and reply[0] == 'OK', reply
                    return reply[1] if len(reply) > 1 else None

            def read(address, width='l'):
                return int(command(f'read{width} {address:#x}'), 0)

            def write(address, value, width='l'):
                command(f'write{width} {address:#x} {value:#x}')

            def put(address, data):
                command(f'write {address:#x} {len(data):#x} 0x{data.hex()}')

            def get(address, length):
                return bytes.fromhex(command(f'read {address:#x} {length:#x}').removeprefix('0x'))

            def step():
                command('clock_step 1000000')

            monitor('qmp_capabilities')
            process.stdin.write(json.dumps(dict(execute='qom-list', arguments=dict(path='/machine/unattached'))).encode() + b'\n')
            process.stdin.flush()
            while True:
                reply = json.loads(process.stdout.readline())
                if 'return' in reply:
                    break
            gic = next(x['name'] for x in reply['return'] if x['type'] == 'child<arm_gic>')
            command('irq_intercept_in /machine/unattached/' + gic)
            dbi, config, bar, phy = 0x2a900000, 0x2a800000, 0x2a810000, 0x2b200000
            assert read(0x2b000010) & 0x404 == 0x404
            assert read(phy + 0x58) == 0
            assert read(phy + 0x210) == 0
            assert read(config) == 0xffffffff
            assert read(dbi + 0x104) & 0x4000
            monitor('system_reset')
            assert read(dbi + 0x104) == 0

            def train():
                write(phy + 0x50, 0)
                write(phy, 0x14)
                write(phy + 0xc, 3)
                assert read(phy + 0x58) >> 16 != 0x11
                write(phy + 0x50, 0x100)
                assert read(phy + 0x58) >> 16 != 0x11
                step()
                assert read(phy + 0x58) >> 16 == 0x11
                for index, words in enumerate([
                    [4, 0x80000000, config, 0, config + 0xffff, 0, 0],
                    [0, 0x80000000, bar, 0, 0x2a8fffff, bar, 0]]):
                    write(dbi + 0x900, index)
                    for offset, value in enumerate(words):
                        write(dbi + 0x904 + offset * 4, value)

            train()
            assert read(config + 8) >> 8 == 0x010802
            write(config + 0x10, bar)
            write(config + 0x14, 0)
            write(config + 0x20, 0x2a820000)
            write(config + 4, 6, 'w')
            assert read(bar + 8) >= 0x00010000
            assert read(phy + 0x210) == 0
            assert read(dbi + 0x104) == 0
            sq0, cq0, data = 0xb2000000, 0xb2001000, 0xb2002000
            sq1, cq1 = 0xb2004000, 0xb2005000
            for address in (sq0, cq0, data, sq1, cq1):
                put(address, bytes(4096))
            write(bar + 0x24, 7 | (7 << 16))
            write(bar + 0x28, sq0)
            write(bar + 0x2c, 0)
            write(bar + 0x30, cq0)
            write(bar + 0x34, 0)
            write(bar + 0x14, 0x460001)
            assert read(bar + 0x1c) & 3 == 1
            assert read(phy + 0x210) == 1
            tails = [0, 0]
            heads = [0, 0]
            phases = [1, 1]
            cid = 0
            msix_active = False
            last_result = 0

            def submit(qid, opcode, nsid=0, buffer=0, cdw10=0, cdw11=0, cdw12=0):
                nonlocal cid, last_result
                cid += 1
                words = [opcode | (cid << 16), nsid, 0, 0, 0, 0,
                         buffer, 0, 0, 0, cdw10, cdw11, cdw12, 0, 0, 0]
                put((sq0 if qid == 0 else sq1) + tails[qid] * 64, struct.pack('<16I', *words))
                tails[qid] = (tails[qid] + 1) % 8
                write(bar + 0x1000 + qid * 8, tails[qid])
                for _ in range(200):
                    step()
                    completion = struct.unpack('<4I', get((cq0 if qid == 0 else cq1) + heads[qid] * 16, 16))
                    if completion[3] & 0xffff == cid and completion[3] >> 16 & 1 == phases[qid]:
                        break
                else:
                    raise AssertionError(('NVMe completion timeout', qid, opcode, completion))
                if not msix_active:
                    assert irq.get(243 - 32, False)
                    assert read(phy + 0x24) & (1 << 28)
                    # The native ISR acknowledges the captured cause before
                    # its consumer advances the still-pending completion queue.
                    write(phy + 0x24, read(phy + 0x24))
                    assert not irq.get(243 - 32, False)
                    assert read(phy + 0x24) & (1 << 28) == 0
                heads[qid] = (heads[qid] + 1) % 8
                if heads[qid] == 0:
                    phases[qid] ^= 1
                write(bar + 0x1004 + qid * 8, heads[qid])
                last_result = completion[0]
                return completion[3] >> 17

            assert submit(0, 6, buffer=data, cdw10=1) == 0
            assert b'Z72-VIRTUAL-NVME' in get(data, 4096)
            assert get(data + 263, 1) == b'\x00'  # NPSS: PS0 only.
            assert submit(0, 10, cdw10=2 | (3 << 8)) == 0 and last_result == 4
            assert submit(0, 10, cdw10=2) == 0 and last_result == 0
            for value in (0, 0x20, 0x40):
                assert submit(0, 9, cdw10=2, cdw11=value) == 0
                assert submit(0, 10, cdw10=2) == 0 and last_result == value
            for value in (1, 0x60, 0x100):
                assert submit(0, 9, cdw10=2, cdw11=value) == 0x4002
                assert submit(0, 10, cdw10=2) == 0 and last_result == 0x40
            assert submit(0, 9, cdw10=0x80000002) == 0x410d
            for selection in (1, 2):
                assert submit(0, 10, cdw10=2 | (selection << 8)) == 0 and last_result == 0
            write(bar + 0x14, 0)
            assert read(phy + 0x210) == 0
            tails[:] = heads[:] = [0, 0]
            phases[:] = [1, 1]
            put(cq0, bytes(4096))
            write(bar + 0x14, 0x460001)
            assert submit(0, 10, cdw10=2) == 0 and last_result == 0
            assert submit(0, 6, nsid=1, buffer=data) == 0
            assert int.from_bytes(get(data, 8), 'little') == 16 * 1024**2 // 512
            assert submit(0, 5, buffer=cq1, cdw10=1 | (7 << 16), cdw11=3) == 0
            assert submit(0, 1, buffer=sq1, cdw10=1 | (7 << 16), cdw11=1 | (1 << 16)) == 0
            marker = bytes((i * 37 + 11) & 255 for i in range(512))
            put(data, marker)
            assert submit(1, 1, nsid=1, buffer=data, cdw10=7) == 0
            assert submit(1, 0, nsid=1) == 0
            put(data, bytes(512))
            assert submit(1, 2, nsid=1, buffer=data, cdw10=7) == 0
            assert get(data, 512) == marker
            assert submit(1, 2, nsid=1, buffer=data, cdw10=0x10000000) != 0
            assert read(dbi + 0x104) == 0
            assert not irq.get(243 - 32, False)
            assert read(phy + 0x24) & 0x30000000 == 0

            capability = read(config + 0x34, 'b')
            while capability and read(config + capability, 'b') != 0x11:
                capability = read(config + capability + 1, 'b')
            assert capability
            table_info = read(config + capability + 4)
            table_bar = read(config + 0x10 + 4 * (table_info & 7))
            table_base = table_bar & ~0xf
            if table_bar & 6 == 4:
                table_base |= read(config + 0x14 + 4 * (table_info & 7)) << 32
            table = table_base + (table_info & ~7)
            write(dbi + 0x820, 0xfee00000)
            write(dbi + 0x828, 1)
            write(table, 0xfee00000)
            write(table + 4, 0)
            write(table + 8, 0)
            write(table + 12, 0)
            write(config + capability + 2, read(config + capability + 2, 'w') | 0x8000, 'w')
            msix_active = True
            put(data, bytes([0xa5]) * 512)
            assert submit(1, 2, nsid=1, buffer=data, cdw10=7) == 0
            assert get(data, 512) == marker
            assert not irq.get(243 - 32, False) and read(phy + 0x24) & (1 << 28) == 0
            assert read(dbi + 0x830) == 1 and irq.get(246 - 32, False)
            write(dbi + 0x830, 1)
            assert read(dbi + 0x830) == 0 and not irq.get(246 - 32, False)
            write(dbi + 0x82c, 1)
            put(data, bytes([0x5a]) * 512)
            assert submit(1, 2, nsid=1, buffer=data, cdw10=7) == 0
            assert get(data, 512) == marker
            assert not irq.get(243 - 32, False) and read(phy + 0x24) & (1 << 28) == 0
            assert read(dbi + 0x830) == 1 and not irq.get(246 - 32, False)
            write(dbi + 0x82c, 0)
            assert irq.get(246 - 32, False)
            write(dbi + 0x830, 1)
            write(phy + 0x2c, 0x100)
            assert read(phy + 0x2c) == 0x100
            write(phy + 0x3c, 0x10)
            step()
            assert read(phy + 0x58) >> 16 == 0x15
            assert read(phy + 0x210) == 0
            assert read(phy + 0x2c) & (1 << 26)
            assert read(0x2b000010) & 0x404 == 0x404
            write(phy + 0x2c, 1 << 26)
            write(phy + 0xc, 0)
            assert read(bar + 0x1c) == 0xffffffff
            train()
            write(config + 0x10, bar)
            write(config + 0x14, 0)
            write(config + 4, 6, 'w')
            assert read(bar + 0x14) == 0 and read(bar + 0x1c) & 3 == 0
            assert read(phy + 0x210) == 0
            monitor('system_reset')
            assert read(dbi + 0x104) == read(dbi + 0x830) == read(phy + 0x58) == 0
            assert read(0x2b000010) & 0x404 == 0x404
            monitor('quit')
            process.wait(timeout=10)
            with image.open('rb') as source:
                assert source.read(512) == original
                source.seek(7 * 512)
                assert source.read(512) == marker
            passed = True
        finally:
            if stream is not None:
                stream.close()
            if wire is not None:
                wire.close()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            if not passed:
                print(process.stderr.read().decode(), flush=True)
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()
    print('PASS NVMe host: native Identify/queues/write/flush/read, INTx/MSI-X, source windows, cancellation, reset and backend bytes')
    missing = subprocess.run([qemu, '-M', 'nikon-z72-lab', '-display', 'none',
        '-serial', 'none', '-monitor', 'none', '-S',
        '-global', 'nikon-z72-boot-config.nvme-drive=missing'],
        capture_output=True, timeout=15)
    assert missing.returncode != 0 and b'selected block backend' in missing.stderr
    print('PASS NVMe host rejects an unknown selected backend')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    run(parser.parse_args().qemu)
