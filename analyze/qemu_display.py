# SPDX-License-Identifier: GPL-2.0-or-later
"""QEMU system-mode laboratory infrastructure.

Provides the RSP/GDB remote, a machine launcher that preloads an image with
the generic loader, and first-level translation-table adaptation. Images are
deliberately preloaded; this cannot verify camera loading. Physical bases are
adapted to laboratory RAM; original section attributes survive.
"""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import PROFILES

class Remote:
    def __init__(self, port):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=10)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(15)
        self.command('qSupported:xmlRegisters=arm')
        self.layout = []
        self.offsets = {}
        self.register_numbers = {}
        self.next_register_number = 0
        def xml(name):
            data = bytearray()
            while True:
                packet = self.command(f'qXfer:features:read:{name}:{len(data):x},fff')
                require(packet[:1] in ('m','l'), 'Missing target XML')
                data.extend(packet[1:].encode())
                if packet[0] == 'l':
                    break
            tree = ET.fromstring(data.decode().replace('xi:include', 'include'))
            for element in ([tree] if tree.tag == 'feature' else tree):
                if element.tag.endswith('include'):
                    xml(element.attrib['href'])
                elif element.tag == 'feature':
                    for reg in element.findall('reg'):
                        self.layout.append((reg.attrib['name'], int(reg.attrib['bitsize']) // 8))
                        number = int(reg.attrib.get('regnum', self.next_register_number))
                        self.register_numbers[reg.attrib['name']] = number
                        self.next_register_number = number + 1
        xml('target.xml')
        offset = 0
        for name,size in self.layout:
            self.offsets[name] = (offset,size)
            offset += size
        for alias,name in [('pc','r15'),('sp','r13'),('lr','r14')]:
            if alias not in self.offsets and name in self.offsets:
                self.offsets[alias] = self.offsets[name]
        self.command('Hg0')

    def command(self, payload):
        encoded = payload.encode()
        self.sock.sendall(b'$' + encoded + b'#' + f'{sum(encoded)&255:02x}'.encode())
        return self.receive()

    def receive(self):
        while True:
            first = self.sock.recv(1)
            require(bool(first), 'Debugger disconnected')
            if first == b'$':
                break
        data = bytearray()
        while True:
            c = self.sock.recv(1)
            if c == b'#':
                break
            require(bool(c), 'Debugger disconnected')
            data.extend(c)
        checksum = self.sock.recv(2)
        if len(checksum) == 1:
            checksum += self.sock.recv(1)
        require(checksum == f'{sum(data)&255:02x}'.encode(), 'Remote checksum mismatch')
        self.sock.sendall(b'+')
        # XML packets are text; register/memory responses are hexadecimal.
        decoded = bytearray()
        index = 0
        while index < len(data):
            value = data[index]
            if value == 125:
                index += 1
                decoded.append(data[index] ^ 32)
            elif value == 42:
                index += 1
                decoded.extend(bytes([decoded[-1]]) * (data[index] - 29))
            else:
                decoded.append(value)
            index += 1
        return decoded.decode()

    def select_thread(self, thread):
        require(self.command(f'Hg{thread:x}') == 'OK', 'Debugger thread selection failed')

    def interrupt(self):
        self.sock.sendall(b'\x03')
        return self.receive()

    def regs(self):
        return bytearray.fromhex(self.command('g'))

    def read_register(self, name):
        # Some system registers are exposed individually but omitted from
        # the bulk packet. Use their XML numbers instead of packet offsets.
        value = self.command(f'p{self.register_numbers[name]:x}')
        require(not value.startswith('E') and bool(value), 'Register read failed')
        return int.from_bytes(bytes.fromhex(value), 'little')

    def get(self, data, name):
        offset,size = self.offsets[name]
        return int.from_bytes(data[offset:offset+size], 'little')

    def set(self, **values):
        data = self.regs()
        for name,value in values.items():
            offset,size = self.offsets[name]
            data[offset:offset+size] = value.to_bytes(size, 'little')
        require(self.command('G'+data.hex()) == 'OK', 'Register write failed')

    def read(self, address, size):
        result = bytearray()
        for start in range(0,size,512):
            response = self.command(f'm{address+start:x},{min(512,size-start):x}')
            require(not response.startswith('E'), 'Memory read failed')
            result.extend(bytes.fromhex(response))
        return bytes(result)

    def write(self, address, data):
        require(self.command(f'M{address:x},{len(data):x}:'+data.hex()) == 'OK', 'Memory write failed')

    def breakpoint(self, address, add=True):
        require(self.command(f'{"Z" if add else "z"}1,{address:x},2') == 'OK', 'Breakpoint failed')

class Machine:
    def __init__(self, qemu, directory, image, table, backend="virt", role="master"):
        require(role in PROFILES, 'Unknown firmware role')
        require(backend in ('virt', 'nikon-z72-lab'), 'Unknown backend')
        directory.mkdir()
        image_file = directory / (role + '.bin')
        image_file.write_bytes(image)
        (directory/'table.bin').write_bytes(table)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            port = sock.getsockname()[1]
        self.stderr = (directory/'qemu.log').open('wb')
        machine = 'virt,virtualization=off,secure=off' if backend == 'virt' else 'nikon-z72-lab'
        if backend == 'nikon-z72-lab' and role == 'slave':
            machine = 'nikon-z72-slave-lab'
        image_base = 0x42020000 if backend == 'virt' else BASE
        command = [qemu,'-M',machine,'-cpu','cortex-a7','-m','256M',
                   '-display','none','-serial','none','-monitor','none','-nic','none','-S',
                   '-gdb',f'tcp:127.0.0.1:{port}',
                   '-device',f'loader,file={directory.parent / "harness.bin"},addr=0x40100000,cpu-num=0,force-raw=on',
                   '-device',f'loader,file={image_file},addr={image_base:#x},force-raw=on',
                   '-device',f'loader,file={directory / "table.bin"},addr=0x40110000,force-raw=on']
        (directory/'command.json').write_text(json.dumps(command,indent=2),encoding='utf-8')
        self.process = subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=self.stderr,
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        try:
            deadline = time.monotonic()+10
            while True:
                try:
                    self.remote = Remote(port)
                    break
                except ConnectionRefusedError:
                    require(self.process.poll() is None, 'QEMU exited during startup')
                    require(time.monotonic()<deadline, 'QEMU startup timed out')
                    time.sleep(0.05)
            self.remote.breakpoint(0x40100080)
            self.remote.command('c')
            require(self.remote.get(self.remote.regs(),'pc')==0x40100080, 'MMU harness did not reach ready')
            self.remote.breakpoint(0x40100080,False)
            for address in (0x40100104,0x4010010C,0x40100110):
                self.remote.breakpoint(address)
        except BaseException:
            self.close()
            raise

    def close(self):
        if hasattr(self,'remote'):
            self.remote.sock.close()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.stderr.close()

def table_for(stock, xn=False, backend="virt", role="master"):
    require(backend in ('virt', 'nikon-z72-lab'), 'Unknown backend')
    require(role in PROFILES, 'Unknown firmware role')
    table = bytearray(16384)
    original = struct.unpack_from('<4096I',stock,0x10000)
    # Preserve original domain/access/cache/XN bits for firmware and RAM.
    windows = PROFILES[role].windows
    for first,last,physical in windows:
        if backend == "nikon-z72-lab":
            physical = first
        for index in range(first,last):
            word = original[index]
            require(word & 3 == 2 and not word & (1<<18), 'Expected section descriptor')
            word = ((physical+index-first)<<20) | (word & 0xFFFFF)
            if xn and index == 0x124:
                word |= 16
            struct.pack_into('<I',table,index*4,word)
    # Synthetic harness/vector/TTBR physical RAM identity mapping.
    struct.pack_into('<I',table,0x401*4,0x40100C02)
    return bytes(table)
