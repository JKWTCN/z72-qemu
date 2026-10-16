# SPDX-License-Identifier: GPL-2.0-or-later
"""Serve a local browser console for the experimental combined machine."""
import argparse
from collections import deque
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from analyze.firmware_structure import analyze_eg
from tools.controller_core_probe import CONTROLLER_SHA256
from tools.create_lab_parameters import parameter_images, resource_header_image
from tools.dual_boot_probe import dual_machine

SYNC_WAIT = 0x102d949e
APP_MANAGER = 0xb1811e40
WEB = ROOT / 'web'


def linux(value):
    return re.sub(r'([A-Za-z]):[\\/][^,]*',
                  lambda m: '/mnt/' + m[1].lower() + '/' +
                            m[0][3:].replace('\\', '/'), str(value))


def ppm_to_png(data):
    """Encode the P6 RGB frames produced by the monitor without dependencies."""
    header = re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\r?\n', data)
    require(header is not None, 'Unexpected frame format')
    width, height = map(int, header.groups())
    pixels = data[header.end():]
    require(0 < width <= 4096 and 0 < height <= 4096 and
            len(pixels) == width * height * 3, 'Invalid frame dimensions or length')

    def chunk(tag, payload):
        raw = tag + payload
        return struct.pack('>I', len(payload)) + raw + struct.pack('>I', zlib.crc32(raw))

    stride = width * 3
    rows = b''.join(b'\0' + pixels[start:start + stride]
                    for start in range(0, len(pixels), stride))
    return (b'\x89PNG\r\n\x1a\n' +
            chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(rows, 3)) + chunk(b'IEND', b''))


class QmpClient:
    def __init__(self, port):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.file = self.sock.makefile('rwb')
        self.read()
        self.command('qmp_capabilities')

    def read(self):
        while True:
            line = self.file.readline()
            if not line:
                raise ConnectionError('Machine monitor disconnected')
            message = json.loads(line)
            if 'event' not in message:
                return message

    def command(self, name, arguments=None):
        request = dict(execute=name)
        if arguments is not None:
            request['arguments'] = arguments
        self.file.write(json.dumps(request).encode() + b'\n')
        self.file.flush()
        reply = self.read()
        if 'error' in reply:
            raise RuntimeError(reply['error'].get('desc', 'Machine monitor error'))
        return reply['return']

    def close(self):
        self.file.close()
        self.sock.close()


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class Machine:
    """Own one process; serialize monitor/input commands and lifecycle changes."""

    def __init__(self, args):
        self.args = args
        self.io = threading.Lock()
        self.lifecycle = threading.Lock()
        self.phase = 'stopped'
        self.error = None
        self.process = self.remote = self.wire = self.qmp = self.work = None
        self.held = set()
        self.requested_keys = set()
        self.key_events = {}
        self.next_key_ticks = {}
        self.key_deadline = 0
        self.started_at = None
        self.shutdown = threading.Event()
        self.worker = None
        self.watchdog = threading.Thread(target=self._release_expired, daemon=True)
        self.watchdog.start()

    def restart(self):
        if self.shutdown.is_set() or not self.lifecycle.acquire(blocking=False):
            return False
        self.phase, self.error = 'starting', None
        self.worker = threading.Thread(target=self._boot, daemon=True)
        self.worker.start()
        return True

    def _boot(self):
        try:
            with self.io:
                self._cleanup()
            self._start()
            self.phase = 'running'
        except Exception as error:
            self.error = str(error)
            with self.io:
                self._cleanup()
            self.phase = 'failed'
            print('Machine start failed:', self.error, flush=True)
        finally:
            self.lifecycle.release()

    def _start(self):
        import hashlib
        master, slave = self.args.master.read_bytes(), self.args.slave.read_bytes()
        for role, data in (('master', master), ('slave', slave)):
            analyze_eg(data, role)
        require(hashlib.sha256(self.args.controller.read_bytes()).hexdigest() ==
                CONTROLLER_SHA256, 'Expected the original controller image')
        (ROOT / '.local').mkdir(exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix='web-console-', dir=ROOT / '.local'))
        qtest_port, qmp_port = free_port(), free_port()
        original = subprocess.Popen
        work = self.work

        class Launcher(original):
            def __init__(child, command, *extra, **keywords):
                command[command.index('-M') + 1] += ',controller-battery-peer=on'
                command += ['-qtest', f'tcp:127.0.0.1:{qtest_port},server=on,wait=off',
                            '-qtest-log', '/dev/null' if os.name != 'nt' or self.args.wsl else 'NUL',
                            '-qmp', f'tcp:127.0.0.1:{qmp_port},server=on,wait=off']
                child.pid_file = work / 'process.pid'
                if self.args.wsl:
                    command = ['wsl.exe', '--exec', 'sh', '-c',
                               'echo $$ > ' + shlex.quote(linux(child.pid_file)) +
                               '; exec ' + shlex.join([linux(part) for part in command])]
                super().__init__(command, *extra, **keywords)

            def terminate(child):
                if self.args.wsl and child.poll() is None and child.pid_file.exists():
                    pid = child.pid_file.read_text().strip()
                    require(pid.isdecimal(), 'Invalid owned process identifier')
                    with original(['wsl.exe', '--exec', 'kill', '-TERM', pid],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  creationflags=subprocess.CREATE_NO_WINDOW) as reaper:
                        reaper.wait(timeout=5)
                else:
                    super().terminate()

        resident = bytearray(0xc000)
        resident[:4] = b'MAKE'
        (work / 'resident.bin').write_bytes(resident)
        primary, auxiliary = bytearray(256), bytearray(256)
        primary[11] = 1
        auxiliary[9], auxiliary[12] = 8, 0xc9
        (work / 'primary.bin').write_bytes(primary)
        (work / 'aux.bin').write_bytes(auxiliary)
        for name, data in zip(('group17.bin', 'group18.bin', 'group32.bin'),
                              (*parameter_images(), resource_header_image())):
            (work / name).write_bytes(data)
        devices = (
            'nikon-z72-controller-register-bank,bus=controller-i2c0,address=79',
            'nikon-z72-controller-expander,bus=controller-i2c0,address=34,id=keys',
            f'nikon-z72-controller-register-bank,bus=controller-i2c0,address=107,initial-state={work / "primary.bin"}',
            f'nikon-z72-controller-register-bank,bus=controller-i2c0,address=13,initial-state={work / "aux.bin"}')
        devices += tuple(f'loader,file={work / name},addr={address:#x},force-raw=on'
                         for name, address in (('group17.bin', 0x132c0000),
                                               ('group18.bin', 0x132e0000),
                                               ('group32.bin', 0x13e80000)))
        devices += tuple(f'nikon-z72-controller-register-bank,bus=master-i2c{i},address=104'
                         for i in range(4))
        self.process, self.remote = dual_machine(self.args.qemu, work, master, slave,
            work / 'console.txt', trace='guest_errors', controller_firmware=self.args.controller,
            controller_link=True, controller_flash_data=work / 'resident.bin', devices=devices,
            globals_=tuple(f'nikon-z72-controller-adc.channel{c}={v}'
                           for c, v in ((0, 1800), (1, 3001), (3, 3001))),
            process_factory=Launcher)
        self.started_at = time.monotonic()
        self.wire = socket.create_connection(('127.0.0.1', qtest_port), timeout=5)
        self.wire_file = self.wire.makefile('rwb')
        self.qmp = QmpClient(qmp_port)
        devices = self.qmp.command('qom-list', {'path': '/machine/unattached'})

        def children(kind):
            return sorted((item['name'] for item in devices if item['type'] == f'child<{kind}>'),
                          key=lambda item: int(re.search(r'\d+', item)[0]))

        gpios, configs = children('nikon-z72-controller-gpio'), children('nikon-z72-boot-config')
        require(len(gpios) == 8 and len(configs) == 2, 'Missing controller or engine inputs')
        for index, pin, level in ((2, 5, 0), (3, 13, 1), (4, 9, 1), (6, 7, 1),
                                  (1, 11, 1), (6, 14, 1), (6, 15, 1)):
            self._qtest(f'set_irq_in /machine/unattached/{gpios[index]} unnamed-gpio-in {pin} {level}')
        require(self.remote.command(f'Z0,{SYNC_WAIT:x},2') == 'OK', 'Could not observe synchronization')
        deadline = time.monotonic() + 180
        self.remote.sock.settimeout(1)
        self.remote.sock.sendall(b'$vCont;c#' + f'{sum(b"vCont;c") & 255:02x}'.encode())
        while True:
            require(not self.shutdown.is_set(), 'Console stopped during startup')
            require(time.monotonic() < deadline, 'Synchronization wait timed out')
            try:
                reply = self.remote.receive()
                break
            except TimeoutError:
                continue
        match = re.search(r'thread:([0-9a-f]+);', reply)
        require(match is not None, 'Missing synchronization stop thread')
        self.remote.select_thread(int(match[1], 16))
        registers = self.remote.regs()
        require(all(self.remote.get(registers, name) == value for name, value in
                    (('pc', SYNC_WAIT), ('r0', 0xb18a764c), ('r1', 8), ('r3', 50))),
                'Unexpected synchronization wait')
        require(int.from_bytes(self.remote.read(0x20060040, 4), 'little') & 0x10,
                'Synchronization input is masked')
        for level in (1, 0):
            self._qtest(f'set_irq_in /machine/unattached/{configs[0]} sync-event 15 {level}')
        require(self.remote.command(f'z0,{SYNC_WAIT:x},2') == 'OK', 'Could not remove observation point')
        # Detaching resumes execution and leaves all subsequent access to the monitor.
        require(self.remote.command('D') == 'OK', 'Could not resume the machine')
        self.remote.sock.close()
        self.remote = None

    def _qtest(self, line):
        self.wire_file.write((line + '\n').encode())
        self.wire_file.flush()
        require(self.wire_file.readline().strip() == b'OK', 'Input delivery failed')

    def _ready(self):
        require(self.phase == 'running' and self.process.poll() is None, '机器尚未就绪')

    def _words(self, address, count):
        text = self.qmp.command('human-monitor-command',
            {'command-line': f'x /{count}wx {address:#x}', 'cpu-index': 0})
        words = [int(value, 16) for line in text.splitlines() if ':' in line
                 for value in re.findall(r'0x[0-9a-fA-F]+', line.split(':', 1)[1])]
        require(len(words) == count, 'Could not read machine state')
        return words

    def _key_clock(self):
        low, high, frequency = self._words(0x04266008, 3)
        require(frequency > 0, 'Input clock is unavailable')
        return low | high << 32, frequency

    def _advance_keys(self):
        if not self.key_events:
            return
        ticks, frequency = self._key_clock()
        for pin, events in tuple(self.key_events.items()):
            if ticks < self.next_key_ticks.get(pin, 0):
                continue
            level = events[0]
            self._qtest(f'set_irq_in /machine/peripheral/keys pins {pin} {level}')
            events.popleft()
            if level == 0:
                self.held.add(pin)
            else:
                self.held.discard(pin)
            # Preserve each edge for 100 ms of guest time, including the
            # released interval between taps. Host speed must not erase clicks.
            self.next_key_ticks[pin] = ticks + (frequency + 9) // 10
            if not events:
                del self.key_events[pin]
            ticks, frequency = self._key_clock()
            self.next_key_ticks[pin] = ticks + (frequency + 9) // 10

    def set_key(self, pin, level):
        require(type(pin) is int and 0 <= pin < 24 and type(level) is int and level in (0, 1),
                'Invalid key input')
        with self.io:
            self._ready()
            events = self.key_events.setdefault(pin, deque())
            previous = events[-1] if events else int(pin not in self.held)
            if level != previous:
                events.append(level)
            if not events:
                del self.key_events[pin]
            if level == 0:
                self.requested_keys.add(pin)
                self.key_deadline = time.monotonic() + 5
            else:
                self.requested_keys.discard(pin)
            self._advance_keys()

    def release(self):
        with self.io:
            self._release()

    def _release(self):
        self.key_events.clear()
        self.next_key_ticks.clear()
        self.requested_keys.clear()
        for pin in tuple(self.held):
            self._qtest(f'set_irq_in /machine/peripheral/keys pins {pin} 1')
            self.held.remove(pin)

    def heartbeat(self):
        with self.io:
            if self.requested_keys:
                self.key_deadline = time.monotonic() + 5

    def _release_expired(self):
        while not self.shutdown.wait(0.05):
            with self.io:
                if self.phase == 'running':
                    try:
                        if self.requested_keys and time.monotonic() > self.key_deadline:
                            self._release()
                        else:
                            self._advance_keys()
                    except (OSError, ValueError, RuntimeError) as error:
                        self.error = str(error)
                        try:
                            self._release()
                        except (OSError, ValueError, RuntimeError):
                            pass
                        self.phase = 'failed'

    def frame_png(self):
        with self.io:
            self._ready()
            path = self.work / 'frame.ppm'
            self.qmp.command('screendump', {'filename': linux(path) if self.args.wsl else str(path)})
            return ppm_to_png(path.read_bytes())

    def status(self):
        state = dict(phase=self.phase, error=self.error, ready=False,
                     menu_inhibited=None,
                     uptime=int(time.monotonic() - self.started_at) if self.started_at else 0)
        if self.phase != 'running':
            return state
        with self.io:
            if self.phase != 'running':
                return dict(state, phase=self.phase)
            if self.process.poll() is not None:
                return dict(state, phase='failed', error='模拟器已退出，请重启')
            state['execution'] = self.qmp.command('query-status')['status']
            words = self._words(APP_MANAGER, 5)
            state.update(ready=words[0] == 1, index=words[4] & 255,
                         held=sorted(self.held))
            state['input_ready'] = state['ready'] and state['index'] in (1, 2, 4)
            if state['ready'] and state['index'] == 3:
                graphics = {name: self.qmp.command('qom-get',
                    {'path': '/machine/master-graphics', 'property': name})
                    for name in ('surface-address', 'rendered-commands',
                                 'failed-requests', 'unsupported-commands')}
                state['input_ready'] = (graphics['surface-address'] != 0 and
                    graphics['rendered-commands'] > 0 and graphics['failed-requests'] == 0 and
                    graphics['unsupported-commands'] == 0)
                size, pointer = self._words(0xb187556c, 2)
                if size == 0x118 and pointer:
                    count = self._words(pointer + 0x110, 1)[0]
                    if count <= 68:
                        codes = self._words(pointer, count) if count else []
                        state['menu_inhibited'] = any(0x3e <= code <= 0x44 for code in codes)
        return state

    def _cleanup(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)
        if self.remote is not None:
            self.remote.sock.close()
        if self.qmp is not None:
            self.qmp.close()
        if self.wire is not None:
            self.wire_file.close()
            self.wire.close()
        if self.work is not None:
            # This directory is created and owned by this console instance.
            shutil.rmtree(self.work)
        self.process = self.remote = self.qmp = self.wire = self.work = None
        self.started_at = None
        self.held.clear()
        self.requested_keys.clear()
        self.key_events.clear()
        self.next_key_ticks.clear()

    def close(self):
        self.shutdown.set()
        with self.lifecycle:
            with self.io:
                self.phase = 'stopped'
                self._cleanup()
        self.watchdog.join(timeout=2)


def make_handler(machine):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, code, body, kind='application/json; charset=utf-8'):
            self.send_response(code)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def valid_host(self):
            port = self.server.server_port
            hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}
            return (self.headers.get('Host') in hosts and
                    self.headers.get('Origin', 'http://' + self.headers.get('Host', ''))
                    in {'http://' + host for host in hosts})

        def do_GET(self):
            if not self.valid_host():
                self.send(403, b'{"error":"Local console only"}')
                return
            assets = {'/': ('index.html', 'text/html; charset=utf-8'),
                      '/console.js': ('console.js', 'text/javascript; charset=utf-8'),
                      '/style.css': ('style.css', 'text/css; charset=utf-8')}
            try:
                if self.path in assets:
                    name, kind = assets[self.path]
                    self.send(200, (WEB / name).read_bytes(), kind)
                elif self.path == '/frame':
                    self.send(200, machine.frame_png(), 'image/png')
                elif self.path == '/status':
                    self.send(200, json.dumps(machine.status(), ensure_ascii=False).encode())
                else:
                    self.send(404, b'{"error":"Not found"}')
            except Exception as error:
                self.send(503, json.dumps(dict(error=str(error)), ensure_ascii=False).encode())

        def do_POST(self):
            if not self.valid_host():
                self.send(403, b'{"error":"Local console only"}')
                return
            try:
                require(self.headers.get_content_type() == 'application/json', 'Expected JSON')
                length = int(self.headers.get('Content-Length', '0'))
                require(0 < length <= 4096, 'Invalid request length')
                request = json.loads(self.rfile.read(length))
                require(isinstance(request, dict), 'Expected a JSON object')
                if self.path == '/key':
                    pin, level = request.get('pin'), request.get('level')
                    require(type(pin) is int and 0 <= pin < 24 and type(level) is int and level in (0, 1),
                            'Invalid key input')
                    machine.set_key(pin, level)
                elif self.path == '/release':
                    machine.release()
                elif self.path == '/heartbeat':
                    machine.heartbeat()
                elif self.path == '/restart':
                    if not machine.restart():
                        self.send(409, b'{"error":"Restart already in progress"}')
                        return
                else:
                    self.send(404, b'{"error":"Not found"}')
                    return
                self.send(200, b'{"ok":true}')
            except (ValueError, KeyError, TypeError) as error:
                self.send(400, json.dumps(dict(error=str(error))).encode())
            except Exception as error:
                self.send(503, json.dumps(dict(error=str(error)), ensure_ascii=False).encode())

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--port', type=int, default=8666)
    parser.add_argument('--wsl', action='store_true', help='Run the Linux QEMU build through WSL on Windows')
    parser.add_argument('--open-browser', action='store_true')
    args = parser.parse_args()
    require(1 <= args.port <= 65535, 'Invalid HTTP port')
    require(not args.wsl or os.name == 'nt', '--wsl requires Windows')
    machine = Machine(args)
    server = None
    try:
        server = ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(machine))
        machine.restart()
        url = f'http://127.0.0.1:{args.port}'
        print('Web console: ' + url, flush=True)
        if args.open_browser:
            webbrowser.open(url)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if server is not None:
            server.server_close()
        machine.close()


if __name__ == '__main__':
    main()
