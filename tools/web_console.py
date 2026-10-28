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
from analyze.decode_z72 import digest, require
from analyze.firmware_structure import analyze_eg
from analyze.update_store import UpdateStore, installable_master
from analyze.update_container import master_member
from analyze.upgrade_signature import verify_update
from analyze.qemu_display import Remote
from tools.controller_core_probe import CONTROLLER_SHA256
from tools.create_lab_parameters import parameter_images, resource_header_image
from tools.dual_boot_probe import dual_machine

SYNC_WAIT = 0x102d949e
APP_MANAGER = 0xb1811e40
MENU_PIN = 9
SHUTTER_HALF = 24
SHUTTER_FULL = 25
SHUTTER_CONTACTS = (1, 13)  # Controller port G: body half/full contacts.
MENU_APPLICATION = 1
ENGINE_ENTRY = 0x10020000
# Original controller shoulder-panel state: the channel-8 snapshot copy, the
# twelve-byte register structure the page functions compose, the panel
# shadow registers and the panel power state byte.
SHOULDER_SNAPSHOT = 0x20018AD4
SHOULDER_STRUCT = 0x2001FB90
SHOULDER_SHADOW = 0x2001FDA4
SHOULDER_POWERED = 0x2001F5A2
CONTROLLER_CPU = 4
BOOT_AUXILIARY = (('group17.bin', 0x132c0000), ('group18.bin', 0x132e0000),
                  ('group32.bin', 0x13e80000))
DEFAULT_STORE = ROOT / '.local' / 'console-update-store'
# Bounded in host time: under the default instruction-count clock the guest
# runs slower than the wall clock, so the foreground switch can take minutes.
MENU_HOLD_SECONDS = 240
AUTO_MENU_POLL_TICKS = 6
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
        self.gdb_port = None
        self.held = set()
        self.requested_keys = set()
        self.key_events = {}
        self.next_key_ticks = {}
        self.key_deadline = 0
        self.started_at = None
        self.menu_open_pending = False
        self.menu_release_held = False
        self.menu_deadline = 0
        self.menu_poll_ticks = 0
        self.app_index = None
        self.auto_menu = bool(getattr(args, 'auto_menu', False))
        self.auto_menu_done = False
        self.auto_menu_ticks = 0
        # The update store survives machine restarts: an installed image is
        # re-verified against its manifest on every boot and then loaded in
        # place of the supplied stock master.
        self.store = UpdateStore(getattr(args, 'update_store', None) or DEFAULT_STORE)
        self.update_image = getattr(args, 'update_image', None)
        self.boot_key = None
        if self.update_image is not None:
            head = self.update_image.read_bytes()[:0x40]
            if len(head) == 0x40 and head[0x20:] == b' ' * 0x20:
                # A whole update file: the header digest check needs the
                # boot-window key material as a second local input.
                boot_key_path = getattr(args, 'boot_key', None)
                require(boot_key_path is not None,
                        'A whole update file requires --boot-key (eight boot-window bytes)')
                key = Path(boot_key_path).read_bytes()
                require(len(key) == 8, 'The boot-window key file must hold exactly eight bytes')
                self.boot_key = key
        self.staged = None
        self.staged_error = None
        self.refresh_staged()
        self.firmware = None
        # Served frames are cached and rate limited so that continuous frame
        # polling cannot starve key delivery of the monitor lock.
        self.frame_cache = (0.0, b'')
        self.frame_interval = 0.05
        self.lcd_cache = (0.0, b'')
        self.lcd_interval = 2.0
        self.shoulder_cache = (0.0, None)
        self.shoulder_interval = 0.4
        self.shutdown = threading.Event()
        self.worker = None
        self.watchdog = threading.Thread(target=self._release_expired, daemon=True)
        self.watchdog.start()

    def restart(self):
        self.frame_cache = (0.0, b'')
        self.lcd_cache = (0.0, b'')
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
            with self.io:
                self.phase = 'running'
                self.auto_menu_done = False
                self.auto_menu_ticks = 0
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
        master, slave = self._select_master(), self.args.slave.read_bytes()
        analyze_eg(slave, 'slave')
        require(hashlib.sha256(self.args.controller.read_bytes()).hexdigest() ==
                CONTROLLER_SHA256, 'Expected the original controller image')
        (ROOT / '.local').mkdir(exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix='web-console-', dir=ROOT / '.local'))
        self.wire_port, self.qmp_port = free_port(), free_port()
        original = subprocess.Popen
        work = self.work
        wire_port, qmp_port = self.wire_port, self.qmp_port

        class Launcher(original):
            def __init__(child, command, *extra, **keywords):
                command[command.index('-M') + 1] += ',controller-battery-peer=on'
                command += ['-qtest', f'tcp:127.0.0.1:{wire_port},server=on,wait=off',
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
            'nikon-z72-controller-expander,bus=controller-i2c0,address=34,id=keys,'
            'interrupt-gpio=/machine/controller/keys-gpio,interrupt-pin=8',
            f'nikon-z72-controller-register-bank,bus=controller-i2c0,address=107,initial-state={work / "primary.bin"}',
            f'nikon-z72-controller-panel,bus=controller-i2c0,address=13,'
            f'id=shoulder,initial-state={work / "aux.bin"}')
        devices += tuple(f'loader,file={work / name},addr={address:#x},force-raw=on'
                         for name, address in (('group17.bin', 0x132c0000),
                                               ('group18.bin', 0x132e0000),
                                               ('group32.bin', 0x13e80000)))
        devices += tuple(f'nikon-z72-controller-register-bank,bus=master-i2c{i},address=104'
                         for i in range(4))
        card = getattr(self.args, 'sd_card', None)
        card_globals, card_arguments = (), ()
        if card is not None:
            require(card.is_file(), 'SD card image does not exist')
            card_path = card.resolve().as_posix().replace(',', ',,')
            devices += ('sd-card,drive=console-card,bus=/z72-sd-slave/sd-bus',)
            card_globals = ('nikon-z72-boot-config.sd-host=on',
                            'nikon-z72-boot-config.pcie-link=on')
            card_arguments = ('-drive', f'if=none,id=console-card,file={card_path},'
                              'format=raw,snapshot=on')
        self.process, self.remote = dual_machine(self.args.qemu, work, master, slave,
            work / 'console.txt',
            icount=None if self.args.realtime else 'shift=0,sleep=off',
            trace='guest_errors',
            controller_firmware=self.args.controller,
            controller_link=True, controller_flash_data=work / 'resident.bin', devices=devices,
            machine_options=(f'master-boot-image={work / "master.bin"}',
                             f'slave-boot-image={work / "slave.bin"}',
                             # Machine options split on commas; double them
                             # so the file list travels as one value.
                             'master-boot-aux=' + ','.join(
                                 f'{work / name}@{address:#x}'
                                 for name, address in BOOT_AUXILIARY).replace(',', ',,')),
            globals_=('nikon-z72-boot-config.frame-sync=on',
                         'nikon-z72-boot-config.sensor-sample=on',
                         'nikon-z72-boot-config.sample-counter=on') +
                     (('nikon-z72-boot-config.display-complete=on',)
                      if getattr(self.args, 'display_complete', False) else ()) +
                     (('nikon-z72-boot-config.input-handshake=on',)
                      if getattr(self.args, 'input_handshake', False) else ()) +
                     (('nikon-z72-boot-config.frame-phase=on',)
                      if getattr(self.args, 'frame_phase', False) else ()) +
                     (('nikon-z72-boot-config.input-stop-complete=on',)
                      if getattr(self.args, 'input_stop_complete', False) else ()) +
                     (('nikon-z72-boot-config.frame-generate=on',)
                      if getattr(self.args, 'frame_generate', False) else ()) +
                     (('nikon-z72-boot-config.frame-notify=on',)
                      if getattr(self.args, 'frame_notify', False) else ()) +
                     card_globals +
                     tuple(f'nikon-z72-controller-adc.channel{c}={v}'
                           for c, v in ((0, 1800), (1, 3001), (3, 3001))),
            extra_arguments=card_arguments,
            process_factory=Launcher)
        self.gdb_port = self.remote.sock.getpeername()[1]
        self.started_at = time.monotonic()
        self.wire = socket.create_connection(('127.0.0.1', self.wire_port), timeout=5)
        self.wire_file = self.wire.makefile('rwb')
        self.qmp = QmpClient(self.qmp_port)
        devices = self.qmp.command('qom-list', {'path': '/machine/unattached'})

        def children(kind):
            return sorted((item['name'] for item in devices if item['type'] == f'child<{kind}>'),
                          key=lambda item: int(re.search(r'\d+', item)[0]))

        gpios, configs = children('nikon-z72-controller-gpio'), children('nikon-z72-boot-config')
        self.gpio_names, self.config_names = gpios, configs
        require(len(gpios) == 8 and len(configs) == 2, 'Missing controller or engine inputs')
        for index, pin, level in ((2, 5, 0), (3, 13, 1), (4, 9, 1), (6, 7, 1),
                                  (1, 11, 1), (6, 14, 1), (6, 15, 1),
                                  (6, SHUTTER_CONTACTS[0], 1),
                                  (6, SHUTTER_CONTACTS[1], 1)):
            self._qtest(f'set_irq_in /machine/unattached/{gpios[index]} unnamed-gpio-in {pin} {level}')
        self._boot_dance()

    def _boot_dance(self):
        """Release the paused machine through its first synchronization wait.

        The original startup polls a synchronization status bit before the
        shooting foreground can appear. The console observes that wait once
        through the debug connection, confirms the surrounding state and then
        supplies the missing synchronization edge and frame timing, exactly
        like the hardware lines the body expects around it.
        """
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
            self._qtest(f'set_irq_in /machine/unattached/{self.config_names[0]} sync-event 15 {level}')
        # The enable line is edge triggered; pulse it so a machine that was
        # already released once re-arms its frame timing after a reset.
        for level in (0, 1):
            self._qtest(f'set_irq_in /machine/unattached/{self.config_names[0]} '
                        f'frame-sync-enable 0 {level}')
        require(self.remote.command(f'z0,{SYNC_WAIT:x},2') == 'OK', 'Could not remove observation point')
        # Detaching resumes execution and leaves all subsequent access to the monitor.
        require(self.remote.command('D') == 'OK', 'Could not resume the machine')
        self.remote.sock.close()
        self.remote = None

    def _machine_reflash(self, image):
        """Program the stored master image and restart through a machine reset.

        Writing the boot-store property is the programming step; the following
        whole-machine reset makes the board reload the stored image set and
        restart both engines at the image entry, so the running machine boots
        the replaced firmware without a host process restart.
        """
        require(self.work is not None and self.phase == 'running', '机器尚未就绪')
        flashed = self.work / 'flashed-master.bin'
        flashed.write_bytes(image)
        path = linux(flashed) if self.args.wsl else str(flashed)
        with self.io:
            self._release()
            self.frame_cache = (0.0, b'')
            self.app_index = None
            self.qmp.command('stop')
            self.qmp.command('qom-set', {'path': '/machine/master-boot-store',
                                         'property': 'image', 'value': path})
            self.qmp.command('system_reset')
            # The reset lands in the emulator loop; the cores restart at the
            # stored entry once the stored image has been copied back in.
            deadline = time.monotonic() + 30
            self.remote = Remote(self.gdb_port)
            try:
                while True:
                    require(time.monotonic() < deadline, 'Machine reset did not complete')
                    self.remote.command('Hg1')
                    if self.remote.get(self.remote.regs(), 'pc') == ENGINE_ENTRY:
                        break
                    time.sleep(0.05)
                self._boot_dance()
            except BaseException:
                if self.remote is not None:
                    try:
                        self.remote.sock.close()
                    except OSError:
                        pass
                    self.remote = None
                raise
        self.started_at = time.monotonic()
        self.auto_menu_done = False
        self.auto_menu_ticks = 0

    def refresh_staged(self):
        """Describe and verify the signed update supplied on the command line."""
        self.staged, self.staged_error = None, None
        if self.update_image is None:
            return
        try:
            described = self._verified_update()
            # The payload bytes never enter the served state.
            self.staged = {key: value for key, value in described.items()
                           if key != 'payload'}
        except (OSError, ValueError) as error:
            self.staged_error = str(error)

    def _reference_master(self):
        """Return the supplied stock master; the check tables live inside it."""
        return self.args.master.read_bytes()

    def _verified_update(self):
        """Verify one update file and describe its payload member.

        A whole update file carries
        the marked body prefix and its header digest; it must reproduce the
        stock whole-file check computed with the supplied boot-window key
        material. For a package the directory and all CRCs are checked before
        selecting the master. A bare member is an experimental local input:
        its CRC and boot structure are checked without the package digest.
        """
        data = self.update_image.read_bytes()
        if len(data) > 0x40 and data[0x20:0x40] == b' ' * 0x20:
            master = self._reference_master()
            require(self.boot_key is not None,
                    'A whole update file requires --boot-key (eight boot-window bytes)')
            described = verify_update(data, self.boot_key, master)
            # A decoded whole package is a directory and several members,
            # not a directly executable master image.
            image = master_member(described['payload'])
            candidate = installable_master(image)
            return dict(candidate, note=str(self.update_image),
                        digest=described['digest'], length=described['length'],
                        signed=True, format='package', payload=image)
        candidate = installable_master(data)
        return dict(candidate, note=str(self.update_image), length=len(data),
                    signed=False, format='member', payload=data)

    def _select_master(self):
        """Load the installed update when present, else the stock master.

        Both paths verify the executed boot structure; the installed path
        pins the whole-image digest recorded at installation time instead
        of the stock identity, because an update may change those bytes.
        """
        store_error = None
        try:
            installed, image = self.store.load()
        except (OSError, ValueError) as error:
            installed, image, store_error = None, None, str(error)
        if installed is not None:
            self.firmware = dict(source='installed',
                                 **{key: installed[key] for key in
                                    ('sha256', 'length', 'version', 'installed_at')},
                                 note=installed.get('note', ''), store_error=None)
            return image
        master = self.args.master.read_bytes()
        analyze_eg(master, 'master')
        self.firmware = dict(source='stock', sha256=digest(master),
                             length=len(master), version=master[0x20:0x2C].decode('ascii'),
                             installed_at='', note='', store_error=store_error)
        return master

    def install_update(self):
        """Complete a menu-driven update through the experimental store.

        The original firmware-update entry scans the memory card through
        services the laboratory does not model, so installation requires
        the recovered menu application in the foreground and commits the
        staged image to the persistent store. The stored image is then
        programmed into the running machine's boot storage and a whole
        machine reset reboots the body from it. Returns the installed
        manifest.
        """
        require(self.update_image is not None,
                'No update image was supplied to this console')
        with self.io:
            self._ready()
            words = self._words(APP_MANAGER, 5)
            require(words[0] == 1 and words[4] & 255 == MENU_APPLICATION,
                    'Open the menu first: updates install from the menu application')
            described = self._verified_update()
            image = described['payload']
            require(self.firmware is None or described['sha256'] != self.firmware.get('sha256'),
                    'The staged update already is the loaded firmware')
            manifest = self.store.install(image, note=str(self.update_image),
                                          signature=dict(
                                              format=described['format'],
                                              digest=described.get('digest', ''),
                                              signed=described['signed']))
            self.staged = {key: value for key, value in described.items()
                           if key != 'payload'}
            self.staged_error = None
            self.firmware = dict(source='installed',
                                 **{key: manifest[key] for key in
                                    ('sha256', 'length', 'version', 'installed_at')},
                                 note=manifest.get('note', ''), store_error=None)
        self._machine_reflash(image)
        return manifest

    def remove_update(self):
        """Roll the console back to the supplied stock master.

        The commit record is removed first so a later process start loads the
        supplied stock master; the running machine is then reprogrammed with
        that master and restarted through the same machine-reset path.
        """
        with self.io:
            require(self.store.installed() is not None, 'No installed update to remove')
            self.store.remove()
        master = self.args.master.read_bytes()
        analyze_eg(master, 'master')
        self.firmware = dict(source='stock', sha256=digest(master),
                             length=len(master), version=master[0x20:0x2C].decode('ascii'),
                             installed_at='', note='', store_error=None)
        self._machine_reflash(master)

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

    def _bytes(self, address, count, cpu=0):
        text = self.qmp.command('human-monitor-command',
            {'command-line': f'x /{count}bx {address:#x}', 'cpu-index': cpu})
        values = [int(value, 16) for line in text.splitlines() if ':' in line
                  for value in re.findall(r'0x[0-9a-fA-F]+', line.split(':', 1)[1])]
        require(len(values) == count, 'Could not read machine state')
        return bytes(values)

    def shoulder(self):
        """Read the original shoulder-panel state from controller memory.

        The channel-8 snapshot at 0x20018AD4 is the master engine's own panel
        copy; the structure and shadow bytes are the controller's register
        output. The optional panel device reports its I2C register image.
        """
        now = time.monotonic()
        cached_at, cached = self.shoulder_cache
        if cached and now - cached_at < self.shoulder_interval:
            return cached
        with self.io:
            self._ready()
            snapshot = self._bytes(SHOULDER_SNAPSHOT, 0x74, CONTROLLER_CPU)
            structure = self._bytes(SHOULDER_STRUCT, 12, CONTROLLER_CPU)
            shadow = self._bytes(SHOULDER_SHADOW, 12, CONTROLLER_CPU)
            powered = self._bytes(SHOULDER_POWERED, 1, CONTROLLER_CPU)[0]
            device = None
            try:
                device = self.qmp.command('qom-get', {
                    'path': '/machine/peripheral/shoulder', 'property': 'image'})
            except Exception:
                device = None
        state = dict(tag=snapshot[0],
                     length=int.from_bytes(snapshot[0x70:0x72], 'little'),
                     snapshot=snapshot[:0x70].hex(),
                     structure=structure.hex(), shadow=shadow.hex(),
                     powered=powered, device_registers=device)
        self.shoulder_cache = (time.monotonic(), state)
        return state

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
            self._drive_key(pin, level)
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
        require(type(pin) is int and 0 <= pin <= SHUTTER_FULL and
                type(level) is int and level in (0, 1),
                'Invalid key input')
        with self.io:
            self._ready()
            self._set_key_locked(pin, level)

    def _drive_key(self, pin, level):
        if pin < SHUTTER_HALF:
            self._qtest(f'set_irq_in /machine/peripheral/keys pins {pin} {level}')
            return
        # The original controller scans body release G1/G13, active low.
        # A full press holds the half contact too; releasing either browser
        # control must preserve the other control's contacts.
        pressed = self.held - {pin}
        if level == 0:
            pressed.add(pin)
        half, full = SHUTTER_CONTACTS
        levels = {half: int(not pressed.intersection((SHUTTER_HALF, SHUTTER_FULL))),
                  full: int(SHUTTER_FULL not in pressed)}
        for contact in (SHUTTER_CONTACTS if level == 0 else reversed(SHUTTER_CONTACTS)):
            self._qtest(f'set_irq_in /machine/unattached/{self.gpio_names[6]} '
                        f'unnamed-gpio-in {contact} {levels[contact]}')

    def _set_key_locked(self, pin, level):
        if pin == MENU_PIN and level == 0:
            # The original menu start executes while the key stays held,
            # so a quick click is stretched to a bounded hold.
            self.menu_open_pending = self.app_index == 3
            self.menu_deadline = time.monotonic() + MENU_HOLD_SECONDS
        if pin == MENU_PIN and level == 1 and self.menu_open_pending and \
                time.monotonic() < self.menu_deadline:
            self.menu_release_held = True
            self.requested_keys.discard(pin)
            return
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

    def _auto_menu_step(self):
        """Press the menu key once while the native start window is open.

        The original firmware executes its direct menu start only in a short
        span after the shooting foreground first appears. The console presses
        the physical input at that moment, exactly like a person clicking in
        time; nothing is written into firmware state.
        """
        if not self.auto_menu or self.auto_menu_done:
            return
        self.auto_menu_ticks += 1
        if self.auto_menu_ticks % AUTO_MENU_POLL_TICKS:
            return
        try:
            words = self._words(APP_MANAGER, 5)
        except (OSError, ValueError, RuntimeError):
            return
        self.app_index = words[4] & 255
        if words[0] == 1 and self.app_index == 3:
            self.auto_menu_done = True
            self._set_key_locked(MENU_PIN, 0)
            self._set_key_locked(MENU_PIN, 1)

    def _menu_hold_step(self):
        """Keep a released menu click pressed until the foreground moves on.

        The press edge was already delivered; the original firmware runs its
        direct menu start only while the input stays low, so the release is
        delayed until the application switches or the bounded hold expires.
        """
        if not self.menu_release_held:
            return
        self.menu_poll_ticks += 1
        expired = time.monotonic() >= self.menu_deadline
        if expired or self.menu_poll_ticks % 6 == 0:
            try:
                index = self._words(APP_MANAGER, 5)[4] & 255
                self.app_index = index
            except (OSError, ValueError, RuntimeError):
                return
            if expired or index != 3:
                self.menu_release_held = False
                self.menu_open_pending = False
                self._qtest(f'set_irq_in /machine/peripheral/keys pins '
                            f'{MENU_PIN} 1')
                self.held.discard(MENU_PIN)

    def release(self):
        with self.io:
            self._release()

    def _release(self):
        self.key_events.clear()
        self.next_key_ticks.clear()
        self.requested_keys.clear()
        self.menu_open_pending = False
        self.menu_release_held = False
        for pin in tuple(self.held):
            self._drive_key(pin, 1)
            self.held.remove(pin)

    def heartbeat(self):
        with self.io:
            if self.requested_keys:
                self.key_deadline = time.monotonic() + 5

    def set_auto_menu(self, enabled):
        require(type(enabled) is bool, 'Expected a boolean')
        with self.io:
            self.auto_menu = enabled

    def _release_expired(self):
        while not self.shutdown.wait(0.05):
            with self.io:
                if self.phase == 'running':
                    try:
                        self._auto_menu_step()
                        self._menu_hold_step()
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
        now = time.monotonic()
        cached_at, cached = self.frame_cache
        if cached and now - cached_at < self.frame_interval:
            return cached
        with self.io:
            self._ready()
            path = self.work / 'frame.ppm'
            self.qmp.command('screendump', {'filename': linux(path) if self.args.wsl else str(path)})
            data = path.read_bytes()
        # The expensive PNG encoding runs without the lock so the watchdog
        # thread can keep delivering key events meanwhile.
        encoded = ppm_to_png(data)
        self.frame_cache = (time.monotonic(), encoded)
        return encoded

    def lcd_png(self):
        """Preview channel 1 background and native UI in grayscale.

        Only the observed equal-size format-6 overlay is decoded: each
        four-byte group starts with two luminance samples, with alpha in
        a separate byte plane. Color conversion and hardware scanout
        latching are not yet modeled by this read-only register snapshot.
        """
        now = time.monotonic()
        if self.lcd_cache and now - self.lcd_cache[0] < self.lcd_interval:
            return self.lcd_cache[1]
        with self.io:
            self._ready()
            running = self.qmp.command('query-status')['status'] == 'running'
            if running:
                self.qmp.command('stop')
            try:
                geometry = self._words(0x20144204, 1)[0]
                width, height = geometry & 0xffff, (geometry >> 16) & 0x3fff
                if not (0 < width <= 4096 and 0 < height <= 4096):
                    raise ValueError('Display output geometry is not configured')

                def plane(address_register, stride_register, minimum_stride):
                    address = self._words(address_register, 1)[0]
                    stride = self._words(stride_register, 1)[0]
                    if not (minimum_stride <= stride <= 16384 and
                            0xb0000000 <= address <= 0xf0000000 - stride * height):
                        raise ValueError('Display output plane is not configured')
                    return bytes(self._bytes(address, stride * height)), stride

                luminance, stride = plane(0x20144210, 0x20144240, width)
                overlay = alpha = None
                if self._words(0x20146110, 1)[0] & 1:
                    if (self._words(0x20146200, 1)[0] & 31 != 6 or
                            self._words(0x20146400, 1)[0] != geometry or width & 1):
                        raise ValueError('Unsupported display overlay format or geometry')
                    overlay, overlay_stride = plane(0x20146440, 0x20146500, width * 2)
                    alpha, alpha_stride = plane(0x201464c0, 0x20146540, width)
            finally:
                if running:
                    self.qmp.command('cont')
        rows = bytearray(width * height * 3)
        for row in range(height):
            for column in range(width):
                value = luminance[row * stride + column]
                if overlay is not None:
                    foreground = overlay[row * overlay_stride + (column // 2) * 4 + column % 2]
                    opacity = alpha[row * alpha_stride + column]
                    value = (foreground * opacity + value * (255 - opacity) + 127) // 255
                # The observed native black/white levels are 16/235.
                value = max(0, min(255, ((value - 16) * 255 + 109) // 219))
                pixel = (row * width + column) * 3
                rows[pixel:pixel + 3] = bytes((value, value, value))
        data = b'P6\n%d %d\n255\n' % (width, height) + bytes(rows)
        encoded = ppm_to_png(data)
        self.lcd_cache = (time.monotonic(), encoded)
        return encoded

    def status(self):
        state = dict(phase=self.phase, error=self.error, ready=False,
                     menu_inhibited=None,
                     uptime=int(time.monotonic() - self.started_at) if self.started_at else 0,
                     firmware=dict(self.firmware or {}),
                     staged=(dict(self.staged or {}, error=self.staged_error)
                             if self.staged or self.staged_error else None),
                     update_ready=False, update_installed=bool(
                         self.firmware and self.firmware.get('source') == 'installed'))
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
            # The version record at the image entry window is what the booted
            # image carries; it evidences which stored firmware executes.
            record = self._words(ENGINE_ENTRY + 0x20, 3)
            state['booted_version'] = b''.join(word.to_bytes(4, 'little')
                                               for word in record).decode('ascii',
                                                                          'replace')
            self.app_index = state['index']
            state['auto_menu'] = ('off' if not self.auto_menu else
                                  'pressed' if self.auto_menu_done else 'armed')
            state['input_ready'] = state['ready'] and state['index'] in (1, 2, 4)
            state['update_ready'] = bool(self.staged and state['ready'] and
                                         state['index'] == MENU_APPLICATION)
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
                elif self.path == '/lcd':
                    self.send(200, machine.lcd_png(), 'image/png')
                elif self.path == '/shoulder':
                    self.send(200, json.dumps(machine.shoulder(),
                                              ensure_ascii=False).encode())
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
                    machine.set_key(pin, level)
                elif self.path == '/release':
                    machine.release()
                elif self.path == '/heartbeat':
                    machine.heartbeat()
                elif self.path == '/auto-menu':
                    enabled = request.get('enabled')
                    require(type(enabled) is bool, 'Expected a boolean enabled field')
                    machine.set_auto_menu(enabled)
                elif self.path == '/update/install':
                    machine.install_update()
                elif self.path == '/update/remove':
                    machine.remove_update()
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
    parser.add_argument('--sd-card', type=Path,
                        help='Raw SD image attached through the original slave '
                             'controller; session writes use a temporary overlay')
    parser.add_argument('--port', type=int, default=8666)
    parser.add_argument('--wsl', action='store_true', help='Run the Linux QEMU build through WSL on Windows')
    parser.add_argument('--display-complete', action='store_true',
                        help='Pulse the recovered display completion lines '
                             'on every laboratory frame tick')
    parser.add_argument('--input-handshake', action='store_true',
                        help='Enable the optional output-triggered laboratory GPIO handshake response')
    parser.add_argument('--realtime', action='store_true',
                        help='Try the real-time virtual clock; menu opening '
                             'prefers the default instruction-count clock')
    parser.add_argument('--auto-menu', action='store_true',
                        help='Press the menu key automatically during the '
                             'native start window (the manual menu key only '
                             'works in that early window)')
    parser.add_argument('--update-image', type=Path,
                        help='Master update file installed through the menu-driven '
                             'firmware update: a whole update file (checked against '
                             'its header digest with --boot-key) or a bare master '
                             'member file (CRC and structure only, like the '
                             'standalone card path); the project ships no tools to '
                             'build either')
    parser.add_argument('--boot-key', type=Path,
                        help='Eight boot-window key bytes the update digest check '
                             'combines with the staged update (local research input)')
    parser.add_argument('--update-store', type=Path, default=DEFAULT_STORE,
                        help='Persistent directory holding the installed '
                             'update and its manifest (survives restarts)')
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
