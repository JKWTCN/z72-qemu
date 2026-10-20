# SPDX-License-Identifier: GPL-2.0-or-later
"""Acceptance check: menu-gated firmware update over the console HTTP path.

The check drives the real interactive console like a person would: wait for
the shooting foreground, confirm the menu gate refuses an early install,
open the menu with one click, install the signed update, and verify the
machine resets and reboots onto the installed image — inside the same
emulator process — and reaches the shooting foreground again. Optional
stages reboot once more through a full process restart (persistence) and
roll back to the supplied stock master. The signed update and its boot-window
key bytes must come from outside this repository; the project ships no tools
to build either.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require

INSTALL_TIMEOUT = 600


class Console:
    def __init__(self, arguments, port):
        self.port = port
        command = [sys.executable, str(ROOT / 'tools' / 'web_console.py'),
                   '--qemu', str(arguments.qemu.resolve()),
                   '--master', str(arguments.master.resolve()),
                   '--slave', str(arguments.slave.resolve()),
                   '--controller', str(arguments.controller.resolve()),
                   '--update-image', str(arguments.update_image.resolve()),
                   '--boot-key', str(arguments.boot_key.resolve()),
                   '--update-store', str(arguments.update_store.resolve()),
                   '--port', str(port)]
        if arguments.realtime:
            command.append('--realtime')
        if os.name == 'nt':
            command.append('--wsl')
        self.process = subprocess.Popen(command, cwd=ROOT,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True)

    def get(self, path):
        with urllib.request.urlopen(f'http://127.0.0.1:{self.port}{path}',
                                    timeout=15) as reply:
            return json.loads(reply.read())

    def post(self, path, body, timeout=15):
        request = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}', data=json.dumps(body).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=timeout) as reply:
            return json.loads(reply.read())

    def rejected(self, path, body):
        try:
            urllib.request.urlopen(urllib.request.Request(
                f'http://127.0.0.1:{self.port}{path}', data=json.dumps(body).encode(),
                headers={'Content-Type': 'application/json'}), timeout=15)
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read()).get('error', '')
        raise AssertionError('The console accepted an out-of-gate request')

    def wait_foreground(self, index, timeout, note):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                last = self.get('/status').get('index')
                if last == index:
                    return True
            except Exception:
                pass
            time.sleep(3)
        print(f'{note}: foreground still {last} after {timeout}s', flush=True)
        return False

    def wait_ready(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                status = self.get('/status')
                if (status.get('ready') and status.get('input_ready')
                        and status.get('index') == 3):
                    return status
            except Exception:
                pass
            time.sleep(5)
        return None

    def click(self, pin):
        self.post('/key', dict(pin=pin, level=0))
        time.sleep(0.4)
        self.post('/key', dict(pin=pin, level=1))

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)


def run(arguments):
    require(arguments.port in range(1024, 65536), 'Invalid local port')
    arguments.destination.mkdir(parents=True, exist_ok=False)
    report = dict(format=2, passed=False, transport='local HTTP console interface',
                  stages=[])
    console = None

    def stage(name, passed, **fields):
        entry = dict(name=name, passed=passed, **fields)
        report['stages'].append(entry)
        print(f'{name}: {passed}', flush=True)
        return passed

    try:
        console = Console(arguments, arguments.port)
        ready = console.wait_ready(900)
        require(ready is not None, 'The console never reached the shooting foreground')
        stock = console.get('/status')
        stage('stock-boot', stock['firmware'].get('source') == 'stock',
              firmware=stock['firmware'], booted_version=stock.get('booted_version'))
        require(stock['firmware'].get('source') == 'stock',
                'The console did not boot the stock master')

        status = console.get('/status')
        require(status['staged'] and not status['staged'].get('error'),
                'The staged update is not reported as valid')
        require(status['staged'].get('signed'),
                'The staged update did not pass the whole-file digest check')
        report['staged'] = {key: status['staged'][key]
                            for key in ('sha256', 'length', 'version', 'digest', 'signed')}
        require(not status['update_ready'], 'Update must stay gated outside the menu')
        code, message = console.rejected('/update/install', {})
        stage('gate-refused', code == 400, http=code, message=message)

        console.click(9)
        opened = console.wait_foreground(1, arguments.result_seconds, 'menu open')
        stage('menu-opened', opened)
        require(opened, 'The menu application did not open')
        status = console.get('/status')
        stage('menu-gate-open', bool(status['update_ready']),
              staged_sha=status['staged']['sha256'])
        require(status['update_ready'], 'The install gate did not open in the menu')

        # The install verifies the signature, programs the stored image and
        # resets the machine in place; the reply arrives once the reboot has
        # been released through its first synchronization wait.
        console.post('/update/install', {}, timeout=INSTALL_TIMEOUT)
        installed = console.wait_ready(900)
        require(installed is not None,
                'The updated firmware never reached the shooting foreground')
        final = console.get('/status')
        firmware = final['firmware']
        stage('installed-reset-boot', firmware.get('source') == 'installed',
              firmware=firmware, booted_version=final.get('booted_version'))
        require(firmware.get('source') == 'installed',
                'The console did not boot the installed update')
        require(firmware.get('sha256') == report['staged']['sha256'],
                'The loaded update digest does not match the staged candidate')
        require(final.get('booted_version') == firmware.get('version'),
                'The machine did not reboot onto the installed image bytes')

        if arguments.verify_restart:
            console.post('/restart', {})
            time.sleep(5)
            again = console.wait_ready(900)
            firmware = console.get('/status')['firmware'] if again else {}
            stage('restart-keeps-update',
                  bool(again) and firmware.get('source') == 'installed', firmware=firmware)

        if arguments.verify_rollback:
            console.post('/update/remove', {}, timeout=INSTALL_TIMEOUT)
            stock_again = console.wait_ready(900)
            rolled = console.get('/status') if stock_again else {}
            stage('rollback-to-stock',
                  bool(stock_again) and rolled.get('firmware', {}).get('source') == 'stock',
                  firmware=rolled.get('firmware'), booted_version=rolled.get('booted_version'))

        report['passed'] = all(item['passed'] for item in report['stages'])
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        if console is not None:
            console.close()
        (arguments.destination / 'report.json').write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(('PASS ' if report['passed'] else 'FAIL ') +
          'menu-driven firmware update', flush=True)
    require(report['passed'], 'Menu-driven firmware update failed')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True, type=Path)
    for name in ('master', 'slave', 'controller', 'update-image', 'boot-key'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--port', type=int, default=8667)
    parser.add_argument('--result-seconds', type=int, default=200)
    parser.add_argument('--realtime', action='store_true')
    parser.add_argument('--verify-restart', action='store_true',
                        help='Also reboot once more and keep the installed update')
    parser.add_argument('--verify-rollback', action='store_true',
                        help='Also roll back to the supplied stock master')
    arguments = parser.parse_args()
    arguments.update_store = arguments.destination / 'update-store'
    run(arguments)


if __name__ == '__main__':
    main()
