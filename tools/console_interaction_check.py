# SPDX-License-Identifier: GPL-2.0-or-later
"""Acceptance check: one menu click must work through the browser console.

The check drives the real interactive console over its local HTTP interface,
which is the same path a person uses in the browser. Each cycle starts from a
fresh machine (the console restarts in place), waits until the shooting
application is foreground and the console accepts input, settles far past the
old startup window, then performs exactly one short menu click and one short
exit click. A cycle passes only when the foreground switches to the menu
application and back on those single clicks.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require


class Console:
    def __init__(self, arguments, port):
        self.port = port
        command = [sys.executable, str(ROOT / 'tools' / 'web_console.py'),
                   '--qemu', str(arguments.qemu.resolve()),
                   '--master', str(arguments.master.resolve()),
                   '--slave', str(arguments.slave.resolve()),
                   '--controller', str(arguments.controller.resolve()),
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
                                    timeout=10) as reply:
            return json.loads(reply.read())

    def post(self, path, body):
        request = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}', data=json.dumps(body).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=10) as reply:
            return json.loads(reply.read())

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
    require(1 <= arguments.cycles <= 8, 'Cycle count must be in [1, 8]')
    require(30 <= arguments.settle_seconds <= 900,
            'Settling time must be in [30, 900] seconds')
    require(1024 <= arguments.port <= 65535, 'Invalid local port')
    arguments.destination.mkdir(parents=True, exist_ok=False)
    report = dict(format=1, passed=False, cycles=[],
                  transport='local HTTP console interface',
                  menu_clicks_per_cycle=1, exit_clicks_per_cycle=1)
    console = None
    try:
        console = Console(arguments, arguments.port)
        for cycle in range(arguments.cycles):
            if cycle:
                console.post('/restart', {})
                time.sleep(5)
            ready = False
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                try:
                    status = console.get('/status')
                    if (status.get('ready') and status.get('input_ready')
                            and status.get('index') == 3):
                        ready = True
                        break
                except Exception:
                    pass
                time.sleep(5)
            require(ready, 'The console never reached the shooting foreground')
            time.sleep(arguments.settle_seconds)
            entry = dict(cycle=cycle, uptime=console.get('/status').get('uptime'))
            console.click(9)
            entry['menu_opened'] = console.wait_foreground(
                1, arguments.result_seconds, f'cycle {cycle} open')
            print(f'cycle {cycle}: menu_opened={entry["menu_opened"]}', flush=True)
            if entry['menu_opened']:
                time.sleep(3)
                console.click(0)
                entry['menu_closed'] = console.wait_foreground(
                    3, arguments.result_seconds, f'cycle {cycle} close')
                print(f'cycle {cycle}: menu_closed={entry["menu_closed"]}', flush=True)
            else:
                entry['menu_closed'] = False
            report['cycles'].append(entry)
            # Reopening without a restart is the documented status boundary,
            # so every cycle begins from a fresh machine.
        report['passed'] = bool(report['cycles']) and all(
            item['menu_opened'] and item['menu_closed'] for item in report['cycles'])
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        if console is not None:
            console.close()
        (arguments.destination / 'report.json').write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(('PASS ' if report['passed'] else 'FAIL ') +
          'console single-click menu interaction', flush=True)
    require(report['passed'], 'Console single-click menu interaction failed')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True, type=Path)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--slave', required=True, type=Path)
    parser.add_argument('--controller', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--cycles', type=int, default=3)
    parser.add_argument('--settle-seconds', type=int, default=200)
    parser.add_argument('--result-seconds', type=int, default=100)
    parser.add_argument('--port', type=int, default=8666)
    parser.add_argument('--realtime', action='store_true',
                        help='Run the console with the real-time virtual clock')
    arguments = parser.parse_args()
    run(arguments)


if __name__ == '__main__':
    main()
