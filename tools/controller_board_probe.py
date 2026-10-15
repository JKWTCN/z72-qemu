# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe original engine and controller images running through private board views."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from analyze.firmware_structure import analyze_eg
from tools.controller_core_probe import CONTROLLER_SHA256
from tools.dual_boot_probe import dual_machine, trace_dual, verify_dual_log
from tools.smp_boot_probe import reach


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('master', 'slave', 'controller', 'destination'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--seconds', type=float, default=10)
    parser.add_argument('--controller-link', action='store_true')
    parser.add_argument('--controller-dma-abort', action='store_true')
    parser.add_argument('--controller-switch-scan', action='store_true')
    args = parser.parse_args()
    require(not args.controller_dma_abort or args.controller_link,
            'Controller DMA abort observation requires the controller link')
    require(not args.controller_switch_scan or args.controller_link,
            'Controller switch scan observation requires the controller link')
    images = {name: getattr(args, name).read_bytes() for name in ('master', 'slave', 'controller')}
    structures = {name: analyze_eg(images[name], name) for name in ('master', 'slave')}
    require(len(images['controller']) == 524290 and
            hashlib.sha256(images['controller']).hexdigest() == CONTROLLER_SHA256,
            'Expected the original controller C 1.30.00 image')
    require(0 < args.seconds <= 60, 'Observation duration must be in (0, 60] seconds')
    args.destination.mkdir(parents=True, exist_ok=False)
    process = remote = None
    try:
        process, remote = dual_machine(args.qemu, args.destination,
            images['master'], images['slave'], args.destination / 'console.txt',
            icount='shift=4,sleep=off', trace='int,guest_errors',
            controller_firmware=args.controller.resolve(),
            devices=('nikon-z72-controller-register-bank,bus=controller-i2c0,address=79',),
            controller_link=args.controller_link)
        remote.select_thread(5)
        regs = remote.regs()
        require(remote.get(regs, 'pc') == 0x080002b4 and
                remote.get(regs, 'sp') == 0x20000c08,
                'Embedded controller did not reset from its original vectors')
        for address in (0x080200a4, 0x080200b6, 0x080200c8, 0x080200da):
            remote.breakpoint(address)
        remote.sock.settimeout(30)
        thread, regs = reach(remote, 0x080213c2)
        require(thread == 5 and remote.read(0xe000ed28, 8) == bytes(8),
                'Embedded controller did not complete post-power initialization without faults')
        initial_tick = int.from_bytes(remote.read(0x20022d58, 4), 'little')
        remote.command('vCont;s:5')
        request = response = abort = switch_scan = None
        if args.controller_link:
            thread, regs = reach(remote, 0x0803423c)
            require(thread == 5, 'Original controller frame checker stopped on the wrong core')
            packet = remote.read(0x20017b76, 256)
            require(packet[:2] == b'\x01\x01' and int.from_bytes(packet[2:4], 'little') == 28 and
                    packet[252:254] == b'\x01\x01' and sum(packet) & 255 == 255 and
                    int.from_bytes(remote.read(0x40026414, 4), 'little') == 0,
                    'Original engine request did not reach the controller receive buffer intact')
            remote.command('vCont;s:5')
            _, regs = reach(remote, 0x080342c6)
            require(remote.get(regs, 'r0') == 1, 'Original controller rejected the received frame')
            request = dict(frame_bytes=256, channel=1, route=1, payload_bytes=28,
                checksum_verified=True, original_checker_result=1,
                receive_dma_completed=True, frame_sha256=hashlib.sha256(packet).hexdigest())
            remote.command('vCont;s:5')
            thread, regs = reach(remote, 0x1020b71e)
            require(thread in (1, 2), 'Original response checker stopped outside the master engine')
            packet = remote.read(0xb1d1ab28, 256)
            require(packet[:2] == b'\x01\x01' and int.from_bytes(packet[2:4], 'little') == 28 and
                    packet[252:254] == b'\x01\x01' and sum(packet) & 255 == 255,
                    'Original controller response did not reach the engine receive buffer intact')
            remote.select_thread(5)
            require(remote.read(0x20017d9a, 256) == packet and
                    int.from_bytes(remote.read(0x4002642c, 4), 'little') == 0,
                    'Engine response differs from the controller transmit DMA frame')
            remote.command('vCont;s:' + format(thread, 'x'))
            thread, regs = reach(remote, 0x08034894)
            require(thread == 5 and int.from_bytes(remote.read(0x40021810, 4), 'little') & 0x40 and
                    int.from_bytes(remote.read(0xe000ed04, 4), 'little') & 0x1ff == 39,
                    'Engine receive confirmation did not invoke the original controller G6 interrupt callback')
            response = dict(frame_bytes=256, channel=1, route=1, payload_bytes=28,
                checksum_verified=True, original_engine_acceptance_pc=0x1020b71e,
                transmit_dma_completed=True, controller_acknowledgement_pc=0x08034894,
                controller_acknowledgement_exception=39, frame_sha256=hashlib.sha256(packet).hexdigest())
            remote.command('vCont;s:5')
        if args.controller_dma_abort:
            thread, regs = reach(remote, 0x08043408)
            require(thread == 5 and remote.get(regs, 'r0') == 0x40026088,
                    'Original abort did not target controller DMA1 stream 5')
            control = int.from_bytes(remote.read(0x40026088, 4), 'little')
            count = int.from_bytes(remote.read(0x4002608c, 4), 'little')
            fifo = int.from_bytes(remote.read(0x4002609c, 4), 'little')
            descriptor = remote.get(regs, 'r4')
            require(control & 1 and remote.get(regs, 'r1') == fifo & ~0x80,
                    'Original abort did not mask FIFO errors while the stream remained enabled')
            remote.command('vCont;s:5')
            require(remote.get(remote.regs(), 'pc') == 0x0804340a and
                    remote.read(0xe000ed28, 8) == bytes(8) and
                    int.from_bytes(remote.read(0x4002609c, 4), 'little') == fifo & ~0x80,
                    'Original FIFO error masking faulted or changed transfer geometry')
            _, regs = reach(remote, 0x0804345a)
            require(not int.from_bytes(remote.read(0x40026088, 4), 'little') & 1 and
                    int.from_bytes(remote.read(0x4002608c, 4), 'little') == count and
                    remote.read(descriptor + 52, 2) == b'\x00\x01',
                    'Original DMA abort did not release the stream without moving disconnected data')
            remote.command('vCont;s:5')
            require(remote.get(remote.regs(), 'r0') == 0, 'Original DMA abort did not return success')
            abort = dict(stream=5, base='0x40026088', fifo_mask_pc='0x08043408',
                fifo_mask_while_enabled_verified=True, remaining_count=count,
                cancelled_without_transfer=True, original_result=0)
        if args.controller_switch_scan:
            thread, regs = reach(remote, 0x0803df98)
            require(thread == 5, 'Original switch scan stopped outside the controller')
            timer = {hex(offset): int.from_bytes(remote.read(0x40014400 + offset, 4), 'little')
                     for offset in (0, 12, 24, 32, 44, 52)}
            require(timer['0x0'] & 1 and timer['0xc'] & 2 and timer['0x18'] & 3 == 0 and
                    timer['0x20'] & 1 and timer['0x34'] > timer['0x2c'],
                    'Original switch scan did not use the enabled compare overflow path')
            remote.command('vCont;s:5')
            thread, regs = reach(remote, 0x0803d710)
            require(thread == 5, 'Original switch result did not reach its controller manager')
            caller = remote.get(regs, 'lr') & ~1
            remote.command('vCont;s:5')
            reach(remote, caller)
            require(remote.read(0x20011670, 4) == b'\x01\x00\x00\x00',
                    'Original switch callback did not publish its initial sample readiness')
            switch_scan = dict(timer_base='0x40014400', timer_registers=timer,
                native_scan_pc='0x0803df98', native_callback_pc='0x0803d710',
                original_sample_readiness_verified=True)
            remote.command('vCont;s:5')
        result = trace_dual(remote, args.destination / 'console.txt',
                            args.destination / 'qemu.log', args.seconds)
        remote.select_thread(5)
        regs = remote.regs()
        final_tick = int.from_bytes(remote.read(0x20022d58, 4), 'little')
        require(remote.read(0xe000ed28, 8) == bytes(8) and final_tick > initial_tick,
                'Embedded controller stopped progressing or recorded a fault')
        result['controller'] = dict(thread=5, original_reset_verified=True,
            post_power_initialization_verified=True, initialization_pc=0x080213c2,
            initial_tick=initial_tick, final_tick=final_tick, native_faults_absent=True,
            stop_pc=remote.get(regs, 'pc'))
        if abort is not None:
            result['controller']['original_dma_abort'] = abort
        if switch_scan is not None:
            result['controller']['original_switch_scan'] = switch_scan
        if request is not None:
            result['controller']['original_engine_request'] = request
            result['controller']['original_controller_response'] = response
            remote.select_thread(1)
            version = remote.read(0xb25db600, 10).split(b'\0')[0]
            require(version == b'01.30.00' and remote.read(0xb25db612, 1) == b'\x68',
                    'Original engine message dispatch did not populate controller identity state')
            response['engine_identity_state_verified'] = True
            response['firmware_version'] = version.decode('ascii')
            result['application_state'] = dict(
                menu_table_pointers=[hex(pointer) for pointer in
                    struct.unpack('<7I', remote.read(0xb201bd08, 28))],
                display_state_byte=remote.read(0xb202c00e, 1)[0])
    finally:
        if remote is not None:
            remote.sock.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    verify_dual_log(result)
    log = (args.destination / 'qemu.log').read_text(errors='replace')
    require(not re.search(r'Taking exception[^\n]*(?:Undefined Instruction|Prefetch Abort|Data Abort)',
                          log, re.IGNORECASE), 'Engine log contains an execution fault')
    for name, image in images.items():
        require(getattr(args, name).read_bytes() == image, 'Board probe modified an input image')
    report = dict(format=1, firmware_sha256={name: structures[name]['sha256']
        for name in ('master', 'slave')}, controller_sha256=CONTROLLER_SHA256,
        original_images_execute_together=True, passed=True,
        controller_request_verified=args.controller_link,
        controller_link_verified=args.controller_link, full_boot_verified=False, menu_verified=False,
        assumptions=['Four engine cores and one controller core, each execution domain with a private memory view.',
            'Controller reset vectors use its flash base 0x08000000; the zero alias remains accessible.',
            'Fixed experimental clocks and an explicit register storage target at address 0x4f.',
            'Original images and read-only observation; no guest runtime tables or code are replaced.',
            'Optional link connects two serial peers, readiness edge interrupts and both acknowledgement directions.',
            'Only the initial request and response exchange is verified; later commands, external capture and menus remain pending.'],
        observation=result)
    (args.destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS original engine and controller images: private reset, initialization and bounded execution')


if __name__ == '__main__':
    main()
