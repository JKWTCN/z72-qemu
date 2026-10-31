# SPDX-License-Identifier: GPL-2.0-or-later
"""Check diagnostic caller ABI and property failures without firmware."""
import hashlib
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
    UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from tools.native_capture_caller import caller_code, CODE, OBJECT, REQUEST, RESULT, ORIGINAL_CALLBACK


def check_case(failure=None, operation=127, program_selected=False, settings_only=False):
    exposure = 1000
    code, _, completion = caller_code(exposure, settings_only)
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    functions = (0x104C8254, 0x10779876, 0x104D12AA, 0x103DC538,
                 0x103BA6EA, 0x104C18E2, 0x104C0F20, 0x10634176,
                 0x10634324, 0x106342DE, 0x104D1620,
                 ORIGINAL_CALLBACK & ~1)
    stop, stack = 0x14000000, 0x14010000
    for page in {CODE & ~4095, OBJECT, stop, stack, *(p & ~4095 for p in functions)}:
        cpu.mem_map(page, 4096)
    cpu.mem_write(CODE, code)
    cpu.mem_write(OBJECT, struct.pack('<I', operation))
    cpu.mem_write(OBJECT + 0x20, struct.pack('<2I', 1, exposure))
    cpu.mem_write(OBJECT + 0x30, struct.pack('<3I', 1, 0, 0))
    cpu.mem_write(REQUEST, struct.pack('<5I', 0, 1, 0, 0, 1))
    saved = {UC_ARM_REG_R4: 0x4444, UC_ARM_REG_R5: 0x5555, UC_ARM_REG_R6: 0x6666}
    for register, value in saved.items():
        cpu.reg_write(register, value)
    cpu.reg_write(UC_ARM_REG_SP, stack + 0x800)
    cpu.reg_write(UC_ARM_REG_LR, stop | 1)
    cpu.reg_write(UC_ARM_REG_R1, OBJECT)
    calls, reads, mode_reads = [], 0, 0

    def hook(uc, address, size, user):
        nonlocal reads, mode_reads
        if address == stop:
            uc.emu_stop()
            return
        if address not in functions:
            return
        require(uc.reg_read(UC_ARM_REG_SP) % 8 == 0, 'Unaligned call stack')
        args = [uc.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                             UC_ARM_REG_R2, UC_ARM_REG_R3)]
        calls.append((address, args))
        result = 0
        if address == 0x104C8254:
            prop, pointer, length, status = args
            require((prop, pointer, length, status) in (
                (0x500e, OBJECT + 0x20, 2, RESULT + 0x48),
                (0x500d, OBJECT + 0x24, 4, RESULT + 0x48)), 'Invalid typed setter ABI')
            result = 0x201c if failure == prop else 0x2001
            uc.mem_write(status, struct.pack('<I', result))
        elif address == 0x10779876:
            reads += 1
            result = 1 if program_selected else 2 if failure == 'program-timeout' or reads < 3 else 1
        elif address == 0x104D12AA:
            result = exposure + (failure == 'exposure-mismatch')
        elif address == 0x10634324:
            require(settings_only and args[:2] == [0, 3], 'Invalid local program validation ABI')
            result = int(failure != 0x500e)
        elif address == 0x106342DE:
            require(settings_only and args[:2] == [0, 3], 'Invalid local program setter ABI')
            result = 0x80000000 if failure == 'local-set-failed' else 0
        elif address == 0x104D1620:
            require(settings_only and args[0] == OBJECT + 0x24 and
                    int.from_bytes(uc.mem_read(args[0], 4), 'little') == exposure,
                    'Invalid local exposure setter ABI')
            result = 0x201c if failure == 0x500d else 0x2001
        elif address == 0x104C18E2:
            result = int(failure != 'mode-denied')
        elif address == 0x104C0F20:
            require(not settings_only and args[:2] == [0x040F0004, OBJECT + 0x30],
                    'Local settings requested remote control or request ABI differs')
            mode, reserved, callback = struct.unpack('<3I', uc.mem_read(args[1], 12))
            require(mode == 1 and reserved == 0 and
                    CODE <= callback < CODE + len(code),
                    'Invalid control-mode request payload')
        elif address == 0x10634176:
            require(args[0] == 0x2400, 'Invalid control-mode readback property')
            mode_reads += 1
            result = int(failure == 'not-local-mode') if settings_only else int(
                failure != 'mode-timeout' and mode_reads >= 3)
        elif address == 0x103DC538:
            require(args[0] == 1, 'Invalid sleep argument')
        elif address == 0x103BA6EA:
            require(args[:2] == [REQUEST, completion | 1], 'Invalid capture ABI')
        uc.reg_write(UC_ARM_REG_R0, result)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, hook)
    cpu.emu_start(CODE | 1, stop + 2, count=50000)
    require(cpu.reg_read(UC_ARM_REG_PC) == stop, 'Caller did not return')
    require(cpu.reg_read(UC_ARM_REG_SP) == stack + 0x800 and
            all(cpu.reg_read(reg) == value for reg, value in saved.items()),
            'Caller damaged callee-saved registers or stack')
    captured = any(address == 0x103BA6EA for address, _ in calls)
    ready_expected = failure is None and operation == 127
    require(captured == (ready_expected and not settings_only), 'Capture bypassed a property gate')
    if operation != 127:
        require([address for address, _ in calls] == [ORIGINAL_CALLBACK & ~1],
                'Non-diagnostic operation did not retain original callback')
    else:
        ready, invoked = struct.unpack('<2I', cpu.mem_read(RESULT + 0x58, 8))
        require((ready, invoked) == (int(ready_expected), int(captured)), 'Incorrect settings markers')
        require(int.from_bytes(cpu.mem_read(RESULT + 4, 4), 'little') == int(captured),
                'Incorrect capture return marker')
    if failure == 'program-timeout':
        require(reads == 1001, 'Program readback did not stop at retry limit')
    if failure == 'mode-timeout':
        require(mode_reads == 1000, 'Control-mode readback did not stop at retry limit')
    if program_selected:
        require(not any(address == 0x104C8254 and args[0] == 0x500e for address, args in calls),
                'Already selected program was unnecessarily set')
    if any(address == 0x104C0F20 for address, _ in calls):
        callback = int.from_bytes(cpu.mem_read(OBJECT + 0x38, 4), 'little')
        cpu.reg_write(UC_ARM_REG_R0, 0x040F0004)
        cpu.reg_write(UC_ARM_REG_R1, 0)
        cpu.reg_write(UC_ARM_REG_LR, stop | 1)
        cpu.emu_start(callback, stop + 2, count=30)
        require(struct.unpack('<4I', cpu.mem_read(RESULT + 0x6c, 16)) ==
                (0x040F0004, 0, 1, 1), 'Control-mode notification damaged request markers')


if __name__ == '__main__':
    require(hashlib.sha256(caller_code()[0]).hexdigest() ==
            '3e6d8b27bc1a887fca77f25631521beef8d215ec08b6a450b90d13ca035fe9c0',
            'Default capture caller changed')
    require(hashlib.sha256(caller_code(1000)[0]).hexdigest() ==
            'c0c794b151ca2ae9499a698ee19326f6499b3d935533492f473a3ba0119672b1',
            'Remote exposure capture caller changed')
    for failure in (None, 0x500e, 0x500d, 'program-timeout', 'exposure-mismatch',
                    'mode-denied', 'mode-timeout'):
        check_case(failure)
    check_case(operation=3)
    check_case(program_selected=True)
    for failure in (None, 0x500e, 0x500d, 'program-timeout', 'exposure-mismatch',
                    'not-local-mode', 'local-set-failed'):
        check_case(failure, settings_only=True)
    check_case(operation=3, settings_only=True)
    check_case(program_selected=True, settings_only=True)
    print('PASS: native caller ABI, readback, property failures and original callback')
