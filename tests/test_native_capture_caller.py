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


def check_case(failure=None, operation=127):
    exposure = 1000
    code, _, completion = caller_code(exposure)
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    functions = (0x104C8254, 0x10779876, 0x104D12AA, 0x103DC538,
                 0x103BA6EA, ORIGINAL_CALLBACK & ~1)
    stop, stack = 0x14000000, 0x14010000
    for page in {CODE & ~4095, OBJECT, stop, stack, *(p & ~4095 for p in functions)}:
        cpu.mem_map(page, 4096)
    cpu.mem_write(CODE, code)
    cpu.mem_write(OBJECT, struct.pack('<I', operation))
    cpu.mem_write(OBJECT + 0x20, struct.pack('<2I', 1, exposure))
    cpu.mem_write(REQUEST, struct.pack('<5I', 0, 1, 0, 0, 1))
    saved = {UC_ARM_REG_R4: 0x4444, UC_ARM_REG_R5: 0x5555, UC_ARM_REG_R6: 0x6666}
    for register, value in saved.items():
        cpu.reg_write(register, value)
    cpu.reg_write(UC_ARM_REG_SP, stack + 0x800)
    cpu.reg_write(UC_ARM_REG_LR, stop | 1)
    cpu.reg_write(UC_ARM_REG_R1, OBJECT)
    calls, reads = [], 0

    def hook(uc, address, size, user):
        nonlocal reads
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
            result = 2 if failure == 'program-timeout' or reads < 3 else 1
        elif address == 0x104D12AA:
            result = exposure + (failure == 'exposure-mismatch')
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
    require(captured == (failure is None and operation == 127), 'Capture bypassed a property gate')
    if operation != 127:
        require([address for address, _ in calls] == [ORIGINAL_CALLBACK & ~1],
                'Non-diagnostic operation did not retain original callback')
    else:
        ready, invoked = struct.unpack('<2I', cpu.mem_read(RESULT + 0x58, 8))
        require((ready, invoked) == ((1, 1) if captured else (0, 0)), 'Incorrect settings markers')
        require(int.from_bytes(cpu.mem_read(RESULT + 4, 4), 'little') == int(captured),
                'Incorrect capture return marker')
    if failure == 'program-timeout':
        require(reads == 1000, 'Program readback did not stop at retry limit')


if __name__ == '__main__':
    require(hashlib.sha256(caller_code()[0]).hexdigest() ==
            '3e6d8b27bc1a887fca77f25631521beef8d215ec08b6a450b90d13ca035fe9c0',
            'Default capture caller changed')
    for failure in (None, 0x500e, 0x500d, 'program-timeout', 'exposure-mismatch'):
        check_case(failure)
    check_case(operation=3)
    print('PASS: native caller ABI, readback, property failures and original callback')
