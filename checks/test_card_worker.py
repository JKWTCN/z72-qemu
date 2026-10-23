# SPDX-License-Identifier: GPL-2.0-or-later
"""Firmware-free regression for the bounded worker's SVC return path."""
import struct
import unittest

from tools.card_worker_probe import CardWorker, SCRATCH


class WorkerTrapTests(unittest.TestCase):
    def test_svc_preserves_the_wrapper_return_stack(self):
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
        from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_R4, UC_ARM_REG_SP

        probe = CardWorker.__new__(CardWorker)
        probe.u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        probe.u.mem_map(0x1000, 0x2000)
        probe.u.mem_map(0x7000, 0x1000)
        probe.u.mem_map(SCRATCH, 0x100000)
        # Save a callee register and LR, issue SVC, restore both, return.
        words = (0xE92D0010, 0xE92D4000, 0xE3A0C006, 0xEF000006,
                 0xE8BD4000, 0xE8BD0010, 0xE12FFF1E)
        probe.u.mem_write(0x1000, struct.pack('<7I', *words))
        probe.u.reg_write(UC_ARM_REG_SP, 0x8000)
        probe.u.reg_write(UC_ARM_REG_LR, 0x2000)
        probe.u.reg_write(UC_ARM_REG_R4, 0x12345678)
        probe.install_svc_trap()
        probe.u.emu_start(0x1000, 0x2000, count=30)
        self.assertEqual(probe.u.reg_read(UC_ARM_REG_SP), 0x8000)
        self.assertEqual(probe.u.reg_read(UC_ARM_REG_LR), 0x2000)
        self.assertEqual(probe.u.reg_read(UC_ARM_REG_R4), 0x12345678)
        self.assertEqual(probe.services, [dict(pc='0x1010', service='0x6')])


if __name__ == '__main__':
    unittest.main()
