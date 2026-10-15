/* SPDX-License-Identifier: GPL-2.0-or-later */
.syntax unified
.arm
.text
.global _start
_start:
    b start
    b .
    b .
    b .
    b .
    b .
    b irq_handler
    b .
.org 0x40
start:
    cpsid aif, #0x12
    ldr sp, =0x04008c00
    cpsid aif, #0x13
    ldr sp, =0x04008e00
    ldr r0, =0x40100000
    mcr p15, 0, r0, c12, c0, 0
    isb
    mrc p15, 4, r0, c15, c0, 0
    cpsie i
    b idle
.org 0x80
idle:
    wfi
    b idle
.org 0x100
irq_handler:
    push {r0, r1, r2, lr}
    ldr r0, =0x04002000
    ldr r1, [r0, #12]
    ldr r2, =0x40100300
    str r1, [r2, #4]
    ldr r1, [r2]
    add r1, r1, #1
    str r1, [r2]
    mov r1, #0
    mcr p15, 0, r1, c14, c2, 1
    ldr r1, [r2, #4]
    str r1, [r0, #16]
    pop {r0, r1, r2, lr}
    subs pc, lr, #4
.org 0x180
timer_start:
    mov r0, #0
    mcr p15, 0, r0, c14, c2, 0
    mov r0, #1
    mcr p15, 0, r0, c14, c2, 1
    b idle
.ltorg
