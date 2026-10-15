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
    mrc p15, 0, r4, c0, c0, 5
    and r4, r4, #0xf
    ldr r0, =0x04008c00
    sub r0, r0, r4, lsl #8
    cpsid aif, #0x12
    mov sp, r0
    add r0, r0, #0x200
    cpsid aif, #0x13
    mov sp, r0
    ldr r0, =0x40100000
    mcr p15, 0, r0, c12, c0, 0
    isb
    ldr r0, =0x40100400
    add r0, r0, r4, lsl #4
    str r4, [r0]
    ldr r0, =0x04001000
    mov r1, #1
    str r1, [r0]
    ldr r1, =0x20000002
    str r1, [r0, #0x100]
    ldr r0, =0x04002000
    mov r1, #0xff
    str r1, [r0, #4]
    mov r1, #1
    str r1, [r0]
    cpsie i
    b idle
.org 0xc0
idle:
    wfi
    b idle
.org 0x100
irq_handler:
    push {r0, r1, r2, r3, lr}
    ldr r0, =0x04002000
    ldr r1, [r0, #12]
    mrc p15, 0, r3, c0, c0, 5
    and r3, r3, #0xf
    ldr r2, =0x40100400
    add r2, r2, r3, lsl #4
    str r1, [r2, #8]
    ldr r3, [r2, #4]
    add r3, r3, #1
    str r3, [r2, #4]
    mov r3, #0
    mcr p15, 0, r3, c14, c2, 1
    str r1, [r0, #16]
    pop {r0, r1, r2, r3, lr}
    subs pc, lr, #4
.org 0x180
timer_start:
    movw r0, #48000
    mcr p15, 0, r0, c14, c2, 0
    mov r0, #1
    mcr p15, 0, r0, c14, c2, 1
    b idle
.org 0x1a0
sgi_send:
    ldr r1, =0x04001f00
    str r0, [r1]
    b idle
.org 0x1b0
type_read:
    ldr r0, =0x04001004
    ldr r0, [r0]
    b idle
.org 0x1c0
iar_read:
    ldr r0, =0x0400200c
    ldr r0, [r0]
    b idle
.ltorg
