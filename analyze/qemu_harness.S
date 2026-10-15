/* SPDX-License-Identifier: GPL-2.0-or-later */
.syntax unified
.cpu cortex-a7
.arm
.global _start
_start:
    cpsid aif
    mov r0, #0
    mcr p15, 0, r0, c2, c0, 2
    ldr r0, =0x40110000
    mcr p15, 0, r0, c2, c0, 0
    ldr r0, =0x55555555
    mcr p15, 0, r0, c3, c0, 0
    ldr r0, =0x40100100
    mcr p15, 0, r0, c12, c0, 0
    mov r0, #0
    mcr p15, 0, r0, c8, c7, 0
    dsb sy
    isb
    mrc p15, 0, r0, c1, c0, 0
    bic r0, r0, #0x2000
    bic r0, r0, #0x1000
    bic r0, r0, #4
    bic r0, r0, #0x30000000
    bic r0, r0, #0x80000
    orr r0, r0, #0x800000
    orr r0, r0, #1
    mcr p15, 0, r0, c1, c0, 0
    isb
    b ready
    .ltorg
    .org 0x80
ready:
    b ready
    .org 0x100
    b .
    b .
    b .
    b .
    b .
    b .
    b .
    b .
