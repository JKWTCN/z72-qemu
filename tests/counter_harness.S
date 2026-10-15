/* SPDX-License-Identifier: GPL-2.0-or-later */
.syntax unified
.arm
.text
.global _start
_start:
    b sample
    b .
    b .
    b .
    b .
.org 0x40
sample:
    ldr r3, =0x40100500
    mrc p15, 0, r0, c14, c0, 0
    str r0, [r3]
    mrrc p15, 0, r0, r1, c14
    strd r0, r1, [r3, #8]
    ldr r2, =0x04266000
    ldr r0, [r2, #8]
    ldr r1, [r2, #12]
    strd r0, r1, [r3, #16]
    b idle
.org 0x80
idle:
    b idle
.org 0x100
store:
    str r0, [r1]
load:
    ldr r2, [r1]
store_byte:
    strb r0, [r1]
load_byte:
    ldrb r2, [r1]
.ltorg
