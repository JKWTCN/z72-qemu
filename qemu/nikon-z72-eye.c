/* SPDX-License-Identifier: GPL-2.0-or-later */
/* RPR-0521RS register profile. No optical samples or measurement IRQs. */
#include "qemu/osdep.h"
#include "hw/i2c/i2c.h"
#include "hw/resettable.h"
#include "qemu/module.h"

#define TYPE_Z72_EYE "nikon-z72-eye"
OBJECT_DECLARE_SIMPLE_TYPE(Z72Eye, Z72_EYE)

struct Z72Eye {
    I2CSlave parent_obj;
    uint8_t regs[0x15];
    unsigned pointer;
    bool command;
};

static bool valid_register(unsigned reg)
{
    return (reg >= 0x40 && reg <= 0x54) || reg == 0x92;
}

static void reset_registers(Z72Eye *s)
{
    memset(s->regs, 0, sizeof(s->regs));
    s->regs[0] = 0x0a;
    s->regs[2] = 2;
    s->regs[3] = 1;
    s->regs[0x0b] = 0xff;
    s->regs[0x0c] = 0x0f;
    s->regs[0x0f] = s->regs[0x10] = 0xff;
}

static void advance_pointer(Z72Eye *s)
{
    s->pointer = s->pointer == 0x54 ? 0x40 : s->pointer + 1;
}

static int eye_event(I2CSlave *slave, enum i2c_event event)
{
    Z72Eye *s = Z72_EYE(slave);
    if (event == I2C_START_SEND) {
        s->command = true;
    } else if (event == I2C_START_RECV && !valid_register(s->pointer)) {
        return -1;
    }
    return 0;
}

static int eye_send(I2CSlave *slave, uint8_t value)
{
    Z72Eye *s = Z72_EYE(slave);
    unsigned reg = s->pointer;
    if (s->command) {
        s->pointer = value;
        s->command = false;
        return valid_register(value) ? 0 : -1;
    }
    /* Unsupported writes NACK; they cannot change identification or samples. */
    if (!valid_register(reg) || reg == 0x92 ||
        (reg >= 0x44 && reg <= 0x49)) {
        return -1;
    }
    if (reg == 0x40) {
        if (value & 0x80) {
            reset_registers(s);
        }
    } else {
        uint8_t mask = 0xff;
        if (reg == 0x42 || reg == 0x43 || reg == 0x4a) {
            mask = 0x3f;
        } else if (reg == 0x4c || reg == 0x4e) {
            mask = 0x0f;
        } else if (reg == 0x54) {
            mask = 3;
        }
        s->regs[reg - 0x40] = value & mask;
    }
    advance_pointer(s);
    return 0;
}

static uint8_t eye_recv(I2CSlave *slave)
{
    Z72Eye *s = Z72_EYE(slave);
    uint8_t value = 0xff;
    if (s->pointer == 0x92) {
        value = 0xe0;
    } else if (valid_register(s->pointer)) {
        value = s->regs[s->pointer - 0x40];
    }
    /* An overlong ID read stays outside the map, without integer wraparound. */
    if (valid_register(s->pointer)) {
        advance_pointer(s);
    }
    return value;
}

static void eye_reset(Object *obj, ResetType type)
{
    Z72Eye *s = Z72_EYE(obj);
    reset_registers(s);
    s->pointer = 0;
    s->command = true;
}

static void eye_class_init(ObjectClass *klass, const void *data)
{
    I2CSlaveClass *ic = I2C_SLAVE_CLASS(klass);
    ic->event = eye_event;
    ic->send = eye_send;
    ic->recv = eye_recv;
    DEVICE_CLASS(klass)->desc = "Eye sensor register profile (no optical input)";
    RESETTABLE_CLASS(klass)->phases.hold = eye_reset;
}

static const TypeInfo eye_info = {
    .name = TYPE_Z72_EYE,
    .parent = TYPE_I2C_SLAVE,
    .instance_size = sizeof(Z72Eye),
    .class_init = eye_class_init,
};

static void eye_register_types(void)
{
    type_register_static(&eye_info);
}
type_init(eye_register_types)
