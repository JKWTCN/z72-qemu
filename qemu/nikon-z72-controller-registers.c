/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/i2c/i2c.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_Z72_REGISTER_BANK "nikon-z72-controller-register-bank"
OBJECT_DECLARE_SIMPLE_TYPE(Z72RegisterBank, Z72_REGISTER_BANK)

struct Z72RegisterBank {
    I2CSlave parent_obj;
    uint8_t registers[256];
    uint8_t initial[256];
    uint8_t pointer;
    bool expect_pointer;
    char *initial_state;
};

static int bank_event(I2CSlave *dev, enum i2c_event event)
{
    Z72RegisterBank *s = Z72_REGISTER_BANK(dev);
    if (event == I2C_START_SEND || event == I2C_FINISH) {
        s->expect_pointer = true;
    }
    return event == I2C_START_SEND_ASYNC ? -1 : 0;
}

static int bank_send(I2CSlave *dev, uint8_t value)
{
    Z72RegisterBank *s = Z72_REGISTER_BANK(dev);
    if (s->expect_pointer) {
        s->pointer = value;
        s->expect_pointer = false;
    } else {
        s->registers[s->pointer++] = value;
    }
    return 0;
}

static uint8_t bank_receive(I2CSlave *dev)
{
    Z72RegisterBank *s = Z72_REGISTER_BANK(dev);
    return s->registers[s->pointer++];
}

static void bank_reset(Object *obj, ResetType type)
{
    Z72RegisterBank *s = Z72_REGISTER_BANK(obj);
    memcpy(s->registers, s->initial, sizeof(s->registers));
    s->pointer = 0;
    s->expect_pointer = true;
}

static void bank_realize(DeviceState *dev, Error **errp)
{
    Z72RegisterBank *s = Z72_REGISTER_BANK(dev);
    if (!I2C_SLAVE(s)->address || I2C_SLAVE(s)->address > 0x7f) {
        error_setg(errp, "Controller register bank requires a nonzero seven-bit address");
        return;
    }
    if (s->initial_state) {
        g_autofree char *data = NULL;
        g_autoptr(GError) error = NULL;
        gsize size = 0;
        if (!g_file_get_contents(s->initial_state, &data, &size, &error)) {
            error_setg(errp, "Cannot read controller register initial state: %s", error->message);
            return;
        }
        if (!size || size > sizeof(s->initial)) {
            error_setg(errp, "Controller register initial state must contain 1..256 bytes");
            return;
        }
        memcpy(s->initial, data, size);
    }
}

static const VMStateDescription bank_state = {
    .name = TYPE_Z72_REGISTER_BANK, .version_id = 1, .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_I2C_SLAVE(parent_obj, Z72RegisterBank),
        VMSTATE_UINT8_ARRAY(registers, Z72RegisterBank, 256),
        VMSTATE_UINT8_ARRAY(initial, Z72RegisterBank, 256),
        VMSTATE_UINT8(pointer, Z72RegisterBank),
        VMSTATE_BOOL(expect_pointer, Z72RegisterBank),
        VMSTATE_END_OF_LIST()
    },
};

static const Property bank_properties[] = {
    DEFINE_PROP_STRING("initial-state", Z72RegisterBank, initial_state),
};

static void bank_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *ic = I2C_SLAVE_CLASS(klass);
    dc->realize = bank_realize;
    dc->vmsd = &bank_state;
    device_class_set_props(dc, bank_properties);
    RESETTABLE_CLASS(klass)->phases.hold = bank_reset;
    ic->event = bank_event;
    ic->send = bank_send;
    ic->recv = bank_receive;
}

static void bank_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_REGISTER_BANK, .parent = TYPE_I2C_SLAVE,
        .instance_size = sizeof(Z72RegisterBank), .class_init = bank_class_init,
    };
    type_register_static(&info);
}
type_init(bank_register_types)
