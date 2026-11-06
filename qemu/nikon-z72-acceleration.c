/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Optional raw input for the C1.70 address-0x1d acceleration path. */
#include "qemu/osdep.h"
#include "hw/i2c/i2c.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qapi/qapi-builtin-visit.h"

#define TYPE_Z72_ACCELERATION "nikon-z72-acceleration"
OBJECT_DECLARE_SIMPLE_TYPE(Z72Acceleration, Z72_ACCELERATION)

struct Z72Acceleration {
    I2CSlave parent_obj;
    int32_t x, y, z;
    bool present, active, selected, failed, receiving;
    uint8_t reg, used, length, control, cursor, sample[6];
};

static void acceleration_transaction(Z72Acceleration *s)
{
    s->selected = s->failed = s->receiving = false;
    s->used = s->length = s->cursor = 0;
}

static int acceleration_event(I2CSlave *dev, enum i2c_event event)
{
    Z72Acceleration *s = Z72_ACCELERATION(dev);
    switch (event) {
    case I2C_START_SEND:
        acceleration_transaction(s);
        break;
    case I2C_START_RECV:
        if (!s->selected || s->failed || s->length ||
            (s->reg == 1 && (!s->active || !s->present))) {
            acceleration_transaction(s);
            return -1;
        }
        s->receiving = true;
        s->cursor = 0;
        if (s->reg == 1) {
            int32_t axes[] = {s->x, s->y, s->z};
            for (unsigned i = 0; i < ARRAY_SIZE(axes); i++) {
                uint16_t raw = (axes[i] & 0xfff) << 4;
                s->sample[2 * i] = raw >> 8;
                s->sample[2 * i + 1] = raw;
            }
        }
        break;
    case I2C_FINISH:
        if (!s->receiving && !s->failed && s->selected) {
            if (!s->length) {
                break; /* Selector survives STOP for a separate receive. */
            }
            if (s->reg == 0x2a && s->used == s->length) {
                s->active = s->control & 1;
            }
        }
        acceleration_transaction(s);
        break;
    case I2C_NACK:
        acceleration_transaction(s);
        break;
    default:
        acceleration_transaction(s);
        return -1;
    }
    return 0;
}

static int acceleration_send(I2CSlave *dev, uint8_t value)
{
    Z72Acceleration *s = Z72_ACCELERATION(dev);
    if (s->failed || s->receiving) {
        return -1;
    }
    if (!s->selected) {
        switch (value) {
        case 0: case 1: s->length = 0; break;
        case 0x0e: case 0x17: s->length = 2; break;
        case 0x11: case 0x15: case 0x2a: s->length = 1; break;
        case 0x1d: s->length = 4; break;
        case 0x23: s->length = 15; break;
        default: s->failed = true; return -1;
        }
        if (s->active && s->length && value != 0x2a) {
            s->failed = true;
            return -1;
        }
        s->reg = value;
        s->selected = true;
        return 0;
    }
    /* Only the default configuration profile is qualified. No calibration
     * or physical scale is inferred from these programming bytes. */
    bool valid = s->reg == 0x2a ?
        (value == 0 || value == 1 || value == 0x2c || value == 0x2d) :
        value == (s->reg == 0x23 ?
                  (s->used == 7 ? 0x2c : s->used == 8 ? 2 : 0) : 0);
    if (s->used >= s->length || !valid) {
        s->failed = true;
        return -1;
    }
    if (s->reg == 0x2a) {
        s->control = value;
    }
    s->used++;
    return 0;
}

static uint8_t acceleration_recv(I2CSlave *dev)
{
    Z72Acceleration *s = Z72_ACCELERATION(dev);
    if (s->receiving && s->reg == 0 && s->cursor++ == 0) {
        return s->active && s->present ? 8 : 0;
    }
    if (s->receiving && s->reg == 1 && s->cursor < sizeof(s->sample)) {
        return s->sample[s->cursor++];
    }
    /* I2C recv cannot NACK a byte. Exhausted or invalid reads return the
     * disconnected value and never repeat or manufacture a sample. */
    s->receiving = false;
    return 0xff;
}

static void acceleration_reset(Object *obj, ResetType type)
{
    Z72Acceleration *s = Z72_ACCELERATION(obj);
    acceleration_transaction(s);
    s->active = false;
    s->control = s->reg = 0;
}

static bool axis_valid(int32_t value)
{
    return value >= -2048 && value <= 2047;
}

static void acceleration_get_sample(Object *obj, Visitor *v, const char *name,
                                    void *opaque, Error **errp)
{
    Z72Acceleration *s = Z72_ACCELERATION(obj);
    int32List z = { .value = s->z };
    int32List y = { .value = s->y, .next = &z };
    int32List x = { .value = s->x, .next = &y };
    int32List *axes = s->present ? &x : NULL;

    visit_type_int32List(v, name, &axes, errp);
}

static void acceleration_set_sample(Object *obj, Visitor *v, const char *name,
                                    void *opaque, Error **errp)
{
    Z72Acceleration *s = Z72_ACCELERATION(obj);
    g_autoptr(int32List) axes = NULL;
    if (!visit_type_int32List(v, name, &axes, errp)) {
        return;
    }
    if (!axes) {
        s->present = false;
        return;
    }
    int32List *y = axes->next;
    int32List *z = y ? y->next : NULL;
    if (!z || z->next || !axis_valid(axes->value) ||
        !axis_valid(y->value) || !axis_valid(z->value)) {
        error_setg(errp, "Expected three signed 12-bit axes or an empty list");
        return;
    }
    s->x = axes->value;
    s->y = y->value;
    s->z = z->value;
    s->present = true;
}

static void acceleration_realize(DeviceState *dev, Error **errp)
{
    Z72Acceleration *s = Z72_ACCELERATION(dev);
    if (!axis_valid(s->x) || !axis_valid(s->y) || !axis_valid(s->z)) {
        error_setg(errp, "Acceleration axes must fit signed 12 bits");
    }
}

static const Property acceleration_properties[] = {
    DEFINE_PROP_BOOL("sample-present", Z72Acceleration, present, false),
    DEFINE_PROP_INT32("sample-x", Z72Acceleration, x, 0),
    DEFINE_PROP_INT32("sample-y", Z72Acceleration, y, 0),
    DEFINE_PROP_INT32("sample-z", Z72Acceleration, z, 0),
};

static const VMStateDescription acceleration_vmstate = {
    .name = TYPE_Z72_ACCELERATION, .unmigratable = true,
};

static void acceleration_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *ic = I2C_SLAVE_CLASS(klass);
    dc->realize = acceleration_realize;
    dc->vmsd = &acceleration_vmstate;
    device_class_set_props(dc, acceleration_properties);
    object_class_property_add(klass, "set-sample", "int32List", acceleration_get_sample,
                              acceleration_set_sample, NULL, NULL);
    RESETTABLE_CLASS(klass)->phases.hold = acceleration_reset;
    ic->event = acceleration_event;
    ic->send = acceleration_send;
    ic->recv = acceleration_recv;
}

static const TypeInfo acceleration_type = {
    .name = TYPE_Z72_ACCELERATION, .parent = TYPE_I2C_SLAVE,
    .instance_size = sizeof(Z72Acceleration), .class_init = acceleration_class_init,
};

static void acceleration_register(void)
{
    type_register_static(&acceleration_type);
}
type_init(acceleration_register)
