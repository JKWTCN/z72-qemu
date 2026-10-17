/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "hw/i2c/i2c.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_Z72_EXPANDER "nikon-z72-controller-expander"
OBJECT_DECLARE_SIMPLE_TYPE(Z72Expander, Z72_EXPANDER)

struct Z72Expander {
    I2CSlave parent_obj;
    uint8_t registers[0x77];
    uint8_t seen[3];
    uint8_t pending[3];
    uint8_t latched[3];
    uint32_t levels;
    uint8_t pointer;
    bool expect_pointer;
    bool increment;
    DeviceState *interrupt_gpio;
    uint8_t interrupt_pin;
    qemu_irq irq;
};

static bool expander_register(unsigned reg)
{
    return (reg <= 0x0e && (reg & 3) < 3) ||
           (reg >= 0x40 && reg <= 0x45) ||
           (reg >= 0x48 && reg <= 0x5a && (reg & 3) < 3) || reg == 0x5c ||
           (reg >= 0x60 && reg <= 0x65) ||
           (reg >= 0x68 && reg <= 0x72 && (reg & 3) < 3) ||
           (reg >= 0x74 && reg <= 0x76);
}

static uint8_t expander_raw(Z72Expander *s, unsigned port, uint32_t levels)
{
    uint8_t inputs = s->registers[0x0c + port];
    uint8_t drain = (s->registers[0x5c] & (1u << port)) ?
                    ~s->registers[0x70 + port] : 0;
    return ((levels >> (port * 8)) & inputs) |
           (s->registers[4 + port] & ~inputs & ~drain);
}

static void expander_update(Z72Expander *s, uint32_t old_levels)
{
    bool active = false;
    for (unsigned port = 0; port < 3; port++) {
        uint8_t raw = expander_raw(s, port, s->levels);
        uint8_t old = expander_raw(s, port, old_levels);
        for (unsigned pin = 0; pin < 8; pin++) {
            uint8_t bit = 1u << pin;
            unsigned edge = (s->registers[0x60 + port * 2 + pin / 4] >>
                             (2 * (pin % 4))) & 3;
            if (!(s->registers[0x0c + port] & bit) ||
                (s->registers[0x54 + port] & bit)) {
                s->pending[port] &= ~bit;
                continue;
            }
            bool triggered = edge ? ((raw ^ old) & bit) &&
                             (edge == 3 || (!!(raw & bit) == (edge == 1))) :
                             ((raw ^ s->seen[port]) & bit);
            bool latch = s->registers[0x48 + port] & bit;
            if (triggered && !(s->pending[port] & bit)) {
                s->latched[port] = (s->latched[port] & ~bit) | (raw & bit);
            }
            if (triggered) {
                s->pending[port] |= bit;
            } else if (!edge && !latch) {
                s->pending[port] &= ~bit;
            }
        }
        active |= s->pending[port] != 0;
    }
    qemu_set_irq(s->irq, !active);
}

static void expander_input(void *opaque, int pin, int level)
{
    Z72Expander *s = opaque;
    uint32_t old = s->levels, bit = 1u << pin;
    s->levels = (old & ~bit) | (level ? bit : 0);
    expander_update(s, old);
}

static void expander_advance(Z72Expander *s)
{
    if (s->increment) {
        do {
            s->pointer = (s->pointer + 1) % sizeof(s->registers);
        } while (!expander_register(s->pointer));
    } else if (s->pointer != 0x5c) {
        unsigned base = s->pointer & ~3u, count = 3;
        if ((s->pointer >= 0x40 && s->pointer <= 0x45) ||
            (s->pointer >= 0x60 && s->pointer <= 0x65)) {
            base = s->pointer & ~7u;
            count = 6;
        }
        s->pointer = base + (s->pointer - base + 1) % count;
    }
}

static int expander_event(I2CSlave *dev, enum i2c_event event)
{
    Z72Expander *s = Z72_EXPANDER(dev);
    if (event == I2C_START_SEND || event == I2C_FINISH) {
        s->expect_pointer = true;
    }
    return event == I2C_START_SEND_ASYNC ? -1 : 0;
}

static int expander_send(I2CSlave *dev, uint8_t value)
{
    Z72Expander *s = Z72_EXPANDER(dev);
    unsigned reg = s->pointer;
    if (s->expect_pointer) {
        if (!expander_register(value & 0x7f)) {
            return -1;
        }
        s->pointer = value & 0x7f;
        s->increment = value & 0x80;
        s->expect_pointer = false;
        return 0;
    }
    if (reg < 3 || (reg >= 0x58 && reg <= 0x5a) ||
        (reg >= 0x6c && reg <= 0x6e) ||
        ((reg == 0x74 || reg == 0x75) && value)) {
        return -1;
    }
    if (reg >= 0x68 && reg <= 0x6a) {
        unsigned port = reg - 0x68;
        s->pending[port] &= ~value;
        s->seen[port] = (s->seen[port] & ~value) |
                        (expander_raw(s, port, s->levels) & value);
    } else {
        uint8_t old = s->registers[reg];
        s->registers[reg] = reg == 0x5c ? value & 7 : value;
        if (reg >= 0x60 && reg <= 0x65) {
            unsigned port = (reg - 0x60) / 2, shift = ((reg - 0x60) % 2) * 4;
            for (unsigned pin = 0; pin < 4; pin++) {
                if (((old >> (pin * 2)) & 3) && !((value >> (pin * 2)) & 3)) {
                    uint8_t bit = 1u << (shift + pin);
                    s->pending[port] &= ~bit;
                    s->seen[port] = (s->seen[port] & ~bit) |
                                    (expander_raw(s, port, s->levels) & bit);
                }
            }
        }
    }
    expander_update(s, s->levels);
    expander_advance(s);
    return 0;
}

static uint8_t expander_receive(I2CSlave *dev)
{
    Z72Expander *s = Z72_EXPANDER(dev);
    unsigned reg = s->pointer;
    uint8_t value = s->registers[reg];
    if (reg < 3) {
        uint8_t raw = expander_raw(s, reg, s->levels);
        uint8_t held = s->pending[reg] & s->registers[0x48 + reg];
        value = ((raw & ~held) | (s->latched[reg] & held)) ^ s->registers[8 + reg];
        s->seen[reg] = raw;
        s->pending[reg] = 0;
        expander_update(s, s->levels);
    } else if (reg >= 0x58 && reg <= 0x5a) {
        value = s->pending[reg - 0x58];
    } else if (reg >= 0x6c && reg <= 0x6e) {
        value = expander_raw(s, reg - 0x6c, s->levels);
    }
    expander_advance(s);
    return value;
}

static void expander_levels_get(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    uint32_t levels = Z72_EXPANDER(obj)->levels;
    visit_type_uint32(v, name, &levels, errp);
}

static void expander_levels_set(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    uint32_t levels;
    if (!visit_type_uint32(v, name, &levels, errp)) {
        return;
    }
    if (levels > 0xffffff) {
        error_setg(errp, "Expander input levels require 24 bits");
        return;
    }
    for (unsigned pin = 0; pin < 24; pin++) {
        expander_input(obj, pin, (levels >> pin) & 1);
    }
}

static void expander_reset(Object *obj, ResetType type)
{
    Z72Expander *s = Z72_EXPANDER(obj);
    memset(s->registers, 0, sizeof(s->registers));
    static const unsigned defaults[] = { 4, 5, 6, 12, 13, 14, 0x40, 0x41, 0x42,
        0x43, 0x44, 0x45, 0x50, 0x51, 0x52, 0x54, 0x55, 0x56 };
    for (unsigned i = 0; i < G_N_ELEMENTS(defaults); i++) {
        s->registers[defaults[i]] = 0xff;
    }
    for (unsigned port = 0; port < 3; port++) {
        s->seen[port] = s->levels >> (8 * port);
    }
    memset(s->pending, 0, sizeof(s->pending));
    memset(s->latched, 0, sizeof(s->latched));
    s->pointer = 0;
    s->expect_pointer = true;
    s->increment = false;
    expander_update(s, s->levels);
}

static void expander_init(Object *obj)
{
    Z72Expander *s = Z72_EXPANDER(obj);
    s->levels = 0xffffff;
    qdev_init_gpio_in_named(DEVICE(obj), expander_input, "pins", 24);
    qdev_init_gpio_out(DEVICE(obj), &s->irq, 1);
}

static const VMStateDescription expander_state = {
    .name = TYPE_Z72_EXPANDER,
    .unmigratable = true,
};

static void expander_realize(DeviceState *dev, Error **errp)
{
    Z72Expander *s = Z72_EXPANDER(dev);

    if (s->interrupt_pin >= 16) {
        error_setg(errp, "Expander interrupt pin must be below 16");
        return;
    }
    if (s->interrupt_gpio) {
        qdev_connect_gpio_out(DEVICE(dev), 0,
            qdev_get_gpio_in(s->interrupt_gpio, s->interrupt_pin));
    }
}

static const Property expander_properties[] = {
    DEFINE_PROP_LINK("interrupt-gpio", Z72Expander, interrupt_gpio,
                     "nikon-z72-controller-gpio", DeviceState *),
    DEFINE_PROP_UINT8("interrupt-pin", Z72Expander, interrupt_pin, 8),
};

static void expander_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *ic = I2C_SLAVE_CLASS(klass);
    dc->vmsd = &expander_state;
    device_class_set_props(dc, expander_properties);
    dc->realize = expander_realize;
    ic->event = expander_event;
    ic->send = expander_send;
    ic->recv = expander_receive;
    object_class_property_add(klass, "input-levels", "uint32", expander_levels_get,
                              expander_levels_set, NULL, NULL);
    RESETTABLE_CLASS(klass)->phases.hold = expander_reset;
}

static void expander_register_type(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_EXPANDER,
        .parent = TYPE_I2C_SLAVE,
        .instance_size = sizeof(Z72Expander),
        .instance_init = expander_init,
        .class_init = expander_class_init,
    };
    type_register_static(&info);
}
type_init(expander_register_type)
