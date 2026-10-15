/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "hw/i2c/i2c.h"
#include "qemu/timer.h"

#define TYPE_Z72_I2C "nikon-z72-i2c"
OBJECT_DECLARE_SIMPLE_TYPE(Z72I2C, Z72_I2C)
#define PORTS 4
#define DEPTH 16

typedef struct Z72I2CPort {
    Z72I2C *owner;
    unsigned index;
    uint32_t regs[12];
    uint8_t tx[DEPTH], rx[DEPTH];
    unsigned tx_count, rx_count, rx_head;
    bool active, bus_active;
    I2CBus *bus;
    QEMUTimer *timer;
} Z72I2CPort;

struct Z72I2C {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq[PORTS];
    Z72I2CPort port[PORTS];
    char *bus_name;
};

static void update_irq(Z72I2CPort *p)
{
    qemu_set_irq(p->owner->irq[p->index],
                 (p->regs[4] & ~p->regs[8] & 0x2ff) != 0);
}

static void finish_bus(Z72I2CPort *p)
{
    if (p->bus_active) {
        i2c_end_transfer(p->bus);
        p->bus_active = false;
    }
}

static void complete(void *opaque)
{
    Z72I2CPort *p = opaque;
    if (!p->active) {
        return;
    }
    if (p->regs[0] & 1) {
        unsigned count = MIN(p->regs[5] & 31, DEPTH - p->rx_count);
        for (unsigned i = 0; i < count; i++) {
            unsigned slot = (p->rx_head + p->rx_count++) % DEPTH;
            p->rx[slot] = i2c_recv(p->bus);
        }
        p->regs[4] |= (count ? 2 : 0) |
                      (count == DEPTH && (p->regs[0] & 0x10) ? 0 : 1);
    } else {
        bool full = p->tx_count == DEPTH;
        for (unsigned i = 0; i < p->tx_count; i++) {
            if (i2c_send(p->bus, p->tx[i])) {
                p->regs[4] |= 4;
                p->tx_count = 0;
                p->active = false;
                finish_bus(p);
                update_irq(p);
                return;
            }
        }
        p->tx_count = 0;
        p->regs[4] |= full && (p->regs[0] & 0x10) ? 2 : 3;
    }
    p->active = false;
    if (!(p->regs[0] & 0x10)) {
        finish_bus(p);
    }
    update_irq(p);
}

static void schedule(Z72I2CPort *p)
{
    p->active = true;
    timer_mod(p->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000);
}

static uint64_t i2c_read(void *opaque, hwaddr address, unsigned size)
{
    Z72I2C *s = opaque;
    Z72I2CPort *p = &s->port[address / 0x1000];
    unsigned offset = address % 0x1000;
    switch (offset) {
    case 4:
        return (p->bus_active ? 0x100 : 0) | (p->rx_count ? 0x20 : 0);
    case 12:
        if (p->rx_count) {
            uint8_t value = p->rx[p->rx_head];
            p->rx_head = (p->rx_head + 1) % DEPTH;
            p->rx_count--;
            return value;
        }
        return 0xff;
    case 20:
        return p->tx_count;
    default:
        return offset < sizeof(p->regs) ? p->regs[offset / 4] : 0;
    }
}

static void i2c_write(void *opaque, hwaddr address, uint64_t value, unsigned size)
{
    Z72I2C *s = opaque;
    Z72I2CPort *p = &s->port[address / 0x1000];
    unsigned offset = address % 0x1000;
    if (offset >= sizeof(p->regs)) {
        return;
    }
    switch (offset) {
    case 0:
        if (value & 0x40) {
            timer_del(p->timer);
            p->active = false;
            p->tx_count = p->rx_count = p->rx_head = 0;
            p->regs[4] = 0;
            finish_bus(p);
        }
        p->regs[0] = value & ~0x40;
        if (!(value & 8)) {
            p->active = false;
            timer_del(p->timer);
            if (!(value & 0x10)) {
                finish_bus(p);
            }
        }
        if (!(value & 0x10) && !p->active && !p->tx_count) {
            finish_bus(p);
        }
        break;
    case 8:
        p->regs[2] = value;
        if (p->regs[0] & 8) {
            finish_bus(p);
            if (i2c_start_transfer(p->bus, value & 0x7f, p->regs[0] & 1)) {
                p->regs[4] |= 4;
            } else {
                p->bus_active = true;
                schedule(p);
            }
        }
        break;
    case 12:
        if (p->tx_count < DEPTH) {
            p->tx[p->tx_count++] = value;
            if (p->bus_active && !p->active && !(p->regs[0] & 1)) {
                schedule(p);
            }
        }
        break;
    case 16:
        p->regs[4] &= ~value;
        break;
    case 20:
        p->regs[5] = value;
        if (p->bus_active && !p->active && (p->regs[0] & 1) && value) {
            schedule(p);
        }
        break;
    case 36:
        p->regs[8] &= ~value;
        break;
    case 40:
        p->regs[8] |= value;
        break;
    default:
        p->regs[offset / 4] = value;
        break;
    }
    update_irq(p);
}

static const MemoryRegionOps i2c_ops = {
    .read = i2c_read, .write = i2c_write, .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void i2c_reset(Object *obj, ResetType type)
{
    Z72I2C *s = Z72_I2C(obj);
    for (unsigned i = 0; i < PORTS; i++) {
        Z72I2CPort *p = &s->port[i];
        timer_del(p->timer);
        finish_bus(p);
        memset(p->regs, 0, sizeof(p->regs));
        p->regs[8] = 0x2ff;
        p->tx_count = p->rx_count = p->rx_head = 0;
        p->active = false;
        update_irq(p);
    }
}

static void i2c_realize(DeviceState *dev, Error **errp)
{
    Z72I2C *s = Z72_I2C(dev);
    for (unsigned i = 0; i < PORTS; i++) {
        g_autofree char *name = g_strdup_printf("%s%u", s->bus_name ? s->bus_name : "engine-i2c", i);
        s->port[i].bus = i2c_init_bus(dev, name);
    }
}

static void i2c_init(Object *obj)
{
    Z72I2C *s = Z72_I2C(obj);
    memory_region_init_io(&s->iomem, obj, &i2c_ops, s, TYPE_Z72_I2C, PORTS * 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    for (unsigned i = 0; i < PORTS; i++) {
        s->port[i].owner = s;
        s->port[i].index = i;
        s->port[i].timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, complete, &s->port[i]);
        sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irq[i]);
    }
}

static void i2c_finalize(Object *obj)
{
    Z72I2C *s = Z72_I2C(obj);
    for (unsigned i = 0; i < PORTS; i++) {
        timer_free(s->port[i].timer);
    }
}

static const Property i2c_properties[] = {
    DEFINE_PROP_STRING("bus-name", Z72I2C, bus_name),
};

static void i2c_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = i2c_realize;
    device_class_set_props(dc, i2c_properties);
    RESETTABLE_CLASS(klass)->phases.hold = i2c_reset;
}

static const TypeInfo i2c_info = {
    .name = TYPE_Z72_I2C, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Z72I2C), .instance_init = i2c_init,
    .instance_finalize = i2c_finalize, .class_init = i2c_class_init,
};

static void i2c_register_types(void)
{
    type_register_static(&i2c_info);
}
type_init(i2c_register_types)
