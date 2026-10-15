/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/i2c/i2c.h"
#include "qapi/error.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_Z72_CONTROLLER_I2C "nikon-z72-controller-i2c"
OBJECT_DECLARE_SIMPLE_TYPE(Z72ControllerI2C, Z72_CONTROLLER_I2C)

struct Z72ControllerI2C {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t registers[10];
    bool address_phase;
    bool start_completion;
    I2CBus *bus;
    char *bus_name;
    bool active;
    bool receiving;
    bool status_seen;
    uint8_t receive_data[2];
    uint8_t receive_count;
    uint8_t final_byte;
    qemu_irq event_irq;
    qemu_irq error_irq;
    qemu_irq requests[2];
};

static void i2c_update_irq(Z72ControllerI2C *s)
{
    qemu_set_irq(s->event_irq, !!((s->registers[1] & 0x200) &&
                                 ((s->registers[5] & 7) ||
                                  ((s->registers[1] & 0x400) &&
                                   (s->registers[5] & 0xc0)))));
    qemu_set_irq(s->error_irq, !!((s->registers[1] & 0x100) &&
                                 (s->registers[5] & 0xf00)));
    bool dma = s->active && (s->registers[0] & 1) &&
               (s->registers[1] & 0x800) && !(s->registers[5] & 2);
    qemu_set_irq(s->requests[0], dma && s->receiving &&
                 (s->registers[5] & 0x40));
    qemu_set_irq(s->requests[1], dma && !s->receiving &&
                 (s->registers[5] & 0x80));
}

static void i2c_clear(Z72ControllerI2C *s)
{
    memset(s->registers, 0, sizeof(s->registers));
    s->address_phase = false;
    s->active = false;
    s->receiving = false;
    s->status_seen = false;
    s->receive_count = 0;
    s->final_byte = 0;
    if (s->bus) {
        i2c_end_transfer(s->bus);
    }
    i2c_update_irq(s);
}

static bool i2c_register(hwaddr offset, unsigned size)
{
    return !(offset & 3) && offset <= 0x24 &&
           (size == 4 || (offset == 0x10 && size == 1));
}

static void i2c_receive_status(Z72ControllerI2C *s)
{
    s->registers[5] &= ~0xc4u;
    if (s->receive_count) {
        s->registers[5] |= 0x40;
    }
    if (s->receive_count == 2) {
        s->registers[5] |= 4;
    }
}

static void i2c_fill(Z72ControllerI2C *s, unsigned count)
{
    while (s->active && s->receive_count < count) {
        s->receive_data[s->receive_count++] = i2c_recv(s->bus);
    }
    i2c_receive_status(s);
}

static MemTxResult i2c_read(void *opaque, hwaddr offset, uint64_t *value,
                           unsigned size, MemTxAttrs attrs)
{
    Z72ControllerI2C *s = opaque;
    if (!i2c_register(offset, size)) {
        return MEMTX_ERROR;
    }
    if (offset == 0x10) {
        if (!s->receiving || !s->receive_count) {
            return MEMTX_ERROR;
        }
        *value = s->receive_data[0];
        s->receive_data[0] = s->receive_data[1];
        s->receive_count--;
        if (s->active && (s->registers[0] & 0x400)) {
            i2c_fill(s, 2);
        } else if (s->active && s->final_byte) {
            s->final_byte--;
            i2c_fill(s, s->receive_count + 1);
        } else {
            i2c_receive_status(s);
        }
        i2c_update_irq(s);
        return MEMTX_OK;
    }
    *value = s->registers[offset / 4];
    if (offset == 0x14) {
        s->status_seen = !!(s->registers[5] & 2);
    } else if (offset == 0x18 && s->status_seen) {
        s->status_seen = false;
        if (s->registers[5] & 2) {
            s->registers[5] &= ~2u;
            if (s->receiving) {
                i2c_fill(s, (s->registers[0] & 0xc00) ? 2 : 1);
            } else {
                s->registers[5] |= 0x80;
            }
            i2c_update_irq(s);
        }
    }
    return MEMTX_OK;
}

static MemTxResult i2c_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size, MemTxAttrs attrs)
{
    Z72ControllerI2C *s = opaque;
    if (!i2c_register(offset, size) || offset == 0x18) {
        return MEMTX_ERROR;
    }
    if (offset == 0) {
        if (value & 0x8000) {
            i2c_clear(s);
            s->registers[0] = 0x8000;
            return MEMTX_OK;
        }
        if (s->receiving && s->active && (s->registers[0] & 0x400) &&
            !(value & 0x400) && !(value & 0x800) && s->receive_count == 2) {
            s->final_byte = 1;
        }
        s->registers[0] = value;
        if (!(value & 1) || (value & 0x200)) {
            if (s->active && s->receiving) {
                i2c_nack(s->bus);
            }
            i2c_end_transfer(s->bus);
            s->active = false;
            s->address_phase = false;
            s->registers[6] = 0;
            s->registers[5] &= ~0x87u;
            if (!(value & 1)) {
                s->receiving = false;
                s->receive_count = s->final_byte = 0;
                s->registers[5] &= ~0xc4u;
            }
            if (s->receiving) {
                i2c_receive_status(s);
            }
            s->registers[0] &= ~0x300u;
        } else if (value & 0x100) {
            s->address_phase = s->start_completion;
            s->status_seen = false;
            s->receive_count = 0;
            s->final_byte = 0;
            s->registers[5] &= ~0xc7u;
            s->registers[6] = 3;
            if (s->start_completion) {
                s->registers[5] |= 1;
            }
        }
    } else if (offset == 0x10) {
        if (value > 0xff || (!s->address_phase && (!s->active || s->receiving))) {
            return MEMTX_ERROR;
        }
        if (s->address_phase) {
            s->address_phase = false;
            s->receiving = value & 1;
            s->registers[0] &= ~0x100u;
            s->registers[5] &= ~1u;
            s->active = !i2c_start_transfer(s->bus, value >> 1, s->receiving);
            if (s->active) {
                s->registers[5] |= 2;
                s->registers[6] = s->receiving ? 3 : 7;
            } else {
                s->registers[5] |= 0x400;
            }
        } else if (i2c_send(s->bus, value)) {
            s->registers[5] |= 0x400;
        } else {
            s->registers[5] |= 0x84;
        }
    } else if (offset == 0x14) {
        s->registers[5] &= value | ~0xf00u;
    } else {
        s->registers[offset / 4] = value;
    }
    i2c_update_irq(s);
    return MEMTX_OK;
}

static const MemoryRegionOps i2c_ops = {
    .read_with_attrs = i2c_read,
    .write_with_attrs = i2c_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void i2c_reset(Object *obj, ResetType type)
{
    i2c_clear(Z72_CONTROLLER_I2C(obj));
}

static int i2c_post_load(void *opaque, int version)
{
    Z72ControllerI2C *s = opaque;
    if (version < 2) {
        s->active = s->receiving = s->status_seen = false;
        s->receive_count = s->final_byte = 0;
    }
    if (s->receive_count > 2 || s->final_byte > 1) {
        return -EINVAL;
    }
    i2c_update_irq(s);
    return 0;
}

static const VMStateDescription i2c_state = {
    .name = TYPE_Z72_CONTROLLER_I2C,
    .version_id = 2,
    .minimum_version_id = 1,
    .post_load = i2c_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(registers, Z72ControllerI2C, 10),
        VMSTATE_BOOL(address_phase, Z72ControllerI2C),
        VMSTATE_BOOL_V(active, Z72ControllerI2C, 2),
        VMSTATE_BOOL_V(receiving, Z72ControllerI2C, 2),
        VMSTATE_BOOL_V(status_seen, Z72ControllerI2C, 2),
        VMSTATE_UINT8_ARRAY_V(receive_data, Z72ControllerI2C, 2, 2),
        VMSTATE_UINT8_V(receive_count, Z72ControllerI2C, 2),
        VMSTATE_UINT8_V(final_byte, Z72ControllerI2C, 2),
        VMSTATE_END_OF_LIST()
    },
};

static const Property i2c_properties[] = {
    DEFINE_PROP_BOOL("start-completion", Z72ControllerI2C, start_completion, true),
    DEFINE_PROP_STRING("bus-name", Z72ControllerI2C, bus_name),
};

static void i2c_realize(DeviceState *dev, Error **errp)
{
    Z72ControllerI2C *s = Z72_CONTROLLER_I2C(dev);
    s->bus = i2c_init_bus(dev, s->bus_name);
}

static void i2c_init(Object *obj)
{
    Z72ControllerI2C *s = Z72_CONTROLLER_I2C(obj);
    memory_region_init_io(&s->iomem, obj, &i2c_ops, s,
                          TYPE_Z72_CONTROLLER_I2C, 0x400);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    sysbus_init_irq(SYS_BUS_DEVICE(s), &s->event_irq);
    sysbus_init_irq(SYS_BUS_DEVICE(s), &s->error_irq);
    qdev_init_gpio_out_named(DEVICE(s), s->requests, "dma-request", 2);
}

static void i2c_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = i2c_realize;
    dc->vmsd = &i2c_state;
    device_class_set_props(dc, i2c_properties);
    RESETTABLE_CLASS(klass)->phases.hold = i2c_reset;
}

static void i2c_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_CONTROLLER_I2C,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(Z72ControllerI2C),
        .instance_init = i2c_init,
        .class_init = i2c_class_init,
    };
    type_register_static(&info);
}
type_init(i2c_register_types)
