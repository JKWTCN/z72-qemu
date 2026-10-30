/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_Z72_CONTROLLER_GPIO "nikon-z72-controller-gpio"
OBJECT_DECLARE_SIMPLE_TYPE(Z72ControllerGPIO, Z72_CONTROLLER_GPIO)

struct Z72ControllerGPIO {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t registers[10];
    uint16_t inputs;
    uint16_t connected;
    qemu_irq outputs[16];
    qemu_irq pads[16];
    qemu_irq alternate2[16];
};

static uint16_t gpio_output_mask(Z72ControllerGPIO *s)
{
    uint16_t mask = 0;
    for (unsigned pin = 0; pin < 16; pin++) {
        if (((s->registers[0] >> (2 * pin)) & 3) == 1) {
            mask |= 1u << pin;
        }
    }
    return mask;
}

static uint16_t gpio_pad_levels(Z72ControllerGPIO *s)
{
    uint16_t outputs = gpio_output_mask(s);
    uint16_t levels = s->inputs & s->connected;
    for (unsigned pin = 0; pin < 16; pin++) {
        if (!(s->connected & (1u << pin)) &&
            ((s->registers[3] >> (2 * pin)) & 3) == 1) {
            levels |= 1u << pin;
        }
    }
    return (levels & ~outputs) | (s->registers[5] & outputs);
}

static void gpio_update(Z72ControllerGPIO *s)
{
    uint16_t levels = gpio_output_mask(s) & s->registers[5];
    uint16_t pads = gpio_pad_levels(s);
    for (unsigned pin = 0; pin < 16; pin++) {
        unsigned mode = (s->registers[0] >> (2 * pin)) & 3;
        unsigned function = (s->registers[8 + pin / 8] >> (4 * (pin % 8))) & 15;
        qemu_set_irq(s->alternate2[pin], mode == 2 && function == 2);
        qemu_set_irq(s->outputs[pin], !!(levels & (1u << pin)));
        qemu_set_irq(s->pads[pin], !!(pads & (1u << pin)));
    }
}

static void gpio_input(void *opaque, int pin, int level)
{
    Z72ControllerGPIO *s = opaque;
    uint16_t bit = 1u << pin;
    s->connected |= bit;
    s->inputs = (s->inputs & ~bit) | (level ? bit : 0);
    gpio_update(s);
}

static bool gpio_register(hwaddr offset, unsigned size)
{
    return size == 4 && !(offset & 3) && offset <= 0x24 && offset != 0x1c;
}

static MemTxResult gpio_read(void *opaque, hwaddr offset, uint64_t *value,
                            unsigned size, MemTxAttrs attrs)
{
    Z72ControllerGPIO *s = opaque;
    if (!gpio_register(offset, size)) {
        return MEMTX_ERROR;
    }
    if (offset == 0x10) {
        *value = gpio_pad_levels(s);
    } else {
        *value = offset == 0x18 ? 0 : s->registers[offset / 4];
    }
    return MEMTX_OK;
}

static MemTxResult gpio_write(void *opaque, hwaddr offset, uint64_t value,
                             unsigned size, MemTxAttrs attrs)
{
    Z72ControllerGPIO *s = opaque;
    if (!gpio_register(offset, size) || offset == 0x10) {
        return MEMTX_ERROR;
    }
    if (offset == 0x18) {
        /* Apply reset bits then set bits to the output latch. */
        s->registers[5] = ((s->registers[5] & ~(value >> 16)) | value) & 0xffff;
    } else {
        s->registers[offset / 4] = (offset == 4 || offset == 0x14) ?
                                  value & 0xffff : value;
    }
    gpio_update(s);
    return MEMTX_OK;
}

static const MemoryRegionOps gpio_ops = {
    .read_with_attrs = gpio_read,
    .write_with_attrs = gpio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void gpio_reset(Object *obj, ResetType type)
{
    Z72ControllerGPIO *s = Z72_CONTROLLER_GPIO(obj);
    memset(s->registers, 0, sizeof(s->registers));
    gpio_update(s);
}

static int gpio_post_load(void *opaque, int version)
{
    gpio_update(opaque);
    return 0;
}

static const VMStateDescription gpio_state = {
    .name = TYPE_Z72_CONTROLLER_GPIO,
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = gpio_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(registers, Z72ControllerGPIO, 10),
        VMSTATE_UINT16(inputs, Z72ControllerGPIO),
        VMSTATE_UINT16(connected, Z72ControllerGPIO),
        VMSTATE_END_OF_LIST()
    },
};

static void gpio_init(Object *obj)
{
    Z72ControllerGPIO *s = Z72_CONTROLLER_GPIO(obj);
    memory_region_init_io(&s->iomem, obj, &gpio_ops, s,
                          TYPE_Z72_CONTROLLER_GPIO, 0x400);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    qdev_init_gpio_in(DEVICE(s), gpio_input, 16);
    qdev_init_gpio_out(DEVICE(s), s->outputs, 16);
    qdev_init_gpio_out_named(DEVICE(s), s->pads, "pad", 16);
    qdev_init_gpio_out_named(DEVICE(s), s->alternate2, "alternate-2-enable", 16);
}

static void gpio_class_init(ObjectClass *klass, const void *data)
{
    DEVICE_CLASS(klass)->vmsd = &gpio_state;
    RESETTABLE_CLASS(klass)->phases.hold = gpio_reset;
}

static void gpio_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_CONTROLLER_GPIO,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(Z72ControllerGPIO),
        .instance_init = gpio_init,
        .class_init = gpio_class_init,
    };
    type_register_static(&info);
}
type_init(gpio_register_types)
