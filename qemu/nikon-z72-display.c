/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Display configuration and the recovered interrupt contract.
 * No pixel transfer, scanout, or automatic completion is generated here. */
#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_Z72_DISPLAY "nikon-z72-display"
OBJECT_DECLARE_SIMPLE_TYPE(Z72Display, Z72_DISPLAY)
#define DISPLAY_SIZE 0xf000

struct Z72Display {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq[2];
    uint32_t registers[DISPLAY_SIZE / 4];
    uint32_t levels[2];
};

static void display_update_irqs(Z72Display *s)
{
    for (unsigned bank = 0; bank < 2; bank++) {
        unsigned mask = (0x1210 + bank * 0x4000) / 4;

        qemu_set_irq(s->irq[bank],
                     (s->registers[mask] & s->registers[mask + 1]) != 0);
    }
}

static void display_event(void *opaque, int line, int level)
{
    Z72Display *s = opaque;
    unsigned bank = line / 32;
    uint32_t bit = 1u << (line % 32);

    if (level && !(s->levels[bank] & bit)) {
        s->registers[(0x1214 + bank * 0x4000) / 4] |= bit;
    }
    s->levels[bank] = level ? s->levels[bank] | bit : s->levels[bank] & ~bit;
    display_update_irqs(s);
}

static uint64_t display_read(void *opaque, hwaddr offset, unsigned size)
{
    Z72Display *s = opaque;

    return s->registers[offset / 4];
}

static void display_write(void *opaque, hwaddr offset, uint64_t value,
                          unsigned size)
{
    Z72Display *s = opaque;

    /* 1046e1ca clears status before enabling the same mask; 1046bc6c
     * acknowledges by reading +214 and writing that value back. */
    if (offset == 0x1214 || offset == 0x5214) {
        s->registers[offset / 4] &= ~value;
    } else {
        s->registers[offset / 4] = value;
    }
    if (offset == 0x1210 || offset == 0x1214 ||
        offset == 0x5210 || offset == 0x5214) {
        display_update_irqs(s);
    }
}

static bool display_accepts(void *opaque, hwaddr offset, unsigned size,
                            bool is_write, MemTxAttrs attrs)
{
    return size == 4 && !(offset & 3);
}

static const MemoryRegionOps display_ops = {
    .read = display_read,
    .write = display_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4,
               .accepts = display_accepts },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void display_reset(Object *obj, ResetType type)
{
    Z72Display *s = Z72_DISPLAY(obj);

    memset(s->registers, 0, sizeof(s->registers));
    memset(s->levels, 0, sizeof(s->levels));
    display_update_irqs(s);
}

static int display_post_load(void *opaque, int version)
{
    display_update_irqs(Z72_DISPLAY(opaque));
    return 0;
}

static const VMStateDescription display_vmstate = {
    .name = TYPE_Z72_DISPLAY,
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = display_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(registers, Z72Display, DISPLAY_SIZE / 4),
        VMSTATE_UINT32_ARRAY(levels, Z72Display, 2),
        VMSTATE_END_OF_LIST()
    },
};

static void display_init(Object *obj)
{
    Z72Display *s = Z72_DISPLAY(obj);

    memory_region_init_io(&s->iomem, obj, &display_ops, s,
                          TYPE_Z72_DISPLAY, DISPLAY_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    for (unsigned bank = 0; bank < 2; bank++) {
        sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irq[bank]);
    }
    qdev_init_gpio_in_named(DEVICE(obj), display_event, "output-event", 64);
}

static void display_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->vmsd = &display_vmstate;
    dc->user_creatable = false;
    RESETTABLE_CLASS(oc)->phases.hold = display_reset;
}

static const TypeInfo display_info = {
    .name = TYPE_Z72_DISPLAY,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Z72Display),
    .instance_init = display_init,
    .class_init = display_class_init,
};

static void display_register_types(void)
{
    type_register_static(&display_info);
}
type_init(display_register_types)
