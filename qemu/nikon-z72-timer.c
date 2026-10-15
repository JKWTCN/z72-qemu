/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Experimental periodic contract for the timer family at 0x2B000000.
 *
 * Firmware evidence from the released startup run: the kernel writes a
 * channel-start word (+0), a period word (+4) and an event mask (+8, observed
 * 0x300 for channels 8/9) and then expects periodic service: the interrupt
 * dispatch table maps line 237 to the channel-status dispatcher, which reads
 * +8, calls one callback per set bit pair and writes the value back. The
 * laboratory models that contract: armed event bits are latched into +8 (and
 * the per-channel status word +0x10) at a selectable period, the line stays
 * asserted until the firmware writes the bits back, and every other word in
 * the block is passive storage. Real channel timing, the period unit and the
 * hardware event sources remain unconfirmed. */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/qdev-properties.h"
#include "hw/irq.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"
#include "qom/object.h"

#define Z72_TIMER_BLOCK 0x3000
#define Z72_TIMER_EVENT 8
#define Z72_TIMER_STATUS 0x10

#define TYPE_NIKON_Z72_TIMER "nikon-z72-timer"
OBJECT_DECLARE_SIMPLE_TYPE(NikonZ72Timer, NIKON_Z72_TIMER)

struct NikonZ72Timer {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint8_t storage[Z72_TIMER_BLOCK];
    DeviceState *intc;
    QEMUTimer *tick;
    uint32_t pending;
    uint32_t armed;
    uint32_t line;
    uint32_t tick_us;
    bool enabled;
};

static void z72_timer_update_line(NikonZ72Timer *s)
{
    if (s->intc) {
        /* Controller input lines start at shared-interrupt id 32; the
         * property carries the dispatcher id the firmware uses. */
        qemu_set_irq(qdev_get_gpio_in(s->intc, s->line - 32), s->pending != 0);
    }
}

static void z72_timer_arm(NikonZ72Timer *s)
{
    if (s->enabled && !timer_pending(s->tick)) {
        timer_mod(s->tick, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                  (uint64_t)s->tick_us * 1000);
    }
}

static void z72_timer_expire(void *opaque)
{
    NikonZ72Timer *s = opaque;
    if (!s->armed) {
        return;
    }
    s->pending |= s->armed;
    uint32_t status;
    memcpy(&status, s->storage + Z72_TIMER_STATUS, 4);
    status |= s->armed;
    memcpy(s->storage + Z72_TIMER_STATUS, &status, 4);
    z72_timer_update_line(s);
    timer_mod(s->tick, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              (uint64_t)s->tick_us * 1000);
}

static uint64_t z72_timer_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72Timer *s = opaque;
    if (!s->enabled) {
        uint64_t stored = 0;
        memcpy(&stored, s->storage + offset, size);
        return stored;
    }
    if (offset == Z72_TIMER_EVENT && size == 4) {
        return s->armed | s->pending;
    }
    uint64_t value = 0;
    memcpy(&value, s->storage + offset, size);
    return value;
}

static void z72_timer_write(void *opaque, hwaddr offset, uint64_t value,
                        unsigned size)
{
    NikonZ72Timer *s = opaque;
    if (!s->enabled) {
        memcpy(s->storage + offset, &value, size);
        return;
    }
    if (offset == Z72_TIMER_EVENT && size == 4) {
        /* The kernel stores its channel mask here and the dispatcher later
         * writes the read value back: the written bits drop the latched
         * events (servicing them) while the mask itself persists. */
        s->pending &= ~(uint32_t)value;
        if (value) {
            s->armed |= value;
            z72_timer_arm(s);
        }
        z72_timer_update_line(s);
        return;
    }
    if (offset == Z72_TIMER_STATUS && size == 4) {
        uint32_t status;
        memcpy(&status, s->storage + Z72_TIMER_STATUS, 4);
        status &= ~(uint32_t)value;
        memcpy(s->storage + Z72_TIMER_STATUS, &status, 4);
        return;
    }
    memcpy(s->storage + offset, &value, size);
}

static const MemoryRegionOps z72_timer_ops = {
    .read = z72_timer_read,
    .write = z72_timer_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void z72_timer_reset(Object *obj, ResetType type)
{
    NikonZ72Timer *s = NIKON_Z72_TIMER(obj);
    memset(s->storage, 0, sizeof(s->storage));
    s->pending = 0;
    s->armed = 0;
    timer_del(s->tick);
    z72_timer_update_line(s);
}

static const VMStateDescription z72_timer_vmstate = {
    .name = TYPE_NIKON_Z72_TIMER,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT8_ARRAY(storage, NikonZ72Timer, Z72_TIMER_BLOCK),
        VMSTATE_UINT32(pending, NikonZ72Timer),
        VMSTATE_UINT32(armed, NikonZ72Timer),
        VMSTATE_END_OF_LIST()
    },
};

static void z72_timer_realize(DeviceState *dev, Error **errp)
{
    NikonZ72Timer *s = NIKON_Z72_TIMER(dev);
    if (s->line < 32 || s->line > 255) {
        error_setg(errp, "Z72 timer line must be a shared interrupt id 32..255");
        return;
    }
    if (!s->tick_us) {
        error_setg(errp, "Z72 timer tick period must be nonzero");
        return;
    }
}

static void z72_timer_unrealize(DeviceState *dev)
{
    NikonZ72Timer *s = NIKON_Z72_TIMER(dev);
    timer_del(s->tick);
}

static const Property z72_timer_properties[] = {
    DEFINE_PROP_LINK("intc", NikonZ72Timer, intc, TYPE_DEVICE, DeviceState *),
    DEFINE_PROP_UINT32("line", NikonZ72Timer, line, 237),
    DEFINE_PROP_UINT32("tick-us", NikonZ72Timer, tick_us, 1000),
    DEFINE_PROP_BOOL("tick-enabled", NikonZ72Timer, enabled, true),
};

static void z72_timer_init(Object *obj)
{
    NikonZ72Timer *s = NIKON_Z72_TIMER(obj);
    memory_region_init_io(&s->iomem, obj, &z72_timer_ops, s,
                          TYPE_NIKON_Z72_TIMER, Z72_TIMER_BLOCK);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    s->tick = timer_new_ns(QEMU_CLOCK_VIRTUAL, z72_timer_expire, s);
}

static void z72_timer_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    device_class_set_props(dc, z72_timer_properties);
    dc->realize = z72_timer_realize;
    dc->unrealize = z72_timer_unrealize;
    dc->vmsd = &z72_timer_vmstate;
    dc->user_creatable = false;
    RESETTABLE_CLASS(oc)->phases.hold = z72_timer_reset;
}

static const TypeInfo z72_timer_info = {
    .name = TYPE_NIKON_Z72_TIMER,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(NikonZ72Timer),
    .instance_init = z72_timer_init,
    .class_init = z72_timer_class_init,
};

static void z72_timer_register_types(void)
{
    type_register_static(&z72_timer_info);
}
type_init(z72_timer_register_types)
