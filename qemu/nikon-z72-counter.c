/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Experimental counter contract observed in the stock runtime callbacks. */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"
#include "target/arm/cpu.h"
#include "nikon-z72-profile.h"

#define TYPE_NIKON_Z72_COUNTER "nikon-z72-counter"
OBJECT_DECLARE_SIMPLE_TYPE(NikonZ72Counter, NIKON_Z72_COUNTER)

struct NikonZ72Counter {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    ARMCPU *cpu;
    uint64_t count, epoch;
    uint32_t control, frequency;
    bool enabled;
};

static uint64_t counter_now(NikonZ72Counter *s)
{
    /* Share the CPU generic timer's virtual-clock period, including QEMU's
     * integer-nanosecond rounding. MMIO gating does not gate the CPU counter. */
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / gt_cntfrq_period_ns(s->cpu);
}

static uint64_t counter_value(NikonZ72Counter *s)
{
    return s->count + ((s->control & 1) ? counter_now(s) - s->epoch : 0);
}

static MemTxResult counter_read(void *opaque, hwaddr offset, uint64_t *value,
                                unsigned size, MemTxAttrs attrs)
{
    NikonZ72Counter *s = opaque;
    if (!s->enabled) {
        return MEMTX_ERROR;
    }
    switch (offset) {
    case 0: *value = s->control; break;
    case 8: *value = (uint32_t)counter_value(s); break;
    case 12: *value = counter_value(s) >> 32; break;
    case 16: *value = s->frequency; break;
    default: return MEMTX_DECODE_ERROR;
    }
    return MEMTX_OK;
}

static MemTxResult counter_write(void *opaque, hwaddr offset, uint64_t value,
                                 unsigned size, MemTxAttrs attrs)
{
    NikonZ72Counter *s = opaque;
    if (!s->enabled) {
        return MEMTX_ERROR;
    }
    switch (offset) {
    case 0:
        if (value & ~3u) {
            return MEMTX_ERROR;
        }
        s->count = counter_value(s);
        s->epoch = counter_now(s);
        s->control = value;
        break;
    case 8:
    case 12:
        if (s->control & 1) {
            return MEMTX_ERROR;
        }
        s->count = offset == 8 ? (s->count & 0xffffffff00000000ULL) | value :
                                (s->count & 0xffffffffULL) | (value << 32);
        break;
    case 16:
        if ((s->control & 1) || value != Z72_COUNTER_FREQUENCY) {
            return MEMTX_ERROR;
        }
        s->frequency = value;
        break;
    default:
        return MEMTX_DECODE_ERROR;
    }
    return MEMTX_OK;
}

static const MemoryRegionOps counter_ops = {
    .read_with_attrs = counter_read,
    .write_with_attrs = counter_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void counter_reset(Object *obj, ResetType type)
{
    NikonZ72Counter *s = NIKON_Z72_COUNTER(obj);
    s->control = s->frequency = 0;
    s->count = s->epoch = 0;
}

static const VMStateDescription counter_vmstate = {
    .name = TYPE_NIKON_Z72_COUNTER,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(count, NikonZ72Counter),
        VMSTATE_UINT64(epoch, NikonZ72Counter),
        VMSTATE_UINT32(control, NikonZ72Counter),
        VMSTATE_UINT32(frequency, NikonZ72Counter),
        VMSTATE_END_OF_LIST()
    },
};

static void counter_init(Object *obj)
{
    NikonZ72Counter *s = NIKON_Z72_COUNTER(obj);
    memory_region_init_io(&s->iomem, obj, &counter_ops, s,
                          TYPE_NIKON_Z72_COUNTER, 0x14);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
}

static void counter_realize(DeviceState *dev, Error **errp)
{
    NikonZ72Counter *s = NIKON_Z72_COUNTER(dev);
    if (!s->cpu || s->cpu->gt_cntfrq_hz != Z72_COUNTER_FREQUENCY) {
        error_setg(errp, "Z72 counter requires a CPU with a 48 MHz timer clock");
    }
}

static void counter_class_init(ObjectClass *oc, const void *data)
{
    static const Property properties[] = {
        DEFINE_PROP_LINK("cpu", NikonZ72Counter, cpu, TYPE_ARM_CPU, ARMCPU *),
        DEFINE_PROP_BOOL("enabled", NikonZ72Counter, enabled, true),
    };
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = counter_realize;
    dc->vmsd = &counter_vmstate;
    device_class_set_props(dc, properties);
    RESETTABLE_CLASS(oc)->phases.hold = counter_reset;
}

static void counter_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_NIKON_Z72_COUNTER,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(NikonZ72Counter),
        .instance_init = counter_init,
        .class_init = counter_class_init,
    };
    type_register_static(&info);
}
type_init(counter_register_types)
