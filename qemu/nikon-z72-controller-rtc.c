/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_Z72_CONTROLLER_RTC "nikon-z72-controller-rtc"
OBJECT_DECLARE_SIMPLE_TYPE(Z72ControllerRTC, Z72_CONTROLLER_RTC)

struct Z72ControllerRTC {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t registers[40];
    uint8_t key_stage;
    bool unlocked;
    bool completion;
};

static void rtc_status(Z72ControllerRTC *s)
{
    uint32_t control = s->registers[2];
    uint32_t status = s->registers[3] & ~0x67u;
    status |= (~(control >> 8)) & 7;
    if (s->completion) {
        status |= (status & 0x80) ? 0x40 : 0x20;
    }
    s->registers[3] = status;
}

static bool rtc_register(hwaddr offset, unsigned size)
{
    return size == 4 && !(offset & 3) && offset < 0xa0 && offset != 0x4c;
}

static MemTxResult rtc_read(void *opaque, hwaddr offset, uint64_t *value,
                           unsigned size, MemTxAttrs attrs)
{
    Z72ControllerRTC *s = opaque;
    if (!rtc_register(offset, size)) {
        return MEMTX_ERROR;
    }
    *value = offset == 0x24 ? 0 : s->registers[offset / 4];
    return MEMTX_OK;
}

static MemTxResult rtc_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size, MemTxAttrs attrs)
{
    Z72ControllerRTC *s = opaque;
    if (!rtc_register(offset, size) || offset == 0x28 ||
        (offset >= 0x30 && offset <= 0x38)) {
        return MEMTX_ERROR;
    }
    if (offset == 0x24) {
        if (value == 0xca) {
            s->key_stage = 1;
            s->unlocked = false;
        } else if (value == 0x53 && s->key_stage == 1) {
            s->key_stage = 0;
            s->unlocked = true;
        } else {
            s->key_stage = 0;
            s->unlocked = false;
        }
        return MEMTX_OK;
    }
    /* Backup words are separate from the clock write-protection sequence. */
    if (!s->unlocked && offset < 0x50 && offset != 0xc) {
        return MEMTX_OK;
    }
    if (offset == 0xc) {
        uint32_t old = s->registers[3];
        s->registers[3] = (old & 0xffff0000) | (old & value & 0xff00) |
                          (old & 0x17) | (s->unlocked ? value & 0x80 : old & 0x80);
    } else {
        s->registers[offset / 4] = value;
    }
    rtc_status(s);
    return MEMTX_OK;
}

static const MemoryRegionOps rtc_ops = {
    .read_with_attrs = rtc_read,
    .write_with_attrs = rtc_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void rtc_reset(Object *obj, ResetType type)
{
    Z72ControllerRTC *s = Z72_CONTROLLER_RTC(obj);
    memset(s->registers, 0, sizeof(s->registers));
    s->key_stage = 0;
    s->unlocked = false;
    rtc_status(s);
}

static const VMStateDescription rtc_state = {
    .name = TYPE_Z72_CONTROLLER_RTC,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(registers, Z72ControllerRTC, 40),
        VMSTATE_UINT8(key_stage, Z72ControllerRTC),
        VMSTATE_BOOL(unlocked, Z72ControllerRTC),
        VMSTATE_END_OF_LIST()
    },
};

static const Property rtc_properties[] = {
    DEFINE_PROP_BOOL("completion", Z72ControllerRTC, completion, true),
};

static void rtc_init(Object *obj)
{
    Z72ControllerRTC *s = Z72_CONTROLLER_RTC(obj);
    memory_region_init_io(&s->iomem, obj, &rtc_ops, s,
                          TYPE_Z72_CONTROLLER_RTC, 0x400);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
}

static void rtc_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->vmsd = &rtc_state;
    device_class_set_props(dc, rtc_properties);
    RESETTABLE_CLASS(klass)->phases.hold = rtc_reset;
}

static void rtc_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_CONTROLLER_RTC,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(Z72ControllerRTC),
        .instance_init = rtc_init,
        .class_init = rtc_class_init,
    };
    type_register_static(&info);
}
type_init(rtc_register_types)
