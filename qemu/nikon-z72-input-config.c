/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Input processing configuration storage recovered from the firmware.
 * Result registers remain at their laboratory reset value of zero until
 * a pixel-processing producer is modeled; no transfers are completed. */
#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_Z72_INPUT_CONFIG "nikon-z72-input-config"
OBJECT_DECLARE_SIMPLE_TYPE(Z72InputConfig, Z72_INPUT_CONFIG)

/* Register offsets below are relative to 0x20068000. The exported region
 * starts at +0x400, beyond the existing input controls and event banks. */
#define CONFIG_FIRST 0x400
#define CONFIG_LIMIT 0x4000

struct Z72InputConfig {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t registers[CONFIG_LIMIT / 4];
};

static bool input_result_register(hwaddr offset)
{
    return (offset >= 0x2100 && offset <= 0x212c) ||
           (offset >= 0x3f00 && offset <= 0x3f2c) ||
           (offset >= 0x23e0 && offset <= 0x23ec) ||
           offset == 0x2044 || offset == 0x3e44 || offset == 0x3988 ||
           offset == 0x3b70 || offset == 0x3b78 || offset == 0x3b7c ||
           offset == 0x3c78 || offset == 0x3c7c ||
           offset == 0x3d78 || offset == 0x3d7c;
}

static bool input_config_accepts(void *opaque, hwaddr offset, unsigned size,
                                 bool is_write, MemTxAttrs attrs)
{
    static const struct { unsigned first, last; } ranges[] = {
        { 0x500, 0x500 }, { 0x508, 0x81c },
        { 0xa00, 0xafc }, { 0xc00, 0xe3c },
        { 0xf00, 0x100c }, { 0x1100, 0x117c },
        { 0x1500, 0x1530 }, { 0x1600, 0x17fc },
        { 0x1d00, 0x1efc }, { 0x1f00, 0x1f00 },
        { 0x2000, 0x2024 }, { 0x2040, 0x2040 },
        { 0x2200, 0x2370 },
        { 0x3000, 0x3200 },
        { 0x3310, 0x33bc }, { 0x33c0, 0x33c0 },
        { 0x33c4, 0x33c8 }, { 0x33cc, 0x33fc },
        { 0x3400, 0x3400 },
        { 0x3800, 0x3984 }, { 0x3a00, 0x3ab8 },
        { 0x3e00, 0x3e24 }, { 0x3e40, 0x3e40 },
    };

    offset += CONFIG_FIRST;
    if (size != 4 || (offset & 3)) {
        return false;
    }
    if (input_result_register(offset)) {
        return !is_write;
    }
    for (unsigned i = 0; i < G_N_ELEMENTS(ranges); i++) {
        if (offset >= ranges[i].first && offset <= ranges[i].last) {
            return true;
        }
    }
    if (offset >= 0x1800 && offset < 0x1c00) {
        unsigned channel = (offset - 0x1800) / 0x100;
        unsigned reg = offset & 0xff;
        bool control = !(channel & 1) &&
            (reg == 0x14 || reg == 0x18 || reg == 0x3c || reg == 0x40 ||
             reg == 0x44 || reg == 0x48 || reg == 0x4c);

        return control || reg == 8 || (reg >= 0x50 && reg <= 0x6c) ||
               (channel == 2 && reg == 0x24) ||
               (channel >= 2 && reg == 0x80);
    }
    if ((offset >= 0x2400 && offset < 0x2e00) ||
        (offset >= 0x3400 && offset < 0x3e00)) {
        unsigned channel = ((offset & 0xfff) - 0x400) / 0x100;
        unsigned reg = offset & 0xff;
        bool planes = channel == 2 || channel == 3 || channel == 4 || channel == 9;

        return reg == 0x14 || reg == 0x18 || reg == 0x24 || reg == 0x3c ||
               reg == 0x40 || reg == 0x44 || reg == 0x48 || reg == 0x4c ||
               reg == 0x50 || reg == 0x60 || reg == 0x74 || reg == 0x80 ||
               (planes && ((reg >= 0x54 && reg <= 0x5c) ||
                           (reg >= 0x64 && reg <= 0x6c)));
    }
    return false;
}

static uint64_t input_config_read(void *opaque, hwaddr offset, unsigned size)
{
    Z72InputConfig *s = opaque;

    return s->registers[(offset + CONFIG_FIRST) / 4];
}

static MemTxResult input_config_write(void *opaque, hwaddr offset, uint64_t value,
                                      unsigned size, MemTxAttrs attrs)
{
    Z72InputConfig *s = opaque;

    offset += CONFIG_FIRST;
    if (offset == 0x500 && value > 0x3fff) {
        return MEMTX_ERROR;
    }
    s->registers[offset / 4] = value;
    return MEMTX_OK;
}

static const MemoryRegionOps input_config_ops = {
    .read = input_config_read,
    .write_with_attrs = input_config_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4,
               .accepts = input_config_accepts },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void input_config_reset(Object *obj, ResetType type)
{
    Z72InputConfig *s = Z72_INPUT_CONFIG(obj);

    memset(s->registers, 0, sizeof(s->registers));
}

static const VMStateDescription input_config_vmstate = {
    .name = TYPE_Z72_INPUT_CONFIG,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(registers, Z72InputConfig, CONFIG_LIMIT / 4),
        VMSTATE_END_OF_LIST()
    },
};

static void input_config_init(Object *obj)
{
    Z72InputConfig *s = Z72_INPUT_CONFIG(obj);

    memory_region_init_io(&s->iomem, obj, &input_config_ops, s,
                          TYPE_Z72_INPUT_CONFIG, CONFIG_LIMIT - CONFIG_FIRST);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
}

static void input_config_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->vmsd = &input_config_vmstate;
    dc->user_creatable = false;
    RESETTABLE_CLASS(oc)->phases.hold = input_config_reset;
}

static const TypeInfo input_config_info = {
    .name = TYPE_Z72_INPUT_CONFIG,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Z72InputConfig),
    .instance_init = input_config_init,
    .class_init = input_config_class_init,
};

static void input_config_register_types(void)
{
    type_register_static(&input_config_info);
}
type_init(input_config_register_types)
