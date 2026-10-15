/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"
#include "qemu/timer.h"

#define TYPE_Z72_CONTROLLER_ADC "nikon-z72-controller-adc"
OBJECT_DECLARE_SIMPLE_TYPE(Z72ControllerADC, Z72_CONTROLLER_ADC)

typedef struct Z72ADCBank {
    Z72ControllerADC *owner;
    QEMUTimer *timer;
    uint32_t registers[20];
    uint16_t sample;
    bool busy;
} Z72ADCBank;

struct Z72ControllerADC {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq;
    Z72ADCBank banks[3];
    uint32_t common_control;
    uint16_t channels[19];
    bool completion;
};

static void adc_irq(Z72ControllerADC *s)
{
    bool pending = false;
    for (unsigned i = 0; i < 3; i++) {
        uint32_t sr = s->banks[i].registers[0];
        uint32_t cr1 = s->banks[i].registers[1];
        pending |= ((sr & 2) && (cr1 & (1u << 5))) ||
                   ((sr & 32) && (cr1 & (1u << 26)));
    }
    qemu_set_irq(s->irq, pending);
}

static void adc_complete(void *opaque)
{
    Z72ADCBank *b = opaque;
    unsigned bits = 12 - 2 * ((b->registers[1] >> 24) & 3);
    uint32_t value = b->sample >> (12 - bits);
    if (b->registers[2] & (1u << 11)) {
        value <<= 16 - bits;
    }
    if (b->registers[0] & 2) {
        b->registers[0] |= 32;
    }
    b->registers[19] = value;
    b->registers[0] |= 2;
    b->busy = false;
    adc_irq(b->owner);
}

static bool adc_offset(hwaddr offset, unsigned size)
{
    return size == 4 && !(offset & 3) &&
           ((offset < 0x300 && (offset & 0xff) <= 0x4c) ||
            offset == 0x300 || offset == 0x304);
}

static MemTxResult adc_read(void *opaque, hwaddr offset, uint64_t *value,
                           unsigned size, MemTxAttrs attrs)
{
    Z72ControllerADC *s = opaque;
    if (!adc_offset(offset, size)) {
        return MEMTX_ERROR;
    }
    if (offset == 0x304) {
        *value = s->common_control;
    } else if (offset == 0x300) {
        *value = 0;
        for (unsigned i = 0; i < 3; i++) {
            *value |= (s->banks[i].registers[0] & 0x3f) << (8 * i);
        }
    } else {
        Z72ADCBank *b = &s->banks[offset >> 8];
        unsigned reg = (offset & 0xff) / 4;
        *value = b->registers[reg];
        if (reg == 19) {
            b->registers[0] &= ~2u;
            adc_irq(s);
        }
    }
    return MEMTX_OK;
}

static MemTxResult adc_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size, MemTxAttrs attrs)
{
    Z72ControllerADC *s = opaque;
    if (!adc_offset(offset, size) || offset == 0x300) {
        return MEMTX_ERROR;
    }
    if (offset == 0x304) {
        s->common_control = value;
        return MEMTX_OK;
    }
    Z72ADCBank *b = &s->banks[offset >> 8];
    unsigned reg = (offset & 0xff) / 4;
    if (reg >= 15) {
        return MEMTX_ERROR;
    }
    if (reg == 0) {
        b->registers[0] &= value & 0x3f;
    } else if (reg == 2) {
        if (value & (1u << 22)) {
            return MEMTX_ERROR;
        }
        if ((value & (1u << 30)) && (value & 1)) {
            unsigned channel = b->registers[13] & 31;
            /* Only independent, software-triggered regular single samples. */
            if (channel >= 19 || (b->registers[11] & 0xf00000) ||
                (b->registers[1] & ~0x0700003fu) ||
                (value & 0x303fc302) || (s->common_control & 0xc01f)) {
                return MEMTX_ERROR;
            }
            if (!b->busy) {
                b->sample = s->channels[channel];
                b->busy = true;
                b->registers[0] |= 16;
                if (s->completion) {
                    timer_mod(b->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000);
                }
            }
        }
        b->registers[2] = value & ~(1u << 30);
        if (!(value & 1)) {
            b->busy = false;
            timer_del(b->timer);
        }
    } else {
        b->registers[reg] = value;
    }
    adc_irq(s);
    return MEMTX_OK;
}

static const MemoryRegionOps adc_ops = {
    .read_with_attrs = adc_read, .write_with_attrs = adc_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void adc_reset(Object *obj, ResetType type)
{
    Z72ControllerADC *s = Z72_CONTROLLER_ADC(obj);
    s->common_control = 0;
    for (unsigned i = 0; i < 3; i++) {
        Z72ADCBank *b = &s->banks[i];
        memset(b->registers, 0, sizeof(b->registers));
        b->registers[9] = 0xfff;
        b->sample = 0;
        b->busy = false;
        timer_del(b->timer);
    }
    adc_irq(s);
}

static int adc_post_load(void *opaque, int version)
{
    Z72ControllerADC *s = opaque;
    for (unsigned i = 0; i < 19; i++) {
        if (s->channels[i] > 4095) {
            return -EINVAL;
        }
    }
    for (unsigned i = 0; i < 3; i++) {
        Z72ADCBank *b = &s->banks[i];
        if (b->sample > 4095 || (b->busy && !(b->registers[2] & 1))) {
            return -EINVAL;
        }
    }
    adc_irq(s);
    return 0;
}

static const VMStateDescription adc_bank_state = {
    .name = "z72-controller-adc-bank", .version_id = 1, .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(registers, Z72ADCBank, 20),
        VMSTATE_UINT16(sample, Z72ADCBank),
        VMSTATE_BOOL(busy, Z72ADCBank),
        VMSTATE_TIMER_PTR(timer, Z72ADCBank),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription adc_state = {
    .name = TYPE_Z72_CONTROLLER_ADC, .version_id = 1, .minimum_version_id = 1,
    .post_load = adc_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_STRUCT_ARRAY(banks, Z72ControllerADC, 3, 1, adc_bank_state, Z72ADCBank),
        VMSTATE_UINT32(common_control, Z72ControllerADC),
        VMSTATE_UINT16_ARRAY(channels, Z72ControllerADC, 19),
        VMSTATE_END_OF_LIST()
    },
};

static const Property adc_properties[] = {
    DEFINE_PROP_BOOL("completion", Z72ControllerADC, completion, true),
#define ADC_INPUT(n) DEFINE_PROP_UINT16("channel" #n, Z72ControllerADC, channels[n], 0)
    ADC_INPUT(0), ADC_INPUT(1), ADC_INPUT(2), ADC_INPUT(3), ADC_INPUT(4),
    ADC_INPUT(5), ADC_INPUT(6), ADC_INPUT(7), ADC_INPUT(8), ADC_INPUT(9),
    ADC_INPUT(10), ADC_INPUT(11), ADC_INPUT(12), ADC_INPUT(13), ADC_INPUT(14),
    ADC_INPUT(15), ADC_INPUT(16), ADC_INPUT(17), ADC_INPUT(18),
#undef ADC_INPUT
};

static void adc_realize(DeviceState *dev, Error **errp)
{
    Z72ControllerADC *s = Z72_CONTROLLER_ADC(dev);
    for (unsigned i = 0; i < 19; i++) {
        if (s->channels[i] > 4095) {
            error_setg(errp, "Controller ADC channel %u exceeds twelve bits", i);
            return;
        }
    }
}

static void adc_init(Object *obj)
{
    Z72ControllerADC *s = Z72_CONTROLLER_ADC(obj);
    memory_region_init_io(&s->iomem, obj, &adc_ops, s, TYPE_Z72_CONTROLLER_ADC, 0x400);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irq);
    for (unsigned i = 0; i < 3; i++) {
        s->banks[i].owner = s;
        s->banks[i].timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, adc_complete, &s->banks[i]);
    }
}

static void adc_unrealize(DeviceState *dev)
{
    Z72ControllerADC *s = Z72_CONTROLLER_ADC(dev);
    for (unsigned i = 0; i < 3; i++) {
        timer_del(s->banks[i].timer);
    }
}

static void adc_finalize(Object *obj)
{
    Z72ControllerADC *s = Z72_CONTROLLER_ADC(obj);
    for (unsigned i = 0; i < 3; i++) {
        timer_free(s->banks[i].timer);
    }
}

static void adc_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = adc_realize;
    dc->unrealize = adc_unrealize;
    dc->vmsd = &adc_state;
    device_class_set_props(dc, adc_properties);
    RESETTABLE_CLASS(klass)->phases.hold = adc_reset;
}

static void adc_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_CONTROLLER_ADC, .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(Z72ControllerADC), .instance_init = adc_init,
        .instance_finalize = adc_finalize, .class_init = adc_class_init,
    };
    type_register_static(&info);
}
type_init(adc_register_types)
