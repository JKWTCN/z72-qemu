/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Bounded transmit interface observed in the stock console routines. */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "hw/resettable.h"
#include "chardev/char-fe.h"
#include "migration/vmstate.h"

#define TYPE_NIKON_Z72_UART "nikon-z72-uart"
OBJECT_DECLARE_SIMPLE_TYPE(NikonZ72Uart, NIKON_Z72_UART)

struct NikonZ72Uart {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    CharFrontend chr;
    uint8_t mode, control, clock, status;
    uint8_t auxiliary_control;
    uint16_t data, divisor, format;
    bool enabled;
};

static bool uart_access(hwaddr offset, unsigned size)
{
    return (size == 1 && (offset <= 3 || offset == 12 ||
                         offset == 13 || offset == 15)) ||
           (size == 2 && (offset == 4 || offset == 6 || offset == 12));
}

static MemTxResult uart_read(void *opaque, hwaddr offset, uint64_t *value,
                             unsigned size, MemTxAttrs attrs)
{
    NikonZ72Uart *s = opaque;
    if (!s->enabled) {
        return MEMTX_ERROR;
    }
    if (!uart_access(offset, size)) {
        return MEMTX_DECODE_ERROR;
    }
    switch (offset) {
    case 0: *value = s->mode; break;
    case 1: *value = s->control; break;
    case 2: *value = s->clock; break;
    case 3: *value = s->status | 2; break;
    case 4: *value = s->data; break;
    case 6: *value = s->divisor; break;
    case 12: *value = size == 1 ? s->format & 0xff : s->format; break;
    case 13: *value = s->format >> 8; break;
    case 15: *value = s->auxiliary_control; break;
    }
    return MEMTX_OK;
}

static MemTxResult uart_write(void *opaque, hwaddr offset, uint64_t value,
                              unsigned size, MemTxAttrs attrs)
{
    NikonZ72Uart *s = opaque;
    if (!s->enabled) {
        return MEMTX_ERROR;
    }
    if (!uart_access(offset, size)) {
        return MEMTX_DECODE_ERROR;
    }
    switch (offset) {
    case 0: s->mode = value; break;
    case 1: s->control = value; break;
    case 2: s->clock = value; break;
    case 3:
        /* TX ready is device-owned. Preserve the observed configuration byte;
         * timing, receive flags and interrupt semantics remain unmodeled. */
        s->status = value & ~2u;
        break;
    case 4: {
        uint8_t byte = value;
        s->data = value;
        /* The laboratory completes each original halfword TX store
         * synchronously, with an optional console backend. */
        qemu_chr_fe_write_all(&s->chr, &byte, 1);
        break;
    }
    case 6: s->divisor = value; break;
    /* A startup-created task also accesses the format halves separately.
     * Both widths refer to the same little-endian configuration field. */
    case 12:
        s->format = size == 1 ? (s->format & 0xff00) | value : value;
        break;
    case 13: s->format = (s->format & 0xff) | (value << 8); break;
    case 15: s->auxiliary_control = value; break;
    }
    return MEMTX_OK;
}

static const MemoryRegionOps uart_ops = {
    .read_with_attrs = uart_read,
    .write_with_attrs = uart_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    /* Keep word transactions intact so the callbacks can reject them before
     * a TX halfword is emitted or a neighboring configuration field changes. */
    .valid = { .min_access_size = 1, .max_access_size = 4, .unaligned = false },
    .impl = { .min_access_size = 1, .max_access_size = 4, .unaligned = false },
};

static void uart_reset(Object *obj, ResetType type)
{
    NikonZ72Uart *s = NIKON_Z72_UART(obj);
    s->mode = s->control = s->clock = s->status = 0;
    s->data = s->divisor = s->format = 0;
    s->auxiliary_control = 0;
}

static const VMStateDescription vmstate_uart = {
    .name = TYPE_NIKON_Z72_UART,
    .version_id = 2,
    .minimum_version_id = 2,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT8(mode, NikonZ72Uart),
        VMSTATE_UINT8(control, NikonZ72Uart),
        VMSTATE_UINT8(clock, NikonZ72Uart),
        VMSTATE_UINT8(status, NikonZ72Uart),
        VMSTATE_UINT16(data, NikonZ72Uart),
        VMSTATE_UINT16(divisor, NikonZ72Uart),
        VMSTATE_UINT16(format, NikonZ72Uart),
        VMSTATE_UINT8(auxiliary_control, NikonZ72Uart),
        VMSTATE_END_OF_LIST()
    }
};

static const Property uart_properties[] = {
    DEFINE_PROP_BOOL("enabled", NikonZ72Uart, enabled, true),
    DEFINE_PROP_CHR("chardev", NikonZ72Uart, chr),
};

static void uart_init(Object *obj)
{
    NikonZ72Uart *s = NIKON_Z72_UART(obj);
    memory_region_init_io(&s->iomem, obj, &uart_ops, s, TYPE_NIKON_Z72_UART, 16);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
}

static void uart_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);
    dc->vmsd = &vmstate_uart;
    dc->desc = "Z72 bounded console transmitter";
    device_class_set_props(dc, uart_properties);
    rc->phases.hold = uart_reset;
}

static void uart_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_NIKON_Z72_UART,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(NikonZ72Uart),
        .instance_init = uart_init,
        .class_init = uart_class_init,
    };
    type_register_static(&info);
}
type_init(uart_register_types)
