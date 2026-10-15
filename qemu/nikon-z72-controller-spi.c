/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/ssi/ssi.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_Z72_CONTROLLER_SPI "nikon-z72-controller-spi"
OBJECT_DECLARE_SIMPLE_TYPE(Z72ControllerSPI, Z72_CONTROLLER_SPI)

struct Z72ControllerSPI {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t registers[9];
    uint16_t transmit;
    bool pending;
    bool busy;
    bool overrun_read;
    bool completion;
    char *bus_name;
    SSIBus *bus;
    QEMUTimer *timer;
    qemu_irq irq;
    qemu_irq requests[2];
};

static unsigned spi_mask(Z72ControllerSPI *s)
{
    return s->registers[0] & 0x800 ? 0xffff : 0xff;
}

static void spi_signals(Z72ControllerSPI *s)
{
    uint32_t cr2 = s->registers[1], sr = s->registers[2];
    bool enabled = s->registers[0] & 0x40;
    qemu_set_irq(s->irq, !!(((sr & 1) && (cr2 & 0x40)) ||
                           ((sr & 2) && (cr2 & 0x80)) ||
                           ((sr & 0x40) && (cr2 & 0x20))));
    qemu_set_irq(s->requests[0], enabled && (cr2 & 1) && (sr & 1));
    qemu_set_irq(s->requests[1], enabled && (cr2 & 2) && (sr & 2));
}

static void spi_receive(Z72ControllerSPI *s, uint32_t value)
{
    if (s->registers[2] & 1) {
        s->registers[2] |= 0x40;
        s->overrun_read = false;
    } else {
        s->registers[3] = value & spi_mask(s);
        s->registers[2] |= 1;
    }
}

static uint32_t spi_clock(Z72ControllerSPI *s, uint32_t input)
{
    uint32_t cr1 = s->registers[0];
    unsigned mask = spi_mask(s);
    if (!(cr1 & 0x40) || (cr1 & 4) ||
        ((cr1 & 0x200) && (cr1 & 0x100)) || !s->completion) {
        return mask;
    }
    uint32_t output = s->pending ? s->transmit : mask;
    s->pending = false;
    s->registers[2] |= 2;
    spi_receive(s, input);
    spi_signals(s);
    return output;
}

static void spi_complete(void *opaque)
{
    Z72ControllerSPI *s = opaque;
    if (!s->busy) {
        return;
    }
    uint32_t value = ssi_transfer(s->bus, s->transmit);
    s->busy = s->pending = false;
    s->registers[2] = (s->registers[2] & ~0x80u) | 2;
    spi_receive(s, value);
    spi_signals(s);
}

static bool spi_access(hwaddr offset, unsigned size)
{
    return !(offset & 3) && offset <= 0x20 &&
           (size == 4 || (offset == 12 && (size == 1 || size == 2)));
}

static MemTxResult spi_read(void *opaque, hwaddr offset, uint64_t *value,
                            unsigned size, MemTxAttrs attrs)
{
    Z72ControllerSPI *s = opaque;
    if (!spi_access(offset, size) || (offset == 12 && size == 1 && spi_mask(s) != 0xff)) {
        return MEMTX_ERROR;
    }
    *value = s->registers[offset / 4];
    if (offset == 12) {
        s->registers[2] &= ~1u;
        s->overrun_read = !!(s->registers[2] & 0x40);
        spi_signals(s);
    } else if (offset == 8 && s->overrun_read) {
        s->overrun_read = false;
        s->registers[2] &= ~0x40u;
        spi_signals(s);
    }
    return MEMTX_OK;
}

static MemTxResult spi_write(void *opaque, hwaddr offset, uint64_t value,
                             unsigned size, MemTxAttrs attrs)
{
    Z72ControllerSPI *s = opaque;
    if (!spi_access(offset, size)) {
        return MEMTX_ERROR;
    }
    if (offset == 0) {
        if (value & ~0xbffu) {
            return MEMTX_ERROR;
        }
        if (s->pending && (value & 0x40) &&
            ((value ^ s->registers[0]) & ~0x40u)) {
            return MEMTX_ERROR;
        }
        s->registers[0] = value;
        if (!(value & 0x40)) {
            timer_del(s->timer);
            s->pending = s->busy = false;
            s->registers[2] = (s->registers[2] & ~0x80u) | 2;
        }
    } else if (offset == 4) {
        if (value & ~0xe7u) {
            return MEMTX_ERROR;
        }
        s->registers[1] = value;
    } else if (offset == 12) {
        if (!(s->registers[0] & 0x40) || !(s->registers[2] & 2) ||
            (size == 1 && spi_mask(s) != 0xff)) {
            return MEMTX_ERROR;
        }
        s->transmit = value & spi_mask(s);
        s->pending = true;
        s->registers[2] &= ~2u;
        if (s->registers[0] & 4) {
            s->busy = true;
            s->registers[2] |= 0x80;
            if (s->completion) {
                timer_mod(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000);
            }
        }
    } else if (offset == 16) {
        s->registers[4] = value & 0xffff;
    } else if (offset == 28 && !(value & 0x800)) {
        s->registers[7] = value & 0x7ff;
    } else if (offset == 32) {
        s->registers[8] = value & 0x3ff;
    } else {
        return MEMTX_ERROR;
    }
    spi_signals(s);
    return MEMTX_OK;
}

static const MemoryRegionOps spi_ops = {
    .read_with_attrs = spi_read, .write_with_attrs = spi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void spi_reset(Object *obj, ResetType type)
{
    Z72ControllerSPI *s = Z72_CONTROLLER_SPI(obj);
    timer_del(s->timer);
    memset(s->registers, 0, sizeof(s->registers));
    s->registers[2] = 2;
    s->registers[4] = 7;
    s->registers[8] = 2;
    s->pending = s->busy = s->overrun_read = false;
    s->transmit = 0;
    spi_signals(s);
}

static int spi_post_load(void *opaque, int version)
{
    Z72ControllerSPI *s = opaque;
    if ((s->busy && (!s->pending || (s->registers[0] & 0x44) != 0x44)) ||
        (s->pending && (!(s->registers[0] & 0x40) || (s->registers[2] & 2)))) {
        return -EINVAL;
    }
    spi_signals(s);
    return 0;
}

static const VMStateDescription spi_state = {
    .name = TYPE_Z72_CONTROLLER_SPI, .version_id = 1, .minimum_version_id = 1,
    .post_load = spi_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(registers, Z72ControllerSPI, 9),
        VMSTATE_UINT16(transmit, Z72ControllerSPI),
        VMSTATE_BOOL(pending, Z72ControllerSPI),
        VMSTATE_BOOL(busy, Z72ControllerSPI),
        VMSTATE_BOOL(overrun_read, Z72ControllerSPI),
        VMSTATE_TIMER_PTR(timer, Z72ControllerSPI),
        VMSTATE_END_OF_LIST()
    },
};

static const Property spi_properties[] = {
    DEFINE_PROP_BOOL("completion", Z72ControllerSPI, completion, true),
    DEFINE_PROP_STRING("bus-name", Z72ControllerSPI, bus_name),
};

static void spi_realize(DeviceState *dev, Error **errp)
{
    Z72ControllerSPI *s = Z72_CONTROLLER_SPI(dev);
    s->bus = ssi_create_bus(dev, s->bus_name);
}

static void spi_init(Object *obj)
{
    Z72ControllerSPI *s = Z72_CONTROLLER_SPI(obj);
    memory_region_init_io(&s->iomem, obj, &spi_ops, s, TYPE_Z72_CONTROLLER_SPI, 0x400);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irq);
    qdev_init_gpio_out_named(DEVICE(s), s->requests, "dma-request", 2);
    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, spi_complete, s);
}

static void spi_finalize(Object *obj)
{
    timer_free(Z72_CONTROLLER_SPI(obj)->timer);
}

static void spi_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = spi_realize;
    dc->vmsd = &spi_state;
    device_class_set_props(dc, spi_properties);
    RESETTABLE_CLASS(klass)->phases.hold = spi_reset;
}

#define TYPE_Z72_SPI_PEER "nikon-z72-controller-spi-peer"
OBJECT_DECLARE_SIMPLE_TYPE(Z72SPIPeer, Z72_SPI_PEER)
struct Z72SPIPeer {
    SSIPeripheral parent_obj;
    Z72ControllerSPI *controller;
};

static void peer_realize(SSIPeripheral *dev, Error **errp)
{
    if (!Z72_SPI_PEER(dev)->controller) {
        error_setg(errp, "Controller serial peer requires its controller link");
    }
}

static uint32_t peer_transfer(SSIPeripheral *dev, uint32_t value)
{
    return spi_clock(Z72_SPI_PEER(dev)->controller, value);
}

static const VMStateDescription peer_state = {
    .name = TYPE_Z72_SPI_PEER, .version_id = 1, .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_SSI_PERIPHERAL(parent_obj, Z72SPIPeer),
        VMSTATE_END_OF_LIST()
    },
};

static const Property peer_properties[] = {
    DEFINE_PROP_LINK("controller", Z72SPIPeer, controller,
                     TYPE_Z72_CONTROLLER_SPI, Z72ControllerSPI *),
};

static void peer_class_init(ObjectClass *klass, const void *data)
{
    SSIPeripheralClass *sc = SSI_PERIPHERAL_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);
    sc->realize = peer_realize;
    sc->transfer = peer_transfer;
    sc->cs_polarity = SSI_CS_LOW;
    dc->vmsd = &peer_state;
    device_class_set_props(dc, peer_properties);
}

static void spi_register_types(void)
{
    static const TypeInfo info[] = {
        { .name = TYPE_Z72_CONTROLLER_SPI, .parent = TYPE_SYS_BUS_DEVICE,
          .instance_size = sizeof(Z72ControllerSPI), .instance_init = spi_init,
          .instance_finalize = spi_finalize, .class_init = spi_class_init },
        { .name = TYPE_Z72_SPI_PEER, .parent = TYPE_SSI_PERIPHERAL,
          .instance_size = sizeof(Z72SPIPeer), .class_init = peer_class_init },
    };
    type_register_static_array(info, ARRAY_SIZE(info));
}
type_init(spi_register_types)
