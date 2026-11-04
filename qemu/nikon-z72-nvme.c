/* SPDX-License-Identifier: GPL-2.0-or-later */
/* C 1.70 PCI I/O windows backed by the native PCI/NVMe devices. */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "hw/resettable.h"
#include "hw/pci-host/gpex.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_host.h"
#include "hw/pci/msi.h"
#include "migration/vmstate.h"
#include "system/address-spaces.h"
#include "system/block-backend-global-state.h"

#define TYPE_Z72_NVME_HOST "nikon-z72-nvme-host"
OBJECT_DECLARE_SIMPLE_TYPE(Z72NVMeHost, Z72_NVME_HOST)

typedef struct Z72PCIWindow {
    uint32_t words[7];
} Z72PCIWindow;

struct Z72NVMeHost {
    SysBusDevice parent_obj;
    MemoryRegion dbi, config, bar, phy;
    MemoryRegion dma_root, dma_alias, msi;
    MemoryRegion *root;
    AddressSpace dma, pci_memory;
    DeviceState *bridge;
    PCIDevice *endpoint;
    char *drive;
    qemu_irq irqs[3], intx_inputs[4];
    QEMUTimer *link_timer;
    Z72PCIWindow windows[2];
    uint32_t viewport, extended[0x8c0 / 4], phy_words[0x400 / 4];
    uint32_t transaction_error, pending24, pending2c, msi_pending, cancel_event;
    uint8_t state, intx;
    bool msi_mapped, spaces_initialized, cancelled, controller_enabled;
};

static void nvme_host_irqs(Z72NVMeHost *s)
{
    qemu_set_irq(s->irqs[0], !!(s->pending24 | s->pending2c));
    qemu_set_irq(s->irqs[1], !!(s->msi_pending &
        s->extended[0x828 / 4] & ~s->extended[0x82c / 4]));
}

static MemTxResult nvme_host_error(Z72NVMeHost *s)
{
    /* The native transaction wrappers consume bit14 after config/BAR I/O. */
    s->transaction_error |= 1u << 14;
    return MEMTX_DECODE_ERROR;
}

static bool nvme_window_enabled(Z72NVMeHost *s, unsigned index)
{
    uint32_t *w = s->windows[index].words;
    return s->state == 0x11 && (w[1] & (1u << 31)) && !w[3] && !w[6] &&
           w[0] == (index ? 0 : 4) &&
           w[2] == (index ? 0x2a810000 : 0x2a800000) &&
           w[4] == (index ? 0x2a8fffff : 0x2a80ffff) &&
           w[5] == (index ? 0x2a810000 : 0);
}

static MemTxResult nvme_config_read(void *opaque, hwaddr offset,
                                   uint64_t *value, unsigned size,
                                   MemTxAttrs attrs)
{
    Z72NVMeHost *s = opaque;
    if (!nvme_window_enabled(s, 0) || offset + size > 0x1000) {
        *value = UINT32_MAX;
        return nvme_host_error(s);
    }
    /* The original selector targets the external function, not GPEX's root. */
    *value = pci_host_config_read_common(s->endpoint, offset, 0x1000, size);
    return MEMTX_OK;
}

static MemTxResult nvme_config_write(void *opaque, hwaddr offset,
                                    uint64_t value, unsigned size,
                                    MemTxAttrs attrs)
{
    Z72NVMeHost *s = opaque;
    if (!nvme_window_enabled(s, 0) || offset + size > 0x1000) {
        return nvme_host_error(s);
    }
    pci_host_config_write_common(s->endpoint, offset, 0x1000, value, size);
    return MEMTX_OK;
}

static MemTxResult nvme_bar_read(void *opaque, hwaddr offset, uint64_t *value,
                                unsigned size, MemTxAttrs attrs)
{
    Z72NVMeHost *s = opaque;
    uint8_t data[4] = {0xff, 0xff, 0xff, 0xff};
    MemTxResult result;
    if (!nvme_window_enabled(s, 1)) {
        *value = UINT32_MAX;
        return nvme_host_error(s);
    }
    result = address_space_read(&s->pci_memory, 0x2a810000 + offset,
                                attrs, data, size);
    *value = size == 4 ? ldl_le_p(data) : size == 2 ? lduw_le_p(data) : data[0];
    if (result != MEMTX_OK) {
        s->transaction_error |= 1u << 14;
    }
    return result;
}

static MemTxResult nvme_bar_write(void *opaque, hwaddr offset, uint64_t value,
                                 unsigned size, MemTxAttrs attrs)
{
    Z72NVMeHost *s = opaque;
    uint8_t data[4];
    MemTxResult result;
    if (!nvme_window_enabled(s, 1)) {
        return nvme_host_error(s);
    }
    stl_le_p(data, value);
    result = address_space_write(&s->pci_memory, 0x2a810000 + offset,
                                 attrs, data, size);
    if (result != MEMTX_OK) {
        s->transaction_error |= 1u << 14;
    }
    return result;
}

static bool nvme_word_access(void *opaque, hwaddr offset, unsigned size,
                             bool write, MemTxAttrs attrs)
{
    return size == 4 && !(offset & 3);
}

static MemTxResult nvme_msi_write(void *opaque, hwaddr offset, uint64_t value,
                                 unsigned size, MemTxAttrs attrs)
{
    Z72NVMeHost *s = opaque;
    if (value >= 32) {
        return MEMTX_DECODE_ERROR;
    }
    s->msi_pending |= 1u << value;
    nvme_host_irqs(s);
    return MEMTX_OK;
}

static const MemoryRegionOps nvme_msi_ops = {
    .write_with_attrs = nvme_msi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4,
               .accepts = nvme_word_access },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void nvme_msi_map(Z72NVMeHost *s)
{
    uint64_t address = (uint64_t)s->extended[0x824 / 4] << 32 |
                       s->extended[0x820 / 4];
    if (s->msi_mapped) {
        memory_region_del_subregion(&s->dma_root, &s->msi);
        s->msi_mapped = false;
    }
    if (address && !(address & 3) && address <= UINT64_MAX - 4) {
        memory_region_add_subregion_overlap(&s->dma_root, address, &s->msi, 1);
        s->msi_mapped = true;
    }
}

static bool nvme_dbi_access(void *opaque, hwaddr offset, unsigned size,
                           bool write, MemTxAttrs attrs)
{
    if (offset < 0x100) {
        return size <= 4 && size && !(offset & (size - 1)) &&
               offset + size <= 0x100;
    }
    if (!nvme_word_access(opaque, offset, size, write, attrs)) {
        return false;
    }
    return (offset >= 0x900 && offset <= 0x91c) || offset == 0x168 ||
           offset == 0x80c || offset == 0x8a8 || offset == 0x8bc ||
           (offset >= 0x820 && offset <= 0x830) ||
           (offset == 0x104 && !write);
}

static MemTxResult nvme_dbi_read(void *opaque, hwaddr offset, uint64_t *value,
                                unsigned size, MemTxAttrs attrs)
{
    Z72NVMeHost *s = opaque;
    if (offset == 0x98 && size == 4) {
        *value = s->state == 0x11 ? 2 : 0;
    } else if (offset < 0x100) {
        *value = pci_host_config_read_common(&GPEX_HOST(s->bridge)->gpex_root.parent_obj,
                                             offset, 0x100, size);
    } else if (offset == 0x104) {
        *value = s->transaction_error;
    } else if (offset == 0x900) {
        *value = s->viewport;
    } else if (offset >= 0x904) {
        if (s->viewport > 1) {
            *value = UINT32_MAX;
            return nvme_host_error(s);
        }
        *value = s->windows[s->viewport].words[(offset - 0x904) / 4];
    } else if (offset == 0x830) {
        *value = s->msi_pending;
    } else {
        *value = s->extended[offset / 4];
    }
    return MEMTX_OK;
}

static MemTxResult nvme_dbi_write(void *opaque, hwaddr offset, uint64_t value,
                                 unsigned size, MemTxAttrs attrs)
{
    Z72NVMeHost *s = opaque;
    if (offset < 0x100) {
        pci_host_config_write_common(&GPEX_HOST(s->bridge)->gpex_root.parent_obj,
                                     offset, 0x100, value, size);
    } else if (offset == 0x900) {
        s->viewport = value;
    } else if (offset >= 0x904) {
        if (s->viewport > 1) {
            return nvme_host_error(s);
        }
        s->windows[s->viewport].words[(offset - 0x904) / 4] = value;
    } else if (offset == 0x830) {
        s->msi_pending &= ~(uint32_t)value;
        nvme_host_irqs(s);
    } else {
        s->extended[offset / 4] = value;
        if (offset == 0x820 || offset == 0x824) {
            nvme_msi_map(s);
        } else if (offset == 0x828 || offset == 0x82c) {
            nvme_host_irqs(s);
        }
    }
    return MEMTX_OK;
}

static bool nvme_training_requested(Z72NVMeHost *s)
{
    return (s->phy_words[0] & 0x1f) == 0x14 &&
           (s->phy_words[0x0c / 4] & 3) == 3 &&
           (s->phy_words[0x50 / 4] & (1u << 8));
}

static void nvme_dma_gate(Z72NVMeHost *s)
{
    if (s->spaces_initialized) {
        bool enabled = s->state == 0x11 && !s->cancelled;
        memory_region_set_enabled(&s->dma_alias, enabled);
        memory_region_set_enabled(&s->msi, enabled);
    }
}

static void nvme_link_complete(void *opaque)
{
    Z72NVMeHost *s = opaque;
    if (s->cancel_event) {
        s->state = 0x15;
        s->pending2c |= s->cancel_event;
        s->phy_words[0x3c / 4] &= ~(1u << 4);
        s->phy_words[0x50 / 4] &= ~(1u << 16);
        s->cancel_event = 0;
        nvme_host_irqs(s);
    } else if (!s->cancelled && nvme_training_requested(s)) {
        s->state = 0x11;
        s->controller_enabled = true;
    }
    nvme_dma_gate(s);
}

static bool nvme_phy_access(void *opaque, hwaddr offset, unsigned size,
                           bool write, MemTxAttrs attrs)
{
    static const uint16_t offsets[] = {
        0, 4, 8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x2c,
        0x30, 0x3c, 0x4c, 0x50, 0x54, 0x58, 0x5c, 0x100, 0x210, 0x300,
    };
    if (!nvme_word_access(opaque, offset, size, write, attrs)) {
        return false;
    }
    for (unsigned i = 0; i < G_N_ELEMENTS(offsets); i++) {
        if (offset == offsets[i]) {
            return !write || (offset != 0x58 && offset != 0x5c && offset != 0x210);
        }
    }
    return false;
}

static uint64_t nvme_phy_read(void *opaque, hwaddr offset, unsigned size)
{
    Z72NVMeHost *s = opaque;
    if (offset == 0x210) {
        uint8_t status[4];
        /* 1049d7c0/1049d800 require this guard before native block I/O.
         * Functional availability derives from the actual controller CSTS;
         * the hardware register's complete bit encoding remains unknown. */
        return !s->cancelled && nvme_window_enabled(s, 1) &&
               address_space_read(&s->pci_memory, 0x2a81001c,
                                  MEMTXATTRS_UNSPECIFIED, status, 4) == MEMTX_OK &&
               (ldl_le_p(status) & 3) == 1;
    }
    if (offset == 0x58) {
        return s->state << 16;
    }
    if (offset == 0x24) {
        return s->phy_words[offset / 4] | s->pending24;
    }
    if (offset == 0x2c) {
        return s->phy_words[offset / 4] | s->pending2c;
    }
    return s->phy_words[offset / 4];
}

static void nvme_phy_write(void *opaque, hwaddr offset, uint64_t value,
                           unsigned size)
{
    Z72NVMeHost *s = opaque;
    if (offset == 0x24) {
        s->pending24 &= ~(uint32_t)value;
        s->phy_words[offset / 4] = value & 0x10001;
    } else if (offset == 0x2c) {
        s->pending2c &= ~(uint32_t)value;
        s->phy_words[offset / 4] = value & ~((1u << 10) | (1u << 14) |
            (1u << 18) | (1u << 26) | (1u << 30));
    } else {
        s->phy_words[offset / 4] = value;
    }
    if ((offset == 0x3c && (value & (1u << 4))) ||
        (offset == 0x50 && (value & (1u << 16)))) {
        s->cancel_event = 1u << (offset == 0x3c ? 26 : 30);
        s->cancelled = true;
        timer_mod(s->link_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 100000);
    } else if (!nvme_training_requested(s)) {
        s->cancelled = false;
        if (s->state == 0x11) {
            s->state = 0;
        }
        if (!s->cancel_event) {
            timer_del(s->link_timer);
        }
        if (s->controller_enabled && offset == 0x0c && (value & 3) != 3) {
            /* Functional controller reset on the native disable sequence. */
            device_cold_reset(DEVICE(s->endpoint));
            s->controller_enabled = false;
        }
    } else if (!s->cancelled) {
        if (s->state != 0x11 && !timer_pending(s->link_timer)) {
            /* Functional training delay, independent of static insertion. */
            timer_mod(s->link_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 100000);
        }
    }
    nvme_dma_gate(s);
    nvme_host_irqs(s);
}

static void nvme_intx(void *opaque, int pin, int level)
{
    Z72NVMeHost *s = opaque;
    uint8_t next = (s->intx & ~(1u << pin)) | (!!level << pin);
    /* 10517046..1051705a reads and writes back the captured causes.
     * The single external function uses INTA, independently of GPEX swizzling. */
    if (!s->intx && next) {
        s->pending24 |= 1u << 28;
    }
    s->intx = next;
    nvme_host_irqs(s);
}

static AddressSpace *nvme_dma_space(PCIBus *bus, void *opaque, int devfn)
{
    return &Z72_NVME_HOST(opaque)->dma;
}

static const PCIIOMMUOps nvme_dma_ops = {
    .get_address_space = nvme_dma_space,
};

#define NVME_PORT_OPS(name, read_fn, write_fn, max_size, accept_fn) \
static const MemoryRegionOps name = { \
    .read_with_attrs = read_fn, .write_with_attrs = write_fn, \
    .endianness = DEVICE_LITTLE_ENDIAN, \
    .valid = { .min_access_size = 1, .max_access_size = max_size, \
               .accepts = accept_fn }, \
    .impl = { .min_access_size = 1, .max_access_size = max_size }, \
}

NVME_PORT_OPS(nvme_config_ops, nvme_config_read, nvme_config_write, 4, NULL);
NVME_PORT_OPS(nvme_bar_ops, nvme_bar_read, nvme_bar_write, 4, NULL);
NVME_PORT_OPS(nvme_dbi_ops, nvme_dbi_read, nvme_dbi_write, 4, nvme_dbi_access);

static const MemoryRegionOps nvme_phy_ops = {
    .read = nvme_phy_read, .write = nvme_phy_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4,
               .accepts = nvme_phy_access },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void nvme_host_reset(Object *obj, ResetType type)
{
    Z72NVMeHost *s = Z72_NVME_HOST(obj);
    timer_del(s->link_timer);
    memset(s->windows, 0, sizeof(s->windows));
    memset(s->extended, 0, sizeof(s->extended));
    memset(s->phy_words, 0, sizeof(s->phy_words));
    s->viewport = s->state = s->intx = 0;
    s->transaction_error = s->pending24 = s->pending2c = s->msi_pending = 0;
    s->cancel_event = 0;
    s->cancelled = s->controller_enabled = false;
    if (s->spaces_initialized) {
        nvme_msi_map(s);
    }
    nvme_dma_gate(s);
    nvme_host_irqs(s);
    qemu_set_irq(s->irqs[2], s->endpoint != NULL);
}

static void nvme_host_realize(DeviceState *dev, Error **errp)
{
    Z72NVMeHost *s = Z72_NVME_HOST(dev);
    BlockBackend *media = s->drive ? blk_by_name(s->drive) : NULL;
    PCIBus *bus;
    if (!media || !s->root) {
        error_setg(errp, "NVMe host requires a selected block backend and engine memory");
        return;
    }
    memory_region_init(&s->dma_root, OBJECT(s), "z72-nvme-dma", UINT64_MAX);
    memory_region_init_alias(&s->dma_alias, OBJECT(s), "z72-nvme-engine-memory",
                              s->root, 0, memory_region_size(s->root));
    memory_region_add_subregion(&s->dma_root, 0, &s->dma_alias);
    address_space_init(&s->dma, &s->dma_root, "z72-nvme-dma");
    s->bridge = qdev_new(TYPE_GPEX_HOST);
    object_property_add_child(OBJECT(s), "pcie", OBJECT(s->bridge));
    qdev_prop_set_bit(s->bridge, "allow-unmapped-accesses", false);
    if (!sysbus_realize_and_unref(SYS_BUS_DEVICE(s->bridge), errp)) {
        return;
    }
    bus = PCI_HOST_BRIDGE(s->bridge)->bus;
    pci_setup_iommu(bus, &nvme_dma_ops, s);
    for (unsigned i = 0; i < 4; i++) {
        s->intx_inputs[i] = qemu_allocate_irq(nvme_intx, s, i);
        sysbus_connect_irq(SYS_BUS_DEVICE(s->bridge), i, s->intx_inputs[i]);
    }
    address_space_init(&s->pci_memory, &GPEX_HOST(s->bridge)->io_mmio,
                       "z72-nvme-pci-memory");
    s->spaces_initialized = true;
    nvme_dma_gate(s);
    msi_nonbroken = true;
    s->endpoint = pci_new(PCI_DEVFN(1, 0), "nvme");
    qdev_prop_set_string(DEVICE(s->endpoint), "serial", "Z72-VIRTUAL-NVME");
    if (!qdev_prop_set_drive_err(DEVICE(s->endpoint), "drive", media, errp)) {
        object_unref(OBJECT(s->endpoint));
        s->endpoint = NULL;
        return;
    }
    if (!pci_realize_and_unref(s->endpoint, bus, errp)) {
        s->endpoint = NULL;
    }
}

static void nvme_host_finalize(Object *obj)
{
    Z72NVMeHost *s = Z72_NVME_HOST(obj);
    timer_free(s->link_timer);
    for (unsigned i = 0; i < 4; i++) {
        qemu_free_irq(s->intx_inputs[i]);
    }
    if (s->spaces_initialized) {
        address_space_destroy(&s->pci_memory);
        address_space_destroy(&s->dma);
    }
}

static void nvme_host_init(Object *obj)
{
    Z72NVMeHost *s = Z72_NVME_HOST(obj);
    SysBusDevice *dev = SYS_BUS_DEVICE(obj);
    memory_region_init_io(&s->dbi, obj, &nvme_dbi_ops, s, "z72-nvme-dbi", 0x1000);
    memory_region_init_io(&s->config, obj, &nvme_config_ops, s, "z72-nvme-config", 0x10000);
    memory_region_init_io(&s->bar, obj, &nvme_bar_ops, s, "z72-nvme-bar", 0xf0000);
    memory_region_init_io(&s->phy, obj, &nvme_phy_ops, s, "z72-nvme-phy", 0x400);
    memory_region_init_io(&s->msi, obj, &nvme_msi_ops, s, "z72-nvme-msi", 4);
    sysbus_init_mmio(dev, &s->dbi);
    sysbus_init_mmio(dev, &s->config);
    sysbus_init_mmio(dev, &s->bar);
    sysbus_init_mmio(dev, &s->phy);
    sysbus_init_irq(dev, &s->irqs[0]);
    sysbus_init_irq(dev, &s->irqs[1]);
    sysbus_init_irq(dev, &s->irqs[2]);
    s->link_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_link_complete, s);
}

static const Property nvme_host_properties[] = {
    DEFINE_PROP_STRING("drive", Z72NVMeHost, drive),
    DEFINE_PROP_LINK("memory", Z72NVMeHost, root, TYPE_MEMORY_REGION, MemoryRegion *),
};

static const VMStateDescription nvme_host_vmstate = {
    .name = TYPE_Z72_NVME_HOST,
    .unmigratable = true,
};

static void nvme_host_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = nvme_host_realize;
    dc->vmsd = &nvme_host_vmstate;
    dc->user_creatable = false;
    device_class_set_props(dc, nvme_host_properties);
    RESETTABLE_CLASS(klass)->phases.hold = nvme_host_reset;
}

static const TypeInfo nvme_host_type = {
    .name = TYPE_Z72_NVME_HOST,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Z72NVMeHost),
    .instance_init = nvme_host_init,
    .instance_finalize = nvme_host_finalize,
    .class_init = nvme_host_class_init,
};

static void nvme_host_register_types(void)
{
    type_register_static(&nvme_host_type);
}

type_init(nvme_host_register_types)
