/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "system/address-spaces.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/or-irq.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "chardev/char.h"
#include "hw/qdev-clock.h"
#include "hw/resettable.h"
#include "hw/core/resetcontainer.h"
#include "qemu/main-loop.h"
#include "hw/arm/armv7m.h"
#include "hw/arm/boot.h"
#include "target/arm/cpu-features.h"
#include "hw/arm/machines-qom.h"
#include "hw/loader.h"
#include "migration/vmstate.h"
#include "nikon-z72-controller.h"

#define TYPE_Z72_CONTROLLER_MACHINE MACHINE_TYPE_NAME("nikon-z72-controller-lab")
OBJECT_DECLARE_SIMPLE_TYPE(Z72ControllerMachine, Z72_CONTROLLER_MACHINE)

struct Z72ControllerMachine {
    MachineState parent_obj;
    Z72ControllerInputs inputs;
};

static char *controller_flash_data_get(Object *obj, Error **errp)
{
    return g_strdup(Z72_CONTROLLER_MACHINE(obj)->inputs.flash_data);
}

static void controller_flash_data_set(Object *obj, const char *value, Error **errp)
{
    Z72ControllerInputs *s = &Z72_CONTROLLER_MACHINE(obj)->inputs;
    g_free(s->flash_data);
    s->flash_data = g_strdup(value);
}

static char *controller_supply_data_get(Object *obj, Error **errp)
{
    return g_strdup(Z72_CONTROLLER_MACHINE(obj)->inputs.supply_data);
}

static void controller_supply_data_set(Object *obj, const char *value, Error **errp)
{
    Z72ControllerInputs *s = &Z72_CONTROLLER_MACHINE(obj)->inputs;
    g_free(s->supply_data);
    s->supply_data = g_strdup(value);
}

static void controller_load_firmware(Z72ControllerInputs *s, ARMCPU *cpu,
                                     const char *firmware, hwaddr load_base)
{
    if (!s->flash_data) {
        armv7m_load_kernel(cpu, firmware, load_base, 0x100000);
        return;
    }
    g_autofree char *image = NULL;
    g_autofree char *data = NULL;
    g_autoptr(GError) error = NULL;
    gsize image_size, data_size;
    if (!firmware ||
        !g_file_get_contents(firmware, &image, &image_size, &error)) {
        error_report("Controller flash data requires a readable raw firmware image");
        exit(1);
    }
    if (image_size < 0x10000 || image_size > 0x100000 ||
        !memcmp(image, "\177ELF", 4)) {
        error_report("Controller flash data requires a raw firmware image of 64 KiB..1 MiB");
        exit(1);
    }
    if (!g_file_get_contents(s->flash_data, &data, &data_size, &error)) {
        error_report("Cannot read controller flash data: %s", error->message);
        exit(1);
    }
    if (data_size != 0xc000) {
        error_report("Controller flash data must contain exactly 49152 bytes");
        exit(1);
    }
    for (gsize i = 0x4000; i < 0x10000; i++) {
        if (image[i]) {
            error_report("Controller flash data requires an empty firmware data window");
            exit(1);
        }
    }
    /* Populate only the empty resident data window; the input file is unchanged. */
    memcpy(image + 0x4000, data, data_size);
    rom_add_blob_fixed_as("z72-controller-resident-flash", image, image_size, load_base,
                          cpu_get_address_space(CPU(cpu), ARMASIdx_NS));
    armv7m_load_kernel(cpu, NULL, 0, 0x100000);
}

static bool controller_power_switch_get(Object *obj, Error **errp)
{
    return Z72_CONTROLLER_MACHINE(obj)->inputs.power_switch;
}

static void controller_power_switch_set(Object *obj, bool value, Error **errp)
{
    Z72ControllerInputs *s = &Z72_CONTROLLER_MACHINE(obj)->inputs;
    s->power_switch = value;
    if (s->switch_input) {
        qemu_set_irq(s->switch_input, value);
    }
}

static int controller_machine_post_load(void *opaque, int version)
{
    Z72ControllerInputs *s = &((Z72ControllerMachine *)opaque)->inputs;
    if (version < 2) {
        s->wake_input = false;
    }
    if (version < 3) {
        s->battery_contact = false;
    }
    if (version < 4) {
        s->supply_input = false;
    }
    if (version < 5) {
        s->auxiliary_input = false;
    }
    qemu_set_irq(s->switch_input, s->power_switch);
    qemu_set_irq(s->wake_signal, s->wake_input);
    qemu_set_irq(s->battery_signal, s->battery_contact);
    qemu_set_irq(s->supply_signal, s->supply_input);
    qemu_set_irq(s->auxiliary_signal, s->auxiliary_input);
    return 0;
}

static const VMStateDescription controller_machine_state = {
    .name = "z72-controller-machine-inputs",
    .version_id = 5,
    .minimum_version_id = 1,
    .post_load = controller_machine_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(inputs.power_switch, Z72ControllerMachine),
        VMSTATE_BOOL_V(inputs.wake_input, Z72ControllerMachine, 2),
        VMSTATE_BOOL_V(inputs.battery_contact, Z72ControllerMachine, 3),
        VMSTATE_BOOL_V(inputs.supply_input, Z72ControllerMachine, 4),
        VMSTATE_BOOL_V(inputs.auxiliary_input, Z72ControllerMachine, 5),
        VMSTATE_END_OF_LIST()
    },
};

static bool controller_wake_get(Object *obj, Error **errp)
{
    return Z72_CONTROLLER_MACHINE(obj)->inputs.wake_input;
}

static void controller_wake_set(Object *obj, bool value, Error **errp)
{
    Z72ControllerInputs *s = &Z72_CONTROLLER_MACHINE(obj)->inputs;
    s->wake_input = value;
    if (s->wake_signal) {
        qemu_set_irq(s->wake_signal, value);
    }
}

static bool controller_battery_get(Object *obj, Error **errp)
{
    return Z72_CONTROLLER_MACHINE(obj)->inputs.battery_contact;
}

static void controller_battery_set(Object *obj, bool value, Error **errp)
{
    Z72ControllerInputs *s = &Z72_CONTROLLER_MACHINE(obj)->inputs;
    s->battery_contact = value;
    if (s->battery_signal) {
        qemu_set_irq(s->battery_signal, value);
    }
}

static bool controller_battery_peer_get(Object *obj, Error **errp)
{
    return Z72_CONTROLLER_MACHINE(obj)->inputs.battery_peer;
}

static void controller_battery_peer_set(Object *obj, bool value, Error **errp)
{
    Z72_CONTROLLER_MACHINE(obj)->inputs.battery_peer = value;
}

static bool controller_supply_get(Object *obj, Error **errp)
{
    return Z72_CONTROLLER_MACHINE(obj)->inputs.supply_input;
}

static void controller_supply_set(Object *obj, bool value, Error **errp)
{
    Z72ControllerInputs *s = &Z72_CONTROLLER_MACHINE(obj)->inputs;
    s->supply_input = value;
    if (s->supply_signal) {
        qemu_set_irq(s->supply_signal, value);
    }
}

static bool controller_auxiliary_get(Object *obj, Error **errp)
{
    return Z72_CONTROLLER_MACHINE(obj)->inputs.auxiliary_input;
}

static void controller_auxiliary_set(Object *obj, bool value, Error **errp)
{
    Z72ControllerInputs *s = &Z72_CONTROLLER_MACHINE(obj)->inputs;
    s->auxiliary_input = value;
    if (s->auxiliary_signal) {
        qemu_set_irq(s->auxiliary_signal, value);
    }
}

#define TYPE_NIKON_Z72_CONTROLLER_CONFIG "nikon-z72-controller-config"
OBJECT_DECLARE_SIMPLE_TYPE(NikonZ72ControllerConfig, NIKON_Z72_CONTROLLER_CONFIG)

struct NikonZ72ControllerConfig {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    MemoryRegion route_iomem;
    MemoryRegion exti_iomem;
    uint32_t rcc[0x100 / 4];
    uint32_t route[9];
    uint32_t exti[6];
    uint16_t port_levels[8];
    uint16_t port_known[8];
    qemu_irq exti_irqs[7];
    bool clock_completion;
};

static void controller_exti_irq(NikonZ72ControllerConfig *s)
{
    static const uint16_t groups[] = { 1, 2, 4, 8, 16, 0x3e0, 0xfc00 };
    uint32_t pending = s->exti[0] & s->exti[5];
    for (unsigned i = 0; i < ARRAY_SIZE(groups); i++) {
        qemu_set_irq(s->exti_irqs[i], !!(pending & groups[i]));
    }
}

static void controller_pad_input(void *opaque, int line, int level)
{
    NikonZ72ControllerConfig *s = opaque;
    unsigned port = line / 16, pin = line % 16;
    uint16_t bit = 1u << pin;
    bool previous = s->port_levels[port] & bit;
    bool known = s->port_known[port] & bit;
    unsigned selected = (s->route[2 + pin / 4] >> (4 * (pin % 4))) & 15;
    s->port_known[port] |= bit;
    s->port_levels[port] = (s->port_levels[port] & ~bit) | (level ? bit : 0);
    if (known && previous != !!level && selected == port &&
        (s->exti[level ? 2 : 3] & bit)) {
        s->exti[5] |= bit;
    }
    controller_exti_irq(s);
}

static bool controller_word(hwaddr offset, unsigned size)
{
    return size == 4 && !(offset & 3) && offset < 0x100;
}

static MemTxResult controller_read(void *opaque, hwaddr offset, uint64_t *value,
                                   unsigned size, MemTxAttrs attrs)
{
    NikonZ72ControllerConfig *s = opaque;
    if (!controller_word(offset, size)) {
        return MEMTX_ERROR;
    }
    *value = s->rcc[offset / 4];
    return MEMTX_OK;
}

/* The original early clock setup waits on oscillator and PLL status and
 * reads back the selected source. Completion is synchronous here; clock
 * frequency and oscillator startup timing remain laboratory choices. */
static MemTxResult controller_write(void *opaque, hwaddr offset, uint64_t value,
                                    unsigned size, MemTxAttrs attrs)
{
    NikonZ72ControllerConfig *s = opaque;
    if (!controller_word(offset, size)) {
        return MEMTX_ERROR;
    }
    if (offset == 0) {
        uint32_t status = (1u << 1) | (1u << 17) | (1u << 25);
        value &= ~status;
        if (s->clock_completion) {
            value |= (value & ((1u << 0) | (1u << 16) | (1u << 24))) << 1;
        }
    } else if (offset == 8) {
        value &= ~0xcu;
        if (s->clock_completion) {
            value |= (value & 3) << 2;
        }
    } else if (offset == 0x70 || offset == 0x74) {
        value &= ~2u;
        if (s->clock_completion) {
            value |= (value & 1) << 1;
        }
    }
    s->rcc[offset / 4] = value;
    return MEMTX_OK;
}

static const MemoryRegionOps controller_ops = {
    .read_with_attrs = controller_read,
    .write_with_attrs = controller_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static MemTxResult route_read(void *opaque, hwaddr offset, uint64_t *value,
                             unsigned size, MemTxAttrs attrs)
{
    NikonZ72ControllerConfig *s = opaque;
    if (size != 4 || (offset & 3) || offset > 0x20 ||
        offset == 0x18 || offset == 0x1c) {
        return MEMTX_ERROR;
    }
    *value = s->route[offset / 4];
    return MEMTX_OK;
}

static MemTxResult route_write(void *opaque, hwaddr offset, uint64_t value,
                              unsigned size, MemTxAttrs attrs)
{
    uint64_t previous;
    NikonZ72ControllerConfig *s = opaque;
    if (route_read(s, offset, &previous, size, attrs) != MEMTX_OK) {
        return MEMTX_ERROR;
    }
    s->route[offset / 4] = value;
    return MEMTX_OK;
}

static MemTxResult exti_read(void *opaque, hwaddr offset, uint64_t *value,
                            unsigned size, MemTxAttrs attrs)
{
    NikonZ72ControllerConfig *s = opaque;
    if (size != 4 || (offset & 3) || offset >= sizeof(s->exti)) {
        return MEMTX_ERROR;
    }
    *value = s->exti[offset / 4];
    return MEMTX_OK;
}

static MemTxResult exti_write(void *opaque, hwaddr offset, uint64_t value,
                             unsigned size, MemTxAttrs attrs)
{
    uint64_t previous;
    NikonZ72ControllerConfig *s = opaque;
    if (exti_read(s, offset, &previous, size, attrs) != MEMTX_OK) {
        return MEMTX_ERROR;
    }
    if (offset == 0x14) {
        s->exti[5] &= ~value;
        s->exti[4] &= ~value;
    } else if (offset == 0x10) {
        s->exti[4] |= value;
        s->exti[5] |= value;
    } else {
        s->exti[offset / 4] = value;
    }
    controller_exti_irq(s);
    return MEMTX_OK;
}

static const MemoryRegionOps route_ops = {
    .read_with_attrs = route_read, .write_with_attrs = route_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static const MemoryRegionOps exti_ops = {
    .read_with_attrs = exti_read, .write_with_attrs = exti_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void controller_reset(Object *obj, ResetType type)
{
    NikonZ72ControllerConfig *s = NIKON_Z72_CONTROLLER_CONFIG(obj);
    memset(s->rcc, 0, sizeof(s->rcc));
    memset(s->route, 0, sizeof(s->route));
    memset(s->exti, 0, sizeof(s->exti));
    s->rcc[0] = s->clock_completion ? 3 : 1;
    controller_exti_irq(s);
}

static int controller_post_load(void *opaque, int version)
{
    NikonZ72ControllerConfig *s = opaque;
    if (version < 2) {
        memset(s->route, 0, sizeof(s->route));
        memset(s->exti, 0, sizeof(s->exti));
    }
    if (version < 3) {
        memset(s->port_levels, 0, sizeof(s->port_levels));
        memset(s->port_known, 0, sizeof(s->port_known));
    }
    controller_exti_irq(s);
    return 0;
}

static const VMStateDescription controller_state = {
    .name = TYPE_NIKON_Z72_CONTROLLER_CONFIG,
    .version_id = 3,
    .minimum_version_id = 1,
    .post_load = controller_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(rcc, NikonZ72ControllerConfig, 0x100 / 4),
        VMSTATE_UINT32_ARRAY_V(route, NikonZ72ControllerConfig, 9, 2),
        VMSTATE_UINT32_ARRAY_V(exti, NikonZ72ControllerConfig, 6, 2),
        VMSTATE_UINT16_ARRAY_V(port_levels, NikonZ72ControllerConfig, 8, 3),
        VMSTATE_UINT16_ARRAY_V(port_known, NikonZ72ControllerConfig, 8, 3),
        VMSTATE_END_OF_LIST()
    },
};

static const Property controller_properties[] = {
    DEFINE_PROP_BOOL("clock-completion", NikonZ72ControllerConfig,
                     clock_completion, true),
};

static void controller_config_init(Object *obj)
{
    NikonZ72ControllerConfig *s = NIKON_Z72_CONTROLLER_CONFIG(obj);
    memory_region_init_io(&s->iomem, obj, &controller_ops, s,
                          TYPE_NIKON_Z72_CONTROLLER_CONFIG, 0x100);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    memory_region_init_io(&s->route_iomem, obj, &route_ops, s,
                          "z72-controller-pin-routing", 0x400);
    memory_region_init_io(&s->exti_iomem, obj, &exti_ops, s,
                          "z72-controller-exti-config", 0x400);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->route_iomem);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->exti_iomem);
    qdev_init_gpio_in(DEVICE(s), controller_pad_input, 128);
    for (unsigned i = 0; i < ARRAY_SIZE(s->exti_irqs); i++) {
        sysbus_init_irq(SYS_BUS_DEVICE(s), &s->exti_irqs[i]);
    }
}

static void controller_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->vmsd = &controller_state;
    device_class_set_props(dc, controller_properties);
    RESETTABLE_CLASS(klass)->phases.hold = controller_reset;
}

static void controller_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_NIKON_Z72_CONTROLLER_CONFIG,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(NikonZ72ControllerConfig),
        .instance_init = controller_config_init,
        .class_init = controller_class_init,
    };
    type_register_static(&info);
}
type_init(controller_register_types)

static void controller_reset_domain(void *opaque)
{
    resettable_reset(OBJECT(opaque), RESET_TYPE_COLD);
}

static void controller_sysreset(void *opaque, int line, int level)
{
    if (level) {
        qemu_bh_schedule(opaque);
    }
}

static void controller_map(ResettableContainer *domain, MemoryRegion *root,
                           DeviceState *dev, unsigned index, hwaddr base)
{
    memory_region_add_subregion(root, base,
                               sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), index));
    if (domain && index == 0) {
        resettable_container_add(domain, OBJECT(dev));
    }
}

static void controller_ram(MemoryRegion *root, const char *name,
                           hwaddr base, uint64_t size)
{
    MemoryRegion *region = g_new0(MemoryRegion, 1);
    memory_region_init_ram(region, NULL, name, size, &error_fatal);
    memory_region_add_subregion(root, base, region);
}

DeviceState *nikon_z72_controller_create(Object *owner, MemoryRegion *root,
                                       Z72ControllerInputs *s,
                                       const char *cpu_type, const char *firmware)
{
    ResettableContainer *domain = RESETTABLE_CONTAINER(
        object_new(TYPE_RESETTABLE_CONTAINER));
    object_property_add_child(owner, "controller-reset-domain", OBJECT(domain));
    object_unref(OBJECT(domain));
    DeviceState *i2c_devices[2];
    DeviceState *dma_devices[2];
    MemoryRegion *flash = g_new0(MemoryRegion, 1);
    MemoryRegion *alias = g_new0(MemoryRegion, 1);
    memory_region_init_rom(flash, NULL, "z72-controller-flash-lab",
                           0x100000, &error_fatal);
    memory_region_add_subregion(root, 0x08000000, flash);
    memory_region_init_alias(alias, owner, "z72-controller-reset-alias",
                             flash, 0, 0x100000);
    memory_region_add_subregion(root, 0, alias);
    controller_ram(root, "z72-controller-sram-lab", 0x20000000, 0x40000);
    /* Early power and flash-control configuration are passive word storage.
     * Flash operations and the controller-to-engine link are absent. */
    controller_ram(root, "z72-controller-power-lab", 0x40007000, 0x100);
    controller_ram(root, "z72-controller-flash-control-lab", 0x40023c00, 0x100);
    DeviceState *config = qdev_new(TYPE_NIKON_Z72_CONTROLLER_CONFIG);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(config), &error_fatal);
    controller_map(domain, root, config, 0, 0x40023800);
    /* Routing selects one port for each of sixteen external-interrupt pins. */
    controller_map(domain, root, config, 1, 0x40013800);
    controller_map(domain, root, config, 2, 0x40013c00);
    for (unsigned port = 0; port < 8; port++) {
        DeviceState *gpio = qdev_new("nikon-z72-controller-gpio");
        s->gpio[port] = gpio;
        sysbus_realize_and_unref(SYS_BUS_DEVICE(gpio), &error_fatal);
        controller_map(domain, root, gpio, 0, 0x40020000 + port * 0x400);
        if (port == 2) {
            s->battery_signal = qdev_get_gpio_in(gpio, 5);
            qemu_set_irq(s->battery_signal, s->battery_contact);
        }
        if (port == 3) {
            s->supply_signal = qdev_get_gpio_in(gpio, 13);
            qemu_set_irq(s->supply_signal, s->supply_input);
        }
        if (port == 4) {
            s->auxiliary_signal = qdev_get_gpio_in(gpio, 9);
            qemu_set_irq(s->auxiliary_signal, s->auxiliary_input);
        }
        for (unsigned pin = 0; pin < 16; pin++) {
            qdev_connect_gpio_out_named(gpio, "pad", pin,
                                       qdev_get_gpio_in(config, port * 16 + pin));
        }
        if (port == 6) {
            object_property_add_const_link(owner, "keys-gpio", OBJECT(gpio));
            s->switch_input = qdev_get_gpio_in(gpio, 5);
            qemu_set_irq(s->switch_input, s->power_switch);
            s->wake_signal = qdev_get_gpio_in(gpio, 7);
            qemu_set_irq(s->wake_signal, s->wake_input);
        }
    }
    DeviceState *rtc = qdev_new("nikon-z72-controller-rtc");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(rtc), &error_fatal);
    /* The backup clock domain survives a controller system reset. */
    controller_map(NULL, root, rtc, 0, 0x40002800);
    DeviceState *adc = qdev_new("nikon-z72-controller-adc");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(adc), &error_fatal);
    controller_map(domain, root, adc, 0, 0x40012000);
    for (unsigned port = 0; port < 2; port++) {
        DeviceState *i2c = qdev_new("nikon-z72-controller-i2c");
        i2c_devices[port] = i2c;
        qdev_prop_set_string(i2c, "bus-name", port ? "controller-i2c1" : "controller-i2c0");
        sysbus_realize_and_unref(SYS_BUS_DEVICE(i2c), &error_fatal);
        controller_map(domain, root, i2c, 0, 0x40005400 + port * 0x400);
    }
    if (s->supply_data) {
        DeviceState *supply = qdev_new("nikon-z72-controller-supply");
        qdev_prop_set_uint8(supply, "address", 0x38);
        qdev_prop_set_string(supply, "initial-state", s->supply_data);
        qdev_realize_and_unref(supply,
            qdev_get_child_bus(i2c_devices[1], "controller-i2c1"), &error_fatal);
        qdev_connect_gpio_out(s->gpio[3], 1, qdev_get_gpio_in(supply, 0));
        qdev_connect_gpio_out(supply, 0, qdev_get_gpio_in(s->gpio[6], 10));
    }

    Clock *cpuclk = clock_new(owner, "controller-cpuclk");
    Clock *refclk = clock_new(owner, "controller-refclk");
    clock_set_hz(cpuclk, 100000000);
    clock_set_hz(refclk, 12500000);
    DeviceState *core = qdev_new(TYPE_ARMV7M);
    hwaddr load_base = root == get_system_memory() ? 0 : 0x08000000;
    /* Use the flash address for private reset vectors, avoiding same-address
     * ROM lookup across independent execution domains. The zero alias remains. */
    qdev_prop_set_uint32(core, "init-nsvtor", load_base);
    qdev_prop_set_string(core, "cpu-type", cpu_type);
    qdev_prop_set_uint32(core, "num-irq", 96);
    qdev_prop_set_uint8(core, "num-prio-bits", 4);
    qdev_prop_set_bit(core, "enable-bitband", true);
    qdev_connect_clock_in(core, "cpuclk", cpuclk);
    qdev_connect_clock_in(core, "refclk", refclk);
    object_property_set_link(OBJECT(core), "memory", OBJECT(root),
                             &error_fatal);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(core), &error_fatal);
    resettable_container_add(domain, OBJECT(core));
    resettable_container_add(domain, OBJECT(&ARMV7M(core)->nvic));
    resettable_container_add(domain, OBJECT(&ARMV7M(core)->systick[M_REG_NS]));
    resettable_container_add(domain, OBJECT(ARMV7M(core)->cpu));
    QEMUBH *reset_bh = qemu_bh_new(controller_reset_domain, domain);
    qdev_connect_gpio_out_named(core, "SYSRESETREQ", 0,
                               qemu_allocate_irq(controller_sysreset, reset_bh, 0));
    DeviceState *rng = qdev_new("nikon-z72-controller-rng");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(rng), &error_fatal);
    controller_map(domain, root, rng, 0, 0x50060800);
    sysbus_connect_irq(SYS_BUS_DEVICE(rng), 0, qdev_get_gpio_in(core, 80));
    if (s->battery_peer) {
        if (qemu_chr_find("controller-battery")) {
            error_setg(&error_fatal, "Battery peer conflicts with controller-battery backend");
        }
        /* Synthetic battery peer; reads the nonce from the controller root. */
        nikon_z72_controller_battery_attach(root);
    }
    DeviceState *uart = qdev_new("stm32f2xx-usart");
    qdev_prop_set_chr(uart, "chardev", qemu_chr_find("controller-console"));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(uart), &error_fatal);
    controller_map(domain, root, uart, 0, 0x40004400);
    sysbus_connect_irq(SYS_BUS_DEVICE(uart), 0, qdev_get_gpio_in(core, 38));
    DeviceState *uart1 = qdev_new("stm32f2xx-usart");
    qdev_prop_set_chr(uart1, "chardev", qemu_chr_find("controller-battery"));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(uart1), &error_fatal);
    controller_map(domain, root, uart1, 0, 0x40011000);
    sysbus_connect_irq(SYS_BUS_DEVICE(uart1), 0, qdev_get_gpio_in(core, 37));
    static const unsigned exti_irqs[] = { 6, 7, 8, 9, 10, 23, 40 };
    for (unsigned i = 0; i < ARRAY_SIZE(exti_irqs); i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(config), i,
                           qdev_get_gpio_in(core, exti_irqs[i]));
    }
    static const unsigned dma_irqs[2][8] = {
        { 11, 12, 13, 14, 15, 16, 17, 47 },
        { 56, 57, 58, 59, 60, 68, 69, 70 },
    };
    for (unsigned bank = 0; bank < 2; bank++) {
        DeviceState *dma = qdev_new("nikon-z72-controller-dma");
        dma_devices[bank] = dma;
        object_property_set_link(OBJECT(dma), "root", OBJECT(root),
                                 &error_fatal);
        sysbus_realize_and_unref(SYS_BUS_DEVICE(dma), &error_fatal);
        controller_map(domain, root, dma, 0, 0x40026000 + bank * 0x400);
        for (unsigned stream = 0; stream < 8; stream++) {
            sysbus_connect_irq(SYS_BUS_DEVICE(dma), stream,
                               qdev_get_gpio_in(core, dma_irqs[bank][stream]));
        }
    }
    for (unsigned port = 0; port < 2; port++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(i2c_devices[port]), 0,
                           qdev_get_gpio_in(core, 31 + port * 2));
        sysbus_connect_irq(SYS_BUS_DEVICE(i2c_devices[port]), 1,
                           qdev_get_gpio_in(core, 32 + port * 2));
    }
    /* Supply transfers use DMA1 streams 2 and 7, both on channel 7. */
    qdev_connect_gpio_out_named(i2c_devices[1], "dma-request", 0,
                               qdev_get_gpio_in(dma_devices[0], 2 * 8 + 7));
    qdev_connect_gpio_out_named(i2c_devices[1], "dma-request", 1,
                               qdev_get_gpio_in(dma_devices[0], 7 * 8 + 7));
    static const hwaddr spi_bases[] = { 0x40013000, 0x40013400, 0x40003c00, 0x40003800 };
    static const unsigned spi_irqs[] = { 35, 84, 51, 36 };
    for (unsigned port = 0; port < ARRAY_SIZE(spi_bases); port++) {
        DeviceState *spi = qdev_new("nikon-z72-controller-spi");
        s->spi[port] = spi;
        g_autofree char *child_name = g_strdup_printf("spi%u", port);
        g_autofree char *bus_name = g_strdup_printf("controller-spi%u", port);
        object_property_add_child(owner, child_name, OBJECT(spi));
        qdev_prop_set_string(spi, "bus-name", bus_name);
        sysbus_realize_and_unref(SYS_BUS_DEVICE(spi), &error_fatal);
        controller_map(domain, root, spi, 0, spi_bases[port]);
        sysbus_connect_irq(SYS_BUS_DEVICE(spi), 0, qdev_get_gpio_in(core, spi_irqs[port]));
        if (port < 2) {
            qdev_connect_gpio_out_named(spi, "dma-request", port ? 1 : 0,
                qdev_get_gpio_in(dma_devices[1], port ? 12 : 3));
        }
    }
    DeviceState *timer = qdev_new("stm32f2xx-timer");
    qdev_prop_set_uint64(timer, "clock-frequency", 100000000);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(timer), &error_fatal);
    controller_map(domain, root, timer, 0, 0x40000c00);
    sysbus_connect_irq(SYS_BUS_DEVICE(timer), 0, qdev_get_gpio_in(core, 50));
    sysbus_connect_irq(SYS_BUS_DEVICE(adc), 0, qdev_get_gpio_in(core, 18));
    DeviceState *shared = qdev_new(TYPE_OR_IRQ);
    qdev_prop_set_uint16(shared, "num-lines", 3);
    qdev_realize_and_unref(shared, NULL, &error_fatal);
    resettable_container_add(domain, OBJECT(shared));
    qdev_connect_gpio_out(shared, 0, qdev_get_gpio_in(core, 26));
    DeviceState *update_irq = qdev_new(TYPE_OR_IRQ);
    qdev_prop_set_uint16(update_irq, "num-lines", 3);
    qdev_realize_and_unref(update_irq, NULL, &error_fatal);
    resettable_container_add(domain, OBJECT(update_irq));
    qdev_connect_gpio_out(update_irq, 0, qdev_get_gpio_in(core, 25));
    DeviceState *advanced = qdev_new("nikon-z72-controller-timer");
    qdev_prop_set_bit(advanced, "advanced", true);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(advanced), &error_fatal);
    controller_map(domain, root, advanced, 0, 0x40010000);
    sysbus_connect_irq(SYS_BUS_DEVICE(advanced), 0, qdev_get_gpio_in(update_irq, 0));
    sysbus_connect_irq(SYS_BUS_DEVICE(advanced), 1, qdev_get_gpio_in(core, 27));
    sysbus_connect_irq(SYS_BUS_DEVICE(advanced), 2, qdev_get_gpio_in(shared, 0));
    sysbus_connect_irq(SYS_BUS_DEVICE(advanced), 3, qdev_get_gpio_in(core, 24));
    DeviceState *compare = qdev_new("nikon-z72-controller-timer");
    qdev_prop_set_uint8(compare, "channels", 1);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(compare), &error_fatal);
    controller_map(domain, root, compare, 0, 0x40014800);
    sysbus_connect_irq(SYS_BUS_DEVICE(compare), 0, qdev_get_gpio_in(shared, 1));
    sysbus_connect_irq(SYS_BUS_DEVICE(compare), 1, qdev_get_gpio_in(shared, 2));
    DeviceState *update_timer = qdev_new("nikon-z72-controller-timer");
    qdev_prop_set_uint8(update_timer, "channels", 1);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(update_timer), &error_fatal);
    controller_map(domain, root, update_timer, 0, 0x40014400);
    sysbus_connect_irq(SYS_BUS_DEVICE(update_timer), 0, qdev_get_gpio_in(update_irq, 1));
    sysbus_connect_irq(SYS_BUS_DEVICE(update_timer), 1, qdev_get_gpio_in(update_irq, 2));
    DeviceState *link_irq = qdev_new(TYPE_OR_IRQ);
    qdev_prop_set_uint16(link_irq, "num-lines", 3);
    qdev_realize_and_unref(link_irq, NULL, &error_fatal);
    resettable_container_add(domain, OBJECT(link_irq));
    qdev_connect_gpio_out(link_irq, 0, qdev_get_gpio_in(core, 43));
    DeviceState *link_timer = qdev_new("nikon-z72-controller-timer");
    qdev_prop_set_uint8(link_timer, "channels", 2);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(link_timer), &error_fatal);
    controller_map(domain, root, link_timer, 0, 0x40001800);
    sysbus_connect_irq(SYS_BUS_DEVICE(link_timer), 0, qdev_get_gpio_in(link_irq, 0));
    sysbus_connect_irq(SYS_BUS_DEVICE(link_timer), 1, qdev_get_gpio_in(link_irq, 1));
    DeviceState *secondary_advanced = qdev_new("nikon-z72-controller-timer");
    qdev_prop_set_bit(secondary_advanced, "advanced", true);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(secondary_advanced), &error_fatal);
    controller_map(domain, root, secondary_advanced, 0, 0x40010400);
    sysbus_connect_irq(SYS_BUS_DEVICE(secondary_advanced), 0, qdev_get_gpio_in(core, 44));
    sysbus_connect_irq(SYS_BUS_DEVICE(secondary_advanced), 1, qdev_get_gpio_in(core, 46));
    sysbus_connect_irq(SYS_BUS_DEVICE(secondary_advanced), 2, qdev_get_gpio_in(core, 45));
    sysbus_connect_irq(SYS_BUS_DEVICE(secondary_advanced), 3, qdev_get_gpio_in(link_irq, 2));
    for (unsigned port = 0; port < 2; port++) {
        DeviceState *counter_irq = qdev_new(TYPE_OR_IRQ);
        qdev_prop_set_uint16(counter_irq, "num-lines", 2);
        qdev_realize_and_unref(counter_irq, NULL, &error_fatal);
        resettable_container_add(domain, OBJECT(counter_irq));
        qdev_connect_gpio_out(counter_irq, 0, qdev_get_gpio_in(core, 29 + port));
        DeviceState *counter_timer = qdev_new("nikon-z72-controller-timer");
        if (port == 0) {
            object_property_add_child(owner, "capture-timer", OBJECT(counter_timer));
        }
        sysbus_realize_and_unref(SYS_BUS_DEVICE(counter_timer), &error_fatal);
        controller_map(domain, root, counter_timer, 0, 0x40000400 + port * 0x400);
        sysbus_connect_irq(SYS_BUS_DEVICE(counter_timer), 0, qdev_get_gpio_in(counter_irq, 0));
        sysbus_connect_irq(SYS_BUS_DEVICE(counter_timer), 1, qdev_get_gpio_in(counter_irq, 1));
    }
    DeviceState *wide_irq = qdev_new(TYPE_OR_IRQ);
    qdev_prop_set_uint16(wide_irq, "num-lines", 2);
    qdev_realize_and_unref(wide_irq, NULL, &error_fatal);
    resettable_container_add(domain, OBJECT(wide_irq));
    qdev_connect_gpio_out(wide_irq, 0, qdev_get_gpio_in(core, 28));
    DeviceState *wide_timer = qdev_new("nikon-z72-controller-timer");
    qdev_prop_set_uint8(wide_timer, "counter-bits", 32);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(wide_timer), &error_fatal);
    controller_map(domain, root, wide_timer, 0, 0x40000000);
    sysbus_connect_irq(SYS_BUS_DEVICE(wide_timer), 0, qdev_get_gpio_in(wide_irq, 0));
    sysbus_connect_irq(SYS_BUS_DEVICE(wide_timer), 1, qdev_get_gpio_in(wide_irq, 1));
    controller_load_firmware(s, ARMV7M(core)->cpu, firmware, load_base);
    return core;
}

static void nikon_z72_controller_init(MachineState *machine)
{
    Z72ControllerMachine *s = Z72_CONTROLLER_MACHINE(machine);
    nikon_z72_controller_create(OBJECT(machine), get_system_memory(), &s->inputs,
                                machine->cpu_type, machine->kernel_filename);
    vmstate_register(NULL, 0, &controller_machine_state, machine);
}

static void nikon_z72_controller_class_init(ObjectClass *klass, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(klass);
    mc->desc = "Z72 isolated controller firmware laboratory";
    mc->init = nikon_z72_controller_init;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-m4");
    mc->default_cpus = mc->max_cpus = 1;
    mc->no_serial = mc->no_parallel = true;
    object_class_property_add_bool(klass, "power-switch", controller_power_switch_get,
                                   controller_power_switch_set);
    object_class_property_set_description(klass, "power-switch",
        "External controller power switch level on port G pin 5");
    object_class_property_add_bool(klass, "wake-input", controller_wake_get,
                                   controller_wake_set);
    object_class_property_set_description(klass, "wake-input",
        "Experimental external signal on port G pin 7");
    object_class_property_add_bool(klass, "battery-contact", controller_battery_get,
                                   controller_battery_set);
    object_class_property_set_description(klass, "battery-contact",
        "Experimental battery contact signal on port C pin 5");
    object_class_property_add_bool(klass, "supply-input", controller_supply_get,
                                   controller_supply_set);
    object_class_property_set_description(klass, "supply-input",
        "Experimental supply selection signal on port D pin 13");
    object_class_property_add_bool(klass, "auxiliary-input", controller_auxiliary_get,
                                   controller_auxiliary_set);
    object_class_property_set_description(klass, "auxiliary-input",
        "Experimental auxiliary target signal on port E pin 9");
    object_class_property_add_str(klass, "flash-data", controller_flash_data_get,
                                 controller_flash_data_set);
    object_class_property_set_description(klass, "flash-data",
        "Private resident flash data for the empty 0x08004000..0x0800ffff window");
    object_class_property_add_str(klass, "supply-data", controller_supply_data_get,
                                 controller_supply_data_set);
    object_class_property_set_description(klass, "supply-data",
        "Experimental supply response records on controller-i2c1 address 0x38");
    object_class_property_add_bool(klass, "battery-peer", controller_battery_peer_get,
                                   controller_battery_peer_set);
    object_class_property_set_description(klass, "battery-peer",
        "Answer original battery serial exchanges with a synthetic peer");
}

static void controller_machine_init(Object *obj)
{
    Z72_CONTROLLER_MACHINE(obj)->inputs.power_switch = true;
}

static void controller_machine_finalize(Object *obj)
{
    g_free(Z72_CONTROLLER_MACHINE(obj)->inputs.flash_data);
    g_free(Z72_CONTROLLER_MACHINE(obj)->inputs.supply_data);
}

static void controller_machine_register(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_CONTROLLER_MACHINE,
        .parent = TYPE_MACHINE,
        .interfaces = arm_machine_interfaces,
        .instance_size = sizeof(Z72ControllerMachine),
        .instance_init = controller_machine_init,
        .instance_finalize = controller_machine_finalize,
        .class_init = nikon_z72_controller_class_init,
    };
    type_register_static(&info);
}
type_init(controller_machine_register)
