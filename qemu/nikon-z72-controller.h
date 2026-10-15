/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NIKON_Z72_CONTROLLER_H
#define NIKON_Z72_CONTROLLER_H

#include "hw/qdev-core.h"
#include "hw/irq.h"
#include "system/memory.h"

typedef struct Z72ControllerInputs {
    bool power_switch;
    bool wake_input;
    bool battery_contact;
    bool supply_input;
    bool auxiliary_input;
    bool battery_peer;
    char *flash_data;
    char *supply_data;
    qemu_irq switch_input;
    qemu_irq wake_signal;
    qemu_irq battery_signal;
    qemu_irq supply_signal;
    qemu_irq auxiliary_signal;
    DeviceState *gpio[8];
    DeviceState *spi[4];
} Z72ControllerInputs;

DeviceState *nikon_z72_controller_create(Object *owner, MemoryRegion *root,
                                       Z72ControllerInputs *inputs,
                                       const char *cpu_type, const char *firmware);

/* Connect the synthetic battery serial peer to a controller memory root. */
void nikon_z72_controller_battery_attach(MemoryRegion *root);

#endif
