/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NIKON_Z72_SPI_H
#define NIKON_Z72_SPI_H

#include "hw/qdev-core.h"

bool nikon_z72_spi_receive(DeviceState *dev, unsigned channel,
                           uint16_t value, unsigned bits);

#endif
