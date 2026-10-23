# SPDX-License-Identifier: GPL-2.0-or-later
"""Integrate the Z72 laboratory board into a verified QEMU 10.2.4 tree."""
from pathlib import Path
import shutil
import sys

def prepare(root):
    if (root / 'VERSION').read_text().strip() != '10.2.4':
        raise ValueError('Expected QEMU 10.2.4')
    project = Path(__file__).resolve().parent
    for name in ('nikon-z72.c', 'nikon-z72-counter.c', 'nikon-z72-delay.c', 'nikon-z72-uart.c',
                 'nikon-z72-input-config.c',
                 'nikon-z72-notify.c', 'nikon-z72-timer.c', 'nikon-z72-spi.c', 'nikon-z72-i2c.c', 'nikon-z72-memory.c', 'nikon-z72-controller.c',
                 'nikon-z72-controller-gpio.c', 'nikon-z72-controller-rtc.c',
                 'nikon-z72-controller-i2c.c', 'nikon-z72-controller-dma.c',
                 'nikon-z72-controller-supply.c', 'nikon-z72-controller-battery.c',
                 'nikon-z72-controller-timer.c',
                 'nikon-z72-controller-adc.c',
                 'nikon-z72-controller-rng.c',
                 'nikon-z72-controller-registers.c',
                 'nikon-z72-controller-expander.c',
                 'nikon-z72-controller-spi.c',
                 'nikon-z72-controller.h',
                 'nikon-z72-profile.h', 'nikon-z72-graphics.c', 'nikon-gpu.h'):
        source, destination = project / name, root / 'hw/arm' / name
        if not destination.exists() or source.read_bytes() != destination.read_bytes():
            shutil.copyfile(source, destination)
    additions = {
        'hw/arm/meson.build': "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72.c'))\n",
        'hw/arm/Kconfig': '\nconfig NIKON_Z72_LAB\n    bool\n    depends on TCG && ARM\n    select GENERIC_LOADER\n    select ARM_GIC\n    select ARM_V7M\n    select STM32F2XX_TIMER\n    select OR_IRQ\n    select I2C\n    select SSI\n    select STM32F2XX_USART\n    select SDHCI\n',
        'configs/devices/arm-softmmu/default.mak': '\nCONFIG_NIKON_Z72_LAB=y\n',
    }
    for name, addition in additions.items():
        path = root / name
        previous = path.read_text()
        data = previous
        if name == 'hw/arm/Kconfig':
            if addition.strip() not in data:
                variants = []
                legacy = addition
                for dependency in ('SDHCI', 'STM32F2XX_USART', 'SSI', 'I2C', 'OR_IRQ', 'STM32F2XX_TIMER', 'ARM_V7M', 'ARM_GIC'):
                    legacy = legacy.removesuffix('    select ' + dependency + '\n')
                    variants.append(legacy)
                for previous_config in variants:
                    if previous_config.strip() in data:
                        data = data.replace(previous_config, addition, 1)
                        break
        if name == 'hw/arm/meson.build':
            supply = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller-supply.c'))\n"
            if supply.strip() not in data:
                data += supply
            battery = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller-battery.c'))\n"
            if battery.strip() not in data:
                data += battery
            input_config = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-input-config.c'))\n"
            if input_config.strip() not in data:
                data += input_config
            delay = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-delay.c'))\n"
            if delay.strip() not in data:
                data += delay
            engine_i2c = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-i2c.c'))\n"
            if engine_i2c.strip() not in data:
                data += engine_i2c
            memory = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-memory.c'))\n"
            if memory.strip() not in data:
                data += memory
            graphics = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-graphics.c'))\n"
            if graphics.strip() not in data:
                data += graphics
            controller_spi = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller-spi.c'))\n"
            if controller_spi.strip() not in data:
                data += controller_spi
            registers = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller-registers.c'))\n"
            if registers.strip() not in data:
                data += registers
            expander = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller-expander.c'))\n"
            if expander.strip() not in data:
                data += expander
            adc = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller-adc.c'))\n"
            if adc.strip() not in data:
                data += adc
            rng = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller-rng.c'))\n"
            if rng.strip() not in data:
                data += rng
            controller_timer = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller-timer.c'))\n"
            if controller_timer.strip() not in data:
                data += controller_timer
            dma = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller-dma.c'))\n"
            if dma.strip() not in data:
                data += dma
            i2c = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller-i2c.c'))\n"
            if i2c.strip() not in data:
                data += i2c
            rtc = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller-rtc.c'))\n"
            if rtc.strip() not in data:
                data += rtc
            gpio = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller-gpio.c'))\n"
            if gpio.strip() not in data:
                data += gpio
            controller = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-controller.c'))\n"
            if controller.strip() not in data:
                data += controller
            counter = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-counter.c'))\n"
            if counter.strip() not in data:
                data += counter
            uart = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-uart.c'))\n"
            if uart.strip() not in data:
                data += uart
            notifier = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-notify.c'))\n"
            if notifier.strip() not in data:
                data += notifier
            spi = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-spi.c'))\n"
            if spi.strip() not in data:
                data += spi
            timer = "arm_ss.add(when: 'CONFIG_NIKON_Z72_LAB', if_true: files('nikon-z72-timer.c'))\n"
            if timer.strip() not in data:
                data += timer
        if addition.strip() not in data:
            data += addition
        if data != previous:
            path.write_text(data)
    print('Prepared', root)

def prepare_screendump(root):
    """Batch RGB output to avoid one filesystem write per display row."""
    path = root / 'ui/ui-qmp-cmds.c'
    data = path.read_text()
    old = '''    linebuf = qemu_pixman_linebuf_create(PIXMAN_BE_r8g8b8, width);
    for (y = 0; y < height; y++) {
        qemu_pixman_linebuf_fill(linebuf, image, width, 0, y);
        if (qio_channel_write_all(QIO_CHANNEL(ioc),
                                  (char *)pixman_image_get_data(linebuf),
                                  pixman_image_get_stride(linebuf), errp) < 0) {
            return false;
        }
    }

    return true;'''
    new = '''    linebuf = qemu_pixman_linebuf_create(PIXMAN_BE_r8g8b8, width);
    size_t stride = pixman_image_get_stride(linebuf);
    g_autofree uint8_t *pixels = g_malloc_n(height, stride);

    for (y = 0; y < height; y++) {
        qemu_pixman_linebuf_fill(linebuf, image, width, 0, y);
        memcpy(pixels + (size_t)y * stride,
               pixman_image_get_data(linebuf), stride);
    }

    return qio_channel_write_all(QIO_CHANNEL(ioc), pixels,
                                 (size_t)height * stride, errp) >= 0;'''
    if data.count(new) == 1:
        return
    if data.count(old) != 1:
        raise ValueError('Unexpected QEMU screendump implementation')
    path.write_text(data.replace(old, new, 1))


if __name__ == '__main__':
    root = Path(sys.argv[1]).resolve()
    prepare(root)
    prepare_screendump(root)
