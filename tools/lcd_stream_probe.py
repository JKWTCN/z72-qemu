# SPDX-License-Identifier: GPL-2.0-or-later
"""Sample native LCD composition and processing buffers without guest writes."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from tools.body_shutter_gate_probe import display_delivery_snapshot, snapshot
from analyze.qemu_display import Remote
from tools.web_console import LIVE_VIEW_OPTIONS, Machine

CAPTURE_INPUTS = ('processing_resource_header', 'controller_actuator', 'controller_step_link',
                  'sampling_output_complete', 'primary_exposure_sync')


def observe(machine, seconds, image_directory=None):
    paths = ['/machine/unattached/' + name for name in machine.config_names]
    with machine.io:
        path = next(path for path in paths if machine.qmp.command(
            'qom-get', dict(path=path, property='master-role')))

    def counters():
        return {name: machine.qmp.command('qom-get', dict(path=path, property=property_name))
                for name, property_name in (('raw', 'input-dma-count'),
                    ('processing', 'processing-dma-count'), ('grids', 'processing-grid-count'),
                    ('startup_grids', 'input-grid-count'), ('primary', 'primary-input-dma-count'))}

    samples = []
    deadline = time.monotonic() + seconds
    last_count = None
    while time.monotonic() < deadline and len(samples) < 6:
        machine.heartbeat()
        with machine.io:
            count = counters()
        if count['processing'] >= 30 and count['processing'] != last_count:
            with machine.io:
                machine.qmp.command('stop')
            try:
                with machine.io:
                    count = counters()
                    geometry = machine._words(0x20144204, 1)[0]
                    width, height = geometry & 0xffff, geometry >> 16 & 0x3fff
                    stride = machine._words(0x20144240, 1)[0]
                    address = machine._words(0x20144210, 1)[0]
                    require(0 < width <= stride <= 4096 and 0 < height <= 4096 and
                            0xb0000000 <= address <= 0xf0000000 - stride * height,
                            'Native LCD plane is not configured')
                    data = machine._bytes(address, stride * height)
                    targets = [machine._words(0x20102200 + (slot * 16 + 4) * 4, 1)[0]
                               for slot in range(4)]
                    # This is a probe-owned fresh instance; disable its read
                    # cache so each image reflects this paused register set.
                    machine.lcd_cache = (0.0, b'')
                    sample = dict(counters=count, width=width, height=height, stride=stride,
                        background=hex(address), processing_targets=[hex(value) for value in targets],
                        background_is_processing_target=address in targets,
                        display_delivery=display_delivery_snapshot(machine._bytes),
                        luminance=dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                            minimum=min(data), maximum=max(data), unique_bytes=len(set(data))),
                        counters_after=count)
                # lcd_png takes the same non-reentrant monitor lock. The
                # VM remains paused while this probe releases that lock.
                png = machine.lcd_png()
                with machine.io:
                    sample.update(png_bytes=len(png), png_sha256=hashlib.sha256(png).hexdigest(),
                                  counters_after=counters())
                samples.append(sample)
                if image_directory is not None:
                    image_directory.mkdir(parents=True, exist_ok=True)
                    (image_directory / f'frame-{len(samples)}.png').write_bytes(png)
                last_count = count['processing']
                print(json.dumps(dict(sample=len(samples), **sample)), flush=True)
            finally:
                with machine.io:
                    machine.qmp.command('cont')
        time.sleep(0.25)
    with machine.io:
        machine.qmp.command('stop')
        remote = Remote(machine.gdb_port)
        try:
            final = snapshot(remote)
            delivery = display_delivery_snapshot(machine._bytes)
        finally:
            remote.command('D')
            remote.sock.close()
    return dict(samples=samples, after=final, display_delivery=delivery,
        distinct_backgrounds=len({sample['luminance']['sha256'] for sample in samples}),
        distinct_images=len({sample['png_sha256'] for sample in samples}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--sd-card', type=Path)
    parser.add_argument('--wsl', action='store_true')
    for name in CAPTURE_INPUTS:
        parser.add_argument('--' + name.replace('_', '-'), action='store_true')
    parser.add_argument('--images', type=Path, help='Private directory for sampled PNG files')
    parser.add_argument('--watch', type=int, default=120)
    parser.add_argument('--icount-shift', type=int, default=2)
    args = parser.parse_args()
    require(30 <= args.watch <= 600 and 0 <= args.icount_shift <= 6, 'Observation bounds invalid')
    require(not args.primary_exposure_sync or args.sampling_output_complete,
            'Primary exposure synchronization requires sampling output completion')
    require(args.images is None or args.images.resolve().is_relative_to((ROOT / '.local').resolve()),
            'Images must remain in the private .local directory')
    args.realtime = args.auto_menu = False
    args.update_store, args.update_image = ROOT / '.local/lcd-stream-store', None
    for name in LIVE_VIEW_OPTIONS:
        setattr(args, name, True)
    machine = Machine(args)
    try:
        machine.restart()
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            state = machine.status()
            require(state['phase'] != 'failed', str(state.get('error')))
            if state.get('ready') and state.get('index') == 3 and state.get('input_ready'):
                break
            time.sleep(1)
        else:
            raise TimeoutError('Shooting foreground did not become ready')
        report = dict(observation='native-lcd-stream-composition', firmware_included=False,
            capture_inputs={name: getattr(args, name) for name in CAPTURE_INPUTS},
            icount_shift=args.icount_shift,
            application=state, trace=observe(machine, args.watch, args.images),
            model_source_sha256=hashlib.sha256((ROOT / 'qemu/nikon-z72.c').read_bytes().replace(
                b'\r\n', b'\n')).hexdigest(),
            limitations=['Laboratory RAW12 source and functional monochrome processing.',
                         'Read-only register composition; hardware scanout and color remain unverified.',
                         'No capture request or photograph is produced by this observation.'])
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
        print('Recorded LCD stream:', args.out)
    finally:
        machine.close()


if __name__ == '__main__':
    main()
