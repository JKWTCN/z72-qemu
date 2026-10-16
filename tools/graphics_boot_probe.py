# SPDX-License-Identifier: GPL-2.0-or-later
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from tools.dual_boot_probe import dual_machine, sample_cores
from tools.smp_boot_probe import reach
from analyze.decode_z72 import require
from analyze.firmware_structure import analyze_eg


def graphics_observation(remote):
    result = {}
    for name in ('successful-uploads', 'render-requests', 'rendered-commands',
                 'unsupported-commands', 'failed-requests', 'surface-address',
                 'target-address', 'target-dimensions', 'target-format', 'target-second-plane'):
        command = 'qom-get /machine/master-graphics ' + name
        response = remote.command('qRcmd,' + command.encode().hex())
        output = bytearray()
        while response.startswith('O') and response != 'OK':
            output.extend(bytes.fromhex(response[1:]))
            response = remote.receive()
        require(response == 'OK', 'Graphics observation command failed')
        result[name.replace('-', '_')] = json.loads(output.decode())
    return result


def application_observation(remote):
    remote.select_thread(1)
    data = remote.read(0xb1811e40, 88)
    applications = []
    for index, name in enumerate(('APPIDLE', 'APPMENU', 'APPPLAY', 'APPLV', 'APPMSG')):
        getter, context, ready = struct.unpack_from('<3I', data, 28 + index * 12)
        applications.append(dict(index=index, name=name, getter=hex(getter),
                                 context=hex(context), ready=ready))
    return dict(initialization_complete=struct.unpack_from('<I', data)[0],
                start_notification_sent=struct.unpack_from('<I', data, 4)[0],
                current_index=data[16], next_index=data[17], state=data[24],
                applications=applications)


def system_observation(remote):
    remote.select_thread(1)
    data = remote.read(0xb1818d24, 44)
    power = int.from_bytes(remote.read(0xb1818ec4, 1), 'little', signed=True)
    transition = remote.read(0xb1818ef0, 24)
    return dict(mode_context=hex(struct.unpack_from('<I', data)[0]),
                current_mode=data[4], previous_mode=data[5], power_input=power,
                configuration_flags=struct.unpack_from('<I', data, 12)[0],
                configuration_secondary_flags=struct.unpack_from('<I', data, 16)[0],
                transition_inhibitors=list(struct.unpack_from('<3I', transition)),
                deferred_transition_flags=struct.unpack_from('<I', transition, 12)[0],
                deferred_target_mode=transition[20]
                if struct.unpack_from('<I', transition, 12)[0] & 4 else None,
                control_ready_bitmap=int.from_bytes(remote.read(0xb18695e4, 4), 'little'),
                pending_settings_bitmap=int.from_bytes(remote.read(0xb1868170, 4), 'little'))


def idle_timer_observation(remote):
    """Read the application timeout policy and its last timer start request.

    The stored interval is not a remaining-time or timer-active indication.
    """
    remote.select_thread(1)
    policy = remote.read(0xb1819aa0, 0x20)
    timer = struct.unpack('<6I', remote.read(0xb1f80168, 24))
    flags = struct.unpack_from('<I', policy, 0x14)[0]
    return dict(policy_context='0xb1819aa0', application_kind=policy[0],
                timeout_seconds=struct.unpack_from('<I', policy, 0x10)[0],
                policy_flags=flags, five_second_policy=bool(flags & 6),
                timer_object='0xb1f80168', timer_handle=hex(timer[0]),
                callback=hex(timer[1]), last_start_milliseconds=timer[2],
                destination_context=hex(timer[3]), message=hex(timer[4]),
                event_slot=timer[5] & 255)


def controller_input_observation(remote):
    """Read controller input samples and the engine's decoded switch words.

    A decoded menu bit does not prove that the foreground accepted the event.
    """
    remote.select_thread(5)
    expander = remote.read(0x2001ff50, 9)
    primary = remote.read(0x200159a4, 16)
    menu = remote.read(0x20011525, 1)[0]
    remote.select_thread(1)
    switches = struct.unpack('<3I', remote.read(0xb25eaeac, 12))
    return dict(expander_mode=expander[0],
                expander_current_sample=expander[3:6].hex(),
                expander_previous_sample=expander[6:9].hex(),
                primary_context='0x200159a4',
                primary_state_prefix=primary.hex(),
                controller_menu_aggregate=menu,
                decoded_switch_words=[hex(value) for value in switches],
                decoded_menu_bit=bool(switches[1] & 0x8000))


def sensor_observation(remote):
    remote.select_thread(1)
    state = remote.read(0xb1807efc, 16)
    context = struct.unpack_from('<I', state, 4)[0]
    descriptors = remote.read(context + 424, 8) if context else bytes(8)
    return dict(context=hex(context),
                sample_ready=struct.unpack_from('<I', state, 12)[0] == 1,
                parameter_descriptors=[hex(pointer) for pointer in
                                       struct.unpack('<2I', descriptors)])


def capture_health_observation(remote):
    """Read native menu inhibition and the resource header used by capture.

    Header acceptance alone does not validate the resource contents or capture.
    """
    remote.select_thread(1)
    size, pointer = struct.unpack('<2I', remote.read(0xb187556c, 8))
    status = remote.read(pointer, 0x118) if size == 0x118 and pointer else None
    count = struct.unpack_from('<I', status, 0x110)[0] if status else None
    codes = (list(struct.unpack_from(f'<{count}I', status))
             if count is not None and count <= 68 else None)
    blocking = ([hex(code) for code in codes if 0x3e <= code <= 0x44]
                if codes is not None else None)
    resource = int.from_bytes(remote.read(0xb18a77a0, 4), 'little')
    version_bytes = remote.read(resource + 0xbe014, 2) if resource else None
    version = ((version_bytes[0] << 4) | (version_bytes[1] >> 4)
               if version_bytes is not None else None)
    return dict(status_parameter='0x1921', status_buffer=hex(pointer),
                status_count=count,
                status_codes=[hex(code) for code in codes] if codes is not None else None,
                menu_blocking_status_codes=blocking,
                menu_inhibited_by_status=bool(blocking) if blocking is not None else None,
                resource_parameter=80, resource_buffer=hex(resource),
                resource_storage='0x13e80000', resource_version_offset='0xbe014',
                resource_version_bytes=version_bytes.hex() if version_bytes is not None else None,
                resource_version=hex(version) if version is not None else None,
                resource_header_check_passed=(0x150 <= version <= 0x15f)
                if version is not None else None)


def temperature_observation(remote):
    remote.select_thread(1)
    power = remote.read(0xb1865210, 16)
    sensor = remote.read(0xb1807f68, 12)
    pointer = struct.unpack_from('<I', sensor)[0]
    return dict(power_parameter_storage=hex(struct.unpack_from('<I', power)[0]),
                power_limit_codes=list(struct.unpack_from('<2I', power, 4)),
                power_limit_flag=struct.unpack_from('<I', power, 12)[0],
                power_temperature_codes=list(struct.unpack('<3i', remote.read(0xb23bcdec, 12))),
                sensor_parameter_buffer=hex(pointer),
                sensor_samples_ready=struct.unpack_from('<I', sensor, 8)[0],
                sensor_limit_codes=list(struct.unpack('<3i', remote.read(pointer + 0x24, 12)))
                if pointer else None,
                sensor_temperature_code=struct.unpack('<h', remote.read(0xb1d0129c, 2))[0])


def main():
    parser = argparse.ArgumentParser(description='Observe original graphics initialization and completion.')
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller', 'destination'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--seconds', type=float, default=5)
    parser.add_argument('--icount-shift', type=int, choices=range(7), default=4)
    parser.add_argument('--controller-expander', action='store_true')
    parser.add_argument('--controller-flash-data', type=Path)
    args = parser.parse_args()
    require(0 < args.seconds <= 60, 'Observation duration must be in (0, 60] seconds')
    destination = args.destination
    master = args.master.read_bytes()
    slave = args.slave.read_bytes()
    controller = args.controller.read_bytes()
    resident = args.controller_flash_data.read_bytes() if args.controller_flash_data is not None else None
    from tools.controller_core_probe import CONTROLLER_SHA256
    require(hashlib.sha256(controller).hexdigest() == CONTROLLER_SHA256,
            'Expected the original controller image')
    identities = {role: analyze_eg(image, role)['sha256'] for role, image in (('master', master), ('slave', slave))}
    destination.mkdir(parents=True, exist_ok=False)
    process = remote = None
    expander = None
    try:
        devices = ['nikon-z72-controller-register-bank,bus=controller-i2c0,address=79']
        if args.controller_expander:
            devices.append('nikon-z72-controller-expander,bus=controller-i2c0,address=34,id=keys')
        process, remote = dual_machine(args.qemu, destination,
            master, slave, destination / 'console.txt',
            icount=f'shift={args.icount_shift},sleep=off',
            trace='guest_errors', controller_firmware=args.controller.resolve(),
            devices=devices,
            controller_link=True,
            controller_flash_data=args.controller_flash_data.resolve()
            if args.controller_flash_data is not None else None)
        for address in (0x080200a4,0x080200b6,0x080200c8,0x080200da,0x10103610,0x1010365c):
            remote.breakpoint(address)
        remote.sock.settimeout(35)
        if args.controller_expander:
            thread, regs = reach(remote, 0x0802fdf0)
            require(thread == 5 and remote.get(regs, 'r0') == 0x44 and
                    remote.get(regs, 'r1') == 0 and remote.get(regs, 'r2') == 3,
                    'Original expander input read parameters differ')
            output, caller = remote.get(regs, 'r3'), remote.get(regs, 'lr') & ~1
            remote.command('vCont;s:5')
            thread, regs = reach(remote, caller)
            require(thread == 5 and remote.get(regs, 'r0') == 1,
                    'Original expander input read did not succeed')
            expander = dict(address=34, address_byte='0x44', input_register=0,
                bytes=3, original_read_verified=True, input_sample=remote.read(output, 3).hex(),
                external_input_levels='0xffffff', interrupt_connected=False)
            remote.command('vCont;s:5')
        thread, regs = reach(remote, 0x106ee09c)
        require(thread in (1, 2), 'Original graphics submit ran outside the master engine')
        descriptor = remote.get(regs,'r4')
        fields = struct.unpack('<4I', remote.read(descriptor,16))
        commands = []
        for channel in range(2):
            address, words = fields[channel*2:channel*2+2]
            require(0 < words <= 0x20000, 'Invalid native command size')
            data = remote.read(address, words*4)
            at = 0
            operations = {}
            while at < len(data):
                header = struct.unpack_from('<I', data, at)[0]
                at += 4
                if not header:
                    continue
                operation, count = header & 7, ((header >> 3) & 255) + 1
                require(operation in (2, 4, 6) and at + count * 4 <= len(data),
                        'Native graphics command list contains an unsupported or truncated packet')
                operations[str(operation)] = operations.get(str(operation), 0) + 1
                at += count * 4
            commands.append(dict(channel=channel,address=hex(address),words=words,
                                 bytes=len(data), operations=operations, sha256=hashlib.sha256(data).hexdigest()))
        remote.command('vCont;s:' + format(thread,'x'))
        for index in range(3):
            thread, regs = reach(remote, 0x106ee3ca)
            callback_context = dict(thread=thread, cpsr=hex(remote.get(regs, 'cpsr')),
                                    caller=hex(remote.get(regs, 'lr')))
            require(remote.read(0x20180c18, 4) == bytes(4),
                    'Graphics device reported a command error')
            require(thread in (1,2) and int.from_bytes(remote.read(0x20181020,4),'little') == 1,
                    'Native graphics callback did not observe upload completion')
            controls=struct.unpack('<8I',remote.read(0x201810d0,32))
            remote.command('vCont;s:' + format(thread,'x'))
            if controls[0]==0 and controls[4]==0 and controls[3] and controls[7]:
                break
        else:
            raise ValueError('Both native upload channels did not finish')
        remote.sock.settimeout(args.seconds)
        try:
            remote.command('vCont;c')
        except TimeoutError:
            remote.interrupt()
        cores = sample_cores(remote)
        graphics = graphics_observation(remote)
        applications = application_observation(remote)
        faults = []
        for core in range(1, 5):
            remote.select_thread(core)
            state = {name: remote.read_register(name) for name in
                     ('DFAR_S', 'IFAR_S', 'DFSR_S', 'IFSR_S')}
            require(not any(state.values()), 'Engine recorded an execution fault')
            faults.append(dict(thread=core, registers=state))
        remote.select_thread(1)
        tables = [hex(pointer) for pointer in struct.unpack('<7I', remote.read(0xb201bd08, 28))]
        require(remote.read(0x20181020, 4) == bytes(4), 'Original callback did not acknowledge graphics completion')
        remote.select_thread(5)
        require(remote.read(0xe000ed28,8)==bytes(8),'Controller recorded a fault')
        if args.controller_expander:
            expander['capture_timer_registers'] = {
                hex(offset): int.from_bytes(remote.read(0x40000400 + offset, 4), 'little')
                for offset in (0, 12, 16, 24, 28, 32)}
            expander['native_capture_callback_verified'] = False
            vector_base = int.from_bytes(remote.read(0xe000ed08, 4), 'little')
            expander['interrupt_vector'] = hex(int.from_bytes(
                remote.read(vector_base + (16 + 29) * 4, 4), 'little'))
        (destination/'report.json').write_text(json.dumps(dict(format=1, passed=True, firmware_sha256=identities, controller_sha256=CONTROLLER_SHA256,
            original_commands=commands, original_completion_callback_verified=True,
            both_upload_channels_completed=True, completion_interrupt=129, callback_context=callback_context, engine_fault_registers=faults,
            original_acknowledgement_verified=True, observation_wall_seconds=args.seconds,
            instruction_time_shift=args.icount_shift,
            cores=cores, menu_table_pointers=tables,
            graphics=graphics,
            application_manager=applications,
            system_controller=system_observation(remote),
            idle_timer=idle_timer_observation(remote),
            sampling_service=sensor_observation(remote),
            capture_health=capture_health_observation(remote),
            temperature_checks=temperature_observation(remote),
            controller_expander=expander,
            controller_flash_data_sha256=hashlib.sha256(resident).hexdigest()
            if resident is not None else None,
            full_boot_verified=False, menu_verified=False),indent=2)+'\n')
        print('PASS native graphics initialization upload',flush=True)
    finally:
        if remote is not None:
            remote.sock.close()
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


if __name__ == '__main__':
    main()
