# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the USB log channel through the capture buffer and upload window.

Requires Unicorn and a locally supplied original master image. Command
registration, queue admission, consumer dispatch, token splitting, memory
dumping, the log-output gate, the print routing decision, the capture
formatter, the RAM appender and the verified upload copy all execute original
code on the startup-restored fixture. The transport buffer/reply, bulk copy,
print sink for synchronous commands, numeric conversion, console-handler
registration service, queued-line name/argument split, kernel service layer,
cache maintenance, platform time service, module environment initialization
and the upload-window limit are host boundaries. No USB device is opened and
no firmware or key bytes are exported.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require, validate_master
from analyze.firmware_structure import scatter_records
from analyze.usb_descriptors import usb_personalities
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                     UC_HOOK_MEM_READ, UC_HOOK_INTR)
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_R0,
                               UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)

COMMAND_COUNT = 17
COMMAND_NAMES = ('echo', 'help', 'watchdog', 'stackdump', 'memdump',
                 'logoutputchg', 'loglevelallchg', 'loglevelchg', 'pt', 'tt',
                 'smt', 'et', 'qt', 'act', 'mt', 'kernelsysmem', 'interrupt')

MODULE_BASE = 0xB2BB0000        # startup-copied RAM appender module
MODULE_SOURCE = 0x2428D80       # its file offset
UPLOAD_WINDOW = 0x12960000      # drain destination window (3 x 128 KiB)


def module_offset(offset):
    """Map a module file offset to its RAM address."""
    return MODULE_BASE + offset - MODULE_SOURCE


class Probe:
    STOP = 0x50020000
    INPUT = 0x50000000
    SAMPLE = INPUT + 0x2000
    QUEUE = 0xB1800038
    LINE_BUFFER = 0xB18AFFD0
    OUTPUT_SELECT = 0xB1800474
    LOG_GATE = 0xB180048C
    CAPTURE_FLAG = 0xB1800060
    CAPTURE_COUNT = 0xB18004F0
    CAPTURE_BUFFER = 0xB1C81898
    WINDOW_LIMIT = 0xB1CF16E0
    TRANSPORT_SLOT = 0xB188B7C8

    def __init__(self, image):
        validate_master(image)
        self.image = image
        self.u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        self.u.mem_map(BASE, (len(image) + 4095) & ~4095)
        self.u.mem_map(0xB1800000, 0x4800000)
        self.u.mem_map(self.INPUT, 0x30000)
        # Upload window, passive console/timer registers and the low scratch
        # region below the mapped image, all passive fixtures.
        self.u.mem_map(UPLOAD_WINDOW, 0x60000)
        self.u.mem_map(0x2C090000, 0x1000)
        self.u.mem_map(0x10000000, 0x20000)
        self.u.mem_map(0x04264000, 0x1000)
        self.u.mem_write(BASE, image)
        self.u.mem_write(0x2C090003, b'\x02')  # console transmit-ready line
        self.records = scatter_records(image)
        for record in self.records:
            if record['kind'] == 'copy':
                start = record['source'] - BASE
                self.u.mem_write(record['destination'],
                                 image[start:start + record['size']])
        self.regs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
        self.responses, self.prints, self.reads = [], [], []
        self.publications, self.service_calls = [], []
        self.supervisor_calls = 0
        self.hooks = {BASE + 0x61C384: self.input_buffer,
                      BASE + 0x61C4FC: self.reply,
                      BASE + 0x340FAC: self.copy,
                      BASE + 0x3BA804: self.print_sink,
                      BASE + 0x3BC46A: self.publish,
                      BASE + 0x222588: self.strtol,
                      # Host boundaries for the upload leg.
                      BASE + 0x348150: self.cache_maintenance,
                      module_offset(0x2429968): self.service_stub,
                      module_offset(0x2429970): self.service_stub,
                      module_offset(0x2429978): self.service_object,
                      module_offset(0x2429998): self.service_lock,
                      module_offset(0x2429240): self.service_submit,
                      module_offset(0x2429412): self.platform_time,
                      module_offset(0x242942C): self.platform_time,
                      module_offset(0x2428ED8): self.environment_init}
        self.reseed = {module_offset(0x2429260): self.WINDOW_LIMIT}
        self.u.hook_add(UC_HOOK_CODE, self.code)
        self.u.hook_add(UC_HOOK_INTR, self.supervisor)
        self.u.hook_add(UC_HOOK_MEM_READ, self.memory_read,
                        begin=self.SAMPLE, end=self.SAMPLE + 0x3FF)

    def word(self, address):
        return struct.unpack('<I', self.u.mem_read(address, 4))[0]

    def put_word(self, address, value):
        self.u.mem_write(address, struct.pack('<I', value))

    def string(self, address):
        result = bytearray()
        for i in range(512):
            value = self.u.mem_read(address + i, 1)[0]
            if not value:
                return result.decode('ascii')
            result.append(value)
        raise ValueError('Unterminated diagnostic string')

    def code(self, u, address, size, unused):
        if address == self.STOP:
            u.emu_stop()
        elif address in self.reseed:
            # Observation point: restore a runtime-seeded limit, then run.
            self.put_word(self.reseed[address], 0x4000000)
        elif address in self.hooks:
            args = [u.reg_read(r) for r in self.regs]
            result = self.hooks[address](*args)
            u.reg_write(UC_ARM_REG_R0, result)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))

    def supervisor(self, u, intno, unused):
        """Host boundary: supervisor calls report success."""
        self.supervisor_calls += 1
        u.reg_write(UC_ARM_REG_R0, 0)

    def memory_read(self, u, access, address, size, value, unused):
        self.reads.extend(range(address, address + size))

    def input_buffer(self, *args):
        return self.INPUT

    def reply(self, packet, response, *args):
        self.responses.append(response)
        return 0

    def copy(self, destination, source, count, unused):
        require(count <= 0x1000, 'Unexpected bulk copy')
        self.u.mem_write(destination, bytes(self.u.mem_read(source, count)))
        return destination

    def print_sink(self, text, *args):
        self.prints.append(self.string(text))
        return 0

    def publish(self, control, handler, descriptor, *args):
        """Host boundary: the console-handler registration service."""
        self.publications.append(dict(control=hex(control), handler=hex(handler)))
        return 0

    def strtol(self, pointer, end_pointer, base, *args):
        """Host boundary: numeric conversion for split command tokens."""
        token = bytearray()
        for i in range(32):
            value = self.u.mem_read(pointer + i, 1)[0]
            if not value or value == 0x20:
                break
            token.append(value)
        return int(token.decode('ascii'), base if base else 10)

    def cache_maintenance(self, *args):
        return 0

    def service_stub(self, *args):
        self.service_calls.append('stub')
        return 0

    def service_object(self, *args):
        self.service_calls.append('object')
        return self.INPUT + 0x4000

    def service_lock(self, obj, mode, *args):
        self.service_calls.append('lock-%d' % mode)
        return 0

    def service_submit(self, code, count, *args):
        self.service_calls.append('submit-%#x-%d' % (code, count))
        return 0

    def platform_time(self, *args):
        self.service_calls.append('time')
        self.put_word(0xB1806F5C, self.INPUT + 0x4000)
        return self.INPUT + 0x4000

    def environment_init(self, *args):
        """Host boundary: module environment lazy initialization."""
        self.service_calls.append('environment-init')
        return 0

    def call(self, offset, *args, limit=12000000):
        for reg, value in zip(self.regs, (*args, 0, 0, 0, 0)):
            self.u.reg_write(reg, value)
        self.u.reg_write(UC_ARM_REG_SP, self.INPUT + 0x18000)
        self.u.reg_write(UC_ARM_REG_LR, self.STOP | 1)
        self.u.emu_start(BASE + offset | 1, self.STOP, count=limit)
        require(self.u.reg_read(UC_ARM_REG_PC) == self.STOP,
                'Native function did not return: ' + hex(offset))
        return self.u.reg_read(UC_ARM_REG_R0)

    def call_absolute(self, address, *args, limit=12000000):
        for reg, value in zip(self.regs, (*args, 0, 0, 0, 0)):
            self.u.reg_write(reg, value)
        self.u.reg_write(UC_ARM_REG_SP, self.INPUT + 0x18000)
        self.u.reg_write(UC_ARM_REG_LR, self.STOP | 1)
        self.u.emu_start(address | 1, self.STOP, count=limit)
        require(self.u.reg_read(UC_ARM_REG_PC) == self.STOP,
                'Native function did not return: ' + hex(address))
        return self.u.reg_read(UC_ARM_REG_R0)

    def enqueue(self, text):
        """Admit one line through the original queue entry point."""
        self.u.mem_write(self.INPUT, text.encode('ascii') + b'\0')
        self.u.mem_write(self.LINE_BUFFER, b'\0' * 0x80)
        self.put_word(self.QUEUE + 0x18, 0)
        self.call(0x39C620, self.INPUT, len(text))
        length = self.word(self.QUEUE + 0x18)
        return length, bytes(self.u.mem_read(self.LINE_BUFFER, max(length, 1)))

    def consume(self, command):
        """Dispatch one command through the original consumer entry.

        The host adapter terminates the command word at its first space and
        passes the remainder as the argument text, matching the consumer's
        separate name/argument entry contract. The adapter is a host
        boundary; the code that performs this split on the camera was not
        located in the mapped image.
        """
        cut = command.find(' ')
        name, rest = (command[:cut], command[cut + 1:]) if cut >= 0 else (command, '')
        blob = name + '\0' + rest
        self.u.mem_write(self.LINE_BUFFER,
                         blob.encode('ascii') + b'\0' * (80 - len(blob)))
        self.prints.clear()
        self.call(0x39C5F6, self.LINE_BUFFER, self.LINE_BUFFER + len(name) + 1, 0, 8)
        return list(self.prints), self.word(self.QUEUE + 8)

    def run(self):
        # 1. Replay the stock debug command registration on the fixture.
        self.call(0x39CBCC, 0)
        count = self.word(self.QUEUE + 0xC)
        require(count == COMMAND_COUNT, 'Expected seventeen commands: ' + str(count))
        require(len(self.publications) == 1 and
                self.publications[0]['handler'] == '0x103bc65d' and
                self.publications[0]['control'] == '0xb18aff30',
                'Console handler publication mismatch')
        records = []
        for index in range(count):
            words = struct.unpack('<9I',
                                  self.u.mem_read(0xB18B0050 + index * 36, 36))
            records.append(dict(name=self.string(0xB18B0050 + index * 36 + 4),
                                callback=hex(words[6]), argument_hint=words[7],
                                raw_form=bool(words[8])))
        require(tuple(r['name'] for r in records) == COMMAND_NAMES,
                'Unexpected command order')

        # 2. The consumer executes a queued memory dump through original code.
        self.u.mem_write(self.SAMPLE, bytes(range(256)) * 4)
        self.u.mem_write(self.OUTPUT_SELECT, b'\x01')
        command = 'memdump 0x%08x 8' % self.SAMPLE
        length, line = self.enqueue(command)
        require(length == len(command) + 1 and
                line == command.encode('ascii') + b'\n',
                'Queue admission mismatch')
        cut = command.find(' ')
        self.u.mem_write(self.LINE_BUFFER + cut, b'\0')
        self.prints.clear()
        self.reads.clear()
        self.call(0x39C5F6, self.LINE_BUFFER, self.LINE_BUFFER + cut + 1, 0, 8)
        require(self.word(self.QUEUE + 8) == 0, 'Consumer must clear the busy flag')
        addresses = sorted(set(self.reads))
        require(addresses == list(range(self.SAMPLE, self.SAMPLE + 16)),
                'Consumer memory dump read extent mismatch')
        require(len(self.prints) == 2 and '%02x' in self.prints[1],
                'Consumer dump print mismatch')
        require(self.word(self.QUEUE + 0x18) == length,
                'Consumer leaves the length field in place')

        # 2b. Without the name/argument split the whole line misses lookup.
        self.enqueue(command)
        self.u.mem_write(self.LINE_BUFFER + length - 1, b'\0')
        self.prints.clear()
        self.call(0x39C5F6, self.LINE_BUFFER, self.LINE_BUFFER + length, 0, 8)
        require(not self.prints and self.word(self.QUEUE + 8) == 0,
                'A whole-line name must not match a command')

        # 3. Raw-form help enumerates every registered command.
        prints, busy = self.consume('help')
        require(busy == 0 and len(prints) == 2 + COMMAND_COUNT and
                prints[1] == 'command list:' and
                all(text == ' %s' for text in prints[2:]),
                'Help must print two banners and one line per command')

        # 4. logoutputchg selects the USB log channel and arms the debug gate.
        log_cases = []
        for command, select, gate in (('logoutputchg 2', 1, 1),
                                      ('logoutputchg 1', 0, 0),
                                      ('logoutputchg 3', 0, 0),
                                      ('logoutputchg', 0, 0)):
            prints, busy = self.consume(command)
            require(busy == 0 and prints, 'logoutputchg produced no output')
            require(self.u.mem_read(self.OUTPUT_SELECT, 1)[0] == select and
                    self.u.mem_read(self.LOG_GATE, 1)[0] == gate,
                    'Log output selection mismatch: ' + command)
            log_cases.append(dict(command=command, output_select=select,
                                  log_gate=gate, reply=prints[0]))

        # 5. PTP diagnostic admission follows the selected log output.
        gate_cases = []
        for enabled in (0, 1):
            self.u.mem_write(self.OUTPUT_SELECT, bytes([enabled]))
            self.put_word(self.QUEUE + 8, 0)
            self.put_word(self.QUEUE + 0x18, 0)
            self.u.mem_write(self.LINE_BUFFER, b'\0' * 0x80)
            text = 'debug memdump 0x%08x 8' % self.SAMPLE
            self.u.mem_write(self.INPUT, text.encode('ascii') + b'\0')
            self.responses.clear()
            require(self.call(0x42418A, 0, self.INPUT) == 1,
                    'Diagnostic executor failed')
            admitted = self.word(self.QUEUE + 0x18)
            expected = len(text) - len('debug ') + 1 if enabled else 0
            require(self.responses == [0x2001] and admitted == expected,
                    'PTP debug admission must follow the log output gate')
            gate_cases.append(dict(output_selected=enabled, queued_length=admitted,
                                   response='0x2001'))

        # 6. Transport ring constants; the object slot itself is empty at boot.
        slot = self.word(self.TRANSPORT_SLOT)
        constants = dict(ring_size=self.call(0x61C392), ring_mask=self.call(0x61C398),
                         packet_limit=self.call(0x61C3A8))
        require(constants == dict(ring_size=0x200000, ring_mask=0x1FFFF8,
                                  packet_limit=0x200),
                'Transport ring constant mismatch')

        # 7. Capture route: replicate the fatal entry's capture-flag store,
        # then run the real print router, formatter and RAM appender.
        self.u.mem_write(self.OUTPUT_SELECT, b'\x01')
        self.put_word(self.CAPTURE_FLAG, 1)
        self.put_word(self.CAPTURE_COUNT, 0)
        del self.hooks[BASE + 0x3BA804]  # the original routing must run
        lines = []
        for index in range(3):
            line = 'capture-line-%d' % index
            self.u.mem_write(self.INPUT, line.encode('ascii') + b'\0')
            self.call(0x3BA804, self.INPUT, index)
            lines.append(line)
        expected_capture = b''.join(
            (line + '\n').encode('ascii') for line in lines)
        captured = self.word(self.CAPTURE_COUNT)
        require(captured == len(expected_capture) and bytes(
            self.u.mem_read(self.CAPTURE_BUFFER, captured)) == expected_capture,
            'Capture route must land formatted text in the capture buffer')
        self.hooks[BASE + 0x3BA804] = self.print_sink

        # 8. Drain: upload the capture buffer into the service window.
        self.service_calls.clear()
        self.call_absolute(MODULE_BASE + 0x52, 0)
        require('submit-0x14b-3' in self.service_calls,
                'Drain must submit its upload request')
        require(self.word(self.CAPTURE_COUNT) == captured + 1,
                'Drain advances the capture count by one')
        window = bytes(self.u.mem_read(UPLOAD_WINDOW, len(expected_capture)))
        require(window == expected_capture,
                'Verified upload copy must place the capture in the window')

        return dict(format=1, master_sha256=MASTER_SHA,
                    registered_commands=records,
                    console_publication=self.publications[0],
                    consumer=dict(execution_entry='0x103bc5f6',
                                  dispatch_entry='0x103bc5a2',
                                  tokenizer_entry='0x103bcc8e',
                                  name_argument_split='host boundary',
                                  memory_dump=dict(
                                      command='memdump <address> <size>',
                                      requested_size=8, row_bytes=16,
                                      synthetic_bytes_read=16, print_calls=2,
                                      busy_cleared=True, length_field_retained=True),
                                  whole_line_lookup_miss=True,
                                  help_print_calls=2 + COMMAND_COUNT),
                    log_output_gate=dict(selector='0x103da664',
                                         output_select_address=hex(self.OUTPUT_SELECT),
                                         log_gate_address=hex(self.LOG_GATE),
                                         cases=log_cases,
                                         gate_shared_with_ptp_debug_admission=True),
                    ptp_debug_admission=gate_cases,
                    capture_route=dict(
                        flag_address=hex(self.CAPTURE_FLAG),
                        flag_set_by='fatal entry 0x10202688 store, replicated by host',
                        print_entry='0x103da804', formatter='0x1020265a',
                        trampoline='0x1032b76c', appender='0xb2bb0000',
                        buffer=hex(self.CAPTURE_BUFFER),
                        count_address=hex(self.CAPTURE_COUNT),
                        formatted_lines=len(lines),
                        captured_bytes=captured),
                    upload=dict(drain_entry='0xb2bb0053',
                                trigger='0x10202b14', trigger_flag='0xb1800064',
                                window=hex(UPLOAD_WINDOW), chunk_bytes=0x20000,
                                chunks=3,
                                services=self.service_calls,
                                supervisor_calls=self.supervisor_calls,
                                window_bytes_verified=len(expected_capture)),
                    transport=dict(object_slot=hex(self.TRANSPORT_SLOT),
                                   boot_slot_value=hex(slot),
                                   ring_constants=constants,
                                   object_runtime_initialized=False),
                    usb_descriptors=usb_personalities(self.image, self.records),
                    host_boundaries=['transport input buffer', 'transport response',
                                     'bulk copy', 'print sink', 'numeric conversion',
                                     'console-handler registration service',
                                     'queued-line name/argument split',
                                     'kernel service layer', 'cache maintenance',
                                     'platform time service',
                                     'module environment initialization',
                                     'upload-window limit seed',
                                     'supervisor-call success returns',
                                     'passive console/timer register pages'],
                    camera_usb_access_verified=False, real_boot_material_recovered=False,
                    k8_recovered=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = Probe(args.master.read_bytes()).run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n',
                           encoding='utf-8', newline='\n')
    print('PASS 17 debug commands, consumer dispatch, USB log-output gate, '
          'PTP admission link, capture route, verified upload, transport '
          'constants, descriptor personalities')
