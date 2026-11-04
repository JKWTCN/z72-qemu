# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original image-interface packet selection and serial write boundaries."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_PC, UC_ARM_REG_LR)

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class SerialProbe(RegionProbe):
    PARAMETERS = 0x51000000

    def __init__(self,image):
        super().__init__(image)
        self.u.mem_map(self.PARAMETERS,0x200000)
        self.u.mem_write(0xb18a77a0,struct.pack('<I',self.PARAMETERS))
        self.u.mem_write(0xb18a7808,struct.pack('<2I',8,0x1234))
        self.mode = 'transport'
        self.chunks, self.selects, self.packets = [], [], []
        self.failure = None

    def boundary(self,u,address,size,unused):
        a,b = u.reg_read(UC_ARM_REG_R0),u.reg_read(UC_ARM_REG_R1)
        if self.mode == 'transport' and address == 0x10385d50:
            self.selects.append([a,b])
            result = 0
        elif self.mode == 'transport' and address == 0x10370a14:
            job = struct.unpack('<6I',u.mem_read(b,24))
            require(a == 8 and job[0] == 0xb2b375ca and job[1] == 0 and
                    job[2] == job[3] and 0 < job[2] <= 192 and job[4:] == (0,0),
                    'Original serial job layout differs')
            words = struct.unpack('<'+'H'*job[2],u.mem_read(job[0],job[2]*2))
            require(all(value <= 255 for value in words), 'Source bytes were not zero-extended to halfwords')
            self.chunks.append(bytes(words))
            result = int(len(self.chunks)-1 == self.failure)
        elif self.mode == 'list' and address == 0x10367fe0:
            self.chunks.append(bytes(u.mem_read(a,b)))
            result = 2 if len(self.chunks)-1 == self.failure else 0
        elif self.mode == 'selector' and address == 0x1030621e:
            lengths = []
            for index in range(64):
                value = int.from_bytes(u.mem_read(b+2*index,2),'little')
                if not value:
                    break
                lengths.append(value)
            else:
                raise ValueError('Synthetic serial length list is not bounded')
            require(sum(lengths) <= 4096,'Synthetic packet payload exceeds its fixture')
            self.packets.append(dict(pointer=a,length_pointer=b,lengths=lengths,
                payload=bytes(u.mem_read(a,sum(lengths)))))
            result = 0
        else:
            return super().boundary(u,address,size,unused)
        u.reg_write(UC_ARM_REG_R0,result)
        u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))


def check(image):
    native = SerialProbe(image)
    source,lengths = native.DATA,native.DATA+0x1000
    transport = []
    for size,failure in ((0,None),(1,None),(192,None),(193,None),(385,None),(385,1)):
        data = bytes(i & 255 for i in range(size))
        native.u.mem_write(source,b'\xa5'+data+b'\x5a')
        native.chunks,native.selects = [],[]
        native.failure = failure
        result = native.call(0x10367fe0-BASE,source+1,size)
        require(result == (2 if failure is not None else 0),'Serial transfer error folding differs')
        require(b''.join(native.chunks) == data and
                [len(row) for row in native.chunks] == [min(192,size-at) for at in range(0,size,192)],
                'Original byte chunking differs')
        require(native.selects == [[0x1234,0],[0x1234,1]],'Serial select lifetime differs')
        require(bytes(native.u.mem_read(source,size+2)) == b'\xa5'+data+b'\x5a','Writer modified the source')
        transport.append(dict(bytes=size,failed_chunk=failure,result=result,
            chunk_sizes=[len(row) for row in native.chunks],select_levels=[row[1] for row in native.selects]))
    native.mode = 'list'
    lists = []
    for values,failure in (([],None),([5,3],None),([5,3],0),([5,3],1)):
        data = bytes(range(sum(values)))
        native.u.mem_write(source,data or b'\0')
        native.u.mem_write(lengths,struct.pack('<'+'H'*(len(values)+1),*values,0))
        native.chunks = []
        native.failure = failure
        result = native.call(0x1030621e-BASE,source,lengths)
        expected_count = len(values) if failure is None else failure+1
        require(len(native.chunks) == expected_count and result == (0 if failure is None else 2),
                'Length-list termination or first-error propagation differs')
        require(b''.join(native.chunks) == data[:sum(values[:expected_count])],
                'Packet-list source advancement differs')
        lists.append(dict(lengths=values,failed_packet=failure,result=result,packets=expected_count))
    native.mode = 'selector'
    request = native.DATA+0x2000
    native.u.mem_write(request,bytes([5])+bytes(0x1ff))
    require(native.call(0x102fe126-BASE,0,request) == 3,'Original input class does not select table column 3')
    offsets = {0:(0xbf080,0xbf180),1:(0xbf280,0xbf2b0),2:(0xbfa10,0xc13b0),
        5:(0xc18e0,0xc19b0),6:(0xc1ae0,0xc1bb0),7:(0xc1cb0,0xc1cd0),
        8:(0xc1e00,0xc1ed0),9:(0xc1fd0,0xc1ff0),10:(0xc2100,0xc2150),
        11:(0xc2260,0xc22b0),12:(0xc23b0,0xc23d0),13:(0xc24d0,0xc24f0),
        14:(0xc25f0,0xc2610),15:(0xc2710,0xc2730),16:(0xc2830,0xc2870),
        17:(0xc2970,0xc2990),18:(0xc2a90,0xc2ad0)}
    selectors = []
    for selector in range(21):
        native.packets = []
        native.u.mem_write(0xb2b37590,bytes(0x280))
        result = native.call(0x102fe1ea-BASE,selector,request)
        require(result == (1 if selector >= 19 else 0),'Original selector result differs')
        require(len(native.packets) == int(selector < 19),'Original selector submission count differs')
        row = dict(selector=selector,result=result)
        if selector in offsets:
            packet = native.packets[0]
            require((packet['pointer']-native.PARAMETERS,packet['length_pointer']-native.PARAMETERS) == offsets[selector],
                    'Resource-backed serial program offsets differ')
            require(packet['lengths'] == [],'Zero resource fixture unexpectedly sends a program')
            row.update(program_offset=hex(offsets[selector][0]),length_table_offset=hex(offsets[selector][1]),
                lengths=[],origin='resource-80')
        elif selector in (3,4):
            packet = native.packets[0]
            expected = [5,5] if selector == 3 else [7,4,4,4,4,5,4,7]
            require(packet['lengths'] == expected,'Built-in packet lengths differ')
            row.update(origin='native-builder',lengths=expected,payload_sha256=hashlib.sha256(packet['payload']).hexdigest())
        selectors.append(row)
    # A nonempty explicit resource program is forwarded by the same original selector.
    program = b'\x81\x12\x34\x56'
    native.u.mem_write(native.PARAMETERS+offsets[5][0],program)
    native.u.mem_write(native.PARAMETERS+offsets[5][1],struct.pack('<2H',len(program),0))
    native.packets = []
    require(native.call(0x102fe1ea-BASE,5,request) == 0 and native.packets[0]['payload'] == program,
            'Explicit resource program was not forwarded')
    return dict(schema=1,result='passed-original-image-interface-serial-contract',master_sha256=MASTER_SHA,
        original=dict(selector='0x102fe1ea',input_class='0x102fe126',packet_list='0x1030621e',
            byte_writer='0x10367fe0',serial_job='0x10370a14'),
        transport=transport,packet_lists=lists,input_class=5,table_column=3,selectors=selectors,
        explicit_program_forwarded=True,
        limitations=['Synthetic serial transport, GPIO descriptor and completion results; no physical peer or bus timing.',
            'Resource data starts zero except for one explicit forwarding fixture; zero-length success is not sensor configuration.',
            'Only input class 5 and table column 3 are covered; electronic exposure and register meanings are not established.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args = parser.parse_args()
    report = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('PASS original serial chunks, select lifetime, packet errors and resource program selection')


if __name__ == '__main__':
    main()
