# SPDX-License-Identifier: GPL-2.0-or-later
"""Check bounded immediate-derived seed candidates against two original packages.

Requires NumPy and Capstone. Reads the Z6 II and Z7 II C 1.70 packages and
Z7 II master locally. Reports hashes, counts and matching model names only;
no firmware or candidate key bytes are written. This is a candidate search,
not a complete constructor analysis or an update acceptance test.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import numpy as np
import capstone
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_GRP_JUMP, CS_GRP_CALL
from capstone.arm import ARM_OP_IMM, ARM_OP_REG
from analyze.upgrade_signature import decode, key_stream, STREAM_TABLE, INDEX_TABLE
from analyze.decode_z72 import crc, require, validate_master


def run(args):
    master = args.master.read_bytes()
    validate_master(master)
    paths = [('z72', args.z72), ('z62', args.z62)]
    samples = {}
    images = []
    for model, path in paths:
        raw = path.read_bytes()
        expected = {'z72': 'fc0e94f57500a1f0e287c6b9a036c81a5ffceccb8432a377d645b3fa35a19b6a',
                    'z62': '5a9640b4c07abe1ecbf5a52655cbec6b893bba045bb2a1a1d21055b9f8f9d06d'}
        if hashlib.sha256(raw).hexdigest() != expected[model]:
            raise ValueError('Requires the original C 1.70 package for ' + model)
        body = raw[32:64] + decode(master, raw[64:], 32)
        require(body[:32] == b' ' * 32 and crc(body[:-14]) == 0,
                'Decoded package marker or CRC mismatch')
        n, header = struct.unpack_from('>2I', body, 32)
        require(n == 5 and header == 208, 'Unexpected package directory')
        members = {}
        for i in range(n):
            name, off, size, r1, r2 = struct.unpack_from('>16s4I', body, 48+i*32)
            name = name.rstrip(b'\0').decode('ascii')
            data = body[off:off+size]
            require(len(data) == size and crc(data) == 0 and r1 == r2 == 0,
                    'Member length, CRC or reserved field mismatch')
            members[name] = data
            if name.startswith('eg'):
                images.append((model, name, data))
        if model == 'z72':
            stream = key_stream(master)
        else:
            zmaster = next(v for k,v in members.items() if '_mas_' in k)
            t1 = zmaster[0x12078C96-0x10020000:0x12078D96-0x10020000]
            t2 = zmaster[0x12078D96-0x10020000:0x12078E96-0x10020000]
            require(t1 == master[STREAM_TABLE:STREAM_TABLE+256] and
                    t2 == master[INDEX_TABLE:INDEX_TABLE+256], 'Cross-model tables differ')
            stream = bytes((t1[72]+t2[20]*((i+1)*0x260+i*(i+1)//2)) & 255 for i in range(8))
        samples[model] = dict(hash=hashlib.sha1(body), digest=raw[:20], stream=stream,
                              sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))

    report = dict(format=1, firmware_included=False,
        scope='Bounded ARM/Thumb immediate-constructor candidates from original engine members',
        assumptions=dict(movw_movt_max_span_bytes=32, word_pair_max_span_bytes=128,
                         byte_orders=['little', 'big'], word_orders=['forward', 'reverse'],
                         conditional_arm_and_thumb16_immediates_included=False),
        samples={k:dict(bytes=v['bytes'], sha256=v['sha256']) for k,v in samples.items()},
        dependencies=dict(numpy=np.__version__, capstone=capstone.__version__),
        images=[], candidates_tested=0, matches=[])
    seen = set()

    def check(candidate):
        if candidate in seen:
            return
        seen.add(candidate)
        report['candidates_tested'] += 1
        # Try both raw boot bytes and the final appended digest bytes.
        for kind in ('B8', 'K8'):
            accepted = []
            for model, sample in samples.items():
                key = candidate
                if kind == 'B8':
                    key = bytes(x ^ y for x, y in zip(candidate, sample['stream']))
                h = sample['hash'].copy()
                h.update(key)
                if h.digest() == sample['digest']:
                    accepted.append(model)
            if accepted:
                report['matches'].append(dict(interpretation=kind, models=accepted,
                                              candidate_sha256=hashlib.sha256(candidate).hexdigest()))

    for model, name, data in images:
        start = time.monotonic()
        words = []
        counts = {}
        for mode, label, width in [(CS_MODE_THUMB, 'thumb', 2), (CS_MODE_ARM, 'arm', 4)]:
            md = Cs(CS_ARCH_ARM, mode)
            md.detail = True
            view = np.frombuffer(data[:len(data)//width*width],
                                 dtype='<u2' if width == 2 else '<u4')
            if width == 2:
                # Starts of MOVW and Thumb-2 modified-immediate MOV/MVN.
                mask = (((view & 0xfbf0) == 0xf240) |
                        ((view & 0xfbff) == 0xf04f) | ((view & 0xfbff) == 0xf06f))
            else:
                mask = (((view & 0x0ff00000) == 0x03000000) |
                        ((view & 0x0fe00000) == 0x03a00000) |
                        ((view & 0x0fe00000) == 0x03e00000))
            sites = np.flatnonzero(mask) * width
            found = 0
            for pos in sites.tolist():
                ins = next(md.disasm(data[pos:pos+4], pos, count=1), None)
                if not ins or ins.mnemonic.split('.')[0] not in ('movw', 'mov', 'movs', 'mvn', 'mvns'):
                    continue
                ops = ins.operands
                if len(ops) != 2 or ops[0].type != ARM_OP_REG or ops[1].type != ARM_OP_IMM:
                    continue
                value = ops[1].imm & 0xffffffff
                if ins.mnemonic.startswith('mvn'):
                    value = ~value & 0xffffffff
                if ins.mnemonic == 'movw':
                    reg = ops[0].reg
                    for nxt in md.disasm(data[pos+ins.size:pos+36], pos+ins.size):
                        if nxt.address - pos > 32:
                            break
                        if nxt.mnemonic == 'movt' and nxt.operands[0].reg == reg:
                            value |= (nxt.operands[1].imm & 0xffff) << 16
                            break
                        if nxt.group(CS_GRP_JUMP) or nxt.group(CS_GRP_CALL):
                            break
                        _, written = nxt.regs_access()
                        if reg in written:
                            break
                words.append((pos, label, value))
                found += 1
            counts[label] = dict(prefilter_sites=len(sites), immediate_values=found)
        words.sort()
        before = report['candidates_tested']
        for i, (pos, label, value) in enumerate(words):
            for j in range(i+1, len(words)):
                p2, l2, v2 = words[j]
                if p2 - pos > 128:
                    break
                if l2 != label or p2 == pos:
                    continue
                for order in ('<', '>'):
                    check(struct.pack(order+'II', value, v2))
                    check(struct.pack(order+'II', v2, value))
        entry=dict(model=model,member=name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
                   scans=counts,new_candidates=report['candidates_tested']-before,
                   boot_prefix_immediate_counts={hex(v): sum(w == v for _, _, w in words)
                       for v in sorted({w for _, _, w in words if 0x10000000 <= w <= 0x10000100})},
                   elapsed_seconds=round(time.monotonic()-start,2))
        report['images'].append(entry)
    report['header_digest_match_found'] = bool(report['matches'])
    report['limitations'] = [
        'Instruction-shaped bytes may be data; a match would require code-path validation.',
        'Only nearby immediate-derived word pairs are covered, not general arithmetic or byte-store constructors.',
        'No boot-window initializer or cross-model shared B8 is established by a negative result.',
        'No camera update acceptance, native programming or persistence is executed.']
    args.report.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(candidates_tested=report['candidates_tested'], matches=report['matches'])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--z72', type=Path, required=True)
    parser.add_argument('--z62', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    run(parser.parse_args())


if __name__ == '__main__':
    main()
