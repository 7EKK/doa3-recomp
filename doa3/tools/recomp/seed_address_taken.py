"""Seed functions that are only ever address-taken."""
import bisect
import json
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM

from . import config

DATA_SECTIONS = ('.rdata', '.data', '$$XTIMAGE', 'DOLBY')


def main():
    xbe = open(sys.argv[1], 'rb').read()
    path = os.path.join(config.DISASM_OUTPUT_DIR, 'functions.json')
    funcs = json.load(open(path))
    starts = {int(f['start'], 16) for f in funcs}

    code = [(n, va, size, raw) for n, va, size, raw in config.SECTIONS if n not in DATA_SECTIONS]
    data = [(n, va, size, raw) for n, va, size, raw in config.SECTIONS if n in DATA_SECTIONS]

    def in_code(v):
        return any(va <= v < va + size for _n, va, size, _r in code)

    def byte(v, k=1):
        off = config.va_to_file_offset(v)
        return xbe[off:off + k] if off is not None else b''

    taken = {}
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    cs.skipdata = True
    for name, va, size, raw in code:
        for ins in cs.disasm(xbe[raw:raw + size], va):
            if ins.id == 0 or ins.mnemonic not in ('push', 'mov', 'lea'):
                continue
            for op in ins.operands:
                if op.type == CS_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                    if in_code(v):
                        taken.setdefault(v, f'{ins.mnemonic} at 0x{ins.address:08X}')
    vtable_slots = set()
    for name, va, size, raw in data:
        blob = xbe[raw:raw + size]
        run = []
        for o in range(0, len(blob) - 3, 4):
            v = struct.unpack_from('<I', blob, o)[0]
            if in_code(v):
                taken.setdefault(v, f'pointer at 0x{va + o:08X}')
                run.append(v)
            else:
                # A run of code pointers with known functions in it is a
                # vtable or callback table;
                if len(run) >= 3 and sum(p in starts for p in run) >= 2:
                    vtable_slots.update(run)
                run = []

    # Where detected functions end: the address after their last instruction.
    ends = {int(f['end'], 16) for f in funcs if f.get('detection_method') != 'link_seed'}

    def ends_in_return(v):
        for k in (1, 3):                    # ret, ret imm16
            ins = next(cs.disasm(byte(v - k, k), v - k), None)
            if ins and ins.size == k and ins.mnemonic == 'ret':
                return True
        return False

    def after_terminator(v):
        if byte(v - 1) in (b'\xcc', b'\x90'):
            return True
        for k in (1, 3, 2, 5):              # ret, ret imm16, jmp short, jmp rel32
            ins = next(cs.disasm(byte(v - k, k), v - k), None)
            if ins and ins.size == k and ins.mnemonic in ('ret', 'jmp'):
                return True
        return False

    section_starts = {va for _n, va, _size, _r in code}

    def starts_function(v, why):
        prev = byte(v - 1)
        if v in section_starts:
            # The first byte of a code section (PSGSFD_I 0x0020FA60:
            return True
        if why.startswith('pointer') and v in vtable_slots:
            return after_terminator(v)
        if why.startswith('pointer'):
            # Any dword in data can look like a code address:
            return (v % 16 == 0 and prev in (b'\xcc', b'\x90')) or \
                   (v in ends and ends_in_return(v))
        if prev in (b'\xcc', b'\x90'):
            return True
        for k in (1, 3, 2, 5):              # ret, ret imm16, jmp short, jmp rel32
            ins = next(cs.disasm(byte(v - k, k), v - k), None)
            if ins and ins.size == k and ins.mnemonic in ('ret', 'jmp'):
                return True
        return False

    bps = sorted({int(f['start'], 16) for f in funcs} | {int(f['end'], 16) for f in funcs})
    added = []
    for v, why in sorted(taken.items()):
        if v in starts or not starts_function(v, why):
            continue
        i = bisect.bisect_right(bps, v)
        end = bps[i] if i < len(bps) else v + 16
        sec = next(n for n, va, size, _r in code if va <= v < va + size)
        funcs.append({
            'start': f'0x{v:08X}', 'end': f'0x{end:08X}', 'size': end - v,
            'name': f'sub_{v:08X}', 'section': sec, 'confidence': 0.5,
            'detection_method': 'addr_seed', 'num_instructions': 0,
            'has_prologue': False, 'calls_to': [], 'called_by': [],
        })
        added.append((v, why))
    funcs.sort(key=lambda f: int(f['start'], 16))
    json.dump(funcs, open(path, 'w'), indent=1)
    for v, why in added[:12]:
        print(f'  0x{v:08X}  ({why})')
    print(f'address-taken candidates={len(taken)} added={len(added)} total_now={len(funcs)}')


if __name__ == '__main__':
    main()
