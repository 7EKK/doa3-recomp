"""
Function-level x86 → C translator.

For each function:
1. Read raw bytes from XBE
2. Disassemble with Capstone
3. Build basic blocks
4. Lift each block to C statements
5. Generate a complete C function

Produces compilable C code using recomp_types.h macros.
"""

import glob
import json
import os
import re

from .config import (va_to_file_offset, is_code_address, TEXT_VA_START, TEXT_VA_END,
                     FALLTHROUGH_RANGES, FALLTHROUGH_KEEP_XDK, BUG14_LATCH_FUNCS, CLOBBERED_FLAGS_UNFIXED, DEFERRED_CMP_UNFIXED, ENTRY_FLAGS_UNFIXED, SHARED_JCC_UNFIXED,
                     SHARED_JCC_ARITH_UNFIXED,
                     FALLTHROUGH_EXTRA, FALLTHROUGH_SKIP, FALLTHROUGH_SYNC, FALLTHROUGH_RET,
                     CARRIER_HOLD_FUNCS, CARRIER_INHERIT_FUNCS, CARRIER_SPLIT_PROLOGUE,
                     CARRIER_SPLIT_EPILOGUE,
                     LEGACY_NO_JT_EXTEND_FUNCS, BODY_SUFFIX, IF0_BODIES, NOT_EMITTED,
                     DISPATCH_SEARCH_LIMIT, DISPATCH_EXCLUDE, CRT_INIT_FUNCS)
from .disasm import Disassembler
from .lifter import Lifter, lift_basic_block


def _fixup_icall_esp_save(lines):
    """
    Post-process generated C lines to insert _icall_esp save points.

    When RECOMP_ICALL_SAFE is used, we need to save g_esp BEFORE any
    args are pushed so the macro can restore it on lookup failure.

    Scans backwards from each RECOMP_ICALL_SAFE line to find consecutive
    PUSH32 lines (the arg pushes), then inserts a save before the first.
    """
    import re
    result = []
    # Find indices of all ICALL_SAFE lines
    icall_indices = []
    for i, line in enumerate(lines):
        if 'RECOMP_ICALL_SAFE(' in line:
            icall_indices.append(i)

    if not icall_indices:
        return lines  # nothing to do

    # For each ICALL, determine where to insert the save
    insert_before = set()  # map: line_index → True (insert save before this line)
    for icall_idx in icall_indices:
        # The ICALL line itself contains "PUSH32(esp, 0); RECOMP_ICALL_SAFE(...)"
        # Look backwards for consecutive lines containing PUSH32(esp,
        first_push_idx = icall_idx
        j = icall_idx - 1
        while j >= 0:
            stripped = lines[j].strip()
            # Skip blank lines
            if not stripped:
                j -= 1
                continue
            # Check if this is a PUSH32 line (arg push)
            if stripped.startswith('PUSH32(esp,'):
                first_push_idx = j
                j -= 1
                continue
            # Check if this is a non-push instruction that could be part of
            # arg evaluation (e.g., "eax = MEM32(...);") - these are interleaved
            # with pushes in the x86 code. We need to look past them.
            # Stop at labels, gotos, other control flow, or other ICALL lines.
            if (re.match(r'^loc_[0-9A-Fa-f]+:', stripped) or
                'goto ' in stripped or
                'RECOMP_ICALL' in stripped or
                'return;' in stripped or
                stripped.startswith('if (') or
                stripped.startswith('POP32(') or
                stripped.startswith('PUSH32(esp, 0); sub_')):
                break
            # It's an interleaved computation - skip past it
            j -= 1
            continue

        insert_before.add(first_push_idx)

    # Build result with saves inserted
    for i, line in enumerate(lines):
        if i in insert_before:
            # Determine indentation from the current line
            indent = line[:len(line) - len(line.lstrip())]
            result.append(f"{indent}{{ uint32_t _icall_esp = g_esp;")
        result.append(line)
        if 'RECOMP_ICALL_SAFE(' in line:
            indent = line[:len(line) - len(line.lstrip())]
            result.append(f"{indent}}}")

    return result


# ── Post-lift fixes ─────────────────────────────────────────────────────
# These used to be scripts run over the generated tree after every
# regeneration (tools/recomp/fix_*.py). They work on a function's emitted
# lines, with the same rules, so a regeneration reproduces the tree.

def _orig_end(lines):
    for l in lines:
        m = re.search(r'Original: 0x([0-9A-Fa-f]+) - 0x([0-9A-Fa-f]+)', l)
        if m:
            return int(m.group(2), 16)
    return None


def fix_carrier(lines, start):
    """ebp is callee-saved, but between generated functions it travels in the
    global g_seh_ebp, which a callee may leave pointing at its own frame. In
    the listed functions, keep the caller's frame: across every call (HOLD),
    from entry to the hand-off (INHERIT), on a split prologue's push and a
    split epilogue's ret."""
    if start not in (CARRIER_HOLD_FUNCS | CARRIER_INHERIT_FUNCS
                     | CARRIER_SPLIT_PROLOGUE | CARRIER_SPLIT_EPILOGUE):
        return lines
    text = "\n".join(lines).split("\n")
    body = text.index("{")
    if start in CARRIER_HOLD_FUNCS:
        out = text[:body + 1]
        for l in text[body + 1:]:
            if re.search(r'PUSH32\(esp, 0\); (sub_\w+\(\);|RECOMP_ICALL_SAFE\()', l):
                ind = l[:len(l) - len(l.lstrip())]
                out += [f"{ind}{{ uint32_t _seh_hold = g_seh_ebp; /* DOA3: ebp survives the call */",
                        l, f"{ind}g_seh_ebp = _seh_hold; }}"]
            else:
                out.append(l)
        text = out
    if start in CARRIER_INHERIT_FUNCS:
        if not any(l.strip().startswith("uint32_t ebp") for l in text[body:]):
            text.insert(body + 1, "    uint32_t ebp;")
            label = next(k for k in range(body, len(text)) if re.match(r'^loc_\w+: ;', text[k]))
            text.insert(label, "    ebp = g_seh_ebp; /* DOA3: carry the caller's frame to the hand-off */")
    if start in CARRIER_SPLIT_PROLOGUE:
        k = next(k for k in range(body, len(text)) if text[k].strip() == "PUSH32(esp, ebp);")
        text.insert(k, "    ebp = g_seh_ebp; /* DOA3: push saves the caller's frame */")
    if start in CARRIER_SPLIT_EPILOGUE:
        out = []
        for l in text:
            if re.match(r'^\s*esp \+= \d+; return;', l):
                out.append("    g_seh_ebp = ebp; /* DOA3: hand back the frame popped above */")
            out.append(l)
        text = out
    return text


def fix_fallthrough(lines, start, end, func_db):
    """A body whose last statement does not end it runs on into the function
    at its end (the detector split the code there): emit that as a tail
    call. Game .text and D3DX, plus the XDK sites known to need it."""
    if start in FALLTHROUGH_SKIP:
        return lines
    if start in FALLTHROUGH_RET:
        close = max(k for k, l in enumerate(lines) if l == "}")
        return (lines[:close]
                + [f"    esp += {FALLTHROUGH_RET[start]}; return; /* DOA3: fall-through into a lone ret */"]
                + lines[close:])
    if start in FALLTHROUGH_EXTRA:
        tgt, sync = FALLTHROUGH_EXTRA[start]
        close = max(k for k, l in enumerate(lines) if l == "}")
        return (lines[:close]
                + [f"    {'g_seh_ebp = ebp; ' if sync else ''}sub_{tgt:08X}(); return; "
                   f"/* DOA3: restored dropped fall-through to sub_{tgt:08X} */"]
                + lines[close:])
    if not (any(lo <= start < hi for lo, hi in FALLTHROUGH_RANGES)
            or start in FALLTHROUGH_KEEP_XDK):
        return lines
    end = _orig_end(lines) or end
    if end not in func_db:
        return lines
    close = max(k for k, l in enumerate(lines) if l == "}")
    has_ebp = any("uint32_t ebp;" in l for l in lines[:close])
    last = ""
    for b in reversed(lines[:close]):
        s = b.strip()
        if (not s or s.startswith("/*") or s.startswith("*") or s.endswith(": ;")
                or s in ("{", "};") or s.startswith("#") or s.startswith("loc_")
                or s.startswith("uint") or s.startswith("int ")):
            continue
        last = s
        break
    term = (("return" in last and not last.startswith("if ")) or
            last.startswith("goto ") or "__debugbreak" in last or last.endswith("break;"))
    if last and term:
        return lines
    tgt = f"sub_{end:08X}"
    sync = "g_seh_ebp = ebp; " if FALLTHROUGH_SYNC.get(start, has_ebp) else ""
    return (lines[:close]
            + [f"    {sync}{tgt}(); return; /* DOA3: restored dropped fall-through to {tgt} */"]
            + lines[close:])


_CT_CALL = re.compile(r'\) \{ (sub_[0-9A-Fa-f]{8}(?:_gen)?\(\); return; \})')


def fix_cond_tailcall_ebp(lines):
    """Conditional tail calls sync g_seh_ebp, as unconditional ones do, in
    functions that keep a local ebp (fpo callees inherit the frame)."""
    if not any(re.match(r'^\s+uint32_t ebp(?: = [^;]+)?;', l) for l in lines):
        return lines
    out = []
    for l in lines:
        if ") { sub_" in l and "(); return; }" in l and "g_seh_ebp" not in l:
            l = _CT_CALL.sub(r") { g_seh_ebp = ebp; \1", l)
        out.append(l)
    return out


def fix_selfspins(lines):
    """XDK busy-waits on hardware registers (`loc_X: if (MEM..) goto loc_X;`):
    nothing behind most of those registers changes, so run them through."""
    out = list(lines)
    for i in range(len(out) - 2):
        m = re.match(r'loc_([0-9A-Fa-f]{8}): ;', out[i].strip())
        if not m:
            continue
        lab = m.group(1)
        for j in (i + 1, i + 2):
            if j >= len(out):
                break
            s = out[j].strip()
            if not s:
                continue
            m2 = re.match(r'if \((.+)\) goto loc_' + lab + r'; (/\*.*\*/)?', s)
            if m2 and "MEM" in m2.group(1):
                indent = out[j][:len(out[j]) - len(out[j].lstrip())]
                out[j] = (indent + "/* DOA3: hw busy-wait forced through (was: if ("
                          + m2.group(1)[:70] + ") goto loc_" + lab + ") */")
            break
    return out


# Deferred compares. The lifter emits cmp/test as a comment and re-evaluates
# the operand expressions at the branch, so a write to an operand register in
# between makes the branch test the wrong values. Such a site is rewritten to
# evaluate the condition at the compare -- but only when the C-to-guest
# mapping is unambiguous: one candidate in the C block, one qualifying
# compare in the guest block, same kind and literal, no flag writer, call or
# branch target in between.

_DC_CMT = re.compile(r'/\* (cmp|test) (.+?) - flags set for next jcc \*/')
_DC_CONS = re.compile(r'(CMP_[A-Z]+|TEST_[A-Z]+)\s*\(')
_DC_LABEL = re.compile(r'^loc_([0-9A-Fa-f]{8}):')
_DC_REGS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_DC_LITERAL = re.compile(r'^(?:0[xX][0-9A-Fa-f]+u?|\d+)$')
_DC_FLAG_WRITERS = {
    "add", "sub", "adc", "sbb", "and", "or", "xor", "cmp", "test", "inc", "dec",
    "neg", "shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr", "shld", "shrd",
    "mul", "imul", "div", "idiv", "bt", "bts", "btr", "btc", "bsf", "bsr",
    "xadd", "cmpxchg", "sahf", "popf", "popfd", "cmps", "cmpsb", "cmpsw", "cmpsd",
    "scas", "scasb", "scasw", "scasd", "aaa", "aad", "aam", "aas", "daa", "das",
    "comiss", "ucomiss", "comisd", "ucomisd", "clc", "stc", "cmc", "std", "cld",
    "lock",
}
_DC_SUBREG = {
    "al": ("eax", 0b0001), "ah": ("eax", 0b0010), "ax": ("eax", 0b0011), "eax": ("eax", 0b1111),
    "bl": ("ebx", 0b0001), "bh": ("ebx", 0b0010), "bx": ("ebx", 0b0011), "ebx": ("ebx", 0b1111),
    "cl": ("ecx", 0b0001), "ch": ("ecx", 0b0010), "cx": ("ecx", 0b0011), "ecx": ("ecx", 0b1111),
    "dl": ("edx", 0b0001), "dh": ("edx", 0b0010), "dx": ("edx", 0b0011), "edx": ("edx", 0b1111),
    "si": ("esi", 0b0011), "esi": ("esi", 0b1111),
    "di": ("edi", 0b0011), "edi": ("edi", 0b1111),
    "bp": ("ebp", 0b0011), "ebp": ("ebp", 0b1111),
    "sp": ("esp", 0b0011), "esp": ("esp", 0b1111),
}
_DC_REG_RE = re.compile(r'\b(e?[abcd]x|[abcd][lh]|e?(?:si|di|bp|sp))\b')
_DC_INSN = re.compile(r'^\s{2}0x([0-9A-Fa-f]{8})\s{2}[0-9a-fA-F]+\s+(\S+)\s*(.*?)\s*$')
_DC_ASM = None


def _dc_guest():
    """Guest listing (tools/disasm/output/asm): address -> (mnemonic,
    operands), and the addresses other code branches to."""
    global _DC_ASM
    if _DC_ASM is None:
        asm_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "disasm", "output", "asm")
        insns, labelled = {}, set()
        for path in glob.glob(os.path.join(asm_dir, "*.asm")):
            pending = False
            for line in open(path, encoding="utf-8", errors="replace"):
                stripped = line.strip()
                if stripped.startswith("; XREF:") or \
                   re.match(r'^(sub|loc)_[0-9A-Fa-f]{8}:', stripped):
                    pending = True
                    continue
                m = _DC_INSN.match(line)
                if m:
                    a = int(m.group(1), 16)
                    insns[a] = (m.group(2).lower(), m.group(3))
                    if pending:
                        labelled.add(a)
                    pending = False
        _DC_ASM = (insns, labelled, sorted(insns))
    return _DC_ASM


def _dc_reg_mask(optext):
    out = {}
    for m in _DC_REG_RE.finditer(optext):
        full, mask = _DC_SUBREG[m.group(1)]
        out[full] = out.get(full, 0) | mask
    return out


def _dc_writes_of(mnem, optext):
    out = {}
    if mnem == "push":
        return {"esp": 0b1111}
    if mnem == "pop":
        out["esp"] = 0b1111
        m = _DC_REG_RE.fullmatch(optext.split(",")[0].strip())
        if m:
            full, mask = _DC_SUBREG[m.group(1)]
            out[full] = out.get(full, 0) | mask
        return out
    if mnem.startswith(("mov", "lea", "cmov", "set", "xchg")):
        parts = [p.strip() for p in optext.split(",")]
        m = _DC_REG_RE.fullmatch(parts[0]) if parts else None
        if m:
            full, mask = _DC_SUBREG[m.group(1)]
            out[full] = out.get(full, 0) | (0b1111 if mnem in ("movzx", "movsx") else mask)
        if mnem == "xchg" and len(parts) > 1:
            m2 = _DC_REG_RE.fullmatch(parts[1])
            if m2:
                full, mask = _DC_SUBREG[m2.group(1)]
                out[full] = out.get(full, 0) | mask
    return out


def _dc_guest_sites(start_va, end_va):
    import bisect
    insns, labelled, order = _dc_guest()
    addrs = order[bisect.bisect_left(order, start_va):bisect.bisect_left(order, end_va)]
    found = []
    for i, a in enumerate(addrs):
        mnem, ops = insns[a]
        if mnem not in ("cmp", "test"):
            continue
        need = _dc_reg_mask(ops)
        if not need:
            continue
        clobber = None
        for k in range(i + 1, len(addrs)):
            b = addrs[k]
            bm, bops = insns[b]
            if b in labelled or bm == "call":
                break
            if (bm.startswith("j") and bm != "jmp") or bm.startswith(("set", "cmov")):
                if clobber:
                    found.append((mnem, ops, clobber))
                break
            if bm in _DC_FLAG_WRITERS:
                break
            for r, mask in _dc_writes_of(bm, bops).items():
                if need.get(r, 0) & mask:
                    clobber = r
                    break
    return found


def _dc_split_ops(s):
    depth, out, cur = 0, [], ""
    for ch in s:
        if ch == "(":
            depth += 1
        if ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    out.append(cur.strip())
    return out


def _dc_c_writes_of(line):
    w = set()
    m = re.match(r'\s*(eax|ebx|ecx|edx|esi|edi|ebp|esp)\s*(?:[-+*|&^]|>>|<<)?=[^=]', line)
    if m:
        w.add(m.group(1))
    for m in re.finditer(r'SET_LO(?:8|16)\((\w+),', line):
        if m.group(1) in _DC_REGS:
            w.add(m.group(1))
    for m in re.finditer(r'POP32\(\s*(\w+)\s*,\s*(\w+)\s*\)', line):
        for g in (m.group(1), m.group(2)):
            if g in _DC_REGS:
                w.add(g)
    if "PUSH32(" in line:
        w.add("esp")
    if re.search(r'\b(sub_[0-9A-Fa-f]{6}\w*|xbox_\w+)\s*\(', line):
        w |= {"eax", "ecx", "edx"}
    return w


def _dc_run_ends(line):
    s = line.strip()
    return bool(_DC_LABEL.match(s) or s in ("}", "};") or s.startswith("goto ")
                or s.startswith("return") or re.match(r'^\}\s*$', s))


def fix_deferred_cmp(lines, start, end):
    labels = [(i, int(m.group(1), 16)) for i, l in enumerate(lines)
              for m in [_DC_LABEL.match(l.strip())] if m]
    end_of = {}
    for k, (i, a) in enumerate(labels):
        end_of[i] = labels[k + 1][1] if k + 1 < len(labels) else end
    cands, block, seen = [], None, {}
    for i, line in enumerate(lines):
        m = _DC_LABEL.match(line.strip())
        if m:
            block = (i, int(m.group(1), 16), end_of[i])
        mc = _DC_CMT.search(line)
        if not mc or block is None:
            continue
        key = f"{mc.group(1)} {mc.group(2)}"
        nth = seen.get(key, 0)
        seen[key] = nth + 1
        if (start, key, nth) in DEFERRED_CMP_UNFIXED:
            continue
        cops = [o.strip() for o in _dc_split_ops(mc.group(2))]
        need = set()
        for o in cops:
            need |= {r for r in _DC_REGS if re.search(r'\b%s\b' % r, o)}
        if not need:
            continue
        clob = False
        for j in range(i + 1, len(lines)):
            l2 = lines[j]
            mcons = _DC_CONS.search(l2)
            if mcons:
                tail = l2[mcons.start():]
                depth, e = 0, None
                for k, ch in enumerate(tail):
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            e = k + 1
                            break
                if e is None:
                    break
                cond = tail[:e]
                bops = [o.strip() for o in _dc_split_ops(cond[cond.index("(") + 1:-1])]
                if bops == cops and clob:
                    cands.append(dict(cmt=i, br=j, cond=cond, kind=mc.group(1),
                                      cops=cops, block=block))
                break
            if _DC_CMT.search(l2) or _dc_run_ends(l2):
                break
            if _dc_c_writes_of(l2) & need:
                clob = True
    if not cands:
        return lines
    by_block = {}
    for c in cands:
        by_block.setdefault(c["block"][0], []).append(c)
    edits = []
    for group in by_block.values():
        if len(group) != 1:
            continue
        c = group[0]
        g = _dc_guest_sites(c["block"][1], c["block"][2])
        if len(g) != 1 or g[0][0] != c["kind"]:
            continue
        gtail = [o.strip() for o in g[0][1].split(",")][-1]
        ctail = c["cops"][-1]
        if _DC_LITERAL.match(gtail) and _DC_LITERAL.match(ctail):
            if int(gtail, 0) != int(ctail.rstrip("uU"), 0):
                continue
        edits.append(c)
    if not edits:
        return lines
    var = "_rcc" if start in BUG14_LATCH_FUNCS else "_rccf"
    out = list(lines)
    note = ("  /* DOA3: x86 latched these flags at the compare above and the "
            "branch below reads them, but an operand is overwritten in "
            "between -- evaluate the condition where the guest does. */")
    for c in edits:
        indent = re.match(r'\s*', lines[c["cmt"]]).group(0)
        out[c["cmt"]] = lines[c["cmt"]] + "\n" + indent + var + " = (" + c["cond"] + ");" + note
        out[c["br"]] = out[c["br"]].replace(c["cond"], var, 1)
    k = out.index("{")
    out[k] = out[k] + f"\n    int {var} = 0; /* DOA3: deferred condition evaluated at the compare */"
    return out


# Hand-written bodies for entry points only data refers to (task tables,
# nop padding a branch lands in): the function detector never finds them.
SEED_BODIES = {
    0x0006F5B0: 'void sub_0006F5B0(void)\n{\n    eax = ZX16(MEM16(0x4A03A4));\n    ecx = ZX8(MEM8(eax + 0x306538));\n    PUSH32(esp, ecx);\n    PUSH32(esp, 0); sub_0007DA70(); /* call 0x0007DA70 */\n    esp = esp + 4;\n    sub_0009E525(); return;         /* jmp 0x0009E525 */\n}',
    0x000DF670: 'void sub_000DF670(void)\n{\n    MEM8(ecx + 4) = 0;\n    MEM8(ecx + 5) = 1;\n    esp += 4;\n}',
    0x000E56A0: 'void sub_000E56A0(void)\n{\n    g_fp_stack[--g_fp_top & 7] = MEMF(0x1ED480);\n    esp += 4;\n}',
    0x00157E7C: 'void sub_00157E7C(void) { sub_00157E80(); }',
}


def _manual_defined():
    """Functions the hand-written sources (src/, outside gen/) define."""
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "src")
    gen = os.path.normpath(os.path.join(src, "game", "recomp", "gen"))
    out = set()
    for f in glob.glob(os.path.join(src, "**", "*.c"), recursive=True):
        if os.path.normpath(f).startswith(gen):
            continue
        text = open(f, encoding="utf-8", errors="ignore").read()
        out.update(re.findall(r"\bvoid\s+(sub_[0-9A-Fa-f]{8})\s*\(\s*void\s*\)\s*\{", text))
        out.update(re.findall(r"\w+\((sub_[0-9A-Fa-f]{8})[,)]", text))
    return out


_CTOR_PRE = '/* Direct lookup for the initializer tables.\n *\n * Deliberately local rather than added to recomp_dispatch.c: that table is\n * binary-searched with a curated size, and editing it would change which\n * indirect-call targets resolve across the whole game. These entries are only\n * ever needed by the _initterm walk in main.c. */\ntypedef void (*doa3_ctor_fn)(void);   /* matches recomp_func_t */\n'
_CTOR_POST = '};\n\ndoa3_ctor_fn doa3_crt_lookup(uint32_t va)\n{\n    size_t i;\n    for (i = 0; i < sizeof(g_doa3_ctors) / sizeof(g_doa3_ctors[0]); i++)\n        if (g_doa3_ctors[i].va == va)\n            return g_doa3_ctors[i].fn;\n    return 0;\n}\n'


def _cond_operands(cond):
    """Operands of a lifted condition, as written in its compare comment."""
    c = cond.strip()
    m = re.match(r'^\(?(CMP_[A-Z]+|TEST_[A-Z]+)\((.*)\)\)?$', c)
    if m:
        ops = [o.strip() for o in _dc_split_ops(m.group(2))]
        # `test a, b` + signed jcc is lifted as CMP_xx(a & b, 0)
        if len(ops) == 2 and ops[1] == "0" and " & " in ops[0]:
            ops = [o.strip() for o in ops[0].split(" & ", 1)]
        return ops
    m = re.match(r'^\(*\(int(?:8|16|32)_t\)\((.*) & (.*)\) [<>=]+ 0\)*$', c)
    if m:
        return [m.group(1).strip(), m.group(2).strip()]
    if "X86_PF8((" in c and ") & (" in c:
        i = c.index("X86_PF8((") + 9
        j = c.index(") & (", i)
        rest = c[j + 5:]
        return [c[i:j].strip(), rest[:rest.index(")")].strip()]
    return None


# A conditional jump, or a setcc, consuming the flags.
_CF_COND = re.compile(r'^(\s*)if \((.*)\) (goto loc_\w+;|\{.*\}|\(void\)0;)(.*)$')
_CF_SETCC = re.compile(r'^(\s*)(SET_LO8\(\w+, )\((.*)\)( \? 1 : 0\);)(.*)$')
# An arithmetic flag setter: its flags come from the register's new value.
_CF_ARITH = re.compile(r'^\s*(eax|ebx|ecx|edx|esi|edi|ebp)(?: = \1 [-+&|^] [^;]+|\+\+|--);')


def _consumer(line):
    """(prefix, condition, suffix) of a flag consumer line, or None."""
    m = _CF_COND.match(line)
    if m:
        return f"{m.group(1)}if (", m.group(2), f") {m.group(3)}{m.group(4)}"
    m = _CF_SETCC.match(line)
    if m:
        return f"{m.group(1)}{m.group(2)}(", m.group(3), f"){m.group(4)}{m.group(5)}"
    return None


def fix_clobbered_flags(lines, start):
    """A flag setter whose operand register is written before the consumer
    that reads its flags, in the same straight-line run: x86 latched the
    flags at the setter, the lifted consumer re-reads the new value.
    Evaluate the condition at the setter (recomp bug #14). Setters are
    cmp/test (by their comment) and arithmetic on a register; consumers are
    conditional jumps and setcc, in every condition form the lifter writes,
    including `fnstsw ax; test ah, N; jp`, which fix_deferred_cmp does not."""
    text = "\n".join(lines).split("\n")
    seen, edits = {}, []
    for i, l in enumerate(text):
        mc = _DC_CMT.search(l)
        ma = None if mc else _CF_ARITH.match(l)
        if not mc and not ma:
            continue
        key = f"{mc.group(1)} {mc.group(2)}" if mc else l.strip().split(";")[0]
        nth = seen.get(key, 0)
        seen[key] = nth + 1
        if (start, key, nth) in CLOBBERED_FLAGS_UNFIXED:
            continue
        if mc:
            cops = [o.strip() for o in _dc_split_ops(mc.group(2))]
            need = set()
            for o in cops:
                need |= {r for r in _DC_REGS if re.search(r'\b%s\b' % r, o)}
        else:
            reg = ma.group(1)
            need = {reg}
        clob = False
        for j in range(i + 1, len(text)):
            c = _consumer(text[j])
            if c:
                cond = c[1]
                if mc:
                    ok = _cond_operands(cond) == cops
                else:
                    ok = (re.fullmatch(r'\(*(?:\(int(?:8|16|32)_t\))?%s [=!<>]+ 0\)*' % reg, cond.strip())
                          is not None)
                if ok and clob:
                    edits.append((i, j, c))
                break
            if _DC_CMT.search(text[j]) or _dc_run_ends(text[j]) or _CF_ARITH.match(text[j]):
                break
            if _dc_c_writes_of(text[j]) & need:
                clob = True
    if not edits:
        return text
    for i, j, (pre, cond, post) in reversed(edits):
        indent = re.match(r'\s*', text[j]).group(0)
        text[j] = f"{pre}_rcc{post}"
        text.insert(i + 1, f"{indent}_rcc = ({cond});  /* DOA3 bug #14: flags evaluated where x86 evaluates them */")
    k = text.index("{")
    text.insert(k + 1, "    int _rcc = 0; /* DOA3 bug #14: condition evaluated at the compare */")
    return text


_RCF = {"je": "JE", "jz": "JE", "jne": "JNE", "jnz": "JNE", "jb": "JB", "jae": "JAE",
        "jbe": "JBE", "ja": "JA", "jl": "JL", "jge": "JGE", "jle": "JLE", "jg": "JG",
        "js": "JS", "jns": "JNS", "jo": "JO", "jno": "JNO", "jp": "JP", "jnp": "JNP"}
_EF = re.compile(r'^(\s*if \()_flags( /\* (\w+): )')


def _sets_flags(s):
    """A lifted statement that changes the flags or makes them unknown."""
    return bool(re.search(r'PUSH32\(esp, 0\); (sub_|RECOMP_)|_cf = |_dividend|_fpu_cmp = |'
                          r'\+\+|--|^(\w+) = \2 [-+&|^]|<<|>>', s)
                or re.match(r'^(SET_LO8|SET_LO16|SET_HI8)\((\w+), (LO8|LO16|HI8)\(\2\) [-+&|^]', s))


def fix_entry_flags(lines):
    """A branch at the start of a fragment, before any compare in it, reads
    the flags of whoever jumped or fell into it: the lifter has no setter
    and emits `if (_flags ...)`, which is never taken. Read the flags the
    caller recorded (RC_F_*, recomp_types.h) instead."""
    text = "\n".join(lines).split("\n")
    body = text.index("{")
    labels = 0
    found = False
    for k in range(body + 1, len(text)):
        s = text[k].strip()
        if re.match(r'^loc_[0-9A-Fa-f]{8}: ;', s):
            labels += 1
            if labels > 1:
                break
            continue
        if not labels:
            continue                     # declarations before the entry label
        if _DC_CMT.search(s) or s.startswith("goto ") or "return;" in s and not s.startswith("if"):
            break
        m = _EF.match(text[k])
        if m and m.group(3) in _RCF:
            text[k] = _EF.sub(lambda mm: f"{mm.group(1)}RC_F_{_RCF[mm.group(3)]}(){mm.group(2)}", text[k])
            found = True
        elif re.match(r'^\s*if \(', text[k]) or _sets_flags(s):
            break
    return text, found


def fix_flag_stores(code, readers):
    """Before a tail call or fall-through into a function in `readers`, the
    compare that sets the flags records its operands (RC_SETF_CMP/TEST)."""
    lines = code.split("\n")
    out = list(lines)
    for j, l in enumerate(lines):
        m = re.search(r'\bsub_([0-9A-Fa-f]{8})\(\); return;', l)
        if not m or int(m.group(1), 16) not in readers or "PUSH32(esp, 0); sub_" in l:
            continue
        for i in range(j - (0 if l.strip().startswith("if") else 1), -1, -1):
            s = lines[i].strip()
            mc = _DC_CMT.search(s)
            if mc and s.startswith("/*"):
                ops = _dc_split_ops(mc.group(2))
                kind = "CMP" if mc.group(1) == "cmp" else "TEST"
                if len(ops) == 2 and "RC_SETF" not in out[i]:
                    indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
                    out[i] = f"{indent}RC_SETF_{kind}({ops[0]}, {ops[1]});   {s}"
                break
            if (re.match(r'^loc_[0-9A-Fa-f]{8}: ;', s) or s.startswith("goto ")
                    or (s.endswith("return;") and not s.startswith("if"))):
                break
    return "\n".join(out)


_FOLD_CMP = {"je": "CMP_EQ", "jne": "CMP_NE", "jb": "CMP_B", "jae": "CMP_AE", "jbe": "CMP_BE",
             "ja": "CMP_A", "jl": "CMP_L", "jge": "CMP_GE", "jle": "CMP_LE", "jg": "CMP_G"}
_FOLD_TEST = {"je": "TEST_Z", "jne": "TEST_NZ"}
_FOLD_JCC = re.compile(r'^(\s*)if \((.*)\) (goto loc_\w+;|\{.*\}) /\* (\w+): ([^*]*)\*/')


def fix_shared_jcc(lines, start):
    """MSVC shares one conditional jump between paths that set its flags
    differently (`cmp a,1 / jmp L / ... cmp a,2 / L: jne X`); the lifter
    builds L's condition from the compare above L only. At each `jmp L` that
    follows its own compare, evaluate L's jump there with this path's
    operands and branch to its targets directly."""
    text = "\n".join(lines).split("\n")
    label_at = {}
    for k, l in enumerate(text):
        m = re.match(r'^loc_([0-9A-Fa-f]{8}): ;', l.strip())
        if m:
            label_at[m.group(1).upper()] = k
    out = list(text)
    for j, l in enumerate(text):
        m = re.match(r'^(\s*)goto loc_([0-9A-Fa-f]{8});\s*$', l)
        if not m or m.group(2).upper() not in label_at:
            continue
        # the compare that sets this path's flags, right above the goto
        i = j - 1
        while i >= 0 and not text[i].strip():
            i -= 1
        mc = _DC_CMT.search(text[i]) if i >= 0 else None
        ma = None if mc else (_CF_ARITH.match(text[i]) if i >= 0 else None)
        if not ma and (not mc or not text[i].strip().startswith("/*")):
            continue
        key = (start, int(m.group(2), 16))
        if key in (SHARED_JCC_ARITH_UNFIXED if ma else SHARED_JCC_UNFIXED):
            continue
        # the shared jump: first statement at the label
        k = label_at[m.group(2).upper()] + 1
        while k < len(text) and not text[k].strip():
            k += 1
        mj = _FOLD_JCC.match(text[k]) if k < len(text) else None
        if not mj:
            continue
        if ma:
            # flags from an arithmetic result: only ZF is reproduced
            op = {"je": "==", "jz": "==", "jne": "!=", "jnz": "!="}.get(mj.group(4))
            if not op:
                continue
            cond = f"({ma.group(1)} {op} 0)"
        else:
            table = _FOLD_CMP if mc.group(1) == "cmp" else _FOLD_TEST
            macro = table.get(mj.group(4))
            if not macro:
                continue
            cond = None
        nxt = next((n for n in range(k + 1, len(text))
                    if re.match(r'^loc_[0-9A-Fa-f]{8}: ;', text[n].strip())), None)
        if nxt is None:
            continue
        if cond is None:
            ops = ", ".join(o.strip() for o in _dc_split_ops(mc.group(2)))
            cond = f"{macro}({ops})"
        if cond == mj.group(2).strip():
            continue                     # same flags on both paths: nothing to fold
        nlab = text[nxt].strip()[:12]
        out[j] = (f"{m.group(1)}if ({cond}) {mj.group(3)} /* {mj.group(4)}: shared jump "
                  f"at loc_{m.group(2)}, this path's flags */\n{m.group(1)}goto {nlab};")
    return "\n".join(out).split("\n")


def apply_hand_edits(lines, hunks):
    """Replace runs of lifted lines with the hand-edited ones (HAND_EDITS)."""
    text = "\n".join(lines).split("\n")
    body = text.index("{")
    found = []
    for old, new, nth in hunks:
        old = list(old)
        hits = [k for k in range(body, len(text)) if text[k:k + len(old)] == old]
        if nth >= len(hits):
            raise ValueError(f"hand edit no longer applies: {old[0][:60]!r}")
        found.append((hits[nth], len(old), list(new)))
    for k, n, new in sorted(found, reverse=True):
        text[k:k + n] = new
    # latch variables an edit uses must be declared
    for var in ("_rcc", "_rccf"):
        used = any(re.search(r'\b%s\b' % var, l) for l in text[body:])
        declared = any(re.match(r'\s*int %s = 0;' % var, l) for l in text[body:])
        if used and not declared:
            text.insert(body + 1, f"    int {var} = 0; /* latched flags */")
    return text


class FunctionTranslator:
    """Translates individual x86 functions to C source code."""

    def __init__(self, xbe_data, func_db, label_db=None, classification_db=None,
                 abi_db=None):
        """
        xbe_data: bytes - raw XBE file contents
        func_db: dict - addr → function info from functions.json
        label_db: dict - addr → name from labels.json
        classification_db: dict - addr → classification from identified_functions.json
        abi_db: dict - addr → ABI info from abi_functions.json
        """
        self.xbe_data = xbe_data
        self.func_db = func_db
        self.label_db = label_db or {}
        self.classification_db = classification_db or {}
        self.abi_db = abi_db or {}
        self.disasm = Disassembler()
        # Functions from here on (chunks recomp_0010.c onward) get their
        # hardware busy-waits run through; set by the batch translator.
        self.selfspin_from = 1 << 32
        self.last_entry_flags = False
        self.lifter = Lifter(func_db=func_db, label_db=label_db, abi_db=abi_db, xbe_data=xbe_data)

    def _read_func_bytes(self, start_va, end_va):
        """Read raw bytes for a function from the XBE."""
        offset = va_to_file_offset(start_va)
        if offset is None:
            return None
        size = end_va - start_va
        if offset + size > len(self.xbe_data):
            return None
        return self.xbe_data[offset:offset + size]

    def _determine_calling_convention(self, func_info):
        """Guess calling convention from function properties."""
        name = func_info.get("name", "")
        # thiscall methods have ecx = this
        if "thiscall" in name or func_info.get("calling_convention") == "thiscall":
            return "thiscall"
        return "cdecl"

    def _func_has_prologue(self, instructions):
        """Check if function starts with push ebp; mov ebp, esp."""
        if len(instructions) < 2:
            return False
        return (instructions[0].mnemonic == "push" and
                instructions[0].op_str == "ebp" and
                instructions[1].mnemonic == "mov" and
                instructions[1].op_str == "ebp, esp")

    def translate_function(self, func_addr, func_info):
        """
        Translate a single function to C code.
        Returns a string of C source code, or None on failure.
        """
        start = func_addr
        end = func_info.get("end")
        if not end:
            end = start + func_info.get("size", 0)
        if end <= start:
            return None

        name = func_info.get("name", f"sub_{start:08X}")
        size = end - start

        # Read bytes from XBE
        raw_bytes = self._read_func_bytes(start, end)
        if not raw_bytes:
            return None

        # Set function bounds for the lifter
        self.lifter.func_start = start
        self.lifter.func_end = end

        # Disassemble
        instructions = self.disasm.disassemble_function(raw_bytes, start, end)
        if not instructions:
            return None

        # ── Extend over intra-function jump-table case bodies ──────────────
        # MSVC switch layout: `jmp [reg*4+tbl]` … case bodies … tbl (data).
        # The function detector often ends the function right after the jmp
        # (everything else looks unreachable), so the case bodies fall outside
        # [start,end) and _analyze_switch_table rejects the table -> the switch
        # was emitted as a broken RECOMP_ITAIL to non-function case labels.
        # Fix: when a jump table lies just past the detected end with all its
        # targets before it, extend the lift range to the table start (bodies
        # end where the table begins) and re-disassemble. Repeat to fixpoint
        # (an extended body can contain another switch).
        for _ in range(0 if start in LEGACY_NO_JT_EXTEND_FUNCS else 8):
            new_end = end
            for insn in instructions:
                if insn.mnemonic != "jmp" or insn.jump_target or not insn.operands:
                    continue
                op = insn.operands[0]
                if op.type != "mem" or not op.mem_disp or not (op.mem_index or op.mem_base):
                    continue
                tbl = op.mem_disp
                targets = self.lifter._read_jump_table(tbl)
                if not targets:
                    continue
                hi = max(targets)
                # Only the pattern "targets below the table, table at/past our
                # end, everything nearby" is safely extendable.
                if (hi >= new_end and hi < tbl and tbl >= new_end
                        and tbl - start < 0x20000):
                    new_end = tbl
            if new_end == end:
                break
            end = new_end
            size = end - start
            raw_bytes = self._read_func_bytes(start, end)
            if not raw_bytes:
                return None
            self.lifter.func_end = end
            instructions = self.disasm.disassemble_function(raw_bytes, start, end)
            if not instructions:
                return None

        # Collect switch table targets as extra block leaders
        switch_leaders = set()
        for insn in instructions:
            if insn.mnemonic == "jmp" and not insn.jump_target and insn.operands:
                targets = self.lifter._analyze_switch_table(insn.operands)
                for t in targets:
                    if start <= t < end:
                        switch_leaders.add(t)

        # Build basic blocks
        blocks = self.disasm.build_basic_blocks(
            instructions, start, end,
            extra_leaders=switch_leaders if switch_leaders else None)
        if not blocks:
            return None

        # Get classification and ABI info
        cls_info = self.classification_db.get(start, {})
        category = cls_info.get("category", "unknown")
        module = cls_info.get("module", "")
        source_file = cls_info.get("source_file", "")
        abi_info = self.abi_db.get(start, {})

        # ABI-derived info (kept for comments)
        cc = abi_info.get("calling_convention", "cdecl")
        num_params = abi_info.get("estimated_params", 0)
        return_hint = abi_info.get("return_hint", "int_or_void")
        frame_type = abi_info.get("frame_type", "fpo_leaf")
        stack_frame_size = abi_info.get("stack_frame_size", 0)

        # Determine which registers are used
        used_regs = self._find_used_registers(instructions)
        used_xmm = self._find_used_xmm(instructions)
        has_prologue = self._func_has_prologue(instructions)
        has_fpu = any(insn.mnemonic.startswith("f") for insn in instructions)

        # Volatile registers (eax, ecx, edx, esp) are globals - don't declare
        # them as locals. The RECOMP_GENERATED_CODE #define maps register names
        # to the global variables via preprocessor macros.
        volatile_regs = {"eax", "ecx", "edx", "esp"}

        # Ensure ebp tracked if function uses 'leave' (implicit ebp)
        if any(insn.mnemonic == "leave" for insn in instructions):
            used_regs.add("ebp")

        # Ensure ebp tracked if function has tail jumps (lifter emits
        # g_seh_ebp = ebp before external jmp and indirect jmp).
        has_tail_jump = any(
            insn.mnemonic == "jmp" and (
                (insn.jump_target and not (start <= insn.jump_target < end))
                or not insn.jump_target  # indirect jmp
            )
            for insn in instructions
        )
        if has_tail_jump:
            used_regs.add("ebp")

        # Ensure ebp tracked if function calls __SEH_prolog or __SEH_epilog
        # (lifter emits ebp = g_seh_ebp readback after these calls).
        SEH_FUNCS = {0x00244784, 0x002447BF}
        if any(insn.call_target in SEH_FUNCS for insn in instructions):
            used_regs.add("ebp")

        # Build call targets list
        call_targets = set()
        for insn in instructions:
            if insn.call_target and is_code_address(insn.call_target):
                call_targets.add(insn.call_target)

        # All translated functions are void(void).
        # Arguments pass via the global simulated stack (push instructions).
        # Return values pass via g_eax (the global eax register).
        ret_type = "void"
        param_str = "void"

        # Generate C code
        lines = []

        # Header comment
        lines.append(f"/**")
        lines.append(f" * {name}")
        lines.append(f" * Original: 0x{start:08X} - 0x{end:08X} ({size} bytes, {len(instructions)} insns)")
        if category != "unknown":
            lines.append(f" * Category: {category}")
        if source_file:
            lines.append(f" * Source: {source_file}")
        lines.append(f" * CC: {cc}, {num_params} params, returns {return_hint}")
        if frame_type == "ebp_frame":
            lines.append(f" * Frame: EBP-based ({stack_frame_size} bytes locals)")
        else:
            lines.append(f" * Frame: {frame_type}")
        lines.append(f" */")

        # Function signature. Bodies recomp_manual.c replaces or wraps get
        # the name it calls them by (sub_X_gen), or are kept under #if 0.
        if start in IF0_BODIES and start not in BODY_SUFFIX:
            lines.append(f"#if 0  /* DOA3: {name} overridden in recomp_manual.c */")
        lines.append(f"{ret_type} {name}{BODY_SUFFIX.get(start, '')}({param_str})")
        lines.append(f"{{")

        # ebp is the only callee-saved register declared as a local.
        # ebx, esi, edi are global via #define macros (g_ebx, g_esi, g_edi)
        # and must NOT be declared locally, otherwise the local shadows
        # the global and cross-function register passing breaks.
        # Volatile registers (eax, ecx, edx, esp) are also global via macros.
        reg_decls = []
        # Force-declare ebp for functions that interact with the SEH frame
        # bridge: the lifter emits "ebp = g_seh_ebp" after calls to
        # __SEH_prolog/__SEH_epilog, and "g_seh_ebp = ebp" at the ret of the
        # helpers themselves. Both reference a local ebp that the normal
        # used-register scan may not have flagged.
        seh_addrs = (self.lifter.SEH_PROLOG, self.lifter.SEH_EPILOG)
        needs_ebp = (
            "ebp" in used_regs
            or start in seh_addrs
            or any(getattr(insn, "call_target", None) in seh_addrs
                   for insn in instructions))
        if needs_ebp:
            reg_decls.append("ebp")
        if reg_decls:
            lines.append(f"    uint32_t {', '.join(reg_decls)};")

        # Add _flags variable if function has conditional instructions
        has_conditionals = any(
            insn.is_cond_jump or insn.mnemonic.startswith("set")
            or insn.mnemonic.startswith("cmov")
            for insn in instructions)
        if has_conditionals:
            lines.append(f"    int _flags = 0; /* fallback flag var */")

        # Add _cf for carry-dependent instructions (sbb, adc)
        has_carry = any(insn.mnemonic in ("sbb", "adc")
                        for insn in instructions)
        if has_carry:
            lines.append(f"    int _cf = 0; /* carry flag */")

        # Add _fpu_cmp for FPU compare instructions (both old and new style).
        # fnstsw also reads _fpu_cmp now (it materializes AH from it, bug #9).
        has_fpu_cmp = any(insn.mnemonic in ("fcompi", "fcomip", "fucomi",
                                             "fucompi", "fucomip", "fcomi",
                                             "fcom", "fcomp", "fcompp",
                                             "fucom", "fucomp", "fucompp",
                                             "fnstsw", "ftst", "fxam",
                                             "comiss", "ucomiss")
                          for insn in instructions)
        if has_fpu_cmp:
            lines.append(f"    int _fpu_cmp = 0; /* FPU compare result: -1/0/1 */")

        # SSE/MMX register declarations
        if used_xmm:
            xmm_regs = sorted([r for r in used_xmm if r.startswith("xmm")])
            mmx_regs = sorted([r for r in used_xmm if r.startswith("mm")
                               and not r.startswith("xmm")])
            if xmm_regs:
                # 128-bit: the XDK maths library runs packed ops on these
                # (movaps/mulps/shufps ...); a scalar float model dropped
                # three of every four lanes and all packed arithmetic.
                lines.append(f"    xmm128_t {', '.join(xmm_regs)};")
            if mmx_regs:
                lines.append(f"    uint64_t {', '.join(mmx_regs)};")

        # FPU stack — GLOBAL (g_fp_stack/g_fp_top in recomp_types.h).
        # It was per-function locals, which broke EVERY cross-function x87
        # value transfer: `fld x; call _ftol2`, float-returning functions
        # (value in ST0), sqrt/sin CRT helpers, etc. — the callee read its
        # own uninitialized stack (recomp bug #8). Real x87 state is global.
        if has_fpu:
            lines.append(f"    #define fp_push(v) (g_fp_stack[--g_fp_top & 7] = (v))")
            lines.append(f"    #define fp_pop() (g_fp_top++)")
            lines.append(f"    #define fp_popp() (fp_pop())")
            lines.append(f"    #define fp_top() g_fp_stack[g_fp_top & 7]")
            lines.append(f"    #define fp_st1() g_fp_stack[(g_fp_top + 1) & 7]")

        # For fpo_leaf functions that use ebp: initialize from g_seh_ebp.
        # In x86, these functions inherit EBP from their caller (typically
        # via a tail jump that shares the caller's frame). In our C translation,
        # ebp is a local variable that would start uninitialized, causing
        # crashes when the function reads MEM32(ebp + offset). The g_seh_ebp
        # global bridges ebp across function boundaries.
        if frame_type == "fpo_leaf" and "ebp" in used_regs and not has_prologue:
            lines.append(f"    ebp = g_seh_ebp; /* fpo_leaf: inherit caller's frame */")

        lines.append(f"")

        # Generate code for each basic block
        # Create a set of addresses that need labels
        label_addrs = set()
        for bb in blocks:
            for succ in bb.successors:
                label_addrs.add(succ)
        # Also add any jump targets within the function
        for insn in instructions:
            if insn.jump_target and start <= insn.jump_target < end:
                label_addrs.add(insn.jump_target)
        # Add switch table targets (indirect jmp with intra-function table)
        for insn in instructions:
            if insn.mnemonic == "jmp" and not insn.jump_target and insn.operands:
                switch_targets = self.lifter._analyze_switch_table(insn.operands)
                for t in switch_targets:
                    label_addrs.add(t)

        flag_state = None
        for bb in blocks:
            # Emit label if this block is a branch target.
            # Always append an empty statement (";") so a terminal label whose
            # basic block lifts to only comments (e.g. nop padding) is still
            # valid C — a label must be followed by a statement.
            if bb.start in label_addrs or bb.start == start:
                lines.append(f"loc_{bb.start:08X}: ;")

            # Propagate flag state from previous block (fallthrough path).
            # This handles patterns like: test eax,eax / ja X / jb Y
            # where jb uses the same flags as ja from the preceding block.
            stmts, flag_state = lift_basic_block(
                self.lifter, bb, flag_state=flag_state)
            for stmt in stmts:
                lines.append(f"    {stmt}")

            lines.append(f"")

        # Insert _icall_esp save points before RECOMP_ICALL_SAFE arg pushes.
        # The pattern is: optional PUSH32 args, then PUSH32(esp, 0); RECOMP_ICALL_SAFE(...).
        # We insert "uint32_t _icall_esp = g_esp;" before the first arg push.
        lines = _fixup_icall_esp_save(lines)

        # Validate: comment out goto targets that reference missing labels
        # (dead code after unconditional jumps may reference non-existent labels)
        import re
        defined_labels = set()
        goto_lines = []
        for idx, line in enumerate(lines):
            lbl_match = re.match(r'^(loc_[0-9A-Fa-f]+):', line)
            if lbl_match:
                defined_labels.add(lbl_match.group(1))
            goto_match = re.search(r'goto (loc_[0-9A-Fa-f]+);', line)
            if goto_match:
                goto_lines.append((idx, goto_match.group(1)))
        for idx, target in goto_lines:
            if target not in defined_labels:
                lines[idx] = lines[idx].replace(
                    f"goto {target};",
                    f"(void)0; /* goto {target} - dead code, label not in function */")

        # Undefine FPU macros
        if has_fpu:
            lines.append(f"    #undef fp_push")
            lines.append(f"    #undef fp_pop")
            lines.append(f"    #undef fp_popp")
            lines.append(f"    #undef fp_top")
            lines.append(f"    #undef fp_st1")

        lines.append(f"}}")
        lines.append(f"")

        # Safety net: emitted code may reference the local `ebp` even when the
        # used-register scan missed it (e.g. the g_seh_ebp sync emitted for
        # conditional tail-jumps). Declare it if any body line references it.
        if not needs_ebp:
            body_refs_ebp = any(re.search(r"\bebp\b", ln) for ln in lines
                                if not ln.lstrip().startswith(("/*", "*", "//")))
            if body_refs_ebp:
                sig_idx = lines.index("{")
                lines.insert(sig_idx + 1, "    uint32_t ebp;")
                # fpo functions inherit the caller's frame pointer
                if frame_type == "fpo_leaf" and not has_prologue:
                    lines.insert(sig_idx + 2,
                                 "    ebp = g_seh_ebp; /* fpo_leaf: inherit caller's frame */")

        if start in IF0_BODIES and start not in BODY_SUFFIX:
            lines.insert(len(lines) - 1, "#endif")
        # Post-lift fixes, in the order they were run over the generated tree.
        lines = fix_carrier(lines, start)
        lines = fix_fallthrough(lines, start, end, self.func_db)
        lines = fix_cond_tailcall_ebp(lines)
        lines = fix_deferred_cmp(lines, start, end)
        lines = fix_clobbered_flags(lines, start)
        lines = fix_shared_jcc(lines, start)
        if start in ENTRY_FLAGS_UNFIXED:
            self.last_entry_flags = False
        else:
            lines, self.last_entry_flags = fix_entry_flags(lines)
        if start >= self.selfspin_from:
            lines = fix_selfspins(lines)
        if start in HAND_EDITS:
            lines = apply_hand_edits(lines, HAND_EDITS[start])
        return "\n".join(lines)

    def _find_used_registers(self, instructions):
        """Find which 32-bit registers are referenced by any instruction."""
        regs = set()
        reg_map = {
            "eax": "eax", "ax": "eax", "al": "eax", "ah": "eax",
            "ebx": "ebx", "bx": "ebx", "bl": "ebx", "bh": "ebx",
            "ecx": "ecx", "cx": "ecx", "cl": "ecx", "ch": "ecx",
            "edx": "edx", "dx": "edx", "dl": "edx", "dh": "edx",
            "esi": "esi", "si": "esi",
            "edi": "edi", "di": "edi",
            "ebp": "ebp", "bp": "ebp",
            "esp": "esp", "sp": "esp",
        }
        for insn in instructions:
            for op in insn.operands:
                if op.type == "reg" and op.reg in reg_map:
                    regs.add(reg_map[op.reg])
                elif op.type == "mem":
                    if op.mem_base and op.mem_base in reg_map:
                        regs.add(reg_map[op.mem_base])
                    if op.mem_index and op.mem_index in reg_map:
                        regs.add(reg_map[op.mem_index])
        return regs

    def _find_used_xmm(self, instructions):
        """Find which XMM and MMX registers are used."""
        regs = set()
        for insn in instructions:
            for op in insn.operands:
                if op.type == "reg" and op.reg:
                    if op.reg.startswith("xmm") or op.reg.startswith("mm"):
                        regs.add(op.reg)
        return regs


class BatchTranslator:
    """Translates multiple functions and writes C source files."""

    def __init__(self, xbe_path, func_json_path, labels_json_path=None,
                 identified_json_path=None, abi_json_path=None,
                 output_dir=None):
        self.xbe_path = xbe_path
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(__file__), "output")

        # Load XBE
        with open(xbe_path, "rb") as f:
            self.xbe_data = f.read()

        # Load function database
        with open(func_json_path, "r") as f:
            func_list = json.load(f)

        self.func_db = {}
        for func in func_list:
            addr = int(func["start"], 16)
            func["_addr"] = addr
            if "end" in func:
                func["end"] = int(func["end"], 16)
            self.func_db[addr] = func

        # Load labels
        self.label_db = {}
        if labels_json_path and os.path.exists(labels_json_path):
            with open(labels_json_path, "r") as f:
                labels = json.load(f)
            for lbl in labels:
                addr = int(lbl["address"], 16)
                self.label_db[addr] = lbl["name"]

        # Load classifications
        self.classification_db = {}
        if identified_json_path and os.path.exists(identified_json_path):
            with open(identified_json_path, "r") as f:
                identified = json.load(f)
            for entry in identified:
                addr = int(entry["start"], 16)
                self.classification_db[addr] = entry

        # Load ABI data
        self.abi_db = {}
        if abi_json_path and os.path.exists(abi_json_path):
            with open(abi_json_path, "r") as f:
                abi_list = json.load(f)
            for entry in abi_list:
                addr = int(entry["address"], 16)
                self.abi_db[addr] = entry

        # Create translator
        self.translator = FunctionTranslator(
            self.xbe_data, self.func_db, self.label_db,
            self.classification_db, self.abi_db)

    def get_functions_by_category(self, categories=None, exclude_categories=None):
        """
        Get function addresses filtered by category.
        Returns list of (addr, func_info) tuples.
        """
        result = []
        for addr, func_info in sorted(self.func_db.items()):
            cls_info = self.classification_db.get(addr, {})
            cat = cls_info.get("category", "unknown")

            if categories and cat not in categories:
                continue
            if exclude_categories and cat in exclude_categories:
                continue

            result.append((addr, func_info))
        return result

    def _make_declaration(self, addr, name):
        """Generate a function declaration string.
        All translated functions are void(void) - args pass via stack,
        return values via g_eax."""
        return f"void {name}(void)"

    def translate_single(self, addr):
        """Translate a single function by address. Returns C code string."""
        func_info = self.func_db.get(addr)
        if not func_info:
            return None
        return self.translator.translate_function(addr, func_info)

    def translate_batch(self, func_list, output_file=None, max_funcs=None,
                        verbose=False):
        """
        Translate a batch of functions.

        func_list: list of (addr, func_info) tuples
        output_file: path to write combined C output
        max_funcs: limit number of functions
        verbose: print progress

        Returns dict with statistics.
        """
        os.makedirs(self.output_dir, exist_ok=True)

        if max_funcs:
            func_list = func_list[:max_funcs]

        stats = {
            "total": len(func_list),
            "translated": 0,
            "failed": 0,
            "total_lines": 0,
            "total_insns": 0,
        }

        c_chunks = []
        c_chunks.append("/**")
        c_chunks.append(" * Dead or Alive 3 - Mechanically Translated Game Code")
        c_chunks.append(f" * Generated by tools/recomp from original Xbox x86 code.")
        c_chunks.append(f" * Functions: {len(func_list)}")
        c_chunks.append(" */")
        c_chunks.append("")
        c_chunks.append('#define RECOMP_GENERATED_CODE')
        c_chunks.append('#include "recomp_types.h"')
        c_chunks.append('#include <math.h>')
        c_chunks.append("")
        c_chunks.append("/* Forward declarations */")

        # Forward declarations
        for addr, func_info in func_list:
            name = func_info.get("name", f"sub_{addr:08X}")
            decl = self._make_declaration(addr, name)
            c_chunks.append(f"{decl};")
        c_chunks.append("")
        c_chunks.append("/* ═══════════════════════════════════════════════════ */")
        c_chunks.append("")

        # Translate each function
        for i, (addr, func_info) in enumerate(func_list):
            name = func_info.get("name", f"sub_{addr:08X}")
            if verbose and (i % 100 == 0 or i == len(func_list) - 1):
                print(f"  [{i+1}/{len(func_list)}] Translating {name} at 0x{addr:08X}...")

            code = self.translator.translate_function(addr, func_info)
            if code:
                c_chunks.append(code)
                stats["translated"] += 1
                stats["total_lines"] += code.count("\n")

                # Count instructions
                num_insns = func_info.get("num_instructions", 0)
                stats["total_insns"] += num_insns
            else:
                c_chunks.append(f"/* FAILED to translate {name} at 0x{addr:08X} */")
                c_chunks.append(f"void {name}(void) {{ /* translation failed */ }}")
                c_chunks.append("")
                stats["failed"] += 1

        # Write output
        if output_file is None:
            output_file = os.path.join(self.output_dir, "recompiled.c")

        output_text = "\n".join(c_chunks)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output_text)

        stats["output_file"] = output_file
        stats["output_size"] = len(output_text)

        return stats

    def translate_by_category(self, categories, output_prefix=None,
                              max_per_file=500, verbose=False):
        """
        Translate functions grouped by category, one file per category.
        Returns dict with per-category stats.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        all_stats = {}

        for cat in categories:
            funcs = self.get_functions_by_category(categories={cat})
            if not funcs:
                continue

            prefix = output_prefix or cat
            out_file = os.path.join(self.output_dir, f"{prefix}.c")

            if verbose:
                print(f"\nCategory: {cat} ({len(funcs)} functions)")

            stats = self.translate_batch(
                funcs, output_file=out_file,
                max_funcs=max_per_file, verbose=verbose)
            all_stats[cat] = stats

        return all_stats

    def translate_batch_split(self, func_list, output_dir, chunk_size=1000,
                              header_name="recomp_funcs.h",
                              prefix="recomp", verbose=False):
        """
        Translate functions into multiple .c files + a shared header.

        Generates:
          output_dir/recomp_funcs.h       - forward declarations for all functions
          output_dir/recomp_0000.c        - chunk 0
          output_dir/recomp_0001.c        - chunk 1
          ...
          output_dir/recomp_dispatch.c    - address -> function pointer table

        Returns dict with stats and list of generated files.
        """
        import sys

        os.makedirs(output_dir, exist_ok=True)

        # Translate all functions first, collecting results
        translations = []
        stats = {
            "total": len(func_list),
            "translated": 0,
            "failed": 0,
            "total_lines": 0,
        }

        if len(func_list) > 10 * chunk_size:
            self.translator.selfspin_from = func_list[10 * chunk_size][0]
        func_list = [f for f in func_list if f[0] not in NOT_EMITTED]
        entry_readers = set()
        for i, (addr, func_info) in enumerate(func_list):
            name = func_info.get("name", f"sub_{addr:08X}")
            if verbose and (i % 500 == 0 or i == len(func_list) - 1):
                print(f"  [{i+1}/{len(func_list)}] Translating {name}...",
                      file=sys.stderr)

            code = self.translator.translate_function(addr, func_info)
            if code and self.translator.last_entry_flags:
                entry_readers.add(addr)
            if code:
                translations.append((addr, name, code))
                stats["translated"] += 1
                stats["total_lines"] += code.count("\n")
            else:
                # Stub for failed translations
                stub = f"/* FAILED: {name} at 0x{addr:08X} */\n"
                stub += f"void {name}(void) {{ /* translation failed */ }}\n"
                translations.append((addr, name, stub))
                stats["failed"] += 1

        # Flags carried into fragments: the compares that hand off to a
        # function reading its caller's flags record them (RC_SETF_*).
        readers = {a for a in entry_readers}
        translations = [(a, n, fix_flag_stores(code, readers)) for a, n, code in translations]

        # Entry points only data refers to: hand-written bodies.
        for addr, code in sorted(SEED_BODIES.items()):
            translations.append((addr, f"sub_{addr:08X}", code + "\n"))
        translations.sort(key=lambda x: x[0])

        # Generate header with all forward declarations
        header_path = os.path.join(output_dir, header_name)
        header_lines = [
            "/**",
            " * Dead or Alive 3 - Recompiled Function Declarations",
            f" * {stats['translated']} functions, auto-generated by tools/recomp",
            " */",
            "",
            "#ifndef RECOMP_FUNCS_H",
            "#define RECOMP_FUNCS_H",
            "",
            '#include "recomp_types.h"',
            "",
        ]
        for addr, name, _ in translations:
            decl = self._make_declaration(addr, name)
            header_lines.append(f"{decl};")
        header_lines.extend(["", "#endif /* RECOMP_FUNCS_H */", ""])

        with open(header_path, "w", encoding="utf-8") as f:
            f.write("\n".join(header_lines))

        # Split translations into chunks and write .c files
        generated_files = [header_path]
        chunks = [translations[i:i+chunk_size]
                  for i in range(0, len(translations), chunk_size)]

        for ci, chunk in enumerate(chunks):
            c_path = os.path.join(output_dir, f"{prefix}_{ci:04d}.c")
            c_lines = [
                "/**",
                f" * Dead or Alive 3 - Recompiled code chunk {ci}",
                f" * Functions: {len(chunk)} "
                f"(0x{chunk[0][0]:08X} - 0x{chunk[-1][0]:08X})",
                " */",
                "",
                "#define RECOMP_GENERATED_CODE",
                f'#include "{header_name}"',
                '#include <math.h>',
                '#include <stdio.h>',
                "",
            ]
            for addr, name, code in chunk:
                c_lines.append(code)

            with open(c_path, "w", encoding="utf-8") as f:
                f.write("\n".join(c_lines))
            generated_files.append(c_path)

            if verbose:
                print(f"  Wrote {c_path} ({len(chunk)} functions)",
                      file=sys.stderr)

        # Generate dispatch table
        dispatch_path = os.path.join(output_dir, f"{prefix}_dispatch.c")
        self._write_dispatch_table(translations, dispatch_path, header_name)
        generated_files.append(dispatch_path)

        # CRT static initializers: looked up directly by main.c's _initterm walk.
        ctor_path = os.path.join(output_dir, f"{prefix}_ctors.c")
        with open(ctor_path, "w", encoding="utf-8") as f:
            f.write("#define RECOMP_GENERATED_CODE\n")
            f.write(f'#include "{header_name}"\n#include <stdio.h>\n#include <math.h>\n\n')
            f.write(_CTOR_PRE)
            f.write("static const struct { uint32_t va; doa3_ctor_fn fn; } g_doa3_ctors[] = {\n")
            for a in CRT_INIT_FUNCS:
                f.write(f"    {{ 0x{a:08X}u, sub_{a:08X} }},\n")
            f.write(_CTOR_POST)
        generated_files.append(ctor_path)

        # Stubs for call targets nothing defines (garbage decoded as code
        # calls into the void); they log the first few calls.
        defined = {name for _, name, _ in translations}
        called = set()
        for _, _, code in translations:
            called.update(re.findall(r"\b(sub_[0-9A-Fa-f]{8})\(\);", code))
        manual = _manual_defined()
        missing = sorted(n for n in called - defined if n not in manual)
        stub_path = os.path.join(output_dir, f"{prefix}_stubs.c")
        with open(stub_path, "w", encoding="utf-8") as f:
            f.write("/* Auto-generated stubs for undefined call targets "
                    "(out-of-section garbage + failed translations). */\n")
            f.write("#define RECOMP_GENERATED_CODE\n")
            f.write(f'#include "{header_name}"\n#include <stdio.h>\n\n')
            for n in missing:
                f.write(f'void {n}(void) {{ static int n=0; if(n++<5) '
                        f'fprintf(stderr, "[STUB] {n} called\\n"); }}\n')
        generated_files.append(stub_path)

        stats["files"] = generated_files
        stats["num_chunks"] = len(chunks)
        stats["chunk_size"] = chunk_size
        return stats

    def _write_dispatch_table(self, translations, output_path, header_name):
        """
        Generate a dispatch table mapping Xbox VA -> function pointer.

        Uses a sorted array + binary search for O(log n) lookup.
        """
        lines = [
            "/**",
            " * Dead or Alive 3 - Recompiled Function Dispatch Table",
            f" * Maps {len(translations)} Xbox VAs to translated function pointers.",
            " * Auto-generated by tools/recomp",
            " */",
            "",
            "#define RECOMP_DISPATCH_H",
            f'#include "{header_name}"',
            '#include <stddef.h>',
            "",
            "/* Generic function pointer type */",
            "typedef void (*recomp_func_t)(void);",
            "",
            "typedef struct {",
            "    uint32_t xbox_va;",
            "    recomp_func_t func;",
            "} recomp_entry_t;",
            "",
            f"static const recomp_entry_t g_recomp_table[] = {{",
        ]

        for addr, name, _ in translations:
            if addr in DISPATCH_EXCLUDE:
                continue
            lines.append(f"    {{ 0x{addr:08X}u, (recomp_func_t){name} }},")

        lines.extend([
            "};",
            "",
            f"static const size_t g_recomp_table_size = "
            f"{DISPATCH_SEARCH_LIMIT};",
            "",
            "/* Binary search for a function by Xbox VA */",
            "recomp_func_t recomp_lookup(uint32_t xbox_va)",
            "{",
            "    size_t lo = 0, hi = g_recomp_table_size;",
            "    while (lo < hi) {",
            "        size_t mid = lo + (hi - lo) / 2;",
            "        if (g_recomp_table[mid].xbox_va < xbox_va)",
            "            lo = mid + 1;",
            "        else if (g_recomp_table[mid].xbox_va > xbox_va)",
            "            hi = mid;",
            "        else",
            "            return g_recomp_table[mid].func;",
            "    }",
            "    return NULL;",
            "}",
            "",
            "/* Get the number of registered functions */",
            "size_t recomp_get_count(void)",
            "{",
            "    return g_recomp_table_size;",
            "}",
            "",
            "/* Call all registered functions (for bulk testing) */",
            "size_t recomp_call_all(void)",
            "{",
            "    size_t i;",
            "    for (i = 0; i < g_recomp_table_size; i++) {",
            "        g_recomp_table[i].func();",
            "    }",
            "    return g_recomp_table_size;",
            "}",
            "",
        ])

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))


# Hand edits in the generated tree that no rule produces: for each
# function, (lifted lines, edited lines, occurrence). Applied last.
HAND_EDITS = {
    0x00011000: [
        (('    if (((int8_t)(HI8(ebx) & HI8(ebx)) >= 0)) { g_seh_ebp = ebp; sub_00011050(); return; } /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(ebx) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) { g_seh_ebp = ebp; sub_00011050(); return; } /* jns: not sign (positive) */',), 0),
    ],
    0x00011055: [
        (('    if (((int8_t)(LO8(ebx) & LO8(ebx)) >= 0)) goto loc_000110EC; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(ebx) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_000110EC; /* jns: not sign (positive) */',), 0),
    ],
    0x00016470: [
        (('    _rcc = (CMP_NE(LO16(edx), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_NE(LO16(edx), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_00017F5A; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_00017F5A; /* jne: not equal / not zero */',), 0),
        (('    _rcc = (CMP_NE(eax, ecx));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_NE(eax, ecx));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_00018010; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_00018010; /* jne: not equal / not zero */',), 0),
    ],
    0x000171BD: [
        (('    _rcc = (CMP_NE(LO8(eax), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_NE(LO8(eax), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_000174F3; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_000174F3; /* jne: not equal / not zero */',), 0),
    ],
    0x000173BE: [
        (('    _rcc = (CMP_NE(LO8(eax), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_NE(LO8(eax), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) { g_seh_ebp = ebp; sub_000174F3(); return; } /* jne: not equal / not zero */',),
         ('    if (_rccf) { g_seh_ebp = ebp; sub_000174F3(); return; } /* jne: not equal / not zero */',), 0),
    ],
    0x00017F84: [
        (('    _rcc = (CMP_NE(eax, ecx));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_NE(eax, ecx));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_00018010; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_00018010; /* jne: not equal / not zero */',), 0),
    ],
    0x0001A204: [
        (('    if (!TEST_S(LO16(eax), LO16(eax))) goto loc_0001A55C; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0001A55C; /* jge: greater or equal (signed >=) */',), 0),
        (('    if (!TEST_S(LO16(eax), LO16(eax))) goto loc_0001A5C1; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0001A5C1; /* jge: greater or equal (signed >=) */',), 0),
        (('    if (!TEST_S(LO16(eax), LO16(eax))) goto loc_0001A614; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0001A614; /* jge: greater or equal (signed >=) */',), 0),
        (('    _rcc = (CMP_NE(MEM8(eax + 0x33), 2));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_NE(MEM8(eax + 0x33), 2));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_0001A63D; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_0001A63D; /* jne: not equal / not zero */',), 0),
        (('    if (!TEST_S(LO16(eax), LO16(eax))) goto loc_0001A647; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0001A647; /* jge: greater or equal (signed >=) */',), 0),
        (('    if ((!TEST_S(LO16(eax), LO16(eax)) && !TEST_Z(LO16(eax), LO16(eax)))) goto loc_0001ACA4; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0001ACA4; /* jg: greater (signed >) */',), 0),
        (('    if ((!TEST_S(LO16(eax), LO16(eax)) && !TEST_Z(LO16(eax), LO16(eax)))) goto loc_0001AD2F; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0001AD2F; /* jg: greater (signed >) */',), 0),
    ],
    0x0001A4E9: [
        (('    _rcc = (CMP_NE(MEM8(eax + 0x33), 2));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_NE(MEM8(eax + 0x33), 2));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_0001A63D; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_0001A63D; /* jne: not equal / not zero */',), 0),
    ],
    0x0001A8E1: [
        (('    if ((!TEST_S(LO16(eax), LO16(eax)) && !TEST_Z(LO16(eax), LO16(eax)))) goto loc_0001ACA4; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0001ACA4; /* jg: greater (signed >) */',), 0),
        (('    if ((!TEST_S(LO16(eax), LO16(eax)) && !TEST_Z(LO16(eax), LO16(eax)))) goto loc_0001AD2F; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0001AD2F; /* jg: greater (signed >) */',), 0),
    ],
    0x0001A920: [
        (('    if ((!TEST_S(LO16(eax), LO16(eax)) && !TEST_Z(LO16(eax), LO16(eax)))) goto loc_0001ACA4; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0001ACA4; /* jg: greater (signed >) */',), 0),
        (('    if ((!TEST_S(LO16(eax), LO16(eax)) && !TEST_Z(LO16(eax), LO16(eax)))) goto loc_0001AD2F; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0001AD2F; /* jg: greater (signed >) */',), 0),
    ],
    0x0001B190: [
        (('    _rcc = (CMP_NE(MEM16(eax + ecx * 8), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_NE(MEM16(eax + ecx * 8), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_0001B21F; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_0001B21F; /* jne: not equal / not zero */',), 0),
    ],
    0x0001DE8B: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_0001DED1; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0001DED1; /* jns: not sign (positive) */',), 0),
    ],
    0x0001DF10: [
        (('    _rcc = (TEST_Z(LO8(edx), LO8(edx)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_Z(LO8(edx), LO8(edx)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_0001E1F5; /* je: equal / zero */',),
         ('    if (_rccf) goto loc_0001E1F5; /* je: equal / zero */',), 0),
        (('    _rcc = (TEST_NZ(LO8(ecx), LO8(ecx)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_NZ(LO8(ecx), LO8(ecx)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_0001E253; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_0001E253; /* jne: not equal / not zero */',), 0),
    ],
    0x0001F590: [
        (('    _rcc = (CMP_NE(LO8(eax), 2));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_NE(LO8(eax), 2));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_0001F871; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_0001F871; /* jne: not equal / not zero */',), 0),
    ],
    0x0001FE10: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_0001FF81; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0001FF81; /* jns: not sign (positive) */',), 0),
    ],
    0x00024920: [
        (('    if (((int8_t)(LO8(ecx) & LO8(ecx)) >= 0)) goto loc_0002494E; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(ecx) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0002494E; /* jns: not sign (positive) */',), 0),
    ],
    0x0002870C: [
        (('    _rcc = (TEST_Z(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_Z(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_000287A8; /* je: equal / zero */',),
         ('    if (_rccf) goto loc_000287A8; /* je: equal / zero */',), 0),
    ],
    0x000289A0: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_0002943D; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0002943D; /* jns: not sign (positive) */',), 0),
    ],
    0x00028FAC: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_0002943D; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0002943D; /* jns: not sign (positive) */',), 0),
    ],
    0x00028FF8: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_0002943D; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0002943D; /* jns: not sign (positive) */',), 0),
    ],
    0x0002A6AB: [
        (('    fp_top() = fp_top() * (double)MEMF(0x1ED480); /* fmul mem */',),
         ('    fp_top() *= (double)MEMF(0x1ED480);',), 0),
        (('    fp_top() = fp_top() - (double)MEMF(0x48081C); /* fsub mem */', '    fp_top() = (double)MEMF(0x47E758) / fp_top(); /* fdivr mem */'),
         ('    fp_top() -= (double)MEMF(0x48081C);', '    fp_top() = (double)MEMF(0x47E758) / fp_top();'), 0),
        (('    { fp_top() = tan(fp_top()); fp_push(1.0); } /* fptan */',),
         ('    fp_top() = tan(fp_top()); fp_push(1.0);',), 0),
        (('    fp_top() = fp_top() / g_fp_stack[(g_fp_top + 2) & 7]; /* fdiv st(2) */', '    g_fp_stack[(g_fp_top + 1) & 7] = g_fp_stack[(g_fp_top + 1) & 7] * fp_top(); fp_pop(); /* fmulp st(1) */'),
         ('    fp_top() /= g_fp_stack[(g_fp_top + 2) & 7];', '    fp_st1() *= fp_top(); fp_pop(); /* fmulp */'), 0),
        (('    fp_top() = fp_top() + fp_top(); /* fadd st(0), st(0) */', '    fp_top() = fp_top() * (double)MEMF(0x1ED480); /* fmul mem */', '    { fp_top() = tan(fp_top()); fp_push(1.0); } /* fptan */'),
         ('    fp_top() += fp_top();', '    fp_top() *= (double)MEMF(0x1ED480);', '    fp_top() = tan(fp_top()); fp_push(1.0);'), 0),
        (('    fp_top() = (double)MEMF(0x1ED554) / fp_top(); /* fdivr mem */', '    fp_top() = fp_top() * (double)MEMF(esi + 0x3A0); /* fmul mem */'),
         ('    fp_top() = (double)MEMF(0x1ED554) / fp_top();', '    fp_top() *= (double)MEMF(esi + 0x3A0);'), 0),
        (('    { fp_top() = tan(fp_top()); fp_push(1.0); } /* fptan */',),
         ('    fp_top() = tan(fp_top()); fp_push(1.0);',), 2),
        (('    fp_top() = (double)MEMF(0x1ED554) / fp_top(); /* fdivr mem */', '    fp_top() = fp_top() * (double)MEMF(esi + 0x3A4); /* fmul mem */'),
         ('    fp_top() = (double)MEMF(0x1ED554) / fp_top();', '    fp_top() *= (double)MEMF(esi + 0x3A4);'), 0),
        (('    fp_top() = fp_top() * (double)MEMF(esi + 0x3A8); /* fmul mem */',),
         ('    fp_top() *= (double)MEMF(esi + 0x3A8);',), 0),
        (('    fp_top() = fp_top() * (double)MEMF(0x48081C); /* fmul mem */',),
         ('    fp_top() *= (double)MEMF(0x48081C);',), 0),
    ],
    0x0002C0C0: [
        (('    _rcc = (TEST_S(LO16(ecx), LO16(ecx)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rcc = (CMP_GE(LO16(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */);  /* DOA3 bug #14: the guest sets these flags at 0002C597 and the branch at 0002C59D reads them; ecx is overwritten in between, so the condition is evaluated here, where x86 evaluates it. */',), 0),
        (('    if (!_rcc) goto loc_0002C5A1; /* jge: greater or equal (signed >=) */',),
         ('    if (_rcc) goto loc_0002C5A1; /* jge: greater or equal (signed >=) */',), 0),
        (('    _rcc = (TEST_S(LO16(ecx), LO16(ecx)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rcc = (CMP_GE(LO16(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */);  /* DOA3 bug #14: the guest sets these flags at 0002C5B0 and the branch at 0002C5B6 reads them; ecx is overwritten in between, so the condition is evaluated here, where x86 evaluates it. */',), 1),
        (('    if (!_rcc) goto loc_0002C5BA; /* jge: greater or equal (signed >=) */',),
         ('    if (_rcc) goto loc_0002C5BA; /* jge: greater or equal (signed >=) */',), 0),
        (('    _rcc = (TEST_S(LO16(eax), LO16(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rcc = (CMP_GE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */);  /* DOA3 bug #14: the guest sets these flags at 0002C5C9 and the branch at 0002C5CF reads them; eax is overwritten in between, so the condition is evaluated here, where x86 evaluates it. */',), 0),
        (('    if (!_rcc) goto loc_0002C5D3; /* jge: greater or equal (signed >=) */',),
         ('    if (_rcc) goto loc_0002C5D3; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x0003166D: [
        (('    _rcc = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_00031DA5; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_00031DA5; /* jne: not equal / not zero */',), 0),
        (('    _rcc = (CMP_EQ(eax, 2));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_EQ(eax, 2));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_0003272E; /* je: equal / zero */',),
         ('    if (_rccf) goto loc_0003272E; /* je: equal / zero */',), 0),
    ],
    0x000323B5: [
        (('    _rcc = (CMP_EQ(eax, 2));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_EQ(eax, 2));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_0003272E; /* je: equal / zero */',),
         ('    if (_rccf) goto loc_0003272E; /* je: equal / zero */',), 0),
    ],
    0x00037A9C: [
        (('    _rcc = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_00037B28; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_00037B28; /* jne: not equal / not zero */',), 0),
    ],
    0x00038310: [
        (('    _rcc = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_0003849C; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_0003849C; /* jne: not equal / not zero */',), 0),
    ],
    0x0003AA4F: [
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_0003AC4C; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0003AC4C; /* jns: not sign (positive) */',), 0),
    ],
    0x0003AAE3: [
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_0003AC4C; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0003AC4C; /* jns: not sign (positive) */',), 0),
    ],
    0x0003C3A0: [
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_0003C3CA; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0003C3CA; /* jns: not sign (positive) */',), 0),
    ],
    0x0003FD20: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_000403BB; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_000403BB; /* jns: not sign (positive) */',), 0),
    ],
    0x00040380: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) { g_seh_ebp = ebp; sub_000403BB(); return; } /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) { g_seh_ebp = ebp; sub_000403BB(); return; } /* jns: not sign (positive) */',), 0),
    ],
    0x000403F0: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_0004127C; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0004127C; /* jns: not sign (positive) */',), 0),
    ],
    0x00042E37: [
        (('    if ((!TEST_S(LO8(eax), LO8(eax)) && !TEST_Z(LO8(eax), LO8(eax)))) goto loc_00042ECA; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_00042ECA; /* jg: greater (signed >) */',), 0),
    ],
    0x00045EC9: [
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_00045F89; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_00045F89; /* jns: not sign (positive) */',), 0),
    ],
    0x0004C930: [
        (('    if (!TEST_S(LO16(eax), LO16(eax))) goto loc_0004C991; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004C991; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x0004CA10: [
        (('    if (!TEST_S(LO16(eax), LO16(eax))) goto loc_0004CA77; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004CA77; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x0004D4D0: [
        (('    if ((TEST_S(LO8(ecx), LO8(ecx)) || TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D5A7; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D5A7; /* jle: less or equal (signed <=) */',), 0),
        (('    if ((!TEST_S(LO8(ecx), LO8(ecx)) && !TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D723; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D723; /* jg: greater (signed >) */',), 0),
        (('    if ((!TEST_S(LO8(ecx), LO8(ecx)) && !TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D723; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D723; /* jg: greater (signed >) */',), 1),
        (('    if ((!TEST_S(LO8(ecx), LO8(ecx)) && !TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D6A8; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D6A8; /* jg: greater (signed >) */',), 0),
        (('    if ((!TEST_S(LO8(ecx), LO8(ecx)) && !TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D723; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D723; /* jg: greater (signed >) */',), 2),
        (('    if ((TEST_S(LO8(ecx), LO8(ecx)) || TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D723; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D723; /* jle: less or equal (signed <=) */',), 0),
        (('    if ((!TEST_S(LO8(ecx), LO8(ecx)) && !TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D721; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D721; /* jg: greater (signed >) */',), 0),
    ],
    0x0004D580: [
        (('    if ((TEST_S(LO8(ecx), LO8(ecx)) || TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D5A7; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D5A7; /* jle: less or equal (signed <=) */',), 0),
        (('    if ((!TEST_S(LO8(ecx), LO8(ecx)) && !TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D723; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D723; /* jg: greater (signed >) */',), 0),
        (('    if ((!TEST_S(LO8(ecx), LO8(ecx)) && !TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D723; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D723; /* jg: greater (signed >) */',), 1),
        (('    if ((!TEST_S(LO8(ecx), LO8(ecx)) && !TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D6A8; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D6A8; /* jg: greater (signed >) */',), 0),
        (('    if ((!TEST_S(LO8(ecx), LO8(ecx)) && !TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D723; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D723; /* jg: greater (signed >) */',), 2),
        (('    if ((TEST_S(LO8(ecx), LO8(ecx)) || TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D723; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D723; /* jle: less or equal (signed <=) */',), 0),
        (('    if ((!TEST_S(LO8(ecx), LO8(ecx)) && !TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0004D721; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004D721; /* jg: greater (signed >) */',), 0),
    ],
    0x0004DE0E: [
        (('    if ((TEST_S(LO8(eax), LO8(eax)) || TEST_Z(LO8(eax), LO8(eax)))) goto loc_0004DE3F; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004DE3F; /* jle: less or equal (signed <=) */',), 0),
        (('    if ((!TEST_S(LO8(eax), LO8(eax)) && !TEST_Z(LO8(eax), LO8(eax)))) goto loc_0004E091; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004E091; /* jg: greater (signed >) */',), 0),
        (('    if ((!TEST_S(LO8(eax), LO8(eax)) && !TEST_Z(LO8(eax), LO8(eax)))) goto loc_0004E091; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004E091; /* jg: greater (signed >) */',), 1),
        (('    if ((TEST_S(LO8(eax), LO8(eax)) || TEST_Z(LO8(eax), LO8(eax)))) goto loc_0004E12F; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004E12F; /* jle: less or equal (signed <=) */',), 0),
        (('    if ((!TEST_S(LO8(eax), LO8(eax)) && !TEST_Z(LO8(eax), LO8(eax)))) goto loc_0004E08D; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0004E08D; /* jg: greater (signed >) */',), 0),
    ],
    0x00051011: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_00051112; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_00051112; /* jns: not sign (positive) */',), 0),
    ],
    0x000570F0: [
        (('    if (!TEST_S(LO16(eax), LO16(eax))) goto loc_000571A9; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_000571A9; /* jge: greater or equal (signed >=) */',), 0),
        (('    if ((TEST_S(LO16(eax), LO16(eax)) || TEST_Z(LO16(eax), LO16(eax)))) goto loc_000572AE; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_000572AE; /* jle: less or equal (signed <=) */',), 0),
        (('    if ((!TEST_S(LO16(eax), LO16(eax)) && !TEST_Z(LO16(eax), LO16(eax)))) goto loc_000572AE; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_000572AE; /* jg: greater (signed >) */',), 0),
    ],
    0x000612E5: [
        (('    if (!TEST_S(LO16(esi), LO16(esi))) goto loc_000616DE; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(esi), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_000616DE; /* jge: greater or equal (signed >=) */',), 0),
        (('    if (!TEST_S(LO16(edi), LO16(edi))) goto loc_000616F7; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(edi), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_000616F7; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x000616B0: [
        (('    if (!TEST_S(LO16(esi), LO16(esi))) goto loc_000616DE; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(esi), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_000616DE; /* jge: greater or equal (signed >=) */',), 0),
        (('    if (!TEST_S(LO16(edi), LO16(edi))) goto loc_000616F7; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(edi), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_000616F7; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x0006F880: [
        (('    if (((int8_t)(LO8(edx) & LO8(edx)) >= 0)) { g_seh_ebp = ebp; sub_0006F8A1(); return; } /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(edx) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) { g_seh_ebp = ebp; sub_0006F8A1(); return; } /* jns: not sign (positive) */',), 0),
    ],
    0x0006F8A3: [
        (('    { double _t = fp_top(); fp_top() = g_fp_stack[(g_fp_top + 1) & 7]; g_fp_stack[(g_fp_top + 1) & 7] = _t; } /* fxch st(1) */',),
         ('    { double _t = fp_top(); fp_top() = fp_st1(); fp_st1() = _t; } /* fxch */',), 0),
    ],
    0x0006F9DC: [
        (('    /* cmp MEM8(ecx * 8 + 0x4A03B2), 0 - flags set for next jcc */', "    if (CMP_NE(MEM8(ecx * 8 + 0x4A03B2), 0)) goto loc_0006FA59; /* jne: shared jump at loc_0006F9FB, this path's flags */"),
         ('    /* DOA3: the jne at 0x6F9FB has two flag producers -- this cmp (reached', '     * via the jmp at 0x6F9F2) and `test cl, cl` at 0x6F9F9. The lift kept', '     * only the second, so on this path it tested cl = the story fight index', '     * instead of the per-fight byte [idx*8 + 0x4A03B2]. On fight 0 that', '     * returned phase 3 instead of 4, and sub_0006FA60 then faded to black', '     * right after the winner pose, over the WINNER/quote screen (black', '     * background, flat white WINNER). Evaluate the real compare here. */', '    if (MEM8(ecx * 8 + 0x4A03B2) != 0) goto loc_0006FA59; /* jne */'), 0),
    ],
    0x00070410: [
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_000705BD; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0)) goto loc_000705BD; /* jns: not sign (positive) */',), 0),
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_000704BE; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0)) goto loc_000704BE; /* jns: not sign (positive) */',), 0),
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_0007050E; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0)) goto loc_0007050E; /* jns: not sign (positive) */',), 0),
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_00070564; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0)) goto loc_00070564; /* jns: not sign (positive) */',), 0),
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_000705BA; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0)) goto loc_000705BA; /* jns: not sign (positive) */',), 0),
    ],
    0x000711F0: [
        (('    _rcc = (CMP_NE(LO8(eax), 5));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_NE(LO8(eax), 5));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_0007123A; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_0007123A; /* jne: not equal / not zero */',), 0),
        (('    _rcc = (CMP_EQ(eax, edx));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_EQ(eax, edx));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_000718E3; /* je: equal / zero */',),
         ('    if (_rccf) goto loc_000718E3; /* je: equal / zero */',), 0),
    ],
    0x000722A0: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_0007269D; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0007269D; /* jns: not sign (positive) */',), 0),
    ],
    0x00074240: [
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_000742CB; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0)) goto loc_000742CB; /* jns: not sign (positive) */',), 0),
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_0007443B; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0)) goto loc_0007443B; /* jns: not sign (positive) */',), 0),
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_0007443B; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0)) goto loc_0007443B; /* jns: not sign (positive) */',), 1),
    ],
    0x00077FF0: [
        (('    _rcc = (CMP_NE(LO8(eax), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_NE(LO8(eax), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    MEM8(esp + 0x11) = (_rcc) ? 1 : 0; /* setne */',),
         ('    MEM8(esp + 0x11) = (_rccf) ? 1 : 0; /* setne */',), 0),
        (('    _rcc = (TEST_Z(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_Z(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_000786A9; /* je: equal / zero */',),
         ('    if (_rccf) goto loc_000786A9; /* je: equal / zero */',), 0),
        (('    _rcc = (CMP_NE(LO8(eax), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_NE(LO8(eax), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 1),
        (('    if (_rcc) goto loc_00078EB2; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_00078EB2; /* jne: not equal / not zero */',), 0),
    ],
    0x0007C1A0: [
        (('    if (((int8_t)(LO8(edx) & LO8(edx)) >= 0)) goto loc_0007C222; /* jns: not sign (positive) */',),
         ('    /* DOA3: jns after test dl,dl tests bit 7 of the byte. The lift cast the', '     * unsigned LO8 to int32_t, which is never negative, so every script sound', '     * command flagged 0x80 - the cutscene dialogue lines - went to the effect', '     * table at 0x7C2B4 instead of the dialogue path (0x9FEE0) and was never', '     * played. (movsx above leaves the low byte unchanged.) */', '    if ((int8_t)LO8(edx) >= 0) goto loc_0007C222; /* jns: not sign (positive) */'), 0),
    ],
    0x0007E720: [
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) { g_seh_ebp = ebp; sub_0007E787(); return; } /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) { g_seh_ebp = ebp; sub_0007E787(); return; } /* jns: not sign (positive) */',), 0),
    ],
    0x0007EE70: [
        (('    _rcc = (TEST_NZ(LO8(edx), LO8(edx)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_NZ(LO8(edx), LO8(edx)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_0007EEA2; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_0007EEA2; /* jne: not equal / not zero */',), 0),
    ],
    0x000819F0: [
        (('    /* cmp MEM8(0x48A470), 1 - flags set for next jcc */',),
         ('    if (CMP_NE(MEM8(0x48A470), 1)) goto loc_00081AC9; /* jne after cmp: not already paused */',), 0),
        (('    if (CMP_NE(MEM8(0x48A470), 1)) goto loc_00081AC9; /* jne: not equal / not zero */',),
         (), 0),
    ],
    0x00084340: [
        (('loc_00084430: ;',),
         ('loc_00084430: ;', '    { extern void doa3_ebxwp_disarm(void); doa3_ebxwp_disarm(); } /* DOA3 diag: end of the ebx watch window */'), 0),
        (('    _cf = ((uint32_t)(MEM32(0x4B82FC)) < (uint32_t)(ebx)); /* CF from cmp */',),
         (), 0),
        (('    _cf = 0; /* CF from or */',),
         (), 0),
    ],
    0x00085235: [
        (('    if ((TEST_S(LO16(eax), LO16(eax)) || TEST_Z(LO16(eax), LO16(eax)))) goto loc_000852A1; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_000852A1; /* jle: less or equal (signed <=) */',), 0),
    ],
    0x00087464: [
        (('    if (_flags /* ja: above (unsigned >) */) { g_seh_ebp = ebp; sub_000878BF(); return; }',),
         ('    if (_flags /* ja: above (unsigned >) */) { sub_000878BF(); return; }',), 0),
        (('    if (_flags /* ja: above (unsigned >) */) { g_seh_ebp = ebp; sub_000878C3(); return; }',),
         ('    if (_flags /* ja: above (unsigned >) */) { sub_000878C3(); return; }',), 0),
    ],
    0x00087478: [
        (('    if (_flags /* ja: above (unsigned >) */) { g_seh_ebp = ebp; sub_000878BF(); return; }',),
         ('    if (_flags /* ja: above (unsigned >) */) { sub_000878BF(); return; }',), 0),
        (('    if (_flags /* ja: above (unsigned >) */) { g_seh_ebp = ebp; sub_000878C3(); return; }',),
         ('    if (_flags /* ja: above (unsigned >) */) { sub_000878C3(); return; }',), 0),
    ],
    0x000888B0: [
        (('    SET_LO8(edx, ((!TEST_S(LO16(ecx), LO16(ecx)) && !TEST_Z(LO16(ecx), LO16(ecx)))) ? 1 : 0); /* setg */',),
         ('    SET_LO8(edx, (CMP_G(LO16(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) ? 1 : 0); /* setg */',), 0),
    ],
    0x0009DF60: [
        (('    PUSH32(esp, 0); RECOMP_ICALL_SAFE(MEM32(ecx + 0x28), _icall_esp); /* indirect call */',),
         ('    uint32_t _tv = MEM32(ecx + 0x28); PUSH32(esp, 0); RECOMP_ICALL_SAFE(_tv, _icall_esp); /* indirect call */',), 0),
        (('    PUSH32(esp, 0); RECOMP_ICALL_SAFE(MEM32(edx + 0x18), _icall_esp); /* indirect call */',),
         ('    uint32_t _tv = MEM32(edx + 0x18); PUSH32(esp, 0); RECOMP_ICALL_SAFE(_tv, _icall_esp); /* indirect call */',), 0),
        (('    PUSH32(esp, 0); RECOMP_ICALL_SAFE(MEM32(esi + 0x2C), _icall_esp); /* indirect call */',),
         ('    uint32_t _tv = MEM32(esi + 0x2C); PUSH32(esp, 0); RECOMP_ICALL_SAFE(_tv, _icall_esp); /* indirect call */',), 0),
    ],
    0x0009FD00: [
        (('    if (((int8_t)(HI8(ecx) & HI8(ecx)) >= 0)) { sub_0009FD18(); return; } /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(ecx) >= 0)) { sub_0009FD18(); return; } /* jns: not sign (positive) */',), 0),
    ],
    0x0009FD70: [
        (('    if (((int8_t)(HI8(edx) & HI8(edx)) >= 0)) { sub_0009FD88(); return; } /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(edx) >= 0)) { sub_0009FD88(); return; } /* jns: not sign (positive) */',), 0),
    ],
    0x0009FFA0: [
        (('    if (((int8_t)(HI8(ecx) & HI8(ecx)) >= 0)) { sub_0009FFB8(); return; } /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(ecx) >= 0)) { sub_0009FFB8(); return; } /* jns: not sign (positive) */',), 0),
    ],
    0x000A0020: [
        (('    if (((int8_t)(HI8(edx) & HI8(edx)) >= 0)) { sub_000A0038(); return; } /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(edx) >= 0)) { sub_000A0038(); return; } /* jns: not sign (positive) */',), 0),
    ],
    0x000A5190: [
        (('    _rcc = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_000A5734; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_000A5734; /* jne: not equal / not zero */',), 0),
    ],
    0x000A7710: [
        (('    _rcc = ((eax == 0));  /* DOA3 bug #14: flags evaluated where x86 evaluates them */',),
         ('    _rcc = (eax == 0); /* DOA3: the je at 000A7727 consumes the flags of this xor (player == 1); the mov below does not touch flags */',), 0),
    ],
    0x000AF6D9: [
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_000AF72B; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_000AF72B; /* jns: not sign (positive) */',), 0),
    ],
    0x000AF6E2: [
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_000AF72B; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_000AF72B; /* jns: not sign (positive) */',), 0),
    ],
    0x000B2BD0: [
        (('    /* cmp MEM8(ebx + 0x5C), 1 - flags set for next jcc */',),
         ('    RC_SETF_CMP(MEM8(ebx + 0x5C), 1);   /* cmp MEM8(ebx + 0x5C), 1 - flags set for next jcc */',), 0),
    ],
    0x000C7420: [
        (('    if (!TEST_S(LO8(eax), LO8(eax))) goto loc_000C74F7; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_000C74F7; /* jge: greater or equal (signed >=) */',), 0),
        (('    if (!TEST_S(LO8(ebx), LO8(ebx))) goto loc_000C753E; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO8(ebx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_000C753E; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x000C8EF0: [
        (('    _rcc = (TEST_Z(LO8(ebx), LO8(ebx)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_Z(LO8(ebx), LO8(ebx)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) { g_seh_ebp = ebp; sub_000C8F77(); return; } /* je: equal / zero */',),
         ('    if (_rccf) { g_seh_ebp = ebp; sub_000C8F77(); return; } /* je: equal / zero */',), 0),
    ],
    0x000CBE00: [
        (('    _rcc = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 1),
        (('    if (_rcc) goto loc_000CC14B; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_000CC14B; /* jne: not equal / not zero */',), 0),
    ],
    0x000E3392: [
        (('    if (!TEST_S(LO8(eax), LO8(eax))) goto loc_000E348C; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_000E348C; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x000E64E2: [
        (('    if (!TEST_S(LO8(eax), LO8(eax))) goto loc_000E65DC; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_000E65DC; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x000EA720: [
        (('    /* cmp LO16(ecx), MEM16(esi + 6) - flags set for next jcc */',),
         ('    RC_SETF_CMP(LO16(ecx), MEM16(esi + 6));   /* cmp LO16(ecx), MEM16(esi + 6) - flags set for next jcc */',), 1),
    ],
    0x000EDCC0: [
        (('    if (_flags /* loope: loope */) { g_seh_ebp = ebp; sub_000EE201(); return; }',),
         ('    if (_flags /* loope: loope */) { sub_000EE201(); return; }',), 0),
        (('    /* nop */',),
         ('    /* nop */', '    g_seh_ebp = ebp; sub_000EE200(); return; /* DOA3: restored dropped fall-through to sub_000EE200 */'), 2),
        (('    g_seh_ebp = ebp; sub_000EE200(); return; /* DOA3: restored dropped fall-through to sub_000EE200 */',),
         (), 0),
    ],
    0x00109BF0: [
        (('    if ((TEST_S(LO16(eax), LO16(eax)) || TEST_Z(LO16(eax), LO16(eax)))) goto loc_00109CA8; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_00109CA8; /* jle: less or equal (signed <=) */',), 0),
    ],
    0x0010BF00: [
        (('    if ((TEST_S(LO16(eax), LO16(eax)) || TEST_Z(LO16(eax), LO16(eax)))) goto loc_0010C00E; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0010C00E; /* jle: less or equal (signed <=) */',), 0),
    ],
    0x0011E680: [
        (('    edx = MEM32(esp + 0x1C);',),
         ('    edx = MEM32(esp + 0x1C);', '    { static int n = 0; if (MEM32(edx + ecx * 4) == 0x1E10D0 && n < 6) { n++;  } } /* DOA3 DIAG */'), 0),
    ],
    0x001200C1: [
        (('    uint32_t ebp;',),
         ('    /* DOA3: snapshot the inherited frame pointer.', "     * This fragment runs inside sub_0011FF70's frame, whose epilogue in", '     * sub_001200E8 restores the stack with `esp = ebp` -- and the recompiler', '     * carries that inherited ebp in the GLOBAL g_seh_ebp. On x86 ebp is', '     * callee-saved, so the six calls below leave it untouched; here each of', '     * them overwrites g_seh_ebp for its own frame and never puts it back, so', '     * sub_001200E8 restored esp from a stale value and lost ~224 bytes per', '     * call. Snapshot on entry and restore before the hand-off. */', '    uint32_t ebp = g_seh_ebp;'), 0),
        (("    ebp = g_seh_ebp; /* DOA3: carry the caller's frame to the hand-off */",),
         (), 0),
        (('    g_seh_ebp = ebp; sub_001200E8(); return; /* DOA3: restored dropped fall-through to sub_001200E8 */',),
         ('    g_seh_ebp = ebp;   /* DOA3: see the note at the top of this fragment */', '    sub_001200E8(); return; /* DOA3: restored dropped fall-through to sub_001200E8 */'), 0),
    ],
    0x0012DFA5: [
        (('    if ((TEST_S(LO16(ecx), LO16(ecx)) || TEST_Z(LO16(ecx), LO16(ecx)))) goto loc_0012E125; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO16(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0012E125; /* jle: less or equal (signed <=) */',), 0),
        (('    if ((TEST_S(LO8(ecx), LO8(ecx)) || TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_0012E103; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0012E103; /* jle: less or equal (signed <=) */',), 0),
    ],
    0x0013BA50: [
        (('    if ((!TEST_S(LO8(eax), LO8(eax)) && !TEST_Z(LO8(eax), LO8(eax)))) goto loc_0013BBF9; /* jg: greater (signed >) */',),
         ('    if (CMP_G(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0013BBF9; /* jg: greater (signed >) */',), 0),
        (('    if ((TEST_S(LO16(eax), LO16(eax)) || TEST_Z(LO16(eax), LO16(eax)))) goto loc_0013BCD1; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0013BCD1; /* jle: less or equal (signed <=) */',), 0),
        (('    if ((TEST_S(LO16(eax), LO16(eax)) || TEST_Z(LO16(eax), LO16(eax)))) goto loc_0013BCF3; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0013BCF3; /* jle: less or equal (signed <=) */',), 0),
    ],
    0x0014012F: [
        (('    if ((TEST_S(LO16(eax), LO16(eax)) || TEST_Z(LO16(eax), LO16(eax)))) goto loc_001402AA; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_001402AA; /* jle: less or equal (signed <=) */',), 0),
        (('    if ((TEST_S(LO16(ecx), LO16(ecx)) || TEST_Z(LO16(ecx), LO16(ecx)))) goto loc_00140286; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO16(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_00140286; /* jle: less or equal (signed <=) */',), 0),
    ],
    0x0014030F: [
        (('    if ((TEST_S(LO16(eax), LO16(eax)) || TEST_Z(LO16(eax), LO16(eax)))) goto loc_0014048A; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0014048A; /* jle: less or equal (signed <=) */',), 0),
        (('    if ((TEST_S(LO16(ecx), LO16(ecx)) || TEST_Z(LO16(ecx), LO16(ecx)))) goto loc_00140466; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO16(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_00140466; /* jle: less or equal (signed <=) */',), 0),
    ],
    0x001406DE: [
        (('    if (!TEST_S(LO8(eax), LO8(eax))) goto loc_0014084C; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_0014084C; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x00140A80: [
        (('    if (!TEST_S(LO8(eax), LO8(eax))) goto loc_00140C0A; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_00140C0A; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x00141EE8: [
        (('    if (!TEST_S(LO16(eax), LO16(eax))) goto loc_00141FC5; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_00141FC5; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x00142888: [
        (('    if (!TEST_S(LO16(eax), LO16(eax))) goto loc_001428B6; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(LO16(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_001428B6; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x0014872B: [
        (('    if ((TEST_S(LO8(eax), LO8(eax)) || TEST_Z(LO8(eax), LO8(eax)))) goto loc_001489CB; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(eax), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_001489CB; /* jle: less or equal (signed <=) */',), 0),
    ],
    0x00157276: [
        (('    uint32_t ebp;',),
         ('    /* This fragment falls through into sub_0015728A, which inherits its', '     * frame pointer from g_seh_ebp and then reads its loop bound from', '     * [ebp+0x48]. g_seh_ebp is a single global, so the sub_001B2390 call', '     * below (or anything in its subtree -- 12902 sites assign it) could', '     * overwrite the pending handoff before the fall-through consumed it.', '     * The generator omitted the usual inherit/re-set pair here because', '     * this fragment does not otherwise mention ebp.', '     *', '     * With a clobbered handoff the bound came from [garbage+0x48], so the', '     * texture-stage loop ran to stage 0x1C (the Xbox has four) and handed', '     * float data to D3DDevice_SetTexture, which passed it to the refcount', '     * walker sub_001B4960 as a resource pointer -- the crash. */', "    uint32_t ebp = g_seh_ebp; /* fpo_leaf: inherit caller's frame */"), 0),
        (("    ebp = g_seh_ebp; /* DOA3: carry the caller's frame to the hand-off */",),
         (), 0),
    ],
    0x001579A2: [
        (('    if (_flags /* jne: not equal / not zero */) { sub_001577B2(); return; }',),
         ('    /* DOA3: the guest is  0x001579A0 test esi,esi / 0x001579A2 jne 0x001577B2.', '     * The lifter split the test and the branch across two fragments, so the', '     * branch was emitted reading an uninitialised local and was never taken:', '     * every stage object whose block chain passed through here stopped at', "     * its first type != 0 block -- the temple's wall panels and the", '     * interior walls. */', '    if (TEST_NZ(esi, esi)) { sub_001577B2(); return; }'), 0),
    ],
    0x00158D60: [
        (('    /* cmp eax, ecx - flags set for next jcc */', '    _rccf = (CMP_EQ(eax, ecx));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */'),
         ('    /* DOA3: the guest is  0x00158D6B cmp eax,ecx / 0x00158D6D mov ecx,[esp+4]', '     * / 0x00158D71 je 0x00158DBB.  The mov clobbers ecx but not the flags;', '     * the lifter re-evaluated the compare at the jcc, so this tested the', "     * render-state generation against the draw descriptor's address instead", '     * of against the generation of the last emitted state block.  That is', '     * never equal, so a fresh command-list entry was started for every single', '     * draw.  sub_00158BE0 still deduped the 0x290-byte state block, so those', '     * extra entries began at a type-1 record with no bind in front of them:', '     * the interpreter replayed them against whatever index buffer the', "     * previous entry had left bound, and the fighters' draws read indices", '     * past the end of it -- the stretched geometry coming off the players. */', '    RC_SETF_CMP(eax, ecx);'), 0),
        (('    if (_rccf) goto loc_00158DBB; /* je: equal / zero */',),
         ('    if (RC_F_JE()) goto loc_00158DBB; /* je: equal / zero */',), 0),
    ],
    0x00158DE0: [
        (('    if (CMP_NE(ebx, MEM32(ebp + 8))) goto loc_00158E20; /* jne: not equal / not zero */',),
         ('    /* Reach-or-pass. ebx only advances (+0x14, +0xC, +0x290) toward the', '     * bound in [ebp+8], and the guest exits only on exact equality --', '     * which never happens when the two do not sit on the same grid, so', '     * the walk runs off through memory. Third instance of this pattern', '     * in the same family (sub_00159010, sub_00159180 were the others);', '     * each one in turn held 100%% of the CPU. */', '    if (CMP_B(ebx, MEM32(ebp + 8))) goto loc_00158E20; /* was jne */'), 0),
    ],
    0x00159010: [
        (('    if (CMP_NE(ecx, eax)) goto loc_00159031; /* jne: not equal / not zero */',),
         ('    /* The guest stops only when the walker lands EXACTLY on the end', '     * sentinel at [0x99A1F8]. Safe on hardware, where start and end bound', '     * a contiguous array of 0x14-byte entries. Here they do not always', '     * agree, the equality never hits, and the walk runs off through memory', '     * calling MatrixStore with [esi+0xC]+4 as the matrix pointer. The', '     * sampling profiler put 100%% of all CPU in this loop -- which is why', '     * the game ran at ~5%% of real time and the screen stayed black. Stop', '     * on reach-or-pass, which is what the equality means for a well-formed', '     * array. */', '    if (CMP_AE(ecx, eax)) {', '        static int _warned = 0;', '        if (ecx != eax && !_warned) { _warned = 1;', '            fprintf(stderr, "[MWALK] overran end: p=%08X end=%08X after %u entries\\n", ecx, eax, edi);', '            fflush(stderr); }', '    } else goto loc_00159031; /* jne: not equal / not zero */'), 0),
        (('    if (CMP_GE(edx, eax)) goto loc_00159117; /* jge: greater or equal (signed >=) */',),
         ('    /* DOA3: on loop-back this jge uses the flags of `cmp edx, [ebp+8]`; eax is stale. */', '    if (CMP_GE(edx, MEM32(ebp + 8))) goto loc_00159117; /* jge: j >= ir */'), 0),
    ],
    0x00159180: [
        (('    if (CMP_B(esi, edx)) goto loc_001592B1; /* jb: below (unsigned <) */',),
         ('    /* Per-stage loop: calls sub_00156300(stage=esi, entry=edi) for [ebp-12]', '     * stages, stepping the entry array by 0x10. The count comes out of a', '     * state block that is not always well formed, and a garbage count is what', '     * produced the wild stage indices seen downstream (0x13, 0x1C, 0xEE0B) --', '     * sub_00156300 indexes [stage*4 + 0x90FD28] with them and its stores land', '     * outside every table. Log any count far past a plausible stage count and', '     * stop there; 512 is orders of magnitude above anything legitimate and far', '     * below the millions that were burning the CPU. */', '    if (esi > 512u) {', '        static int _warned = 0;', '        if (!_warned) { _warned = 1;', '            fprintf(stderr, "[STGLOOP] count=%u (bounded at %u)\\n", edx, esi);', '            fflush(stderr); }', '    } else if (CMP_B(esi, edx)) goto loc_001592B1; /* jb: below (unsigned <) */'), 0),
        (('    if (CMP_NE(ebx, MEM32(0x99A1FC))) goto loc_001591E0; /* jne: not equal / not zero */',),
         ('    /* Reach-or-pass instead of exact equality. These pointer walks step by', '     * 0x14 (and 0x290) toward a sentinel and only stop when they land on it', '     * exactly -- safe on hardware where the bounds always agree, but here a', '     * mismatched start/end means the equality never hits and the walk runs', '     * off through memory. sub_00159010 had the identical bug and was taking', '     * 100%% of the CPU; after fixing it the profiler moved wholly into this', '     * function (54.7 + 26.3 + 10.0 + 9.0%%). */', '    if (CMP_B(ebx, MEM32(0x99A1FC))) goto loc_001591E0; /* was jne */'), 0),
        (('    if (CMP_NE(eax, ecx)) goto loc_001591D0; /* jne: not equal / not zero */',),
         ('    if (CMP_B(eax, ecx)) goto loc_001591D0; /* was jne: reach-or-pass */',), 0),
    ],
    0x0015CF90: [
        (('    if (((int8_t)(HI8(eax) & HI8(eax)) >= 0)) goto loc_0015D0D0; /* jns: not sign (positive) */',),
         ('    if (((int8_t)HI8(eax) >= 0) /* DOA3 group D: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0015D0D0; /* jns: not sign (positive) */',), 0),
    ],
    0x0015FFE0: [
        (('    if ((TEST_S(LO8(ecx), LO8(ecx)) || TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_001607BC; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_001607BC; /* jle: less or equal (signed <=) */',), 0),
        (('    _rcc = (CMP_GE(edx, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_GE(edx, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 0),
        (('    if (_rcc) goto loc_001611FC; /* jge: greater or equal (signed >=) */',),
         ('    if (_rccf) goto loc_001611FC; /* jge: greater or equal (signed >=) */',), 0),
        (('    _rcc = (CMP_GE(edx, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (CMP_GE(edx, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 1),
        (('    if (_rcc) goto loc_0016155C; /* jge: greater or equal (signed >=) */',),
         ('    if (_rccf) goto loc_0016155C; /* jge: greater or equal (signed >=) */',), 0),
        (('    if ((TEST_S(LO8(ecx), LO8(ecx)) || TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_001618EE; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_001618EE; /* jle: less or equal (signed <=) */',), 0),
        (('    _rcc = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 1),
        (('    if (_rcc) goto loc_00161A03; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_00161A03; /* jne: not equal / not zero */',), 0),
        (('    _rcc = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    _rccf = (TEST_NZ(LO8(eax), LO8(eax)));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',), 2),
        (('    if (_rcc) goto loc_00161AFF; /* jne: not equal / not zero */',),
         ('    if (_rccf) goto loc_00161AFF; /* jne: not equal / not zero */',), 0),
    ],
    0x00160693: [
        (('    if ((TEST_S(LO8(ecx), LO8(ecx)) || TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_001607BC; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_001607BC; /* jle: less or equal (signed <=) */',), 0),
    ],
    0x0016069E: [
        (('    if ((TEST_S(LO8(ecx), LO8(ecx)) || TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_001607BC; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_001607BC; /* jle: less or equal (signed <=) */',), 0),
    ],
    0x00160870: [
        (('    if ((TEST_S(LO8(ecx), LO8(ecx)) || TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_001618EE; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_001618EE; /* jle: less or equal (signed <=) */',), 0),
    ],
    0x00161867: [
        (('    if ((TEST_S(LO8(ecx), LO8(ecx)) || TEST_Z(LO8(ecx), LO8(ecx)))) goto loc_001618EE; /* jle: less or equal (signed <=) */',),
         ('    if (CMP_LE(LO8(ecx), 0) /* DOA3: x&x promoted to int, sign lost at width */) goto loc_001618EE; /* jle: less or equal (signed <=) */',), 0),
    ],
    0x001634C4: [
        (('    /* cmp eax, esi - flags set for next jcc */', '    _rccf = (CMP_GE(eax, esi));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */'),
         ('    /* RECOMP BUG #14 (deferred compare, operand clobbered before the jcc).', '     * The original is `cmp eax, esi` (esi == 0) / `pop esi` / `jge`, so the', '     * branch tests the NT status against ZERO. Evaluating the comparison at', "     * the jcc used the POPPED esi -- the caller's saved value -- instead, so", '     * this directory find-next reported failure on every successful call.', '     * The wxCi cache scanner therefore took one entry per directory and', "     * stopped: z:\\ registered only '\\bgm.afs', loadfile.afs was never in the", '     * cache registry, and every post-movie resource load came back with an', '     * untouched buffer. Snapshot the operand before the pop. */', '    { uint32_t _cmp_lhs = eax, _cmp_rhs = esi;'), 0),
        (('    if (_rccf) { g_seh_ebp = ebp; sub_001634FF(); return; } /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(_cmp_lhs, _cmp_rhs)) { g_seh_ebp = ebp; sub_001634FF(); return; } } /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x001649A8: [
        (('    { uint32_t _icall_esp = g_esp;', '    PUSH32(esp, MEM32(esp + 0x10));', '    eax = esi;', '    esi = MEM32(esi);', '    PUSH32(esp, 0); RECOMP_ICALL_SAFE(MEM32(eax + 8), _icall_esp); /* indirect call */', '    }'),
         ('    /* Guest loop: walk the list (esi = [esi]) calling [node+8] on each node', '     * until esi == edi. The back-edge lives in sub_001649B3, which the lifter', '     * emitted as a CALL back to here -- so every iteration burned a host', '     * stack frame and a long or cyclic list blew the stack (0xC00000FD in', '     * sub_001649A8, with the ICALL trace alternating between two garbage', '     * targets). Run it as an actual loop, and bound it: an unterminated chain', '     * is corrupt, and forcing esi == edi makes the exit path in sub_001649B3', '     * run normally instead of recursing again. */', '    { unsigned _iter = 0;', '      for (;;) {', '        { uint32_t _icall_esp = g_esp;', '        PUSH32(esp, MEM32(esp + 0x10));', '        eax = esi;', '        esi = MEM32(esi);', '        PUSH32(esp, 0); RECOMP_ICALL_SAFE(MEM32(eax + 8), _icall_esp); /* indirect call */', '        }', '        if (esi == edi) break;', '        if (++_iter > 8192u) {', '            static int _warned = 0;', '            if (!_warned) { _warned = 1;', '                fprintf(stderr, "[LWALK] unterminated node list at %08X - bounded\\n", esi);', '                fflush(stderr); }', '            esi = edi;   /* take the exit path in sub_001649B3 */', '            break;', '        }', '      } }'), 0),
    ],
    0x00164FEF: [
        (('    MEM32(ecx + 0xC) = esp;',),
         ('    MEM32(ecx + 0xC) = esp;', '    { extern void doa3_esp_load_log(int, uint32_t, uint32_t); doa3_esp_load_log(1, esp, MEM32(eax + 0xC)); }'), 0),
    ],
    0x00169AF0: [
        (('    _rccf = (CMP_GE(ecx, esi));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    uint32_t _d14_1167_a = (uint32_t)(ecx), _d14_1167_b = (uint32_t)(esi); /* bug14 hoist */',), 0),
        (('    if (_rccf) goto loc_00169B1F; /* jge: greater or equal (signed >=) */',),
         ('    if (CMP_GE(_d14_1167_a, _d14_1167_b)) goto loc_00169B1F; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x0016D0F0: [
        (('    edx = esp + 0x10;',),
         ('    edx = esp + 0x10;', '    /* The cache lookup builds sprintf(buf, "%s%s", prefix, nodename) and', '     * strcmps it against the requested path. The registered prefix ends', '     * with a separator ("d:\\\\") and the stored node names begin with one', '     * ("\\bgm.afs" -- the same form as the file mask the guest passes to', '     * NtQueryDirectoryFile), so the concatenation yields "d:\\\\bgm.afs"', '     * and never matches "d:\\bgm.afs". Every wxCiOpen/wxCiGetFileSize then', '     * reports "not in cache", the post-movie load fails in a retry loop and', '     * the title screen never builds.', '     *', '     * Collapse the doubled separator in the constructed path. That is', '     * exactly the string correct prefix/name data would have produced, so', '     * it only affects paths that are already malformed. */', '    { uint32_t _r = edx, _w = edx;', '      int _prev = 0, _guard = 0;', '      for (; _guard < 260; _guard++) {', '        uint8_t _c = MEM8(_r++);', '        if (_c == 0x5C && _prev == 0x5C) continue;   /* skip a repeated backslash */', '        MEM8(_w++) = _c;', '        _prev = _c;', '        if (!_c) break;', '      } }'), 0),
    ],
    0x00171780: [
        (('    ecx = MEM32(esi + 0xC);',),
         ('    ecx = MEM32(esi + 0xC);', '    if (ecx == 0) ecx = 0x800; /* DOA3 diag: AFS sector size unread (file not opened) — avoid div-by-zero to observe downstream flow */'), 0),
    ],
    0x00172770: [
        (('    _rccf = (CMP_NE(ecx, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc1 = (CMP_NE(ecx, eax)); /* DOA3: flags from the compare above; ecx is overwritten before the jcc */',), 0),
        (('    if (_rccf) goto loc_0017284D; /* jne: not equal / not zero */',),
         ('    if (_cc1) goto loc_0017284D; /* jne: not equal / not zero */',), 0),
        (('    eax = MEM32(esp + 0x2C);', '    /* test eax, eax - flags set for next jcc */', '    _rccf = (TEST_Z(eax, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */', '    eax = MEM32(esp + 0x18);', '    if (_rccf) goto loc_0017285C; /* je: equal / zero */'),
         ('    { int _ch0 = (MEM32(esp + 0x2C) == 0); /* DOA3: `test eax,eax` was on the channel index, evaluated BEFORE eax became the destination pointer */', '      eax = MEM32(esp + 0x18);', '      if (_ch0) goto loc_0017285C; /* je: equal / zero */ }'), 0),
    ],
    0x001735F0: [
        (('    _rccf = (CMP_NE(eax, 2));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc1 = (CMP_NE(eax, 2)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rccf) { g_seh_ebp = ebp; sub_001736C8(); return; } /* jne: not equal / not zero */',),
         ('    if (_cc1) { g_seh_ebp = ebp; sub_001736C8(); return; } /* jne: not equal / not zero */',), 0),
    ],
    0x00174F30: [
        (('    _rccf = (CMP_LE(MEM16(eax + edx + 8), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc2 = (CMP_LE(MEM16(eax + edx + 8), 1)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rccf) { sub_00174F7F(); return; } /* jle: less or equal (signed <=) */',),
         ('    if (_cc2) { sub_00174F7F(); return; } /* jle: less or equal (signed <=) */',), 0),
    ],
    0x001779D0: [
        (('    if (_flags /* ja: above (unsigned >) */) goto loc_00177A45;',),
         ('    /* DOA3 fix (bug #16): lifter emitted the uninitialized _flags fallback for', '     * `dec eax; ja` -- the CSC row loop ran once (2 rows/frame). dec leaves CF', '     * clear here, so ja == (eax != 0): loop over all row pairs. */', '    if (eax != 0) goto loc_00177A45;'), 0),
    ],
    0x00178980: [
        (('    _rccf = (TEST_NZ(eax, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc3 = (TEST_NZ(eax, eax)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rccf) goto loc_00178AB7; /* jne: not equal / not zero */',),
         ('    if (_cc3) goto loc_00178AB7; /* jne: not equal / not zero */',), 0),
    ],
    0x00178A20: [
        (('    _rccf = (TEST_NZ(eax, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc1 = (TEST_NZ(eax, eax)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rccf) goto loc_00178AB7; /* jne: not equal / not zero */',),
         ('    if (_cc1) goto loc_00178AB7; /* jne: not equal / not zero */',), 0),
    ],
    0x0017A0F0: [
        (('    /* test eax, eax - flags set for next jcc */',),
         ('    /* test eax, eax - flags set for next jcc */', '    int _cc4 = (CMP_EQ(eax, ecx)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */'), 0),
        (('    if (CMP_EQ(eax, ecx)) { g_seh_ebp = ebp; sub_0017A188(); return; } /* je: equal / zero */',),
         ('    if (_cc4) { g_seh_ebp = ebp; sub_0017A188(); return; } /* je: equal / zero */',), 0),
    ],
    0x0017A6D0: [
        (('    eax = MEM32(esp + 0x10);',),
         ('    { extern uint32_t g_doa3_a6d0_frame;', '      eax = g_doa3_a6d0_frame ? MEM32(g_doa3_a6d0_frame - 56)', '                              : MEM32(esp + 0x10); }'), 0),
        (('    ecx = MEM32(esp + 0x10);',),
         ('    { extern uint32_t g_doa3_a6d0_frame;   /* slot ptr again (pre-drift) */', '      ecx = g_doa3_a6d0_frame ? MEM32(g_doa3_a6d0_frame - 56)', '                              : MEM32(esp + 0x10); }'), 0),
    ],
    0x0017AAF0: [
        (('    /* cmp eax, esi - flags set for next jcc */', '    _rccf = (CMP_L(eax, esi));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */'),
         ('    /* RECOMP BUG #14: the original is "cmp eax,esi; pop esi; jl" - pop does', '     * not modify flags, but the deferred CMP_L below would use the POPPED', '     * esi. Evaluate the comparison BEFORE the pop. */', '    { int _lt_014 = ((int32_t)eax < (int32_t)esi);'), 0),
        (('    if (_rccf) { sub_0017AB33(); return; } /* jl: less (signed <) */',),
         ('    if (_lt_014) { sub_0017AB33(); return; } } /* jl: less (signed <) */',), 0),
    ],
    0x0017BB10: [
        (('    _rccf = (CMP_EQ(eax, edi));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    uint32_t _d14_2269_a = (uint32_t)(eax), _d14_2269_b = (uint32_t)(edi); /* bug14 hoist */',), 0),
        (('    if (_rccf) goto loc_0017BBA8; /* je: equal / zero */',),
         ('    if (CMP_EQ(_d14_2269_a, _d14_2269_b)) goto loc_0017BBA8; /* je: equal / zero */',), 0),
    ],
    0x0017BFD0: [
        (('    _rccf = (CMP_EQ(ebx, ebp));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    /* DOA3 item 195: RECOMP BUG #14, FIFTH SIGHTING — live ES-delivery path.', '     * Original at 0x0017C025:  cmp ebx, ebp / mov ebp,[esp+0x1c] / je', '     * The mov CLOBBERS ebp, an operand, before the jcc; the deferred emission', '     * evaluated the compare against the RELOADED ebp, so the FIRST video PES', '     * (the 2018-byte packet at file offset 8204 carrying the MPEG sequence', '     * header) was never delivered -> movie started 1.6s in. Hoist both', '     * operands before the clobber. */', '    uint32_t _d14_c025_a = (uint32_t)ebx, _d14_c025_b = (uint32_t)ebp;'), 0),
        (('    if (_rccf) goto loc_0017C098; /* je: equal / zero */',),
         ('    if (CMP_EQ(_d14_c025_a, _d14_c025_b)) goto loc_0017C098; /* je: equal / zero */',), 0),
        (('    /* cmp LO8(eax), 0xB8 - flags set for next jcc */',),
         ('    /* cmp LO8(eax), 0xB8 - flags set for next jcc */', '    int _cc2 = (TEST_Z(eax, eax)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */'), 0),
        (('    if (TEST_Z(eax, eax)) goto loc_0017C098; /* je: equal / zero */',),
         ('    if (_cc2) goto loc_0017C098; /* je: equal / zero */',), 1),
    ],
    0x0017CC30: [
        (('    _rcc = (CMP_GE(eax, esi));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc1 = (CMP_GE(eax, esi)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rcc) goto loc_0017CC81; /* jge: greater or equal (signed >=) */',),
         ('    if (_cc1) goto loc_0017CC81; /* jge: greater or equal (signed >=) */',), 0),
    ],
    0x0017D380: [
        (('    /* test eax, eax - flags set for next jcc */', '    _rccf = (TEST_NZ(eax, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */'),
         ("    /* test eax, eax: the flags come from sub_0017D1D0's return, but the", '     * next instruction overwrites eax with [esi+0x40], so the deferred', '     * compare was evaluating the wrong value (same defect as the', '     * documented 0x0017C025 case). D1D0 returns 0 and [esi+0x40] is 1 on', '     * the end-of-play path, so the branch was taken and the handle stored', '     * 1 instead of 6 (PLAYEND) -- it then cycled 1->2->4->1 forever with', '     * [esi+0x44] already 6, and the movie never reported finished.', '     * Snapshot the return before the clobber. */', '    { uint32_t _d1d0_ret = eax;'), 0),
        (('    if (_rccf) goto loc_0017D430; /* jne: not equal / not zero */',),
         ('    if (TEST_NZ(_d1d0_ret, _d1d0_ret)) goto loc_0017D430; } /* jne */',), 0),
    ],
    0x0017D417: [
        (('    /* test eax, eax - flags set for next jcc */', '    _rccf = (TEST_NZ(eax, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */'),
         ("    /* test eax, eax: the flags come from sub_0017D1D0's return, but the", '     * next instruction overwrites eax with [esi+0x40], so the deferred', '     * compare was evaluating the wrong value (same defect as the', '     * documented 0x0017C025 case). D1D0 returns 0 and [esi+0x40] is 1 on', '     * the end-of-play path, so the branch was taken and the handle stored', '     * 1 instead of 6 (PLAYEND) -- it then cycled 1->2->4->1 forever with', '     * [esi+0x44] already 6, and the movie never reported finished.', '     * Snapshot the return before the clobber. */', '    { uint32_t _d1d0_ret = eax;'), 0),
        (('    if (_rccf) goto loc_0017D430; /* jne: not equal / not zero */',),
         ('    if (TEST_NZ(_d1d0_ret, _d1d0_ret)) goto loc_0017D430; } /* jne */',), 0),
    ],
    0x0017D452: [
        (('    int _flags = 0; /* fallback flag var */', '', 'loc_0017D452: ;', '    edi = edi;', '    /* TODO: out dx, al */', '    /* TODO: rcl dword ptr [edi], cl */', '    MEM8(edi) = MEM8(edi) + LO8(eax);', '    /* TODO: aam 0x17 */', '    MEM8(eax) = MEM8(eax) + LO8(edx);', '    /* TODO: aam 0x17 */', '    MEM8(edi) = MEM8(edi) + LO8(edx);', '    /* TODO: aam 0x17 */', '    MEM8(eax) = MEM8(eax) + HI8(edx);', '    /* TODO: aam 0x17 */', '    MEM8(eax) = MEM8(eax) + HI8(edx);', '    /* TODO: aam 0x17 */', '    MEM8(eax + 0x56909090) = MEM8(eax + 0x56909090) + LO8(edx);', '    esi = MEM32(esp + 8);', '    PUSH32(esp, esi);', '    PUSH32(esp, 0); sub_0017C660(); /* call 0x0017C660 */', '', 'loc_0017D47B: ;', '    esp = esp + 4;', '    if (TEST_Z(eax, eax)) goto loc_0017D493; /* je: equal / zero */', '', 'loc_0017D482: ;', '    PUSH32(esp, 0xFF000138u);', '    PUSH32(esp, 0);', '    PUSH32(esp, 0); sub_0017C6A0(); /* call 0x0017C6A0 */', '', 'loc_0017D48E: ;', '    esp = esp + 8;', '    POP32(esp, esi);', '    esp += 4; return; /* ret */', '', 'loc_0017D493: ;', '    eax = esi;', '    MEM32(esi + 0x3C) = 1;', '    PUSH32(esp, 0); sub_0017D380(); /* call 0x0017D380 */', '', 'loc_0017D4A1: ;', '    eax = 0; /* xor self */', '    POP32(esp, esi);', '    esp += 4; return; /* ret */', ''),
         ('    /* PHANTOM (jumptable data misdetected as code). Never a real call target', '     * on hardware. No-op safely. */', '    eax = 0; esp += 4; return;'), 0),
    ],
    0x0017E9B0: [
        (('    _rccf = (CMP_NE(ecx, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc2 = (CMP_NE(ecx, eax)); /* DOA3: flags from the compare above; ecx is overwritten before the jcc */',), 0),
        (('    if (_rccf) goto loc_0017EA13; /* jne: not equal / not zero */',),
         ('    if (_cc2) goto loc_0017EA13; /* jne: not equal / not zero */',), 0),
    ],
    0x001809FE: [
        (('    fp_top() = fp_top() * (double)SMEM32(esp + 0x10); /* fimul mem */', '    fp_top() = fp_top() / (double)SMEM32(esp + 0x14); /* fidiv mem */', '    fp_top() = fp_top() + (double)MEMD(0x1F5960); /* fadd mem */'),
         ('    /* The lifter emitted the next two as comments only and mistranslated', '     * the memory-operand fadd as faddp, so this returned the raw timestamp', '     * instead of round(time * rate / 22500000). That is the PTS -> frame', '     * conversion behind the movie timecode, so every picture timestamp came', '     * out ~750x too large, the timecode raced (31 frames read as 7m29s) and', '     * the end-of-display test could never fire. */', '    fp_top() *= (double)SMEM32(esp + 0x10); /* fimul dword ptr [esp+0x10] */', '    fp_top() /= (double)SMEM32(esp + 0x14); /* fidiv dword ptr [esp+0x14] */', '    fp_top() += MEMD(0x1F5960); /* fadd qword ptr [0x1F5960] (0.5, rounding) */'), 0),
    ],
    0x00182630: [
        (('    _rccf = (CMP_A(ecx, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc3 = (CMP_A(ecx, eax)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rccf) goto loc_0018269C; /* ja: above (unsigned >) */',),
         ('    if (_cc3) goto loc_0018269C; /* ja: above (unsigned >) */',), 0),
    ],
    0x001827B0: [
        (('    /* cmp edx, ebx - flags set for next jcc */', '    _rccf = (CMP_B(edx, ebx));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */', '    POP32(esp, ebx);', '    if (_rccf) goto loc_001827F0; /* jb: below (unsigned <) */'),
         ('    /* DOA3 fix (bug #14, 2nd sighting): the cmp uses the COMPUTED ebx', "     * (ring end); the pop restores the caller's ebx before the jcc, and the", '     * deferred-flag emission compared against the restored value -> the', '     * ring-wrap subtract fired spuriously and every picture-index lookup', '     * missed (movie decode stalled after the prebuffer batch). */', '    { int _wrap_lt = (edx < ebx);', '      POP32(esp, ebx);', '      if (_wrap_lt) goto loc_001827F0; }'), 0),
    ],
    0x0018438D: [
        (('    if (_flags /* jnp: not parity */) { g_seh_ebp = ebp; sub_001843E9(); return; }',),
         ('    if (_flags /* jnp: not parity */) { sub_001843E9(); return; }',), 0),
    ],
    0x00186890: [
        (('    _rccf = (TEST_Z(HI8(eax), 0x41));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc1 = (TEST_Z(HI8(eax), 0x41)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rccf) goto loc_001868D5; /* je: equal / zero */',),
         ('    if (_cc1) goto loc_001868D5; /* je: equal / zero */',), 0),
        (('    _rccf = (TEST_Z(HI8(eax), 0x41));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc2 = (TEST_Z(HI8(eax), 0x41)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 1),
        (('    if (_rccf) goto loc_0018690E; /* je: equal / zero */',),
         ('    if (_cc2) goto loc_0018690E; /* je: equal / zero */',), 0),
        (('    _rccf = (TEST_Z(HI8(eax), 0x41));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc3 = (TEST_Z(HI8(eax), 0x41)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 2),
        (('    if (_rccf) goto loc_00186946; /* je: equal / zero */',),
         ('    if (_cc3) goto loc_00186946; /* je: equal / zero */',), 0),
        (('    _rccf = (TEST_Z(HI8(eax), 0x41));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc4 = (TEST_Z(HI8(eax), 0x41)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 3),
        (('    if (_rccf) goto loc_0018697F; /* je: equal / zero */',),
         ('    if (_cc4) goto loc_0018697F; /* je: equal / zero */',), 0),
        (('    _rccf = (TEST_Z(HI8(eax), 0x41));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc5 = (TEST_Z(HI8(eax), 0x41)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 4),
        (('    if (_rccf) goto loc_001869B8; /* je: equal / zero */',),
         ('    if (_cc5) goto loc_001869B8; /* je: equal / zero */',), 0),
        (('    _rccf = (TEST_Z(HI8(eax), 0x41));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc6 = (TEST_Z(HI8(eax), 0x41)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 5),
        (('    if (_rccf) goto loc_001869F1; /* je: equal / zero */',),
         ('    if (_cc6) goto loc_001869F1; /* je: equal / zero */',), 0),
        (('    _rccf = (TEST_Z(HI8(eax), 0x41));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc7 = (TEST_Z(HI8(eax), 0x41)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 6),
        (('    if (_rccf) goto loc_00186A2A; /* je: equal / zero */',),
         ('    if (_cc7) goto loc_00186A2A; /* je: equal / zero */',), 0),
        (('    _rccf = (TEST_Z(HI8(eax), 0x41));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc8 = (TEST_Z(HI8(eax), 0x41)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 7),
        (('    if (_rccf) goto loc_00186A63; /* je: equal / zero */',),
         ('    if (_cc8) goto loc_00186A63; /* je: equal / zero */',), 0),
    ],
    0x0018DB30: [
        (('    g_fp_stack[(g_fp_top + 1) & 7] = g_fp_stack[(g_fp_top + 1) & 7] - fp_top(); fp_pop(); /* fsubp st(1) */',),
         ('    fp_st1() -= fp_top(); fp_pop(); /* fsubp */',), 0),
    ],
    0x0018DB53: [
        (('    g_fp_stack[(g_fp_top + 1) & 7] = g_fp_stack[(g_fp_top + 1) & 7] - fp_top(); fp_pop(); /* fsubp st(1) */',),
         ('    fp_st1() -= fp_top(); fp_pop(); /* fsubp */',), 0),
    ],
    0x0018DF33: [
        (('    { uint32_t _seh_hold = g_seh_ebp; /* DOA3: ebp survives the call */',),
         ('    /* DOA3: this fragment has no ebp of its own, and the epilogue it falls', '     * into (sub_0018DF3B: mov esp, ebp) inherits g_seh_ebp. _except1', '     * (sub_00191848) tail-jumps internally and leaves g_seh_ebp pointing at', '     * its own frame, so floor() came back with esp 52 bytes low. Keep the', "     * caller's frame pointer across the call. */", '    { uint32_t _seh = g_seh_ebp;'), 0),
        (('    g_seh_ebp = _seh_hold; }',),
         ('    g_seh_ebp = _seh; }',), 0),
    ],
    0x0018E217: [
        (('    if (_flags /* loop: loop */) { g_seh_ebp = ebp; sub_0018E243(); return; }',),
         ('    if (_flags /* loop: loop */) { sub_0018E243(); return; }',), 0),
    ],
    0x0018E3A1: [
        (('    ebx = MEM32(ebp + 0xC);',),
         ('    ebx = MEM32(ebp + 0xC);', '    { extern void doa3_esp_load_log(int, uint32_t, uint32_t); doa3_esp_load_log(2, esp, MEM32(ebx + -4)); }'), 0),
    ],
    0x0018E4A5: [
        (('    ebx = MEM32(ebp + 0xC);',),
         ('    ebx = MEM32(ebp + 0xC);', '    { extern void doa3_esp_load_log(int, uint32_t, uint32_t); doa3_esp_load_log(3, esp, MEM32(ebx + 0x1C)); }'), 0),
    ],
    0x0018E813: [
        (('    _rccf = (TEST_Z(eax, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc12 = (TEST_Z(eax, eax)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rccf) goto loc_0018E858; /* je: equal / zero */',),
         ('    if (_cc12) goto loc_0018E858; /* je: equal / zero */',), 0),
    ],
    0x0018ED7D: [
        (('    if (_flags /* je: equal / zero */) { g_seh_ebp = ebp; sub_0018EDD8(); return; }',),
         ('    if (_flags /* je: equal / zero */) { sub_0018EDD8(); return; }',), 0),
        (('    g_x87_cw = MEM16(0x21896C); /* fldcw */',),
         ('    g_x87_cw = MEM16(0x21896c); /* fldcw */',), 0),
    ],
    0x0018F862: [
        (('    _rcc = ((X86_PF8((HI8(eax)) & (0x44))));  /* DOA3 bug #14: flags evaluated where x86 evaluates them */',),
         ('    int _cc1 = ((X86_PF8((HI8(eax)) & (0x44)))); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rcc) goto loc_0018F8AB; /* jp: parity */',),
         ('    if (_cc1) goto loc_0018F8AB; /* jp: parity */',), 0),
    ],
    0x00191A4D: [
        (('    MEM16(ebp + -4) = g_x87_cw; /* fnstcw */',),
         ('    MEM16(ebp - 4) = g_x87_cw; /* fnstcw */',), 0),
        (('    g_x87_cw = MEM16(ebp + 0xC); /* fldcw */',),
         ('    g_x87_cw = MEM16(ebp + 0xc); /* fldcw */',), 0),
    ],
    0x00193721: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_0019376F; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group C: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0019376F; /* jns: not sign (positive) */',), 0),
    ],
    0x00193ACC: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_00193C89; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group C: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_00193C89; /* jns: not sign (positive) */',), 0),
    ],
    0x00194FFA: [
        (('    MEM16(ebp + -4) = g_x87_cw; /* fnstcw */',),
         ('    MEM16(ebp - 4) = g_x87_cw; /* fnstcw */',), 0),
        (('    g_x87_cw = MEM16(ebp + 0xC); /* fldcw */',),
         ('    g_x87_cw = MEM16(ebp + 0xc); /* fldcw */',), 0),
    ],
    0x00195740: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_0019578C; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group C: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_0019578C; /* jns: not sign (positive) */',), 0),
    ],
    0x00195DFA: [
        (('    /* cmp MEM32(ebp + -16), 0 - flags set for next jcc */',),
         ('    RC_SETF_CMP(MEM32(ebp + -16), 0);   /* cmp MEM32(ebp + -16), 0 - flags set for next jcc */',), 0),
        (('    if (_flags /* jno: not overflow */) { g_seh_ebp = ebp; sub_0019627D(); return; }',),
         ('    if (_flags /* jno: not overflow */) { sub_0019627D(); return; }',), 0),
    ],
    0x00196071: [
        (('    /* cmp MEM32(ebp + -16), 0 - flags set for next jcc */',),
         ('    RC_SETF_CMP(MEM32(ebp + -16), 0);   /* cmp MEM32(ebp + -16), 0 - flags set for next jcc */',), 0),
        (('    if (_flags /* jno: not overflow */) { g_seh_ebp = ebp; sub_0019627D(); return; }',),
         ('    if (_flags /* jno: not overflow */) { sub_0019627D(); return; }',), 0),
    ],
    0x00196104: [
        (('    /* cmp MEM32(ebp + -16), 0 - flags set for next jcc */',),
         ('    RC_SETF_CMP(MEM32(ebp + -16), 0);   /* cmp MEM32(ebp + -16), 0 - flags set for next jcc */',), 0),
        (('    if (_flags /* jno: not overflow */) { g_seh_ebp = ebp; sub_0019627D(); return; }',),
         ('    if (_flags /* jno: not overflow */) { sub_0019627D(); return; }',), 0),
    ],
    0x001B1160: [
        (('    PUSH32(esp, 0); RECOMP_ICALL_SAFE(MEM32(0x1ED26C), _icall_esp); /* indirect call */',),
         ('    uint32_t _tv = MEM32(0x1ED26C); PUSH32(esp, 0); RECOMP_ICALL_SAFE(_tv, _icall_esp); /* indirect call */',), 0),
    ],
    0x001B1180: [
        (('    PUSH32(esp, 0); RECOMP_ICALL_SAFE(MEM32(0x1ED26C), _icall_esp); /* indirect call */',),
         ('    uint32_t _tv = MEM32(0x1ED26C); PUSH32(esp, 0); RECOMP_ICALL_SAFE(_tv, _icall_esp); /* indirect call */',), 0),
    ],
    0x001B1BE0: [
        (('    if (CMP_EQ(eax, ecx)) goto loc_001B1C8A; /* je: equal / zero */',),
         ('    /* Walk of the device active-resource list (head [esi+0x488], linked', '     * through +0x8C), unlinking this node before it is re-pushed below.', '     * A cycle in that chain makes this loop non-terminating, and it was:', '     * the sampling profiler put 100%% of all CPU in this one loop, which', '     * is why the game advanced at ~5%% of real time and never rendered.', '     * Same self-referencing-node corruption already seen in sub_001B4960', '     * (obj=002DD3D8 child=002DD3D8). Bound the walk: a real list is a few', '     * hundred nodes, and falling out to the not-found path is what the', '     * code does for a node that is not linked anyway. */', '    { static unsigned _spin = 0, _warned = 0;', '      if (++_spin > 65536u) {', '        _spin = 0;', '        if (!_warned) { _warned = 1;', '          fprintf(stderr, "[D3DLIST] cyclic resource list at %08X (next=%08X) - walk bounded\\n",', '                  eax, (eax >= 0x1000u && eax < 0x08000000u) ? MEM32(eax + 0x8C) : 0);', '          fflush(stderr); }', '        goto loc_001B1C96;', '      }', '      if (CMP_EQ(eax, ecx)) { _spin = 0; goto loc_001B1C8A; } }'), 0),
    ],
    0x001B38A0: [
        (('loc_001B38A0: ;',),
         ('loc_001B38A0: ;', '    { extern void doa3_pb_tss_marker(void); doa3_pb_tss_marker(); }'), 0),
    ],
    0x001B3C30: [
        (('    if (((int8_t)(LO8(ebx) & LO8(ebx)) >= 0)) goto loc_001B3C79; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(ebx) >= 0) /* DOA3 group B: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_001B3C79; /* jns: not sign (positive) */',), 0),
    ],
    0x001B3D11: [
        (('    esi = MEM32(esp + 0x10);',),
         ('    esi = MEM32(esp + 0x10);', '    /* DOA3: DROPPED FALL-THROUGH 0x001B3D11 -> 0x001B3D15.', '     * This fragment is a single 4-byte `mov esi,[esp+0x10]` (8B 74 24 10)', '     * and the next instruction is the loop head at 0x001B3D15, so control', '     * continues there. Without it the push-buffer copy loop in', '     * sub_001B3D15 ran once and, worse, its epilogue at loc_001B3D90 --', '     * which pops edi/esi/ebp/EBX/ecx -- never ran. ebx still held', '     * device+0x18C0 (0x001C20C0), which sub_001B42C0 then passed to', '     * XMETAL_Reserve as the device. Reserve read a null cursor there and', '     * wrapped the write pointer, the parse went out of step, and vertex', '     * index data was decoded as method headers straight through the', '     * render-state block (SET_DEPTH_FUNC came out as 0x03090308). */', '    sub_001B3D15();'), 0),
        (('    sub_001B3D15(); return; /* DOA3: restored dropped fall-through to sub_001B3D15 */',),
         (), 0),
    ],
    0x001B4230: [
        (('    int _flags = 0; /* fallback flag var */',),
         ('    int _flags = 0; /* fallback flag var */', '    int stride_changed;'), 0),
        (('    /* cmp eax, ecx - flags set for next jcc */', '    _rccf = (CMP_NE(eax, ecx));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */'),
         ('    stride_changed = CMP_NE(eax, ecx);',), 0),
        (('    if (_rccf) { g_seh_ebp = ebp; sub_001B429A(); return; } /* jne: not equal / not zero */',),
         ('    if (stride_changed) { g_seh_ebp = ebp; sub_001B429A(); return; } /* jne: not equal / not zero */',), 0),
    ],
    0x001B4880: [
        (('    PUSH32(esp, 0); RECOMP_ICALL_SAFE(MEM32(0x1ED134), _icall_esp); /* indirect call */',),
         ('    uint32_t _tv = MEM32(0x1ED134); PUSH32(esp, 0); RECOMP_ICALL_SAFE(_tv, _icall_esp); /* indirect call */',), 0),
        (('    PUSH32(esp, 0); RECOMP_ICALL_SAFE(MEM32(0x1ED134), _icall_esp); /* indirect call */',),
         ('    uint32_t _tv = MEM32(0x1ED134); PUSH32(esp, 0); RECOMP_ICALL_SAFE(_tv, _icall_esp); /* indirect call */',), 1),
        (('    PUSH32(esp, 0); RECOMP_ICALL_SAFE(MEM32(0x1ED134), _icall_esp); /* indirect call */',),
         ('    uint32_t _tv = MEM32(0x1ED134); PUSH32(esp, 0); RECOMP_ICALL_SAFE(_tv, _icall_esp); /* indirect call */',), 2),
    ],
    0x001B7700: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_001B7908; /* jns: not sign (positive) */',),
         ('    if ((LO8(eax) & 0x80) == 0) goto loc_001B7908; /* jns: not sign (positive) */',), 0),
    ],
    0x001B9BA0: [
        (('    eax = (int32_t)(MEMF(esp + 4)); /* cvttss2si */',),
         ('    eax = (int32_t)MEMF(esp + 4); /* cvttss2si */',), 0),
    ],
    0x001BA090: [
        (('    if (((int8_t)(LO8(eax) & LO8(eax)) >= 0)) goto loc_001BA0D2; /* jns: not sign (positive) */',),
         ('    if (((int8_t)LO8(eax) >= 0) /* DOA3 group B: byte sign test (was an unsigned byte cast to int32_t, never negative) */) goto loc_001BA0D2; /* jns: not sign (positive) */',), 0),
    ],
    0x001C4348: [
        (('    if (_flags /* jl: less (signed <) */) { g_seh_ebp = ebp; sub_001C43C3(); return; }',),
         ('    if (_flags /* jl: less (signed <) */) { sub_001C43C3(); return; }',), 0),
    ],
    0x001C64DB: [
        (('    _rccf = (CMP_NE(ecx, eax));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc1 = (CMP_NE(ecx, eax)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rccf) goto loc_001C653B; /* jne: not equal / not zero */',),
         ('    if (_cc1) goto loc_001C653B; /* jne: not equal / not zero */',), 0),
    ],
    0x001C677D: [
        (('    if (CMP_A(eax, 0x41)) goto loc_001C67A2; /* ja: above (unsigned >) */',),
         ('    if (CMP_A(eax, 0x41)) { g_seh_ebp = ebp; sub_001C67A2(); return; } /* ja: above (unsigned >) */',), 0),
        (('    { uint32_t _jt = MEM32(eax * 4 + 0x1C67A7); /* switch: 4 entries, 4 targets */', '    if (_jt == 0x001C6794u) goto loc_001C6794;', '    if (_jt == 0x001C6798u) goto loc_001C6798;', '    if (_jt == 0x001C679Du) goto loc_001C679D;', '    if (_jt == 0x001C67A2u) goto loc_001C67A2;', '    g_seh_ebp = ebp; RECOMP_ITAIL(_jt); return; }', '', 'loc_001C6794: ;', '    PUSH32(esp, 4);', '    goto loc_001C679A;', '', 'loc_001C6798: ;', '    PUSH32(esp, 2);', '', 'loc_001C679A: ;', '    POP32(esp, eax);', '    goto loc_001C67A4;', '', 'loc_001C679D: ;', '    eax = 0; /* xor self */', '    eax++;', '    goto loc_001C67A4;', '', 'loc_001C67A2: ;', '    eax = 0; /* xor self */', '', 'loc_001C67A4: ;', '    esp += 8; return; /* ret 4 */', '', '    g_seh_ebp = ebp; sub_001C67A4(); return; /* DOA3: restored dropped fall-through to sub_001C67A4 */'),
         ('    /* DOA3: XGBytesPerPixelFromFormat. The guest dispatches through the', '     * four-entry jump table at 0x1C67A7 to three stubs INSIDE this function', '     * (0x1C6794 "push 4", 0x1C6798 "push 2", 0x1C679D "xor/inc" = 1) and', '     * to 0x1C67A2 (= 0). The lift emitted an indirect tail-jump whose', '     * targets were never lifted, so at runtime the jump resolved to', '     * nothing: eax kept the index byte and the `ret 4` never happened,', "     * leaving the caller's stack 4 bytes off. sub_00159D60 then read every", "     * argument for XGSwizzleBox from the wrong slot and swizzled X Octagon's", '     * 256x256x2 spotlight texture to destination 0 -- 128 KB over the XBE', "     * header and the first part of .text (the walk interpreter's jump table", '     * at 0x1E9B0 and the float constants around 0x1ED554), which froze the', '     * fighters and produced the black wedge geometry. Decode the table here. */', '    switch (eax) {', '    case 0:  eax = 1; break;   /* 0x1C679D */', '    case 1:  eax = 2; break;   /* 0x1C6798 */', '    case 2:  eax = 4; break;   /* 0x1C6794 */', '    default: eax = 0; break;   /* 0x1C67A2 */', '    }', '    g_seh_ebp = ebp; sub_001C67A4(); return; /* ret 4 */'), 0),
    ],
    0x001C80A4: [
        (('    /* cmp LO8(eax), LO8(ecx) - flags set for next jcc */',),
         ('    /* cmp LO8(eax), LO8(ecx) - flags set for next jcc */', '    int _cc1 = (CMP_EQ(MEM32(eax), 0)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */'), 0),
        (('    if (CMP_EQ(MEM32(eax), 0)) goto loc_001C80D4; /* je: equal / zero */',),
         ('    if (_cc1) goto loc_001C80D4; /* je: equal / zero */',), 0),
    ],
    0x001C8317: [
        (('    _rccf = (TEST_Z(LO8(eax), 0x10));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc2 = (TEST_Z(LO8(eax), 0x10)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rccf) goto loc_001C837E; /* je: equal / zero */',),
         ('    if (_cc2) goto loc_001C837E; /* je: equal / zero */',), 0),
    ],
    0x001C841E: [
        (('    { uint32_t _seh_hold = g_seh_ebp; /* DOA3: ebp survives the call */',),
         ('    uint32_t _seh_hold = g_seh_ebp; /* DOA3: ebp survives a call; the callee left its own frame in the carrier, so sub_001C842F/sub_001C8433 read the list counter at the wrong [ebp-4], it never reached 0 and the drain walked off the three voice lists forever */',), 0),
        (('    g_seh_ebp = _seh_hold; }',),
         ('    g_seh_ebp = _seh_hold;',), 0),
    ],
    0x001C984F: [
        (('    _rccf = (CMP_NE(MEM16(eax), 0x69));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */', '    eax = ZX16(MEM16(eax + 0xC));', '    if (_rccf) { g_seh_ebp = ebp; sub_001C986E(); return; } /* jne: not equal / not zero */'),
         ('    { int _tag_ne = (MEM16(eax) != 0x69); /* DOA3: cmp [fmt],0x69 is evaluated BEFORE eax becomes nBlockAlign (lifter recomputed it after) */', '      eax = ZX16(MEM16(eax + 0xC));', '      if (_tag_ne) { g_seh_ebp = ebp; sub_001C986E(); return; } } /* jne: not equal / not zero */'), 0),
    ],
    0x001C9C92: [
        (('    /* DOA3: hw busy-wait forced through (was: if (TEST_NZ(MEM32(ecx + 8), 0x10000000)) goto loc_001C9C98) */',),
         ("    /* Wait until DirectSound's interrupt handler has retired the voice (it", '     * clears 0x10000000 in 0x1C84D0 after unlinking the buffer from its voice', '     * list). DOA3: this wait used to be forced through, so a buffer the game', '     * stopped and immediately refilled was relinked while still on the list,', '     * and the completion drain looped forever on the resulting cycle. The APU', '     * interrupt reaches the game thread from the present hook otherwise, so', '     * the wait delivers it itself, as the hardware interrupt would arrive. */', '    { extern void doa3_apu_wait_retire(uint32_t); doa3_apu_wait_retire(ecx); }'), 0),
    ],
    0x001CA5B1: [
        (('    _rccf = (TEST_Z(MEM8(edi + 0xC), 0x10));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc4 = (TEST_Z(MEM8(edi + 0xC), 0x10)); /* DOA3: flags from the compare above; edi is overwritten before the jcc */',), 0),
        (('    if (_rccf) goto loc_001CA5C7; /* je: equal / zero */',),
         ('    if (_cc4) goto loc_001CA5C7; /* je: equal / zero */',), 0),
    ],
    0x001CB531: [
        (('    _rccf = (TEST_NZ(HI8(eax), 1));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc1 = (TEST_NZ(HI8(eax), 1)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rccf) goto loc_001CB631; /* jne: not equal / not zero */',),
         ('    if (_cc1) goto loc_001CB631; /* jne: not equal / not zero */',), 0),
    ],
    0x001CC02F: [
        (('    _rccf = (CMP_NE(MEM16(eax), 0x69));  /* DOA3: x86 latched these flags at the compare above and the branch below reads them, but an operand is overwritten in between -- evaluate the condition where the guest does. */',),
         ('    int _cc6 = (CMP_NE(MEM16(eax), 0x69)); /* DOA3: flags from the compare above; eax is overwritten before the jcc */',), 0),
        (('    if (_rccf) { g_seh_ebp = ebp; sub_001CC04F(); return; } /* jne: not equal / not zero */',),
         ('    if (_cc6) { g_seh_ebp = ebp; sub_001CC04F(); return; } /* jne: not equal / not zero */',), 0),
    ],
    0x001CECC8: [
        (('    if (_flags /* jb: below (unsigned <) */) { g_seh_ebp = ebp; sub_001CEE84(); return; }',),
         ('    if (_flags /* jb: below (unsigned <) */) { sub_001CEE84(); return; }',), 0),
    ],
    0x001E4C40: [
        (('    { uint32_t _icall_t = MEM32(ebp + 0x23C); PUSH32(esp, 0); RECOMP_ICALL_SAFE(_icall_t, _icall_esp); } /* indirect call */',),
         ('    { uint32_t _icall_t = MEM32(ebp + 0x23C);', '      PUSH32(esp, 0); RECOMP_ICALL_SAFE(_icall_t, _icall_esp); } /* indirect call */'), 0),
    ],
}
