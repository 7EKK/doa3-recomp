"""Suggest a port of recomp_manual.c (USA) to the Japanese release."""
import collections
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DOA3 = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import release_addr  # noqa: E402

SRC = os.path.join(DOA3, 'src', 'game', 'recomp', 'recomp_manual.c')
OUT_C = os.path.join(HERE, 'output_jpn', 'recomp_manual_jpn.c')
OUT_PY = os.path.join(HERE, 'output_jpn', 'body_suffix.py')
OUT_TXT = os.path.join(HERE, 'output_jpn', 'port_manual.txt')

# Image range of the USA build (literals outside it are never addresses).
IMG_LO, IMG_HI = 0x00011000, 0x00C31500

# Symbols other parts of the runtime (kernel, APU, input, online, main)
# call or read; a left-out definition becomes a stub.
REQUIRED = None   # computed from the rest of src/

# Literals that bound a library rather than name an address: USA -> JPN.
# DSOUND is 0x001C6AA0..0x001E1A54 in USA, 0x001F1260..0x0020C6A4 in Japan.
LITERALS = {
    0x001C0000: 0x001EE000,   # "a DSOUND routine": range low
    0x001E0000: 0x0020D000,   # range high
}

# Data addresses verified by hand where no matched pair names them: the
# referencing code was compared side by side (scratch xref).
VERIFIED = {
    0x00B24D38: 0x0040C6F8,   # CRI lock count: lock/unlock 0x16A450/0x16A490 == 0x1925D0/0x192610
    # Pad block 0x5E5CD0 -> 0x73C6C8 (exact), same layout (stride 0x80, handle
    # +0x78: 0x9EE45 == 0xA5105);
    0x005E5CFF: 0x0073C6F7,
    0x005E5CE9: 0x0073C6E1,
}

# Items whose addresses translate but whose body does not apply as written.
OMIT = {
    'doa3_netplay_force_pads': 'online only; the XInput pad block layout changed in XDK 4134 '
                               '(0x5E5CC8 -> 0x73C6BC sits 0xC below the pads, not 8)',
}


def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    text = re.sub(r'//[^\n]*', ' ', text)
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', text)


MACRO_CALL = re.compile(r'^\s*([A-Z][A-Z0-9_]*)\s*\(\s*(sub_[0-9A-F]{8})\b[^;{]*\)\s*;?\s*$')


def override_macros(text):
    """Macros that define fn as a wrapper of fn##_gen (one override per use)."""
    out = set()
    for m in re.finditer(r'^#\s*define\s+([A-Z][A-Z0-9_]*)\(([^)]*)\)((?:[^\n]*\\\n)*[^\n]*)',
                         text, re.M):
        if re.search(r'##\s*_gen', m.group(3)):
            out.add(m.group(1))
    return out


def split_items(text):
    """Top-level items: (leading comments + item text) in file order."""
    lines = text.split('\n')
    items, cur, depth, in_comment = [], [], 0, False
    i = 0
    while i < len(lines):
        line = lines[i]
        cur.append(line)
        code = line
        # track /* */ across lines
        out = ''
        j = 0
        open_at = None          # where a comment still open at line end began
        while j < len(code):
            if in_comment:
                k = code.find('*/', j)
                if k < 0:
                    j = len(code)
                    break
                in_comment = False
                open_at = None
                j = k + 2
            elif code.startswith('/*', j):
                in_comment = True
                open_at = j
                j += 2
            elif code.startswith('//', j):
                break
            elif code[j] == '"':
                k = j + 1
                while k < len(code) and code[k] != '"':
                    k += 2 if code[k] == '\\' else 1
                out += '""'
                j = k + 1
            elif code[j] == "'":
                k = j + 1
                while k < len(code) and code[k] != "'":
                    k += 2 if code[k] == '\\' else 1
                out += "''"
                j = k + 1
            else:
                out += code[j]
                j += 1
        s = out.strip()
        if depth == 0 and s.startswith('#'):
            while line.rstrip().endswith('\\') and i + 1 < len(lines):
                i += 1
                line = lines[i]
                cur.append(line)
            items.append('\n'.join(cur))
            cur = []
            i += 1
            continue
        depth += out.count('{') - out.count('}')
        if depth == 0 and s and (s.endswith(';') or s.endswith('}') or MACRO_CALL.match(s)):
            if in_comment and open_at is not None:
                # A comment opened after the code belongs to the next item.
                cur[-1] = line[:open_at].rstrip()
                items.append('\n'.join(cur))
                cur = [line[open_at:]]
            else:
                items.append('\n'.join(cur))
                cur = []
        i += 1
    if cur:
        items.append('\n'.join(cur))
    return items


DEF_FUNC = re.compile(r'^\s*(static\s+)?(?:inline\s+|__inline\s+|__forceinline\s+)?'
                      r'[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\(([^;{]*)\)\s*\{', re.S)
DEF_VAR = re.compile(r'^\s*(static\s+)?(?:volatile\s+|const\s+)*[A-Za-z_][\w]*(?:\s+[A-Za-z_]\w*)*'
                     r'[\s\*]+([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*(=|;)', re.S)
DEF_MACRO = re.compile(r'^\s*#\s*define\s+([A-Za-z_]\w*)')


def item_kind(code, macros=frozenset()):
    """(kind, name, is_static) of an item's code (comments stripped)."""
    c = code.strip()
    if not c:
        return 'blank', None, False
    m = MACRO_CALL.match(c)
    if m and m.group(1) in macros:
        return 'func', m.group(2), False      # an override defined by a macro
    m = DEF_MACRO.match(c)
    if m:
        return 'macro', m.group(1), False
    if c.startswith('#'):
        return 'pp', None, False
    m = DEF_FUNC.match(c)
    if m:
        return 'func', m.group(2), bool(m.group(1))
    if c.startswith('extern ') or re.match(r'^[^=]*\([^)]*\)\s*;\s*$', c, re.S):
        return 'decl', None, False
    m = re.match(r'^(static\s+)?(?:const\s+)?struct\s*\w*\s*\{.*?\}\s*([A-Za-z_]\w*)\s*'
                 r'(?:\[[^\]]*\])?\s*(?:=|;)', c, re.S)
    if m:
        return 'var', m.group(2), bool(m.group(1))
    m = DEF_VAR.match(c)
    if m:
        return 'var', m.group(2), bool(m.group(1))
    return 'other', None, False


class Porter:
    def __init__(self):
        self.t = release_addr.Translator()
        self.code_refs = self.t._ref_index()   # USA addresses code references
        self.usa_starts = {int(f['start'], 16) for f in json.load(open(
            os.path.join(DOA3, 'tools', 'disasm', 'output', 'functions.json')))}
        self.cache = {}

    def is_code(self, v):
        # Only a code section's bytes on disk are code; its BSS tail is data
        # (D3D keeps its device and vblank event there: 0x1C0800, 0x1C2CF0).
        s = self.t.X.sec(v)
        return bool(s) and s[0] not in ('.rdata', '.data', '$$XTIMAGE', 'DOLBY') \
            and v < s[1] + s[4]

    def map(self, v):
        """(jpn, why) or (None, why)."""
        if v in self.cache:
            return self.cache[v]
        if v in LITERALS:
            r = (LITERALS[v], 'library bound')
        elif v in VERIFIED:
            r = (VERIFIED[v], 'verified by hand')
        elif self.is_code(v):
            c = self.t.code(v)
            r = (c, 'code') if c is not None else (None, 'code address with no JPN counterpart')
        elif v in self.t.D and self.t.D[v][1] == self.t.D[v][2]:
            # Every identical instruction that names v names the same JPN
            # address: that beats inferring it from neighbouring fields.
            r = (self.t.D[v][0], f'data exact x{self.t.D[v][1]}')
        else:
            # Inferring from neighbouring fields is a guess (it picked the
            # wrong CRT lock table, 0x2587C8 for 0x2587E0); never port on it.
            guess = self.t.data(v).most_common(1)
            r = (None, 'data address with no identical instruction naming it'
                 + (f' (neighbour guess {guess[0][0]:08X})' if guess else ''))
        self.cache[v] = r
        return r

    def is_address(self, v):
        """Whether a literal in recomp_manual.c is a guest address."""
        if v in LITERALS or v in VERIFIED:
            return True
        if not (IMG_LO <= v < IMG_HI):
            return False
        if self.is_code(v):
            # Code: an instruction or function start, or something code names.
            # A round number that does not translate is a size or a flag.
            if v % 0x1000 == 0 and self.t.code(v) is None:
                return False
            return v in self.usa_starts or v in self.t.I or v in self.code_refs
        # Round numbers code never points at are sizes/flags, not addresses.
        return not (v % 0x1000 == 0 and v not in self.code_refs
                    and v not in self.t.F and v not in self.t.I)


def required_symbols(defined):
    """Names recomp_manual.c defines that the rest of src/ uses."""
    other = []
    for root, _dirs, files in os.walk(os.path.join(DOA3, 'src')):
        r = root.replace('\\', '/')
        if '/gen' in r or '/third_party' in r:
            continue
        for f in files:
            if f.endswith(('.c', '.cpp', '.h')) and not f.startswith('recomp_manual'):
                other.append(strip_comments(open(os.path.join(root, f), encoding='utf-8',
                                                 errors='replace').read()))
    text = '\n'.join(other)
    return {d for d in defined if re.search(r'\b' + re.escape(d) + r'\b', text)}


SUB = re.compile(r'\bsub_([0-9A-F]{8})((?:_[A-Za-z0-9]+)?)\b')
HEX = re.compile(r'\b0x([0-9A-Fa-f]{5,8})([uU]?[lL]{0,2})\b')
IDENT = re.compile(r'\b[A-Za-z_]\w*\b')


def main():
    usa_cfg = {}
    exec(open(os.path.join(HERE, 'config_usa.py'), encoding='utf-8').read(), usa_cfg)
    body_suffix, if0 = usa_cfg['BODY_SUFFIX'], usa_cfg['IF0_BODIES']

    text = open(SRC, encoding='utf-8', errors='replace').read()
    items = split_items(text)
    macros = override_macros(text)
    P = Porter()

    def addr_problems(code):
        problems = []
        for m in SUB.finditer(code):
            a = int(m.group(1), 16)
            j, why = P.map(a)
            if j is None:
                problems.append(f'sub_{a:08X}: {why}')
        for m in HEX.finditer(code):
            v = int(m.group(1), 16)
            if P.is_address(v):
                j, why = P.map(v)
                if j is None:
                    problems.append(f'0x{v:08X}: {why}')
        return problems

    info, left_out_rows = [], []
    for it in items:
        code = strip_comments(it)
        kind, name, static = item_kind(code, macros)
        problems = addr_problems(code)
        if problems and kind == 'var':
            # A table: keep the rows that translate, drop the others.
            rows, dropped_rows = [], []
            for line in it.split('\n'):
                if re.match(r'^\s*\{.*\},', line) and addr_problems(strip_comments(line)):
                    dropped_rows.append(line.strip())
                else:
                    rows.append(line)
            it = '\n'.join(rows)
            code = strip_comments(it)
            problems = addr_problems(code)
            if not problems and dropped_rows:
                left_out_rows.append((name, dropped_rows))
        if name in OMIT:
            problems.insert(0, OMIT[name])
        if kind == 'func' and name and name.startswith('sub_'):
            a = int(name[4:12], 16)
            sim = P.t.Fsim.get(a)
            if sim != 1.0 and not problems:
                problems.append(f'override target not instruction-identical in JPN (sim {sim})')
        info.append(dict(text=it, code=code, kind=kind, name=name, static=static,
                         problems=problems, keep=not problems and kind != 'blank'))

    # Left-out definitions take their users with them.
    defined = collections.defaultdict(list)
    for k, d in enumerate(info):
        if d['name'] and d['kind'] in ('func', 'var', 'macro'):
            defined[d['name']].append(k)
    changed = True
    while changed:
        changed = False
        dropped = {n for n, ks in defined.items() if not any(info[k]['keep'] for k in ks)}
        for d in info:
            if not d['keep']:
                continue
            refs = set(IDENT.findall(d['code'])) & dropped
            refs.discard(d['name'])
            # sub_X_gen exists only where the override of sub_X is kept.
            for m in SUB.finditer(d['code']):
                base = f'sub_{m.group(1)}'
                if m.group(2) and base != d['name'] and base in dropped:
                    refs.add(base + m.group(2))
            if refs:
                d['keep'] = False
                d['problems'].append('uses left-out ' + ', '.join(sorted(refs)))
                changed = True

    required = required_symbols({n for n in defined if not n.startswith('sub_')})

    # Emit.
    def rewrite(s):
        def sub_(m):
            a = int(m.group(1), 16)
            j, _ = P.map(a)
            return f'sub_{j:08X}{m.group(2)}' if j is not None else m.group(0)

        def hex_(m):
            v = int(m.group(1), 16)
            if not P.is_address(v):
                return m.group(0)
            j, _ = P.map(v)
            return f'0x{j:08X}{m.group(2)}' if j is not None else m.group(0)
        return HEX.sub(hex_, SUB.sub(sub_, s))

    out = ['/*',
           ' * Suggested port of recomp_manual.c to the Japanese release, written by',
           ' * tools/recomp/port_manual.py (src/game/recomp/recomp_manual_jpn.c is the',
           ' * hand-maintained file). Addresses are translated to the Japanese build;',
           ' * port_manual.txt lists every item left out. Comments keep USA addresses',
           ' * where none maps.',
           ' */']
    stubs = []
    kept = 0
    for d in info:
        if d['keep']:
            out.append(rewrite(d['text']))
            kept += 1
        elif d['kind'] == 'func' and d['name'] in required and not any(
                info[k]['keep'] for k in defined[d['name']]):
            stubs.append(d)
        elif d['kind'] in ('pp',):
            out.append(d['text'])
    done = set()
    if stubs:
        out.append('\n/* ── Not ported yet: inert stubs so the runtime links ──────────── */')
    for d in stubs:
        if d['name'] in done:
            continue
        done.add(d['name'])
        sig = d['code'].strip()
        sig = sig[:sig.index('{')].strip()
        ret = sig.split(d['name'])[0].replace('static', '').strip()
        body = '' if ret == 'void' else ' return 0;'
        out.append(f'/* {d["name"]}: {d["problems"][0]} */\n{sig} {{{body} }}')

    # Gen-side naming for the bodies the kept items replace or call.
    jsuffix, jif0 = {}, set()
    for d in info:
        if not d['keep']:
            continue
        if d['kind'] == 'func' and d['name'] and d['name'].startswith('sub_'):
            a = int(d['name'][4:12], 16)
            j, _ = P.map(a)
            if a in body_suffix:
                jsuffix[j] = body_suffix[a]
            elif MACRO_CALL.match(d['code'].strip()):
                jsuffix[j] = '_gen'                  # the macro pastes name##_gen
            if a in if0:
                jif0.add(j)

    open(OUT_C, 'w', encoding='utf-8', newline='\n').write('\n'.join(out) + '\n')
    with open(OUT_PY, 'w', encoding='utf-8', newline='\n') as f:
        f.write('"""Written by tools/recomp/port_manual.py: the BODY_SUFFIX / IF0_BODIES\n'
                'the suggested recomp_manual_jpn.c needs (config_jpn.py holds the real ones)."""\n\n')
        f.write('BODY_SUFFIX = {\n' + ''.join(f'    0x{a:08X}: {s!r},\n' for a, s in sorted(jsuffix.items())) + '}\n\n')
        f.write('IF0_BODIES = {' + ''.join(f'0x{a:08X}, ' for a in sorted(jif0)) + '}\n')
    os.makedirs(os.path.dirname(OUT_TXT), exist_ok=True)
    with open(OUT_TXT, 'w', encoding='utf-8', newline='\n') as f:
        left = [d for d in info if not d['keep'] and d['kind'] in ('func', 'var', 'macro', 'other')]
        f.write(f'kept {kept} items, left out {len(left)}, stubbed {len(done)}\n\n')
        for tname, rows in left_out_rows:
            f.write(f'table {tname}: rows left out\n')
            for r in rows:
                f.write(f'    {r}\n')
        for d in left:
            tag = 'STUB ' if d['name'] in done else ''
            f.write(f'{tag}{d["kind"]} {d["name"]}:\n')
            for p in d['problems'][:6]:
                f.write(f'    {p}\n')
    funcs = [d for d in info if d['kind'] == 'func']
    print(f'items {len(info)}: functions {len(funcs)}, kept {sum(d["keep"] for d in funcs)}; '
          f'stubs {len(done)}; BODY_SUFFIX {len(jsuffix)}')
    print(f'overrides kept {sum(1 for d in funcs if d["keep"] and d["name"].startswith("sub_"))}'
          f' of {sum(1 for d in funcs if d["name"].startswith("sub_"))}')


if __name__ == '__main__':
    main()
