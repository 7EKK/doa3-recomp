"""Function map between two DOA3 releases (USA -> JPN), for porting
address-keyed fixes and overrides from one tree to the other. Run from doa3/:"""
import json, struct, sys, hashlib, difflib, bisect, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

LO, HI = 0x10000, 0xD00000


class Xbe:
    def __init__(self, path):
        d = open(path, 'rb').read()
        self.d = d
        base, = struct.unpack_from('<I', d, 0x104)
        n, p = struct.unpack_from('<II', d, 0x11C)
        self.secs = []
        for i in range(n):
            o = p - base + i * 56
            fl, va, vs, ra, rs, np_ = struct.unpack_from('<IIIIII', d, o)
            name = d[np_ - base:d.index(b'\0', np_ - base)].decode()
            self.secs.append((name, va, vs, ra, rs))

    def sec(self, va):
        for s in self.secs:
            if s[1] <= va < s[1] + s[2]:
                return s
        return None

    def read(self, va, n):
        s = self.sec(va)
        off = va - s[1]
        n = max(0, min(n, s[4] - off))
        return self.d[s[3] + off:s[3] + off + n]


cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs.detail = True


def cfg_insns(x, start, stops):
    """Instructions reachable from start without entering another function."""
    seen = {}
    work = [start]
    sec = x.sec(start)
    lo, hi = sec[1], sec[1] + sec[4]
    while work:
        pc = work.pop()
        while lo <= pc < hi and pc not in seen and len(seen) < 20000:
            if pc != start and pc in stops:
                break
            ins = next(cs.disasm(x.read(pc, 16), pc), None)
            if ins is None:
                break
            seen[pc] = ins
            mn = ins.mnemonic
            tgt = None
            if ins.operands and ins.operands[0].type == CS_OP_IMM:
                tgt = ins.operands[0].imm & 0xFFFFFFFF
            if mn in ('ret', 'retn', 'retf', 'int3', 'hlt'):
                break
            if mn == 'jmp':
                if tgt is not None and not (tgt in stops and tgt != start):
                    work.append(tgt)
                break
            if mn.startswith('j') or mn.startswith('loop'):
                if tgt is not None and not (tgt in stops and tgt != start):
                    work.append(tgt)
            pc += ins.size
    return [seen[a] for a in sorted(seen)]


def norm(x, start, stops):
    toks, addrs, calls, insns = [], [], [], []
    for ins in cfg_insns(x, start, stops):
        ops = []
        aops = []
        tgt = None
        for op in ins.operands:
            if op.type == CS_OP_IMM:
                v = op.imm & 0xFFFFFFFF
                if ins.mnemonic == 'call' or ins.mnemonic.startswith('j') or ins.mnemonic.startswith('loop'):
                    tgt = v
                    ops.append('T')
                elif LO <= v < HI:
                    ops.append('A'); aops.append(v)
                else:
                    ops.append(hex(v))
            elif op.type == CS_OP_MEM:
                v = op.mem.disp & 0xFFFFFFFF
                if LO <= v < HI and (op.mem.base == 0 or v > 0x100000):
                    ops.append('M%d%d' % (op.mem.base, op.mem.index)); aops.append(v)
                else:
                    ops.append('M%d%d%d%x' % (op.mem.base, op.mem.index, op.mem.scale, v))
            else:
                ops.append('r%d' % op.reg)
        toks.append(ins.mnemonic + ' ' + ','.join(ops))
        addrs.append(aops)
        insns.append(ins.address)
        if ins.mnemonic == 'call' and tgt is not None:
            calls.append(tgt)
    return toks, addrs, calls, insns


def units(x, fj):
    fs = json.load(open(fj))
    ends = {int(f['start'], 16): int(f['end'], 16) for f in fs}
    starts = sorted({int(f['start'], 16) for f in fs if f.get('detection_method') != 'link_seed'})
    allstarts = sorted({int(f['start'], 16) for f in fs})
    out = {}
    for i, s in enumerate(starts):
        sec = x.sec(s)
        if not sec:
            continue
        e = starts[i + 1] if i + 1 < len(starts) else sec[1] + sec[2]
        e = min(e, sec[1] + sec[4], s + 0x8000, max(ends.get(s, e), s + 1))
        out[s] = dict(sec=sec[0], end=e)
    return out, allstarts


def build(x, fj):
    u, allstarts = units(x, fj)
    stops = set(u)
    for s, f in u.items():
        f['toks'], f['addrs'], f['calls'], f['insns'] = norm(x, s, stops)
        f['h'] = hashlib.sha1('\n'.join(f['toks']).encode()).hexdigest()
    return u, allstarts


def main():
    ux, ufj, jx, jfj, outp = sys.argv[1:6]
    U, uall = build(Xbe(ux), ufj)
    J, jall = build(Xbe(jx), jfj)
    m = {}
    # 1. unique exact hashes
    uh = collections.defaultdict(list); jh = collections.defaultdict(list)
    for a, f in U.items(): uh[f['h']].append(a)
    for a, f in J.items(): jh[f['h']].append(a)
    for h, la in uh.items():
        if len(la) == 1 and len(jh.get(h, [])) == 1:
            m[la[0]] = (jh[h][0], 1.0, 'exact')
    print('exact unique', len(m), file=sys.stderr)

    def sim(a, b):
        ta, tb = U[a]['toks'], J[b]['toks']
        if not ta or not tb:
            return 0
        if min(len(ta), len(tb)) / max(len(ta), len(tb)) < 0.5:
            return 0
        return difflib.SequenceMatcher(None, ta, tb, autojunk=False).ratio()

    # 2. order-preserving gap fill per section between anchors
    def gapfill():
        added = 0
        for secname in {f['sec'] for f in U.values()}:
            ua = sorted(a for a in U if U[a]['sec'] == secname)
            ja = sorted(a for a in J if J[a]['sec'] == secname)
            jidx = {a: i for i, a in enumerate(ja)}
            anchors = [(-1, -1)] + sorted((i, jidx[m[a][0]]) for i, a in enumerate(ua)
                                          if a in m and m[a][0] in jidx) + [(len(ua), len(ja))]
            used = {m[a][0] for a in m}
            for (ui0, ji0), (ui1, ji1) in zip(anchors, anchors[1:]):
                if ji1 <= ji0:
                    continue
                gu = [a for a in ua[ui0 + 1:ui1] if a not in m]
                gj = [b for b in ja[ji0 + 1:ji1] if b not in used]
                if not gu or not gj or len(gu) * len(gj) > 4000:
                    continue
                # greedy monotone: best pairs first, keep order consistent
                cands = sorted(((sim(a, b), a, b) for a in gu for b in gj), reverse=True)
                taken_u, taken_j, pairs = set(), set(), []
                for s, a, b in cands:
                    if s < 0.6 or a in taken_u or b in taken_j:
                        continue
                    if any((a < pa) != (b < pb) for pa, pb in pairs):
                        continue
                    pairs.append((a, b)); taken_u.add(a); taken_j.add(b)
                    m[a] = (b, round(s, 3), 'order'); used.add(b); added += 1
        return added

    # 3. call-graph propagation: same-index call targets of matched pairs
    def callprop():
        added = 0
        used = {v[0] for v in m.values()}
        for a, (b, s, k) in list(m.items()):
            ca, cb = U[a]['calls'], J[b]['calls']
            sm = difflib.SequenceMatcher(None, U[a]['toks'], J[b]['toks'], autojunk=False)
            ia = [i for i, t in enumerate(U[a]['toks']) if t.startswith('call T')]
            ib = [i for i, t in enumerate(J[b]['toks']) if t.startswith('call T')]
            imap = {}
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag == 'equal':
                    for d in range(i2 - i1):
                        imap[i1 + d] = j1 + d
            tga = dict(zip(ia, ca)); tgb = dict(zip(ib, cb))
            for i, t in tga.items():
                j = imap.get(i)
                if j is None or j not in tgb:
                    continue
                x, y = t, tgb[j]
                if x in U and y in J and x not in m and y not in used:
                    s2 = sim(x, y)
                    if s2 >= 0.5:
                        m[x] = (y, round(s2, 3), 'call'); used.add(y); added += 1
        return added

    def ngram():
        used = {v[0] for v in m.values()}
        grams = lambda t: {tuple(t[i:i+4]) for i in range(max(1, len(t) - 3))}
        idx = collections.defaultdict(set)
        jg = {}
        for b, f in J.items():
            if b in used: continue
            jg[b] = grams(f['toks'])
            for g in jg[b]: idx[g].add(b)
        best = {}
        for a, f in U.items():
            if a in m: continue
            ga = grams(f['toks'])
            cnt = collections.Counter()
            for g in ga:
                if len(idx.get(g, ())) <= 20:
                    for b in idx.get(g, ()): cnt[b] += 1
            sc = sorted(((sim(a, b), b) for b, _ in cnt.most_common(8)), reverse=True)
            if sc and sc[0][0] >= 0.6 and (len(sc) == 1 or sc[0][0] - sc[1][0] >= 0.05):
                best[a] = sc[0]
        inv = collections.defaultdict(list)
        for a, (s, b) in best.items(): inv[b].append((s, a))
        added = 0
        for b, la in inv.items():
            la.sort(reverse=True)
            if len(la) == 1 or la[0][0] - la[1][0] >= 0.05:
                m[la[0][1]] = (b, round(la[0][0], 3), 'ngram'); added += 1
        return added

    for it in range(6):
        g = gapfill() + ngram(); c = callprop()
        print('iter', it, 'gap', g, 'call', c, 'total', len(m), file=sys.stderr)
        if not g and not c:
            break

    # Instruction pairs inside aligned runs of matched functions, and the
    # image addresses those equal instructions reference (data, mostly).
    imap = {}
    dvotes = collections.defaultdict(collections.Counter)
    for a, (b, _s, _k) in m.items():
        ta, tb = U[a]['toks'], J[b]['toks']
        sm = difflib.SequenceMatcher(None, ta, tb, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag != 'equal':
                continue
            for d in range(i2 - i1):
                imap[U[a]['insns'][i1 + d]] = J[b]['insns'][j1 + d]
                for x, y in zip(U[a]['addrs'][i1 + d], J[b]['addrs'][j1 + d]):
                    dvotes[x][y] += 1
    data = {}
    for x, c in dvotes.items():
        (y, n), total = c.most_common(1)[0], sum(c.values())
        data['%08X' % x] = ['%08X' % y, n, total]
    json.dump({
        'functions': {'%08X' % a: ['%08X' % b, s, k] for a, (b, s, k) in sorted(m.items())},
        'insns': {'%08X' % a: '%08X' % b for a, b in sorted(imap.items())},
        'data': dict(sorted(data.items())),
    }, open(outp, 'w'), indent=0)
    bysec = collections.Counter(f['sec'] for f in U.values())
    msec = collections.Counter(U[a]['sec'] for a in m)
    for s in sorted(bysec):
        print(f'{s:10} {msec[s]:5}/{bysec[s]:5}', file=sys.stderr)
    print('JPN units', len(J), 'USA units', len(U), file=sys.stderr)


if __name__ == '__main__':
    main()

