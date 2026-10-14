"""Translate guest addresses from the USA release to the Japanese one. py -3
tools/recomp/release_addr.py 1C2CF0 9D440 ..."""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import release_map as rm  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))   # holds doa3gamefiles*
MAP = os.path.join(HERE, 'output_jpn', 'release_map.json')


def operand_values(ins):
    out = []
    for op in ins.operands:
        if op.type == rm.CS_OP_IMM:
            out.append(op.imm & 0xFFFFFFFF)
        elif op.type == rm.CS_OP_MEM:
            out.append(op.mem.disp & 0xFFFFFFFF)
    return out


class Translator:
    def __init__(self):
        R = json.load(open(MAP))
        self.F = {int(k, 16): int(v[0], 16) for k, v in R['functions'].items()}
        self.Fsim = {int(k, 16): v[1] for k, v in R['functions'].items()}
        self.I = {int(k, 16): int(v, 16) for k, v in R['insns'].items()}
        self.D = {int(k, 16): (int(v[0], 16), v[1], v[2]) for k, v in R['data'].items()}
        self.X = rm.Xbe(os.path.join(ROOT, 'doa3gamefiles', 'default.xbe'))
        self.Y = rm.Xbe(os.path.join(ROOT, 'doa3gamefiles_jpn', 'default.xbe'))
        self._refs = None

    def _ref_index(self):
        """USA instruction address -> operand values, for every mapped insn."""
        if self._refs is None:
            self._refs = collections.defaultdict(list)
            for ua in self.I:
                ins = next(rm.cs.disasm(self.X.read(ua, 16), ua), None)
                if ins:
                    for v in operand_values(ins):
                        if 0x10000 <= v < 0xD00000:
                            self._refs[v].append(ua)
        return self._refs

    def code(self, a):
        """JPN address of USA code address a, or None."""
        if a in self.I:
            return self.I[a]
        if a in self.F:
            return self.F[a]
        return None

    def data(self, a, slack=0x40):
        """(jpn, evidence) for USA data address a: votes by JPN value."""
        votes = collections.Counter()
        if a in self.D:
            y, n, _t = self.D[a]
            votes[y] += n
        refs = self._ref_index()
        for base in range(a - slack, a + 1):
            for ua in refs.get(base, ()):
                ja = self.I[ua]
                jins = next(rm.cs.disasm(self.Y.read(ja, 16), ja), None)
                if not jins:
                    continue
                for v in operand_values(jins):
                    if 0x10000 <= v < 0xD00000:
                        votes[v + (a - base)] += 1
        return votes


def main():
    t = Translator()
    for arg in sys.argv[1:]:
        a = int(arg, 16)
        c = t.code(a)
        if c is not None:
            print(f'{a:08X} code -> {c:08X} (function sim {t.Fsim.get(a, "-")})')
            continue
        if a in t.D:
            y, n, total = t.D[a]
            print(f'{a:08X} data -> {y:08X} (exact: {n} of {total} identical instructions)')
            continue
        best = t.data(a).most_common(3)
        print(f'{a:08X} data -> ' + ('GUESS from neighbouring fields: ' +
              ', '.join(f'{y:08X} x{n}' for y, n in best) if best else 'UNKNOWN'))


if __name__ == '__main__':
    main()
