"""Static evaluator for pure-arithmetic Dalvik static methods (baksmali output). Never executes the sample: it interprets
const/move/long+int ALU ops, static calls between methods in the same dump, simple if/goto loops. Anything else raises.
Day 23 'analysis' codec: Release.code() is a chain of static long mixers ending in 'ANS-' + 16 hex nibbles."""
import os, re, shutil, subprocess, sys, zipfile, io, time

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1


def s64(x):
    x &= M64
    return x - (1 << 64) if x >> 63 else x


def s32(x):
    x &= M32
    return x - (1 << 32) if x >> 31 else x


def _lit(t):
    t = t.strip()
    if t.endswith("L"):
        t = t[:-1]
    return int(t, 0)


class Dump:
    def __init__(self, root):
        self.methods = {}              # (Class, name, desc) -> (registers, lines)
        self.statics = {}              # full field ref "L..;->name:type" -> value (shared static-field store)
        self.field_consts = {}         # full field ref -> compile-time inline constant (from ".field ... = <const>")
        self.clinits = []              # (Class, "<clinit>", "()V") keys, run before the target method populates statics
        self.assets = {}               # asset filename -> raw bytes, for the split-asset reader hook (Day 26 'analysis')
        for dp, _, fs in os.walk(root):
            for f in fs:
                if f.endswith(".smali"):
                    self._load(os.path.join(dp, f), f[:-6])

    def _load(self, path, cls):
        cur = None
        full = None                                            # full class descriptor "Lpkg/Class;" from the .class line
        for raw in open(path, encoding="utf-8", errors="replace"):
            ln = raw.strip()
            if ln.startswith(".class"):
                mm = re.search(r"(L\S+;)\s*$", ln)
                if mm:
                    full = mm.group(1)
            elif ln.startswith(".method"):
                m = re.match(r"\.method\s+.*?(\S+)\((\S*?)\)(\S+)\s*$", ln)
                cur = [cls, m.group(1), "(" + m.group(2) + ")" + m.group(3), 0, []]
            elif cur is not None and ln.startswith(".end method"):
                self.methods[(cur[0], cur[1], cur[2])] = (cur[3], cur[4])
                if cur[1] == "<clinit>":
                    self.clinits.append((cur[0], cur[1], cur[2]))
                cur = None
            elif cur is not None:
                if ln.startswith(".registers"):
                    cur[3] = int(ln.split()[1])
                elif ln and not ln.startswith(".") and not ln.startswith("#"):
                    cur[4].append(ln)
                elif ln.startswith(".catch"):
                    pass
            elif cur is None and ln.startswith(".field") and full and "=" in ln:
                m = re.match(r"\.field\s+.*?(\S+:\S+)\s*=\s*(\S+)", ln)
                if m:
                    try:
                        self.field_consts["%s->%s" % (full, m.group(1))] = s64(_lit(m.group(2)))
                    except Exception:
                        pass                                   # non-numeric inline constant (e.g. a string): left unset, read falls back to None


def _argslots(desc):
    ps = desc[1:desc.index(")")]
    out, i = [], 0
    while i < len(ps):
        c = ps[i]
        if c == "L":
            j = ps.index(";", i)
            out.append(1)
            i = j + 1
        elif c == "[":
            i += 1
            continue
        else:
            out.append(2 if c in "JD" else 1)
            i += 1
    return out


def _reg(tok, nregs, nargs):
    tok = tok.strip().rstrip(",")
    if tok[0] == "v":
        return tok
    if tok[0] == "p":
        return "v%d" % (nregs - nargs + int(tok[1:]))
    raise ValueError("register %r" % tok)


def _is_split_reader(method, desc):
    """True for a (Ljava/lang/String;)[B method that reads an asset out of a feature/config split: it reaches the
    Context (sget-object), walks splitSourceDirs and opens a ZipFile entry. We hook such a method instead of trying
    to model the Android runtime. Matched by behaviour (opcodes present), not by class/method name, so it generalises."""
    if desc != "(Ljava/lang/String;)[B":
        return False
    body = method[1]
    return any("splitSourceDirs" in l for l in body) and any("getEntry" in l for l in body)


def _read_asset(dump, name):
    """Return assets/<name> from the bundle as a list of SIGNED bytes (Dalvik aget-byte sign-extends), or raise if the
    feature split was not supplied. Keyed tolerantly so a caller that passes 'x' or 'assets/x' both resolve."""
    if not isinstance(name, str):
        raise ValueError("split-asset reader called with non-string name %r" % (name,))
    data = dump.assets.get(name)
    if data is None:
        data = dump.assets.get(name.split("assets/", 1)[-1])
    if data is None:
        data = dump.assets.get("assets/" + name)
    if data is None:
        raise ValueError("feature-split asset %r not available in the bundle (base-only artifact?)" % (name,))
    return [b - 256 if b > 127 else b for b in bytes(data)]


def run(dump, cls, name, desc, args, depth=0, stop_at_new_instance=False):
    nregs, lines = dump.methods[(cls, name, desc)]
    slots = _argslots(desc)
    nargs = sum(slots)
    R = {}
    base = nregs - nargs
    k = 0
    for sl, a in zip(slots, args):
        R["v%d" % (base + k)] = a
        k += sl
    labels = {ln: i for i, ln in enumerate(lines) if ln.startswith(":")}
    last = None
    pc = 0
    steps = 0
    def rg(t):
        return _reg(t, nregs, nargs)
    while pc < len(lines):
        steps += 1
        if steps > 2000000:
            raise RuntimeError("step budget")
        ln = lines[pc]
        pc += 1
        if ln.startswith(":") or ln.startswith("nop"):
            continue
        ln = re.sub(r"\s+#.*$", "", ln)
        op, _, rest = ln.partition(" ")
        ops = [x.strip() for x in rest.split(",")] if rest else []
        if op.startswith("const"):
            v = _reg(ops[0], nregs, nargs)
            if op.startswith("const-string"):
                ms = re.search(r'"((?:[^"\\]|\\.)*)"', rest)   # carry the real literal so a downstream asset/name lookup works
                try:
                    R[v] = ms.group(1).encode("utf-8").decode("unicode_escape") if ms else None
                except Exception:
                    R[v] = ms.group(1) if ms else None
            elif op.startswith("const-class"):
                R[v] = None
            elif op.startswith("const-wide"):
                R[v] = s64(_lit(ops[1]))
            elif op == "const/high16":
                R[v] = s32(_lit(ops[1]))
            else:
                R[v] = s32(_lit(ops[1]))
        elif op in ("move-wide", "move", "move-object", "move-wide/from16", "move/from16"):
            R[rg(ops[0])] = R[rg(ops[1])]
        elif op.startswith("move-result"):
            R[rg(ops[0])] = last
        elif op == "int-to-long":
            R[rg(ops[0])] = s64(R[rg(ops[1])])
        elif op == "long-to-int":
            R[rg(ops[0])] = s32(R[rg(ops[1])])
        elif op in ("return", "return-wide", "return-object"):
            return R[rg(ops[0])]
        elif op == "return-void":
            return None
        elif op in ("goto", "goto/16", "goto/32"):
            pc = labels[ops[0]]
        elif op.startswith("if-"):
            cond = op[3:]
            if cond.endswith("z"):
                a, b, lab = R[rg(ops[0])], 0, ops[1]
                cond = cond[:-1]
            else:
                a, b, lab = R[rg(ops[0])], R[rg(ops[1])], ops[2]
            t = {"eq": a == b, "ne": a != b, "lt": a < b, "ge": a >= b, "gt": a > b, "le": a <= b}[cond]
            if t:
                pc = labels[lab]
        elif op == "invoke-static":
            m = re.match(r"\{([^}]*)\},\s*L[^;]*/([^/;]+);->(\S+?)(\(\S*?\)\S+)$", rest.strip())
            if not m:
                raise ValueError("invoke %r" % ln)
            regs = [x.strip() for x in m.group(1).split(",") if x.strip()]
            callee = (m.group(2), m.group(3), m.group(4))
            if callee not in dump.methods:
                raise ValueError("unsupported call %r" % (callee,))
            cargs, i = [], 0
            for sl in _argslots(callee[2]):
                cargs.append(R[_reg(regs[i], nregs, nargs)])
                i += sl
            if _is_split_reader(dump.methods[callee], callee[2]):
                # Day 26 'analysis': (String)[B reader that pulls assets/<name> out of a feature/config split via the
                # Context + splitSourceDirs + ZipFile. We never model the Android APIs; we serve the real bundle bytes.
                last = _read_asset(dump, cargs[0])
            else:
                last = run(dump, callee[0], callee[1], callee[2], cargs, depth + 1)
        elif op == "new-array":
            R[rg(ops[0])] = [0] * R[rg(ops[1])]
        elif op == "array-length":
            R[rg(ops[0])] = len(R[rg(ops[1])])
        elif op.startswith("aput"):
            R[rg(ops[1])][R[rg(ops[2])]] = R[rg(ops[0])]
        elif op.startswith("aget"):
            R[rg(ops[0])] = R[rg(ops[1])][R[rg(ops[2])]]
        elif op == "new-instance" and stop_at_new_instance:
            return R
        elif op.startswith("sput"):
            ref = ops[1].strip()                               # "L..;->name:type" ; store the value under the full field ref
            dump.statics[ref] = R[rg(ops[0])]
        elif op.startswith("sget"):
            ref = ops[1].strip()                               # read back a static field; fall back to an inline compile-time const, else None
            if ref in dump.statics:
                R[rg(ops[0])] = dump.statics[ref]
            else:
                R[rg(ops[0])] = dump.field_consts.get(ref)
        else:
            m = re.match(r"(add|sub|mul|xor|or|and|shl|shr|ushr|rem|div)-(int|long)(/2addr|/lit8|/lit16)?$", op)
            if not m:
                raise ValueError("unsupported op %r" % op)
            f, ty, form = m.group(1), m.group(2), m.group(3)
            if form == "/2addr":
                d = rg(ops[0]); a = R[d]; b = R[rg(ops[1])]
            elif form:
                d = rg(ops[0]); a = R[rg(ops[1])]; b = _lit(ops[2])
            else:
                d = rg(ops[0]); a = R[rg(ops[1])]; b = R[rg(ops[2])]
            bits = 64 if ty == "long" else 32
            mask = (1 << bits) - 1
            sg = s64 if ty == "long" else s32
            sh = b & (bits - 1)
            if f == "add": r = a + b
            elif f == "sub": r = a - b
            elif f == "mul": r = a * b
            elif f == "xor": r = a ^ b
            elif f == "or": r = a | b
            elif f == "and": r = a & b
            elif f == "shl": r = a << sh
            elif f == "shr": r = a >> sh
            elif f == "ushr": r = (a & mask) >> sh
            elif f == "rem": r = abs(a) % abs(b) * (1 if a >= 0 else -1)
            else: r = int(a / b)
            R[d] = sg(r)
    raise RuntimeError("fell off method end")


def _patch_payload_loaders(d, payload):
    """Day 24 dynamic_dex: a (J)J method loads assets/payload.dex with InMemoryDexClassLoader and calls one static (J)J payload method
    by reflection (const-string name -> getDeclaredMethod -> Method.invoke). Replace such a method with a direct invoke-static of that
    payload method, whose smali is merged into the Dump. Static only; returns how many loaders were patched."""
    n = 0
    for key, (nregs, lines) in list(d.methods.items()):
        if key[2] != "(J)J" or not any("InMemoryDexClassLoader" in ln for ln in lines):
            continue
        name = None
        strs = {}
        for ln in lines:
            m = re.match(r'const-string\s+(v\d+),\s*"([^"]*)"', ln)
            if m:
                strs[m.group(1)] = m.group(2)
            m = re.match(r"invoke-virtual\s+\{([^}]*)\},\s*Ljava/lang/Class;->getDeclaredMethod\(", ln)
            if m:
                regs = [x.strip() for x in m.group(1).split(",")]
                if len(regs) >= 2 and regs[1] in strs:
                    name = strs[regs[1]]
        cands = [k for k in payload.methods if k[1] == name and k[2] == "(J)J"] if name else []
        if len(cands) != 1:
            continue
        for k, v in payload.methods.items():
            d.methods.setdefault(k, v)
        d.methods[key] = (6, ["invoke-static {p0, p1}, Lpayload/%s;->%s(J)J" % (cands[0][0], name), "move-result-wide v0", "return-wide v0"])
        n += 1
    return n


def answer_from_dex(dex_bytes, workdir, payload_dex=None, splits=None):
    """-> 'ANS-' + 16 uppercase hex, or None. baksmali (disassembler) is the only external tool; nothing is executed.
    payload_dex: the APK's assets/payload.dex bytes (Day 24 dynamic_dex variants), or None.
    splits: {asset_filename: bytes} from the feature/config split APKs of a Day 26 'analysis' App Bundle (e.g.
    {'huntress_feature.bin': <16 bytes>}); Release.code() folds assets/huntress_feature.bin into its long mixer."""
    os.makedirs(workdir, exist_ok=True)
    dp = os.path.join(workdir, "classes.dex")
    out = os.path.join(workdir, "smali")
    open(dp, "wb").write(dex_bytes)
    shutil.rmtree(out, ignore_errors=True)
    subprocess.run(["baksmali", "d", dp, "-o", out], check=True, capture_output=True, timeout=120)
    d = Dump(out)
    d.assets = dict(splits or {})
    if payload_dex:
        pp = os.path.join(workdir, "payload.dex")
        pout = os.path.join(workdir, "payload_smali")
        open(pp, "wb").write(payload_dex)
        shutil.rmtree(pout, ignore_errors=True)
        subprocess.run(["baksmali", "d", pp, "-o", pout], check=True, capture_output=True, timeout=120)
        _patch_payload_loaders(d, Dump(pout))
    for ck in d.clinits:                                  # populate any statics set in <clinit> before the target runs
        try:
            run(d, ck[0], ck[1], ck[2], [])
        except Exception:
            pass                                          # a clinit with unmodelable ops must not sink the arithmetic path
    cands = [k for k in d.methods if k[0] == "Release" and k[1] == "code"]
    if not cands:
        return None
    k = cands[0]
    # code() ends by formatting v0 as 16 hex nibbles after the first new-instance; evaluate up to there
    R = run(d, k[0], k[1], k[2], [None], stop_at_new_instance=True)
    if not isinstance(R, dict):
        return None
    v = R.get("v0")
    if not isinstance(v, int):
        return None
    return "ANS-%016X" % (v & M64)


if __name__ == "__main__":
    z = zipfile.ZipFile(sys.argv[1])
    sp = {}
    for _n in z.namelist():                               # pull any feature/config split assets out of a bundle for CLI use
        if _n.lower().endswith((".apk", ".zip")):
            try:
                _zz = zipfile.ZipFile(io.BytesIO(z.read(_n)))
                for _m in _zz.namelist():
                    if "assets/" in _m and not _m.endswith("huntress_puzzle.json"):
                        sp[_m.split("assets/", 1)[1]] = _zz.read(_m)
            except Exception:
                pass
    _dex = z.read("classes.dex") if "classes.dex" in z.namelist() else z.read([n for n in z.namelist() if n.endswith("base.apk")][0])
    print(answer_from_dex(_dex, sys.argv[2] if len(sys.argv) > 2 else ".tmp/smali_static", splits=sp))
