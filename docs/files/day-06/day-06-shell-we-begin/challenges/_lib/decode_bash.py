#!/usr/bin/env python3
"""Static decoder for Huntress 'Script Triage' fixtures (Day 06 Bash layer + generic codec engine).
Never executes fixture code. Reads Material_/Codec_ (bash), MATERIAL_/CODEC_ (python, via ast.literal_eval),
and JScript packed literals, then reproduces the declared codec in Python and validates the output.

Codec string: '<representation>|<transform>|<param>' (e.g. base64_chunks|reverse_then_xor|3a).
Descriptor output: 'v=1|steps=a,b|adapter=..|stage_count=N|campaign_id=..|...'

usage: python3 decode_bash.py <dir>      # prints one summary line per .sh / .py file
"""
import ast, base64, json, os, re, sys

DESC_RE = re.compile(r'v=\d+\|steps=[a-z_,]+\|adapter=')


def _printable(b):
    return all(32 <= x < 127 for x in b)


def _ok_desc(b):
    return _printable(b) and bool(DESC_RE.match(bytes(b).decode('latin-1')))


# ---------------- representation -> byte list ----------------
def _b64(s, urlsafe=False):
    s = re.sub(r'\s', '', s)
    s += '=' * (-len(s) % 4)
    return list(base64.urlsafe_b64decode(s) if urlsafe else base64.b64decode(s))


def to_bytes(mat, rep):
    """mat: str / bytes / list / tuple. rep: representation token from the codec string."""
    rev = rep.startswith('reversed_')
    core = rep[len('reversed_'):] if rev else rep
    if isinstance(mat, (bytes, bytearray)):
        b = list(mat)
    elif isinstance(mat, (list, tuple)):
        b = [int(x) for x in mat]
    else:
        s = mat
        if 'base64' in core:
            b = _b64(s, urlsafe=('urlsafe' in core or '-' in s or '_' in s))
        elif core.startswith('percent'):
            b = [int(x, 16) for x in s.split('%') if x]
        elif core.startswith('hex'):
            hs = re.sub(r'[^0-9a-fA-F]', '', s) if any(c in s for c in ':- ,') is False else None
            if hs is not None:
                b = [int(hs[i:i + 2], 16) for i in range(0, len(hs), 2)]
            else:
                b = [int(x, 16) for x in re.split(r'[:\- ,]+', s) if x]
        else:  # decimal_* / integer_*
            b = [int(x) for x in re.split(r'[^0-9]+', s) if x]
    return b[::-1] if rev else b


# ---------------- transform ----------------
def _keylist(param):
    return [int(x, 16) for x in re.split(r'[,\s]+', param) if x]


def _rolling(b, k):
    """Two plausible rolling-xor variants; caller validates."""
    out1, prev = [], k
    for x in b:          # chain on ciphertext
        out1.append(x ^ prev); prev = x
    out2, prev = [], k
    for x in b:          # chain on plaintext
        y = x ^ prev; out2.append(y); prev = y
    return [out1, out2]


def apply_transform(b, tr, param):
    keys = _keylist(param) if param else []
    k = keys[0] if keys else 0
    if tr == 'identity':
        return [b]
    if tr == 'reverse_bytes':
        return [b[::-1]]
    if tr == 'reverse_then_xor':
        return [[x ^ k for x in b[::-1]]]
    if tr == 'single_byte_xor':
        return [[x ^ k for x in b]]
    if tr == 'add_modulo_256':      # encoder added k -> decoder subtracts (as the fixtures do)
        return [[(x - k) % 256 for x in b], [(x + k) % 256 for x in b]]
    if tr == 'subtract_modulo_256':
        return [[(x + k) % 256 for x in b], [(x - k) % 256 for x in b]]
    if tr == 'rolling_xor':
        return _rolling(b, k)
    if tr == 'repeating_key_xor':
        return [[x ^ keys[i % len(keys)] for i, x in enumerate(b)]]
    return []


def brute(b, extra_keys=()):
    for base in (b, b[::-1]):
        yield base
        for k in range(256):
            yield [x ^ k for x in base]
            yield [(x + k) % 256 for x in base]
            yield [(x - k) % 256 for x in base]
            for r in _rolling(base, k):
                yield r
        for key in extra_keys:
            out = [x ^ key[i % len(key)] for i, x in enumerate(base)]
            yield out
            yield out[::-1]


GENERIC_REPS = ('base64_literal', 'urlsafe_base64', 'percent_hex', 'hex_compact', 'hex_colon',
                'decimal_space', 'octal_space')


def _octal(s):
    return [int(x, 8) for x in re.split(r'[^0-7]+', s) if x]


def _reps_for(mat, rep):
    """Yield (rep_label, byte list): declared representation first, then every generic loader."""
    seen = []
    for r in (rep,) + GENERIC_REPS:
        try:
            b = _octal(mat) if (r.startswith('octal') and isinstance(mat, str)) else to_bytes(mat, r)
        except Exception:
            continue
        if not b or not all(0 <= x < 256 for x in b) or b in seen:
            continue
        seen.append(b)
        yield r, b


def decode_codec(mat, codec, valid=_ok_desc, extra_keys=()):
    """Return (text, method): 'declared' (codec reproduced as stated), 'brute' (declared
    representation, unknown/mismatched transform) or 'generic' (other loader x transform)."""
    parts = (codec.split('|') + ['', '', ''])[:3]
    rep, tr, param = [x.strip().lower() for x in parts]
    keys = list(extra_keys)
    try:
        pk = _keylist(param)
        if len(pk) > 1:
            keys.append(pk)
    except ValueError:
        pass
    for i, (r, b) in enumerate(_reps_for(mat, rep)):
        try:
            cands = apply_transform(b, tr, param)
        except Exception:
            cands = []
        for c in cands:
            if valid(c):
                return bytes(c).decode('latin-1'), ('declared' if i == 0 else 'generic')
        for c in brute(b, keys):
            if valid(c):
                return bytes(c).decode('latin-1'), ('brute' if i == 0 else 'generic')
    raise RuntimeError('cannot decode codec ' + codec)


def kv_of(s):
    return dict(x.split('=', 1) for x in s.strip().split('|') if '=' in x)


# ---------------- Bash ----------------
def bash_material(src):
    m = re.search(r'(?i)\bMaterial_(\w+)=((?:\'[^\']*\'|"[^"]*")+)', src)
    if not m:
        raise RuntimeError('no Material_')
    val = ''.join(p[1:-1] for p in re.findall(r'\'[^\']*\'|"[^"]*"', m.group(2)))
    c = re.search(r'(?i)\bCodec_' + re.escape(m.group(1)) + r'=(?:\'([^\']*)\'|"([^"]*)")', src)
    if not c:
        raise RuntimeError('no Codec_')
    return val, (c.group(1) if c.group(1) is not None else c.group(2))


def decode_bash(path):
    src = open(path, encoding='utf-8', errors='replace').read()
    mat, codec = bash_material(src)
    text, how = decode_codec(mat, codec)
    return {'lang': 'sh', 'codec': codec, 'method': how, 'text': text, 'kv': kv_of(text)}


# ---------------- Python carrier (static, ast only) ----------------
def py_material(src):
    tree = ast.parse(src)
    mats, codecs = {}, {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            n = node.targets[0].id
            if n.upper().startswith('MATERIAL_') or n.upper().startswith('CODEC_'):
                try:
                    v = ast.literal_eval(node.value)
                except Exception:
                    continue
                (mats if n.upper().startswith('MATERIAL_') else codecs)[n.split('_', 1)[1].lower()] = v
    for h, v in mats.items():
        if h in codecs:
            if isinstance(v, tuple) and v and all(isinstance(x, str) for x in v):
                v = ''.join(v)
            return v, codecs[h]
    raise RuntimeError('no MATERIAL_/CODEC_ pair')


def decode_py(path):
    src = open(path, encoding='utf-8', errors='replace').read()
    mat, codec = py_material(src)
    text, how = decode_codec(mat, codec)
    return {'lang': 'py', 'codec': codec, 'method': how, 'text': text, 'kv': kv_of(text)}


# ---------------- JScript (static) ----------------
def _js_json_ok(b):
    if not _printable(b):
        return False
    t = bytes(b).decode('latin-1')
    if '"steps"' not in t:
        return False
    try:
        o = json.loads(t)
        return isinstance(o, dict) and 'steps' in o
    except Exception:
        return False


def decode_js(path):
    """Static recovery of the JScript JSON config. Returns dict(cfg=..., method=...)."""
    src = open(path, encoding='utf-8', errors='replace').read()
    num = r'(?:0[xX][0-9a-fA-F]+|\d+)'
    arrays = [[int(x.strip(), 0) if not re.fullmatch(r'0\d+', x.strip()) else int(x.strip(), 10)
               for x in a.split(',') if x.strip()]
              for a in re.findall(r'\[\s*(' + num + r'(?:\s*,\s*' + num + r')+)\s*\]', src)]
    keys = [a for a in arrays if 2 <= len(a) <= 16]
    data = [a for a in arrays if len(a) > 16]
    # string literals on the right of an assignment, joining "a" + "b" concatenation; one line only
    lit = r'"(?:[^"\\\n]|\\.)*"'
    strs = []
    for m in re.finditer(r'=\s*(' + lit + r'(?:\s*\+\s*' + lit + r')*)', src):
        s = ''.join(p[1:-1] for p in re.findall(lit, m.group(1)))
        if len(s) >= 24:
            strs.append(s)
    cands = []
    if data:
        cands += data
        if len(data) > 1:
            cands.append([x for a in data for x in a])
    for s in strs:
        s2 = s.encode('latin-1').decode('unicode_escape')
        for rep in ('percent_hex', 'hex_colon', 'hex_compact', 'base64_literal', 'decimal_csv'):
            try:
                if rep == 'hex_compact' and not re.fullmatch(r'(?:[0-9a-fA-F]{2})+', s2): continue
                if rep == 'percent_hex' and '%' not in s2: continue
                if rep == 'hex_colon' and ':' not in s2: continue
                if rep == 'decimal_csv' and not re.fullmatch(r'[\d,\s\-:;|.]+', s2): continue
                if rep == 'base64_literal' and not re.fullmatch(r'[A-Za-z0-9+/=_\-\s]+', s2): continue
                cands.append(to_bytes(s2, rep))
            except Exception:
                pass
    for b in cands:
        for c in brute(b, keys):
            if _js_json_ok(c):
                return {'cfg': json.loads(bytes(c).decode('latin-1')), 'method': 'static'}
    raise RuntimeError('cannot statically decode ' + path)


if __name__ == '__main__':
    d = sys.argv[1]
    for f in sorted(os.listdir(d)):
        p = os.path.join(d, f)
        try:
            if f.endswith('.sh'):
                r = decode_bash(p)
            elif f.endswith('.py'):
                r = decode_py(p)
            elif f.endswith('.js'):
                r = decode_js(p); print(f, r['method'], json.dumps(r['cfg'])[:120]); continue
            else:
                continue
            print(f, r['codec'], r['method'], '|', r['text'][:140])
        except Exception as e:
            print(f, 'ERROR', e)
