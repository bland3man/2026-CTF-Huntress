#!/usr/bin/env python3
"""Static, generic decoder for Huntress 'Script Triage' VBS fixtures. Never executes anything.
Returns (representation_label, transform_label, plaintext) where labels are the Codec_ tokens verbatim
(GM-accepted as the representation/transform answers on Day 04 single solve)."""
import re, sys, os, base64, glob

def _ints(parts, base):
    return [int(x, base) for x in parts if x != '']

def parse(mat, fmt):
    rev = fmt.startswith('reversed_')
    core = fmt[len('reversed_'):] if rev else fmt
    if core.startswith('base64'):
        b = list(base64.b64decode(mat + '=' * (-len(mat) % 4)))
    else:
        base = 16 if core.startswith('hex') else 10
        seps = {'pipe': '|', 'dash': '-', 'colon': ':', 'comma': ',', 'space': ' ', 'dot': '.', 'semicolon': ';'}
        sep = next((v for k, v in seps.items() if core.endswith(k)), None)
        if core.endswith('compact') or sep is None:
            if base == 16 and re.fullmatch(r'[0-9a-fA-F]+', mat): b = [int(mat[i:i+2], 16) for i in range(0, len(mat), 2)]
            else:
                for s in '|-:, .;':
                    if s in mat: b = _ints(mat.split(s), base); break
                else: b = [int(mat[i:i+2], 16) for i in range(0, len(mat), 2)]
        else: b = _ints(mat.split(sep), base)
    return b[::-1] if rev else b

def _candidates(b, keys):
    for base in (b, b[::-1]):
        yield base
        for k in range(256):
            yield [x ^ k for x in base]
            yield [(x + k) % 256 for x in base]
            yield [(x - k) % 256 for x in base]
            out = []; prev = k
            for x in base: out.append(x ^ prev); prev = x
            yield out
        for key in keys:
            yield [x ^ key[i % len(key)] for i, x in enumerate(base)]

def decode(path):
    s = open(path, encoding='utf-8', errors='replace').read()
    mat = re.search(r'Const Material_\w+ = "([^"]*)"', s).group(1)
    cm = re.search(r'Const Codec_\w+ = "([^"]*)"', s).group(1).split('|')
    fmt, tr = cm[0], cm[1]
    keys = [[int(x) for x in m.split(',')] for m in re.findall(r'Array\(([\d, ]+)\)', s) if len(m.split(',')) >= 2]
    b = parse(mat, fmt)
    for c in _candidates(b, keys):
        t = bytes(c)
        if re.match(rb'v=1\|steps=[a-z_,]+\|adapter=', t) and all(32 <= x < 127 for x in t): return fmt, tr, t.decode('latin-1')
    raise RuntimeError('cannot decode ' + path + ' codec ' + '|'.join(cm))

if __name__ == '__main__':
    for f in sorted(glob.glob(os.path.join(sys.argv[1], '*.vbs'))):
        fmt, tr, t = decode(f); print(os.path.basename(f), fmt, tr, '|', t[:60])
