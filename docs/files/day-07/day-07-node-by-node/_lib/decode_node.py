#!/usr/bin/env python3
"""Static decoder for Huntress Day 07 'Node by Node' .mjs operation-graph fixtures.
Never executes fixture code. Reads Material_<id> (string literal) + Codec_<id>
('<representation>|<transform>|<param>'), reproduces the codec in Python, validates the
output is the 'v=1|...' descriptor. Representations seen: base64_chunks, base64_literal,
hex_buffer, hex_array (JSON array of hex strings), escaped_octets (\\xHH text).
Transforms reuse decode_bash.apply_transform (identity, reverse_bytes, single_byte_xor,
rolling_xor, ...).

usage: python3 decode_node.py <dir-or-file>
"""
import re, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decode_bash as DB


def _js_unescape(s):
    out = []; i = 0
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            n = s[i + 1]
            simple = {'\\': '\\', '"': '"', "'": "'", '/': '/',
                      'n': '\n', 't': '\t', 'r': '\r', 'b': '\b', 'f': '\f'}
            if n in simple:
                out.append(simple[n]); i += 2; continue
            # keep backslash+char (e.g. the literal \xHH escaped_octets rely on)
            out.append(c); out.append(n); i += 2; continue
        out.append(c); i += 1
    return ''.join(out)


def mjs_material(src):
    m = re.search(r'Material_(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"', src, re.S)
    if not m:
        raise RuntimeError('no Material_')
    hid = m.group(1); raw = _js_unescape(m.group(2))
    c = re.search(r'Codec_' + re.escape(hid) + r'\s*=\s*"((?:[^"\\]|\\.)*)"', src, re.S)
    if not c:
        raise RuntimeError('no Codec_')
    return hid, raw, _js_unescape(c.group(1))


def _lenient(b):
    if not DB._printable(b):
        return False
    t = bytes(b).decode('latin-1')
    return t.startswith('v=1|') and '|' in t and '=' in t


def _one_string_cands(s):
    """Byte-list interpretations of a single string (no string-reversal here)."""
    cands = []
    if s.startswith('['):
        try:
            arr = json.loads(s)
            for conv in (lambda x: int(x, 16) & 0xff, lambda x: int(x) & 0xff):
                try:
                    cands.append([conv(x) for x in arr])
                except Exception:
                    pass
        except Exception:
            pass
    if re.search(r'\\x[0-9a-fA-F]{2}', s):
        cands.append([int(h, 16) for h in re.findall(r'\\x([0-9a-fA-F]{2})', s)])
    for us in (False, True):
        try:
            cands.append(DB._b64(s, urlsafe=us))
        except Exception:
            pass
    try:
        hs = re.sub(r'[^0-9a-fA-F]', '', s)
        if hs and len(hs) % 2 == 0:
            cands.append([int(hs[i:i + 2], 16) for i in range(0, len(hs), 2)])
    except Exception:
        pass
    try:
        nums = [int(x) for x in re.split(r'[^0-9]+', s) if x]
        if nums and all(0 <= n < 256 for n in nums):
            cands.append(nums)
    except Exception:
        pass
    return cands


def _escape_cands(raw):
    """Interpret JS \\uXXXX / \\xHH escape sequences (the 'unicode_escapes' representation family)."""
    cands = []
    u = re.findall(r'\\u([0-9a-fA-F]{4})', raw)
    if u:
        cands.append([int(h, 16) & 0xff for h in u])
    if '\\u' in raw or '\\x' in raw:
        try:
            dec = raw.encode('latin-1', 'ignore').decode('unicode_escape')
            cands.append([ord(ch) & 0xff for ch in dec])
            cands.extend(_one_string_cands(dec))        # decoded text may itself be base64/hex
        except Exception:
            pass
    return cands


def _candidate_byte_lists(raw):
    """Every plausible material->bytes interpretation, by CONTENT (rep token is only a hint).
    Tries the string AND its reversal (covers reversed_<rep> codecs where the STRING is reversed)."""
    s = raw.strip()
    cands = _one_string_cands(s) + _one_string_cands(s[::-1]) + _escape_cands(raw)
    uniq = []
    for c in cands:
        if c and all(0 <= x < 256 for x in c) and c not in uniq:
            uniq.append(c)
    return uniq


def robust_decode(material, codec, valid=_lenient):
    """Content-driven decode: try every byte interpretation of material (and its string reversal)
    x the declared transform x brute, validating on `valid`. Used for .mjs and any mutated fixture
    whose declared representation token (e.g. reversed_base64) the plain engine does not reproduce."""
    for mat in _candidate_byte_lists(material):
        try:
            return DB.decode_codec(mat, codec, valid=valid)
        except Exception:
            pass
    return DB.decode_codec(material, codec, valid=valid)   # last resort: engine's own rep loaders


def decode_node(path):
    src = open(path, encoding='utf-8', errors='replace').read()
    hid, raw, codec = mjs_material(src)
    text, how = robust_decode(raw, codec)
    return {'lang': 'mjs', 'codec': codec, 'method': how, 'text': text, 'kv': DB.kv_of(text)}


if __name__ == '__main__':
    tgt = sys.argv[1]
    paths = ([os.path.join(tgt, f) for f in sorted(os.listdir(tgt)) if f.endswith('.mjs')]
             if os.path.isdir(tgt) else [tgt])
    for p in paths:
        try:
            r = decode_node(p)
            print(os.path.basename(p), '|', r['codec'], r['method'], '|', r['text'])
        except Exception as e:
            print(os.path.basename(p), 'ERROR', repr(e))
