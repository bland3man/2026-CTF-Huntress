#!/usr/bin/env python3
"""Generic mobile-android solver (Huntress CTF 2026 lane `mobile-android`, Days 01-07). ctf_gm.solve_mode contract:
compute(start, blobs) -> {answer_id: answer}, derived from THIS attempt's own APK bytes. No day or id is hardcoded.

Every day so far ships assets/huntress_puzzle.json inside the APK: {"codec": ..., "data": ..., [key|parts/order]}.
The answer is data run through the declared codec. Codecs seen: plain/identity/none (D01), reverse (D02), base64 (D03),
xor+key over base64 data (D04), split parts+order (D05), hex/rot13 (D06), caesar+key (D07). Containers: an APK, a zip
holding APK(s) (D05) or raw JSON. Mastery = several deliveries, one per answer_id; each question names its artifact
("delivery N: <filename>"). An UNKNOWN codec is not fatal: every decoder is tried and the result must match the
question's answer format (ANS-<16 uppercase hex>), so a new codec usually still solves; otherwise it raises with the
codec name so the agent knows exactly what to add.

CLI: python3 autosolve_mobile.py <challenge id> [--dry]   (--dry: start + download + compute, print, no submit)
"""
import base64, binascii, bz2, codecs, gzip, hashlib, html, io, json, lzma, os, re, sys, threading, time, urllib.parse, zipfile, zlib

ANS = re.compile(r"^ANS-[0-9A-F]{16}$")
ANS_ANY = re.compile(r"(?<![0-9A-Za-z])ANS-[0-9A-F]{16}(?![0-9A-Za-z])")


def _b64(s):
    s = s.strip()
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _key_bytes(k):
    if isinstance(k, int):
        return bytes([k & 0xFF])
    if isinstance(k, list):
        return bytes(int(x) & 0xFF for x in k)
    k = str(k)
    if re.fullmatch(r"0x[0-9a-fA-F]+", k):
        return bytes([int(k, 16) & 0xFF])
    if re.fullmatch(r"\d+", k):
        return bytes([int(k) & 0xFF])
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", k):
        return bytes.fromhex(k)
    return k.encode()


def _raw(d):
    """bytes behind a data field: base64 (D04 xor) or hex, else the text itself"""
    if isinstance(d, list):
        return bytes(int(x) & 0xFF for x in d)
    for f in (lambda s: bytes.fromhex(s) if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s) else None, _b64):
        try:
            b = f(d)
            if b:
                return b
        except Exception:
            pass
    return d.encode("latin1")


def _caesar(d, k):
    return "".join(chr(ord(c) - k) for c in d)


def _xor(d, key):
    kb = _key_bytes(key)
    raw = _raw(d)
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(raw)).decode("latin1")


def _split(p):
    parts, order = p["parts"], p["order"]
    return "".join(parts[i] for i in sorted(range(len(parts)), key=lambda i: order[i]))


def _indexed(p):
    """D17: data permuted by 'order' (a permutation of range(len(data))). Scatter (out[order[i]]=data[i]) is the
    verified direction; gather (out[i]=data[order[i]]) is the inverse.
    2026-10-18 (remediation W4): a direction is accepted only when (a) the payload DECLARES it ('direction': 'scatter' | 'gather') and the
    declared reading is a valid ANS, or (b) exactly ONE of the two readings is a valid ANS (the other is an invalid reading, not a
    competitor). Both valid and different -> ValueError (AMBIGUOUS, never a silent pick). Neither valid -> ValueError (not a guess)."""
    d, o = p["data"], [int(x) for x in p["order"]]
    if len(d) != len(o) or sorted(o) != list(range(len(d))):
        raise ValueError("order is not a permutation of data")
    sc = [""] * len(d)
    for i, q in enumerate(o):
        sc[q] = d[i]
    sc = "".join(sc)
    ga = "".join(d[q] for q in o)
    declared = str(p.get("direction") or "").strip().lower()
    if declared in ("scatter", "gather"):
        c = sc if declared == "scatter" else ga
        if not ANS.match(c.strip()):
            raise ValueError("declared direction %r does not yield ANS-<16 hex>" % declared)
        return c
    hits = sorted({c for c in (sc, ga) if ANS.match(c.strip())})
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise ValueError("neither permutation direction yields ANS-<16 hex>; not guessing")
    raise ValueError("ambiguous permutation direction: scatter and gather both yield valid answers (declare 'direction')")


DECODERS = {
    "indexed": _indexed, "index": _indexed, "permute": _indexed, "permuted": _indexed, "scatter": _indexed,
    "plain": lambda p: p["data"], "identity": lambda p: p["data"], "none": lambda p: p["data"], "": lambda p: p["data"],
    "reverse": lambda p: p["data"][::-1], "rev": lambda p: p["data"][::-1],
    "base64": lambda p: _b64(p["data"]).decode(), "b64": lambda p: _b64(p["data"]).decode(),
    "hex": lambda p: bytes.fromhex(p["data"]).decode(),
    "rot13": lambda p: codecs.decode(p["data"], "rot13"),
    "caesar": lambda p: _caesar(p["data"], int(p.get("key", 0))),
    "xor": lambda p: _xor(p["data"], p.get("key", 0)),
    "split": _split,
}


def _fallbacks(p):
    """an unseen codec: try every known transform, plus keyed ones over a small key range, plus layered reverse"""
    d = p.get("data", "")
    yield from (f for f in DECODERS.values())
    key = p.get("key")
    if isinstance(d, str):
        for k in ([int(key)] if str(key).lstrip("-").isdigit() else []) + list(range(1, 26)):
            yield lambda p, k=k: _caesar(d, k)
            yield lambda p, k=k: _caesar(d, -k)
        yield lambda p: _b64(d[::-1]).decode()
        yield lambda p: bytes.fromhex(d[::-1]).decode()
        yield lambda p: _b64(d).decode()[::-1]
    if key is not None:
        yield lambda p: _xor(d, key)
    for k in range(256):
        yield lambda p, k=k: _xor(d, k)


# ---------------------------------------------------------------------------------------------------------------------------
# STRUCTURED SEARCH (2026-10-10, catalog-driven, see _test_mobile_catalog.py). Everything above handles the shapes seen on Days
# 1-10 (ONE codec per day, named in "codec"). This block covers what a puzzle author could plausibly do next: renamed fields,
# codec aliases, a stack of codecs ("a+b", "a|b", a "layers" list...), data that is one layer deeper than the codec says, keys
# that are stored in another form or not stored at all, split with another order convention, and the wider encoding space
# (base32/45/58/62/85, gzip/zlib/bz2/lzma, url, decimal/octal/binary, html, rot47, atbash). Every candidate is verified against
# the question's answer format, so a still-encoded string that merely looks right can never be returned.
# ---------------------------------------------------------------------------------------------------------------------------
_CODEC_ALT = ("encoding", "method", "type", "algorithm", "cipher_type", "scheme", "transform", "format")
_DATA_ALT = ("payload", "encoded", "value", "blob", "cipher", "ciphertext", "text", "message", "content", "secret", "body", "enc")
_KEY_ALT = ("shift", "k", "xor_key", "xorkey", "rot", "offset", "caesar_key", "caesar_shift", "xor")
_STACK_FIELDS = ("codecs", "layers", "chain", "stack", "steps", "pipeline", "transforms", "encodings")
_B64_CHARS = re.compile(rb"[A-Za-z0-9+/_\-]+={0,2}")


def _is_puzzle(j):
    if not isinstance(j, dict):
        return False
    if "codec" in j or str(j.get("schema", "")).startswith("huntress.mobile") or any(f in j for f in _STACK_FIELDS):
        return True
    return any(k in j for k in _CODEC_ALT) and any(k in j for k in ("data",) + _DATA_ALT)


def _unwrap(j):
    if _is_puzzle(j):
        return j
    if isinstance(j, dict):
        for v in j.values():
            if _is_puzzle(v):
                return v
    return None


def _loads(raw):
    for f in (lambda: json.loads(raw), lambda: json.loads(raw.decode("utf-8-sig"))):
        try:
            return f()
        except Exception:
            pass
    return None


def normalize_puzzle(p):
    """map renamed fields (payload/encoding/shift ...) onto data / codec / key; a copy, the input is never modified"""
    q = dict(p)
    if "codec" not in q:
        for k in _CODEC_ALT:
            if isinstance(q.get(k), (str, list)):
                q["codec"] = q[k]
                break
    if "data" not in q:
        for k in _DATA_ALT:
            if isinstance(q.get(k), (str, list)):
                q["data"] = q[k]
                break
    if "key" not in q:
        for k in _KEY_ALT:
            if q.get(k) is not None and not isinstance(q[k], (dict, bool)):
                q["key"] = q[k]
                break
    return q


def _canon(tok):
    """codec name -> (internal name, key from the name or None); None when the name is not recognised"""
    t = re.sub(r"[\s_\-.]+", "", str(tok).lower())
    t = re.sub(r"(?:encoded|encoding|encode|decoded|decode|text|string|cipher)$", "", t) or t
    if t in ("", "plain", "identity", "none", "raw", "clear", "cleartext", "noop", "nothing", "verbatim"):
        return ("plain", None)
    if t.startswith("rot47"):
        return ("rot47", None)
    m = re.fullmatch(r"(?:rot|caesar|shift|rotate|rotation)(\d+)?(?:alpha|ord|ascii|letters|bytes)?", t)
    if m:
        return ("caesar", int(m.group(1)) if m.group(1) else None)
    if t.startswith("xor"):
        return ("xor", None)
    if t.startswith("atbash"):
        return ("atbash", None)
    if t in ("reverse", "rev", "reversed", "strrev", "backwards", "flip", "reversestring", "mirror"):
        return ("reverse", None)
    if t.startswith(("base64", "b64")) or t in ("mime", "urlsafebase64"):
        return ("b64", None)
    if t.startswith(("base32hex", "b32hex")):
        return ("b32hex", None)
    if t.startswith(("base32", "b32")):
        return ("b32", None)
    if t.startswith(("base16", "b16", "hex")):
        return ("hex", None)
    if t.startswith(("ascii85", "a85", "base85", "b85", "z85")):
        return ("b85", None)
    for pre, nm in (("base58", "b58"), ("b58", "b58"), ("base62", "b62"), ("b62", "b62"), ("base45", "b45"), ("b45", "b45")):
        if t.startswith(pre):
            return (nm, None)
    if t in ("gzip", "gz", "gunzip", "zlib", "deflate", "bz2", "bzip2", "lzma", "xz", "compress", "compressed"):
        return ("comp", None)
    if t.startswith(("url", "percent", "uri")):
        return ("url", None)
    if t in ("decimal", "dec", "ascii", "charcodes", "charcode", "ords", "ordinal", "intlist", "integers", "ints", "bytes", "asciicodes", "decimalcodes"):
        return ("dec", None)
    if t in ("octal", "oct"):
        return ("oct", None)
    if t in ("binary", "bin", "bits", "bitstring"):
        return ("bin", None)
    if t.startswith(("html", "entities", "xmlentit")):
        return ("html", None)
    if t in ("split", "chunks", "chunk", "fragments", "fragment", "parts", "shuffle", "shuffled", "reassemble", "join", "segments", "pieces", "scatter", "splitjoin", "chunked"):
        return ("split", None)
    return None


def _layer_spec(q):
    """declared layers [(name, key)] in the order written, or None if any name is unknown / the shape is not a layer list"""
    raw = None
    for f in _STACK_FIELDS:
        if isinstance(q.get(f), list) and q[f]:
            raw = q[f]
            break
    if raw is None and isinstance(q.get("codec"), list):
        raw = q["codec"]
    key = q.get("key")
    if raw is None:
        s = q.get("codec", "")
        if not isinstance(s, str):
            return None
        raw = [x for x in re.split(r"\s*(?:->|=>|>|\+|\||,|;|/|_then_|\bthen\b)\s*|\s+", s.strip()) if x and x.lower() not in ("and", "of", "then")]
    out = []
    for item in raw:
        ik = key
        if isinstance(item, dict):
            nm = next((item[k] for k in ("codec",) + _CODEC_ALT if isinstance(item.get(k), str)), "")
            ik = next((item[k] for k in ("key",) + _KEY_ALT if item.get(k) is not None), key)
        else:
            nm = item
        r = _canon(nm)
        if r is None:
            return None
        out.append((r[0], r[1] if r[1] is not None else ik))
    return out


def _tx(b, f):
    return f(b.decode("latin1")).encode("latin1")


def _o_b64(b):
    t = re.sub(rb"\s+", b"", b)
    if not t or not _B64_CHARS.fullmatch(t):
        return []
    t = t.replace(b"-", b"+").replace(b"_", b"/")
    return [base64.b64decode(t + b"=" * (-len(t) % 4), validate=True)]


def _o_b32(b):
    t = re.sub(rb"\s+", b"", b).upper()
    if not re.fullmatch(rb"[A-Z2-7]+=*", t):
        return []
    t = t.rstrip(b"=")
    return [base64.b32decode(t + b"=" * (-len(t) % 8))]


def _o_b32hex(b):
    t = re.sub(rb"\s+", b"", b).upper()
    f = getattr(base64, "b32hexdecode", None)
    if f is None or not re.fullmatch(rb"[0-9A-V]+=*", t):
        return []
    t = t.rstrip(b"=")
    return [f(t + b"=" * (-len(t) % 8))]


def _o_hex(b):
    t = re.sub(rb"0x|\\x|[\s,:;]", b"", b, flags=re.I)
    if not t or len(t) % 2 or not re.fullmatch(rb"[0-9a-fA-F]+", t):
        return []
    return [binascii.unhexlify(t)]


def _o_inner(b):
    """the bytes a compressed / keyed payload may be wrapped in: itself, its base64, its hex"""
    out = [b]
    for f in (_o_b64, _o_hex):
        try:
            out += f(b)
        except Exception:
            pass
    return out


def _o_comp(b):
    out = []
    for inner in _o_inner(b):
        for fn in (gzip.decompress, zlib.decompress, bz2.decompress, lzma.decompress):
            try:
                out.append(fn(inner))
            except Exception:
                pass
    return out


def _o_url(b):
    return [urllib.parse.unquote_to_bytes(b.decode("latin1"))] if b"%" in b else []


def _o_dec(b):
    if not re.fullmatch(rb"[\d\s,;]+", b) or not re.search(rb"\d\D+\d", b):
        return []
    nums = [int(x) for x in re.findall(rb"\d+", b)]
    return [bytes(nums)] if nums and max(nums) < 256 else []


def _o_oct(b):
    t = re.sub(rb"0o|\\", b" ", b, flags=re.I)
    if not re.fullmatch(rb"[0-7\s,;]+", t):
        return []
    toks = re.findall(rb"[0-7]+", t)
    if len(toks) == 1 and len(toks[0]) % 3 == 0 and len(toks[0]) > 3:
        toks = [toks[0][i:i + 3] for i in range(0, len(toks[0]), 3)]
    vals = [int(x, 8) for x in toks]
    return [bytes(vals)] if vals and max(vals) < 256 else []


def _o_bin(b):
    t = re.sub(rb"0b|\s", b"", b, flags=re.I)
    if not t or not re.fullmatch(rb"[01]+", t):
        return []
    out = []
    for w in (8, 7):
        if len(t) % w == 0:
            vals = [int(t[i:i + w], 2) for i in range(0, len(t), w)]
            out.append(bytes(vals))
    return out


def _o_html(b):
    t = b.decode("latin1")
    return [html.unescape(t).encode("latin1")] if "&" in t else []


def _o_b85(b):
    out = []
    t = re.sub(rb"\s+", b"", b)
    for f in (base64.b85decode, base64.a85decode, lambda x: base64.a85decode(x, adobe=True)):
        try:
            out.append(f(t))
        except Exception:
            pass
    return out


def _o_b58(b):
    import decode_chain
    r = decode_chain._b58(re.sub(rb"\s+", b"", b).decode("ascii"))
    return [r] if r else []


def _o_b62(b):
    import decode_chain, string
    t = re.sub(rb"\s+", b"", b).decode("ascii")
    return [x for x in (decode_chain._b62(t, string.digits + string.ascii_uppercase + string.ascii_lowercase),
                        decode_chain._b62(t, string.ascii_uppercase + string.ascii_lowercase + string.digits)) if x]


def _o_b45(b):
    import decode_chain
    r = decode_chain._b45(b.strip().decode("ascii"))
    return [r] if r else []


_UNKEYED = {
    "b64": _o_b64, "b32": _o_b32, "b32hex": _o_b32hex, "hex": _o_hex, "comp": _o_comp, "url": _o_url, "dec": _o_dec, "oct": _o_oct, "bin": _o_bin,
    "html": _o_html, "b85": _o_b85, "b58": _o_b58, "b62": _o_b62, "b45": _o_b45,
    "rot13": lambda b: [_tx(b, lambda t: codecs.decode(t, "rot13"))],
    "rot47": lambda b: [_tx(b, lambda t: "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in t))],
    "atbash": lambda b: [_tx(b, lambda t: "".join(chr(122 - (ord(c) - 97)) if "a" <= c <= "z" else chr(90 - (ord(c) - 65)) if "A" <= c <= "Z" else c for c in t))],
    "reverse": lambda b: [b[::-1]],
}


def _caesar_outputs(b, key):
    t = b.decode("latin1")
    try:
        ks = [abs(int(str(key).strip(), 0))]
        ks_alpha = ks_ord = ks
    except Exception:
        ks_alpha, ks_ord = list(range(1, 26)), list(range(1, 65))
    out = []
    for k in ks_ord:
        for s in (-k, k):
            if all(0 <= ord(c) + s <= 255 for c in t):
                out.append("".join(chr(ord(c) + s) for c in t).encode("latin1"))
    for k in ks_alpha:
        for s in (-k, k):
            out.append("".join(chr((ord(c) - 65 + s) % 26 + 65) if "A" <= c <= "Z" else chr((ord(c) - 97 + s) % 26 + 97) if "a" <= c <= "z" else c for c in t).encode("latin1"))
    return out


def _xor_keys(key):
    if key is None:
        return None
    if isinstance(key, bool):
        return None
    if isinstance(key, int):
        return [bytes([key & 0xFF])]
    if isinstance(key, list):
        try:
            return [bytes(int(x) & 0xFF for x in key)]
        except Exception:
            return None
    s = str(key).strip()
    out = []
    if re.fullmatch(r"0x[0-9a-fA-F]+", s):
        h = s[2:]
        out.append(bytes.fromhex(h if len(h) % 2 == 0 else "0" + h))
    if re.fullmatch(r"\d+", s) and int(s) < 256:
        out.append(bytes([int(s)]))
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s):
        out.append(bytes.fromhex(s))
    if s:
        out.append(s.encode("latin1", "ignore"))
    return list(dict.fromkeys(out)) or None


def _xor_with(raw, kb):
    return bytes(x ^ kb[i % len(kb)] for i, x in enumerate(raw))


def _xor_outputs(b, key, final):
    ins = []
    for cand in [b] + [x for f in (_o_hex, _o_b64) for x in _safe(f, b)]:
        if cand and cand not in ins:
            ins.append(cand)
    keys = _xor_keys(key)
    out = []
    if keys:
        for kb in keys:
            for raw in ins:
                out.append(_xor_with(raw, kb))
        return out
    for raw in ins:
        for k in range(1, 256):
            out.append(bytes(x ^ k for x in raw))
        if final and len(raw) >= 4:                      # known-plaintext crib: the answer starts "ANS-" (covers repeating keys of 2-4 bytes)
            ks = bytes(c ^ pc for c, pc in zip(raw[:4], b"ANS-"))
            for n in (2, 3, 4):
                out.append(_xor_with(raw, ks[:n]))
    return out


def _safe(f, b):
    try:
        return list(f(b))
    except Exception:
        return []


def _layer_outputs(name, key, b, final):
    if name == "plain":
        return [b]
    if name in _UNKEYED:
        return _safe(_UNKEYED[name], b)
    if name == "caesar":
        return _caesar_outputs(b, key)
    if name == "xor":
        return _xor_outputs(b, key, final)
    return []


def _oracle(b, fmt, embedded=True):
    """the whole text IS an answer, or (embedded=True, ANS format only) it is mostly printable prose holding exactly one answer code.
    embedded is turned OFF for anything reached by brute-forcing a key: a wrong key can plant a code-shaped substring in noise."""
    t = b.decode("utf-8", "ignore")
    s = t.strip()
    if s and fmt.match(s):
        return s
    if embedded and fmt is ANS and len(t) <= 4096 and sum(32 <= ord(c) < 127 or c in "\r\n\t" for c in t) >= 0.95 * len(t):
        hits = set(ANS_ANY.findall(t))
        if len(hits) == 1:
            return hits.pop()
    return None


def _to_bytes(d):
    if isinstance(d, list):
        return bytes(int(x) & 0xFF for x in d)
    try:
        return d.encode("latin1")
    except UnicodeEncodeError:
        return d.encode("utf-8")


def _init_states(q):
    out = []
    parts, order = q.get("parts"), q.get("order")
    if isinstance(parts, list) and parts and all(isinstance(x, str) for x in parts):
        n = len(parts)
        seqs = []
        if isinstance(order, list) and len(order) == n and all(isinstance(x, int) and not isinstance(x, bool) for x in order):
            seqs.append(sorted(range(n), key=lambda i: order[i]))                       # real shape: order[i] = rank of parts[i]
            if sorted(order) == list(range(n)):
                seqs.append(list(order))                                                  # order = reading sequence of indices
            elif sorted(order) == list(range(1, n + 1)):
                seqs.append([x - 1 for x in order])
        seqs += [list(range(n)), list(range(n))[::-1]]
        seqs = [s for i, s in enumerate(seqs) if s not in seqs[:i]]
        for sq in seqs:
            out.append("".join(parts[i] for i in sq).encode("latin1", "ignore"))
        for nm in ("b64", "hex", "b32", "reverse", "rot13", "atbash", "rot47", "url"):   # every part encoded on its own
            dec = []
            for x in parts:
                r = _layer_outputs(nm, None, x.encode("latin1", "ignore"), False)
                if not r:
                    break
                dec.append(r[0])
            else:
                for sq in seqs:
                    out.append(b"".join(dec[i] for i in sq))
    d = q.get("data", "")
    if d:
        out.append(_to_bytes(d))
    return list(dict.fromkeys(out))


def _run_layers(init, layers, fmt, cap=3000):
    states = init
    for i, (name, key) in enumerate(layers):
        nxt, seen = [], set()
        for s in states:
            for o in _layer_outputs(name, key, s, i == len(layers) - 1):
                if o not in seen:
                    seen.add(o)
                    nxt.append(o)
                    if len(nxt) >= cap:
                        break
            if len(nxt) >= cap:
                break
        states = nxt
    brute = any(nm in ("xor", "caesar") and _keyless(nm, k) for nm, k in layers)
    for s in states:
        v = _oracle(s, fmt, embedded=not brute)
        if v:
            return v
    return None


def _keyless(name, key):
    """True when a keyed layer will be brute-forced (no usable key was declared)"""
    if key is None:
        return True
    if name == "caesar":
        try:
            int(str(key).strip(), 0)
            return False
        except Exception:
            return True
    return not _xor_keys(key)


def _generic(init, key, fmt, deadline, max_depth=4, max_states=600):
    """breadth-first peel over every unkeyed decoder; caesar / xor are expanded with the declared key only, but tried with EVERY key as a last step"""
    names = list(_UNKEYED) + (["caesar", "xor"] if key is not None else [])
    frontier, seen, n = [(s, 0) for s in init], set(), 0
    while frontier and n < max_states and time.time() < deadline:
        s, d = frontier.pop(0)
        if s in seen:
            continue
        seen.add(s)
        n += 1
        v = _oracle(s, fmt)
        if v:
            return v
        if 4 <= len(s) <= 4096:
            for nm in ("caesar", "xor"):
                for o in _layer_outputs(nm, None, s, True):
                    v = _oracle(o, fmt, embedded=False)
                    if v:
                        return v
        if d >= max_depth:
            continue
        for nm in names:
            for o in _layer_outputs(nm, key, s, False):
                if o not in seen and o:
                    frontier.append((o, d + 1))
    return None


def _structured(q, fmt, budget_s=8.0):
    if fmt is None:
        return None
    deadline = time.time() + budget_s
    init = _init_states(q)
    if not init:
        return None
    spec = _layer_spec(q)
    if spec is not None:
        layers = [l for l in spec if l[0] not in ("split", "plain")]
        orders = [layers] + ([layers[::-1]] if layers[::-1] != layers else [])
        for ly in orders:
            v = _run_layers(init, ly, fmt)
            if v:
                return v
    return _generic(init, q.get("key"), fmt, deadline)


def _dynamic(p, fmt):
    """Day 20 codec 'dynamic': data names a secondary DEX asset (assets/payload.dex); the module contract string
    ANS-<16 hex> is a string_id item in that DEX. STATIC read only (never executed). Exactly one distinct hit or nothing."""
    pl = p.get("_payload")
    if not isinstance(pl, (bytes, bytearray)):
        return None
    pat = re.compile(rb"ANS-[0-9A-F]{16}(?![0-9A-Fa-z])")
    hits = {m.group(0).decode() for m in pat.finditer(bytes(pl))}
    if len(hits) == 1:
        v = hits.pop()
        return v if (fmt is None or fmt.match(v)) else None
    return None


CODECS_USED = {}                                 # codec name -> answers it produced in the current compute() call (labels only, never data)


_ANALYSIS_MEMO = {}                              # sha256(exact APK bytes) -> decoded ANS string or None (process-local; pure function of the bytes)


def _analysis(p, fmt):
    blob = p.get("_apk")
    if not isinstance(blob, (bytes, bytearray)):
        return None
    h = hashlib.sha256(bytes(blob))
    sp = p.get("_splits")                                     # the answer also depends on feature-split assets (Day 26): include them in the key
    if isinstance(sp, dict):
        for nm in sorted(sp):
            h.update(nm.encode("utf-8", "replace"))
            h.update(b"\x00")
            h.update(bytes(sp[nm]))
    key = h.hexdigest()
    if key in _ANALYSIS_MEMO:
        return _ANALYSIS_MEMO[key]
    v = _analysis_uncached(p, fmt, key)
    _ANALYSIS_MEMO[key] = v
    return v


def _prewarm_analysis(puzzles):
    """decode every DISTINCT analysis APK once, a few at a time (baksmali is an external process, so threads overlap); compute() then only reads the memo"""
    try:
        todo = {}
        for q in puzzles:
            if str(q.get("codec", "")).strip().lower() == "analysis" and isinstance(q.get("_apk"), (bytes, bytearray)):
                k = hashlib.sha256(bytes(q["_apk"])).hexdigest()
                if k not in _ANALYSIS_MEMO:
                    todo.setdefault(k, q)
        if len(todo) < 2 or os.environ.get("HUNTRESS_MOBILE_PARALLEL", "1") == "0":
            return
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max(2, min(4, len(todo), os.cpu_count() or 2))) as ex:
            list(ex.map(lambda q: _analysis(q, ANS), todo.values()))
    except Exception:
        pass                                      # best effort: the per-question loop decodes anything still missing, exactly as before


def _analysis_uncached(p, fmt, key=""):
    """Day 23 codec 'analysis' (keys build/codec/day/schema, no data): STATIC read of the whole APK (never executed).
    Dumps the APK next to the Day 23 scripts for offline inspection; returns an ANS string only if exactly one distinct hit."""
    blob = p.get("_apk")
    if not isinstance(blob, (bytes, bytearray)):
        return None
    bundle = p.get("_bundle")                                 # the FULL downloaded blob (base+feature App Bundle) when there was one
    evidence = bundle if isinstance(bundle, (bytes, bytearray)) else blob
    try:
        d = os.path.join("challenges", "Day 23", "scripts")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "analysis_%d_%s.apk" % (int(time.time()), key[:8])), "wb") as f:
            f.write(bytes(evidence))                          # save the whole bundle so the feature split is preserved for evidence/replay
    except Exception:
        pass
    pat = re.compile(rb"ANS-[0-9A-F]{16}(?![0-9A-Fa-z])")
    hits = set()
    try:
        z = zipfile.ZipFile(io.BytesIO(bytes(blob)))
        for n in z.namelist():
            if not n.endswith("huntress_puzzle.json"):
                hits |= {m.group(0).decode() for m in pat.finditer(z.read(n))}
    except Exception:
        pass
    if len(hits) == 1:
        return hits.pop()
    try:                                          # Day 23: no literal ANS string; Release.code() is pure static long arithmetic in the DEX
        import smali_static
        z = zipfile.ZipFile(io.BytesIO(bytes(blob)))
        payload = z.read("assets/payload.dex") if "assets/payload.dex" in z.namelist() else None     # Day 24 dynamic_dex: reflective Module.share(long)
        splits = p.get("_splits") if isinstance(p.get("_splits"), dict) else None                    # Day 26 'analysis': feature-split assets (huntress_feature.bin) the DEX folds in
        return smali_static.answer_from_dex(z.read("classes.dex"), os.path.join(".tmp", "smali_static_%d_%d" % (os.getpid(), threading.get_ident())), payload, splits)
    except Exception as e:
        print("AUTOSOLVE mobile: analysis static evaluation failed: %s" % type(e).__name__, flush=True)
        return None


def decode_puzzle(p, fmt=ANS):
    if str(p.get("codec", "")).strip().lower() == "analysis" and p.get("_apk") is not None:
        v = _analysis(p, fmt)
        if v:
            print("AUTOSOLVE mobile: codec 'analysis' - one ANS string read statically from the APK", flush=True)
            return v
    if str(p.get("codec", "")).strip().lower() in ("dynamic", "dynamic_dex", "dex") and p.get("_payload") is not None:
        v = _dynamic(p, fmt)
        if v:
            print("AUTOSOLVE mobile: codec 'dynamic' - ANS string read statically from the secondary DEX", flush=True)
            return v
    p = normalize_puzzle(p)
    c = str(p.get("codec", "")).strip().lower() if not isinstance(p.get("codec"), list) else ""
    if c in DECODERS:
        try:
            v = DECODERS[c](p).strip()
            if fmt is None or fmt.match(v):
                CODECS_USED[c] = CODECS_USED.get(c, 0) + 1          # provenance (2026-10-21): the Day 21 writeup could not say which codec solved it; compute() prints one summary line
                return v
        except Exception:
            pass
    for f in _fallbacks(p):
        try:
            v = f(p).strip()
        except Exception:
            continue
        if fmt is not None and fmt.match(v):
            return v
    # LAST RESORT (2026-10-09): _fallbacks above covers the known transforms, caesar, layered reverse and all 256 xor
    # keys, but NOT the wider encoding space (base32/45/58/62/85, zlib/gzip/bz2/lzma, octal, binary, rot47, atbash).
    # decode_chain already searches exactly that, so try it before halting the mode - today's new layer is usually one
    # more encoding, and a hard raise here would force a live adapter patch under the timed clock.
    try:                                        # 2026-10-10: structured search (stacks, aliases, keys in other forms, wider encodings), format-verified
        v = _structured(p, fmt)
        if v:
            print("AUTOSOLVE mobile: codec %r not a single known codec - recovered via structured search" % (p.get("codec"),), flush=True)
            return v
    except Exception:
        pass
    try:
        import decode_chain
        d = p.get("data", "")
        raw = d.encode() if isinstance(d, str) else bytes(int(x) & 0xFF for x in d)
        for row in decode_chain.best_chains(raw, depth=6, top=5):   # rows are (score, chain, data)
            cand = row[-1]
            v = (cand.decode("utf-8", "ignore") if isinstance(cand, bytes) else str(cand)).strip()
            if fmt is not None and fmt.match(v):
                print("AUTOSOLVE mobile: codec %r unknown - recovered via decode_chain" % p.get("codec"), flush=True)
                return v
        if fmt is None:                          # no format to verify against: only accept ONE unambiguous answer-shaped string, never "the best-looking" text
            found = set()
            for row in decode_chain.best_chains(raw, depth=6, top=5):
                found.update(decode_chain.find_answers(row[-1].decode("utf-8", "ignore")))
            if len(found) == 1:
                print("AUTOSOLVE mobile: codec %r unknown - one answer-shaped string via decode_chain" % p.get("codec"), flush=True)
                return found.pop()
    except Exception:
        pass
    raise ValueError("cannot decode puzzle codec=%r keys=%s - add a decoder for it" % (p.get("codec"), sorted(p)))


def puzzles_in(blob):
    """every huntress_puzzle.json reachable in this blob (APK, zip of APKs/zips, or raw JSON), in name order"""
    j = _unwrap(_loads(blob))
    if j is not None:
        return [j]
    out = []
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
    except Exception:
        return out
    names = sorted(z.namelist())
    for n in names:
        if n.endswith("huntress_puzzle.json"):
            try:
                j = _unwrap(_loads(z.read(n)))
                if j is not None:
                    d = j.get("data") if isinstance(j, dict) else None
                    if isinstance(j, dict) and str(j.get("codec", "")).lower() == "analysis":
                        j["_apk"] = blob
                    if isinstance(d, str) and d in names:       # Day 20 'dynamic': data is a path to a member (secondary DEX)
                        j["_payload"] = z.read(d)
                    out.append(j)
            except Exception:
                pass
    if out:
        return out
    for n in names:                              # a renamed puzzle file: any other .json under assets/ that has the puzzle shape
        if n.lower().endswith(".json") and "assets/" in n:
            try:
                j = _unwrap(_loads(z.read(n)))
                if j is not None:
                    out.append(j)
            except Exception:
                pass
    if out:
        return out
    for pw in (None, b"infected"):
        feature_assets = {}                                     # Day 26 'analysis' App Bundle: feature/config split assets the base DEX reads via readSplit
        for n in names:
            if n.lower().endswith((".apk", ".zip")):
                try:
                    sub = z.read(n, pwd=pw)
                except Exception:
                    continue
                try:
                    out += puzzles_in(sub)
                except Exception:
                    pass
                try:
                    sz = zipfile.ZipFile(io.BytesIO(sub))
                    for mm in sz.namelist():
                        if "assets/" in mm and not mm.endswith("huntress_puzzle.json"):
                            feature_assets.setdefault(mm.split("assets/", 1)[1], sz.read(mm))
                except Exception:
                    pass
        if out:
            if feature_assets:                                  # hand the whole bundle + its split assets to any analysis puzzle (its DEX needs them)
                for p in out:
                    if isinstance(p, dict) and str(p.get("codec", "")).strip().lower() == "analysis":
                        p.setdefault("_splits", feature_assets)
                        p.setdefault("_bundle", blob)
            return out
    return out


def _fmt(q):
    syn = json.dumps((q or {}).get("answer_format", "")).lower()
    return ANS if ("ans-" in syn or not q) else None


def _merge_split_fragments(puzzles):
    """Day 26 'split' over an Android App Bundle / .apks: the pieces are distributed across the base split and one or
    more configuration/feature splits. The base huntress_puzzle.json carries the 'parts'/'order' skeleton with empty
    slots; each feature split carries a single fragment as {'part': <str>, 'part_index': <int>} (a config JSON, not a
    full puzzle on its own). Fold every fragment into the base 'parts' at its declared index and drop the fragment
    entries, so decode_puzzle() sees one coherent split puzzle with all slots filled. Inputs with no such fragment
    (single-file puzzles, Day 05 single-container splits) pass through unchanged. The input list/dicts are never
    mutated; ambiguous shapes (no fragment, not exactly one base, or a malformed index) are left untouched - no guess."""
    if not isinstance(puzzles, list) or len(puzzles) < 2:
        return puzzles
    frags = [p for p in puzzles if isinstance(p, dict) and "part" in p and "part_index" in p
             and not isinstance(p.get("parts"), list)]
    bases = [p for p in puzzles if isinstance(p, dict) and isinstance(p.get("parts"), list)]
    if not frags or len(bases) != 1:
        return puzzles
    base = dict(bases[0])
    parts = list(base.get("parts") or [])
    for fr in frags:
        try:
            i = int(fr["part_index"])
        except (TypeError, ValueError):
            return puzzles                                       # malformed index: don't guess, leave input unchanged
        if i < 0:
            return puzzles
        while i >= len(parts):
            parts.append("")
        parts[i] = fr["part"]
    base["parts"] = parts
    return [base] + [p for p in puzzles if p is not bases[0] and p not in frags]


def compute(start, blobs):
    ids = start["answer_ids"]
    arts = start.get("artifacts") or []
    names = [a.get("filename", "") for a in arts]
    per_blob = [_merge_split_fragments(puzzles_in(b)) for b in blobs]
    flat = [p for ps in per_blob for p in ps]
    if not flat:
        raise ValueError("no huntress_puzzle.json found in %d artifact(s) %s" % (len(blobs), names))
    _prewarm_analysis(flat)
    qs = {q.get("id"): q for q in (start.get("questions") or [])}
    ans = {}
    CODECS_USED.clear()
    for i, aid in enumerate(ids):
        q = qs.get(aid) or {}
        art = str(q.get("artifact", ""))
        idx = None
        for k, n in enumerate(names):                       # 1) by the filename the question names
            if n and n in art and k < len(per_blob) and per_blob[k]:
                idx = k
        if idx is None:                                     # 2) by "delivery N"
            m = re.search(r"delivery\s+(\d+)", art)
            if m and int(m.group(1)) - 1 < len(per_blob) and per_blob[int(m.group(1)) - 1]:
                idx = int(m.group(1)) - 1
        if idx is not None:
            p = per_blob[idx][0]
        else:                                               # 3) by position across all puzzles found
            p = flat[min(i, len(flat) - 1)]
        ans[aid] = decode_puzzle(p, _fmt(q))
    if CODECS_USED:
        print("AUTOSOLVE mobile: %d answer(s) decoded; codec(s) used: %s" % (len(ans), ", ".join("%s x%d" % kv for kv in sorted(CODECS_USED.items()))), flush=True)
    return ans


if __name__ == "__main__":
    sys.path.insert(0, "challenges/_lib")
    from ctf_gm import GM, solve_mode
    cid = sys.argv[1]
    gm = GM()
    if "--dry" in sys.argv:
        st = gm.start(cid)
        blobs = [gm.download(cid, e, i) for i, e in enumerate(gm.artifacts(st))]
        print(json.dumps(compute(st, blobs)))
    else:
        r = solve_mode(gm, cid, compute)
        print(json.dumps({k: r.get(k) for k in ("result", "remaining", "status")}))
