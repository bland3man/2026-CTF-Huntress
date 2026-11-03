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
import base64, binascii, bz2, codecs, gzip, html, io, json, lzma, re, sys, time, urllib.parse, zipfile, zlib

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


def _analysis_member_literals(blob):
    """distinct ANS-<16 upper hex> literals in every NON-puzzle member of an APK/zip (the pre-DEX 'analysis' fast path)"""
    pat = re.compile(rb"ANS-[0-9A-F]{16}(?![0-9A-Fa-z])")
    hits = set()
    try:
        z = zipfile.ZipFile(io.BytesIO(bytes(blob)))
        for n in z.namelist():
            if not n.endswith("huntress_puzzle.json"):
                hits |= {m.group(0).decode() for m in pat.finditer(z.read(n))}
    except Exception:
        pass
    return hits


def _analysis(p, fmt):
    """codec 'analysis' (Days 23-26: keys build/codec/day/schema, no data): the answer is whatever Release.code() computes
    from the artifact's own DEX. Executed by the stdlib interpreter on the APK (or the whole base+feature bundle when there
    was one, so feature-split assets are visible). Only an artifact with no DEX / no Release.code may fall back to ONE
    unambiguous ANS literal in a non-puzzle member. Anything else unsupported raises a typed DexHeld, never a guess."""
    blob = p.get("_bundle") if isinstance(p.get("_bundle"), (bytes, bytearray)) else p.get("_apk")
    if not isinstance(blob, (bytes, bytearray)):
        return None
    blob = bytes(blob)
    try:
        v = _apk_run_release(blob).strip()
        if not ANS.match(v):
            raise DexHeld("analysis: Release.code() result is not ANS-<16 upper hex>")
    except DexNoRelease:
        lits = _analysis_member_literals(blob)
        if len(lits) != 1:
            raise DexHeld("analysis: no Release.code() in the artifact's DEX and %d distinct ANS literal(s) in non-puzzle members" % len(lits))
        v = next(iter(lits))
    if fmt is not None and not fmt.match(v):
        return None
    return v


def decode_puzzle(p, fmt=ANS):
    if str(p.get("codec", "")).strip().lower() == "analysis" and (p.get("_apk") is not None or p.get("_bundle") is not None):
        v = _analysis(p, fmt)
        if v:
            CODECS_USED["analysis"] = CODECS_USED.get("analysis", 0) + 1
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
                    if isinstance(j, dict) and str(j.get("codec", "")).strip().lower() == "analysis":
                        j["_apk"] = blob                         # the answer lives in this APK's own DEX, not in the JSON
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
        for n in names:
            if n.lower().endswith((".apk", ".zip")):
                try:
                    out += puzzles_in(z.read(n, pwd=pw))
                except Exception:
                    continue
        if out:
            for p in out:                                       # Day 26 App Bundle: give an analysis puzzle the whole base+feature bundle so its DEX can read the feature split
                if isinstance(p, dict) and str(p.get("codec", "")).strip().lower() == "analysis":
                    p.setdefault("_bundle", blob)
            return out
    return out


def _merge_split_fragments(puzzles):
    """Day 26/27 'split' over a base+feature bundle: the base huntress_puzzle.json carries the parts/order skeleton with
    empty slots; the feature split carries one fragment as {'part': <str>, 'part_index': <int>}. Fold each fragment into
    the base 'parts' at its declared index and drop the fragment entries. Inputs with no fragment, not exactly one base,
    or a malformed index pass through unchanged (no guess). The input list/dicts are never mutated."""
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
            return puzzles
        if i < 0:
            return puzzles
        while i >= len(parts):
            parts.append("")
        parts[i] = fr["part"]
    base["parts"] = parts
    return [base] + [p for p in puzzles if p is not bases[0] and p not in frags]


def _fmt(q):
    syn = json.dumps((q or {}).get("answer_format", "")).lower()
    return ANS if ("ans-" in syn or not q) else None


# ---------- Day 28 Protocol Reconstruction (.apk) scaffold (2026-10-28 PORT) ----
# Defensive .apk extractor. The adapter previously had zero coverage for .apk-shaped
# protocol-reconstruction challenges and would HELD on first contact. This scaffold
# handles the common field families (urls, permissions, package name, main activity)
# via string scanning across classes.dex + AndroidManifest.xml (binary AXML strings
# section). It is intentionally defensive -- an agent clones+refines when the GM
# asks something structural the scaffold can't yet reach.

def _looks_like_apk(blob):
    """APKs are zips containing classes.dex + AndroidManifest.xml."""
    if not blob or blob[:4] != b"PK\x03\x04":
        return False
    try:
        import zipfile as _zf, io as _io
        with _zf.ZipFile(_io.BytesIO(blob)) as z:
            names = z.namelist()
            return "AndroidManifest.xml" in names and any(n.startswith("classes") and n.endswith(".dex") for n in names)
    except Exception:
        return False


def _apk_members(blob):
    """{member_name: bytes} for the known APK roles we extract (not every member)."""
    import zipfile as _zf, io as _io
    out = {}
    try:
        with _zf.ZipFile(_io.BytesIO(blob)) as z:
            for n in z.namelist():
                if n == "AndroidManifest.xml" or (n.startswith("classes") and n.endswith(".dex")) or n == "resources.arsc":
                    out[n] = z.read(n)
    except Exception:
        pass
    return out


_DEX_PRINTABLE_RE = re.compile(rb"[\x20-\x7E]{4,}")


def _dex_strings(dex):
    """Minimal DEX string scan. Pulls all 4+ byte printable ASCII runs; good enough
    for URL/permission/class-name recovery without a full DEX parser."""
    if not dex or dex[:3] != b"dex":
        return []
    # ASCII-only sweep is good enough for URLs/permissions/class refs. A proper DEX
    # parser (string_ids table) would also catch UTF-8 encoded data but at ~10x cost;
    # the agent clones+refines when a specific question needs that.
    return [m.group(0).decode("ascii", "ignore") for m in _DEX_PRINTABLE_RE.finditer(dex)]


def _manifest_strings(axml):
    """AndroidManifest.xml is BINARY AXML. The strings section lives after an 8-byte
    header + a string-pool chunk header. Pull UTF-16LE and UTF-8 printable runs; this
    catches the package name, uses-permission names, activity names reliably."""
    if not axml or len(axml) < 12:
        return []
    out = set()
    # Scan for UTF-16LE printable runs (every other byte 0x00 for ASCII chars):
    for m in re.finditer(rb"(?:[\x20-\x7E]\x00){4,}", axml):
        out.add(m.group(0).decode("utf-16-le", "ignore"))
    # Scan for UTF-8 printable runs too (AXML v2+ may use UTF-8 strings):
    for m in _DEX_PRINTABLE_RE.finditer(axml):
        out.add(m.group(0).decode("ascii", "ignore"))
    return sorted(out)


_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%\-]+")
_PERM_RE = re.compile(r"android\.permission\.[A-Z_]+")
_ACTIVITY_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+Activity")
# Minimal Android package pattern (reverse-dns, lowercase): com.example.app
_PKG_RE = re.compile(r"\b([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,})\b")


def _apk_facts(blob):
    """Dict of recovered facts from an APK blob. Empty values mean 'not recoverable
    by this scaffold'; the agent can refine. ASCII-only output."""
    members = _apk_members(blob)
    axml_strs = _manifest_strings(members.get("AndroidManifest.xml", b""))
    dex_blobs = [v for k, v in members.items() if k.startswith("classes") and k.endswith(".dex")]
    dex_strs = []
    for d in dex_blobs:
        dex_strs.extend(_dex_strings(d))
    all_strs = set(axml_strs) | set(dex_strs)

    urls = sorted({u for s in all_strs for u in _URL_RE.findall(s)})
    perms = sorted({p for s in all_strs for p in _PERM_RE.findall(s)})
    activities = sorted({a for s in all_strs for a in _ACTIVITY_RE.findall(s)})
    # Package: first reverse-DNS token that appears in manifest + referenced in a dex
    # class name. Heuristic; refine via clone when the GM wants an exact value.
    axml_set = set(axml_strs)
    pkg_cands = []
    for s in axml_strs:
        for m in _PKG_RE.findall(s):
            if m.count(".") >= 2 and not m.startswith(("android.", "java.", "androidx.", "kotlin.")):
                pkg_cands.append(m)
    # Prefer the one that also appears as a dex string class ref:
    for p in pkg_cands:
        if any(p in s for s in dex_strs):
            pkg = p
            break
    else:
        pkg = pkg_cands[0] if pkg_cands else None

    # Main activity: either an "<pkg>.<Name>Activity" in manifest, or ".MainActivity":
    main_act = None
    for a in activities:
        if ".MainActivity" in a or a.endswith(".MainActivity"):
            main_act = a
            break
    if main_act is None and activities:
        main_act = activities[0]

    return {
        "package_name": pkg,
        "endpoint_urls": urls,
        "permission_list": perms,
        "activities": activities,
        "main_activity": main_act,
        "member_count": len(members),
        "dex_count": len(dex_blobs),
    }


def _apk_j(xs):
    """Compact JSON array of strings (adapter-wide convention)."""
    return json.dumps(list(xs), separators=(",", ":"), ensure_ascii=False)


def _apk_answer(aid, suf, facts):
    """Map an answer_id suffix to an _apk_facts field. Returns None when the field is
    unknown to this scaffold (caller falls through to generic/HELD)."""
    s = suf.lower()
    if "url" in s or "endpoint" in s:
        return _apk_j(facts.get("endpoint_urls") or [])
    if "permission" in s:
        return _apk_j(facts.get("permission_list") or [])
    if "package" in s:
        return facts.get("package_name") or ""
    if "main_activity" in s or "entry_activity" in s or ("main" in s and "activity" in s):
        return facts.get("main_activity") or ""
    if s in ("activities", "activity_list"):
        return _apk_j(facts.get("activities") or [])
    if "member_count" in s or "entry_count" in s:
        return str(facts.get("member_count") or 0)
    if "dex_count" in s or "class_file_count" in s:
        return str(facts.get("dex_count") or 0)
    return None


def _apk_compute(start, blobs):
    """compute()-shaped answer map for APK artifacts. Pairs each answer_id to the
    scaffold facts of whichever blob is an APK (first wins; CTF days rarely ship
    multiple APKs per attempt)."""
    arts = start.get("artifacts") or []
    names = [a.get("filename", "") for a in arts]
    apk_facts_by_idx = {i: _apk_facts(b) for i, b in enumerate(blobs) if _looks_like_apk(b)}
    if not apk_facts_by_idx:
        raise ValueError("no .apk artifact found")
    qs = {q.get("id"): q for q in (start.get("questions") or [])}
    ans = {}
    for aid in start["answer_ids"]:
        q = qs.get(aid) or {}
        # D29 P0-B (2026-10-28): the former `next(iter(apk_facts_by_idx))` fallback picked
        # the FIRST APK whenever the question's artifact text did not substring-match a
        # filename. That could attribute an answer to the WRONG APK when the attempt ships
        # multiple APKs. The resolver below demands a UNIQUE contract-anchored match
        # (filename / hash / delivery / set_id / provable singleton) and HELDs otherwise.
        idx = _resolve_blob_binding(aid, q, start, names, list(apk_facts_by_idx.keys()))
        facts = apk_facts_by_idx[idx]
        # Strip set prefix if present (set1.protocol.urls -> protocol.urls)
        bare_aid = aid.split(".", 1)[1] if ("." in aid and aid.split(".", 1)[0].startswith("set")) else aid
        # Try protocol-prefixed and raw suffixes:
        suf = bare_aid
        for prefix in ("protocol.", "protocol_", "apk.", "apk_", "manifest.", "manifest_"):
            if suf.startswith(prefix):
                suf = suf[len(prefix):]
                break
        v = _apk_answer(aid, suf, facts)
        if v is None:
            # unknown field: raise so the agent sees exactly which question needs a
            # new extractor (clone + refine)
            raise ValueError("apk scaffold: no handler for answer_id %r (suffix %r); facts available: %s" % (aid, suf, sorted(facts.keys())))
        ans[aid] = v
    return ans


# ---------- Day 28 Protocol Reconstruction DEX port (2026-10-28 WS agent-5) -----
# Pure extraction helpers ported from challenges/Day 28/Protocol Reconstruction/
# scripts/solve_dex.py so the lane does NOT need androguard at adapter runtime.
# These helpers are PURE and READ-ONLY (no bytecode execution, no network I/O):
#   - MASK32 / MASK64 / _java_s32 / _java_s64            Java 2's-complement semantics
#   - _java_shr(a,n) / _java_ushr64(a,n) / _java_shl64   Java 64-bit arithmetic + logical shifts
#   - _descriptor_types                                   Dalvik method-descriptor arg parser
#   - _apks_members                                       .apks (ZIP of APKs) feature-split walker
#   - _dex_header / _dex_string_ids                       real DEX structural parser (string table)
#   - _dex_strings_structured                             returns the full string pool, UTF-8 safe
#   - _dex_find_ans_constants                             scans string pool for embedded ANS-<16 hex>
#   - _decode_ha_frame                                    SS packet framing (0x48 0x41 LL ... 0x11)
#   - _apk_release_ans_candidates                         SS/pre-computed-literal ANS discovery for an APK
#
# WHY not call solve_dex.py as a subprocess: operator directive #3 says do not. The
# adapter must stay importable without androguard, pytest, or any CTF-day dep. For
# TT/MM the real DEX bytecode must be interpreted to recover the computed answer;
# this adapter does NOT ship a Dalvik VM, so TT/MM paths fall back to:
#   (a) string-pool scan for a literal ANS- constant (works when the author embeds
#       the pre-computed answer, as in SS), then
#   (b) HELD with a precise message that names the missing capability so the agent
#       can clone the Day 28 solve_dex.py locally with androguard installed.
MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1


def _java_s32(value):
    """Reinterpret a Python int as a Java 32-bit signed int (two's complement)."""
    value &= MASK32
    return value if value < (1 << 31) else value - (1 << 32)


def _java_s64(value):
    """Reinterpret a Python int as a Java 64-bit signed long (two's complement)."""
    value &= MASK64
    return value if value < (1 << 63) else value - (1 << 64)


def _java_shr(a, n, width=64):
    """Java arithmetic right shift (`>>`): sign-extends. Width is 32 or 64.
    Python's `>>` already sign-extends for *negative* ints, but when `a` is held
    as an unsigned 2's-complement mask, Python treats it as a huge positive int
    (no sign bit) and `>>` fills with zeros instead of the sign bit — exactly
    the bug this helper exists to prevent on the Protocol Reconstruction lane."""
    if width not in (32, 64):
        raise ValueError("Java shr width must be 32 or 64, got %r" % width)
    n &= (width - 1)
    mask = MASK64 if width == 64 else MASK32
    signed = _java_s64(a) if width == 64 else _java_s32(a)
    return (signed >> n) & mask


def _java_ushr(a, n, width=64):
    """Java logical right shift (`>>>`): never sign-extends. Zero-fills."""
    if width not in (32, 64):
        raise ValueError("Java ushr width must be 32 or 64, got %r" % width)
    n &= (width - 1)
    mask = MASK64 if width == 64 else MASK32
    return (a & mask) >> n


def _java_shl(a, n, width=64):
    """Java left shift. Wraps at width bits (overflow is truncated silently)."""
    if width not in (32, 64):
        raise ValueError("Java shl width must be 32 or 64, got %r" % width)
    n &= (width - 1)
    mask = MASK64 if width == 64 else MASK32
    return (a << n) & mask


def _java_long_wrap(a):
    """Reduce a Python int to a Java 64-bit signed long (wrap on over/underflow)."""
    return _java_s64(a & MASK64)


def _descriptor_types(descriptor):
    """Parse a Dalvik method descriptor like '(IJLjava/lang/String;)V' and return
    the argument type descriptors as a list (e.g. ['I', 'J', 'Ljava/lang/String;']).
    Supports array types (e.g. '[B', '[[Ljava/lang/Object;'). Pure, no DEX needed."""
    if "(" not in descriptor or ")" not in descriptor:
        raise ValueError("not a method descriptor: %r" % descriptor)
    body = descriptor[descriptor.index("(") + 1: descriptor.index(")")].replace(" ", "")
    result = []
    i = 0
    while i < len(body):
        start = i
        while i < len(body) and body[i] == "[":
            i += 1
        if i >= len(body):
            raise ValueError("truncated descriptor: %r" % descriptor)
        if body[i] == "L":
            end = body.find(";", i)
            if end < 0:
                raise ValueError("unterminated L-type: %r" % descriptor)
            i = end + 1
        else:
            i += 1
        result.append(body[start:i])
    return result


def _looks_like_apks(blob):
    """`.apks` split packages are an outer ZIP whose entries are themselves APKs."""
    if not blob or blob[:4] != b"PK\x03\x04":
        return False
    try:
        import zipfile as _zf, io as _io
        with _zf.ZipFile(_io.BytesIO(blob)) as z:
            names = z.namelist()
            # at least one inner .apk; no top-level AndroidManifest.xml (that marks a plain APK)
            if "AndroidManifest.xml" in names:
                return False
            return any(n.endswith(".apk") for n in names)
    except Exception:
        return False


def _apks_members(blob):
    """Walk a `.apks` split bundle and return a dict mapping each inner APK's name
    to the dict _apk_members() returns for it (plus every asset under 'assets/').
    This is the .apks feature-split handler called out in the operator spec."""
    import zipfile as _zf, io as _io
    out = {}
    try:
        with _zf.ZipFile(_io.BytesIO(blob)) as outer:
            for inner_name in outer.namelist():
                if not inner_name.endswith(".apk"):
                    continue
                try:
                    inner_blob = outer.read(inner_name)
                except Exception:
                    continue
                roles = _apk_members(inner_blob)
                # also collect every asset under assets/ (feature split carries huntress_feature.bin here)
                try:
                    with _zf.ZipFile(_io.BytesIO(inner_blob)) as inner_z:
                        for n in inner_z.namelist():
                            if n.startswith("assets/"):
                                roles[n] = inner_z.read(n)
                except Exception:
                    pass
                out[inner_name] = roles
    except Exception:
        pass
    return out


# -------- Real DEX structural parser (string_ids + header) ---------------------
# This is NOT a Dalvik VM. It's a defensive reader for the string pool, which lets
# the adapter find embedded ANS-xxx constants without executing any bytecode.

def _uleb128(buf, pos):
    """Decode an unsigned LEB128 integer starting at buf[pos]. Returns (value, new_pos)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("uleb128 ran off end of DEX string entry")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, pos
        shift += 7
        if shift > 35:
            raise ValueError("uleb128 too long (corrupt DEX)")


def _dex_header(dex):
    """Parse the DEX file header. Returns a dict with the fields the string-table
    parser needs: magic, string_ids_size, string_ids_off. Raises on malformed input."""
    if not dex or len(dex) < 0x70:
        raise ValueError("DEX too short to hold a header (%d bytes)" % (len(dex) if dex else 0))
    if dex[:4] != b"dex\n":
        raise ValueError("DEX magic mismatch: %r" % dex[:4])
    # Endianness tag at offset 0x28; 0x12345678 is little-endian (the only sane value)
    endian = int.from_bytes(dex[0x28:0x2C], "little")
    if endian not in (0x12345678, 0x78563412):
        raise ValueError("DEX endian tag unexpected: 0x%08X" % endian)
    byteorder = "little" if endian == 0x12345678 else "big"
    string_ids_size = int.from_bytes(dex[0x38:0x3C], byteorder)
    string_ids_off = int.from_bytes(dex[0x3C:0x40], byteorder)
    file_size = int.from_bytes(dex[0x20:0x24], byteorder)
    return {
        "magic": dex[:8],
        "version": dex[4:8],
        "endian": byteorder,
        "file_size": file_size,
        "string_ids_size": string_ids_size,
        "string_ids_off": string_ids_off,
    }


def _dex_string_ids(dex, header=None):
    """Yield each string from the DEX string pool, UTF-8 (modified UTF-8) decoded.
    Raises ValueError on structural corruption; a single bad entry logs and skips.
    Does NOT execute any bytecode."""
    if header is None:
        header = _dex_header(dex)
    n = header["string_ids_size"]
    off = header["string_ids_off"]
    bo = header["endian"]
    if off == 0 and n == 0:
        return
    if off + 4 * n > len(dex):
        raise ValueError("string_ids table extends past DEX end")
    out = []
    for i in range(n):
        data_off = int.from_bytes(dex[off + 4 * i: off + 4 * i + 4], bo)
        if data_off <= 0 or data_off >= len(dex):
            continue
        try:
            _utf16_size, data_pos = _uleb128(dex, data_off)
            end = dex.find(b"\x00", data_pos)
            if end < 0:
                continue
            raw = dex[data_pos:end]
            # DEX uses MUTF-8 (standard UTF-8 is a superset for the ASCII range we care about).
            try:
                out.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                out.append(raw.decode("utf-8", "replace"))
        except Exception:
            continue
    return out


def _dex_strings_structured(dex):
    """Full DEX string pool as a list. On header failure returns the regex sweep
    (same behavior as _dex_strings) so callers degrade gracefully."""
    try:
        return _dex_string_ids(dex)
    except Exception:
        return _dex_strings(dex)


_ANS_LITERAL_RE = re.compile(r"ANS-[0-9A-F]{16}")


def _dex_find_ans_constants(dex):
    """Scan the DEX string pool for literal ANS-<16 hex> constants. Returns a
    sorted set of distinct matches. Protocol Reconstruction's Release.code() COMPUTES
    the answer from bytecode (so for TT/MM this will usually be empty), but SS cases
    and any variant where the pre-computed answer is embedded as a string literal
    will produce a hit. ASCII-only, no bytecode execution."""
    hits = set()
    for s in _dex_strings_structured(dex):
        if isinstance(s, str):
            for m in _ANS_LITERAL_RE.findall(s):
                hits.add(m)
    return sorted(hits)


# -------- SS packet framing (0x48 0x41 LL <payload> 0x11) ----------------------

def _decode_ha_frame(frame_bytes):
    """Decode the Protocol Reconstruction SS framing documented in the Day 28
    writeup: `0x48 0x41 | <length byte> | <payload> | 0x11`. Returns the ASCII
    payload or None when the input does not fit the frame shape. Pure, defensive.

    Signed-byte length is honored (treated unsigned over 0..255; the writeup example
    length = 0x14 = 20 bytes). Trailing bytes after the terminator are tolerated."""
    if not frame_bytes or len(frame_bytes) < 4:
        return None
    buf = bytes(frame_bytes)
    if buf[0] != 0x48 or buf[1] != 0x41:
        return None
    length = buf[2]
    if length == 0 or 3 + length + 1 > len(buf):
        return None
    if buf[3 + length] != 0x11:
        return None
    payload = buf[3:3 + length]
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError:
        return None


def _apk_release_ans_candidates(blob):
    """Collect every ANS-<16 hex> literal recoverable from an APK or APKS artifact
    without bytecode execution. Returns a sorted list of distinct matches.
    Sources, in priority order:
      1. SS framing (0x48 0x41 LL ... 0x11) inside any `assets/huntress_puzzle.json`
         or similarly placed asset blob (treated as raw bytes, not JSON).
      2. SS framing anywhere inside each inner APK's assets (feature-split case).
      3. DEX string_ids pool scan for literal ANS- constants.
    This is NOT a Release.code() emulator; it is the no-VM fallback for lane
    autosolve. TT/MM where the answer is computed from Release.code() will produce
    an empty list and the caller MUST HELD with a precise message, not guess."""
    import zipfile as _zf, io as _io

    candidates = []

    def _scan_asset_blob(ab):
        if not ab:
            return
        # Try the HA framing on the raw bytes directly (SS writeup example).
        v = _decode_ha_frame(ab)
        if v:
            m = _ANS_LITERAL_RE.search(v)
            if m:
                candidates.append(m.group(0))
        # Also sweep the asset for any embedded ANS literal (defensive).
        for m in _ANS_LITERAL_RE.finditer(ab.decode("latin1", "ignore")):
            candidates.append(m.group(0))

    def _scan_apk(apk_blob):
        try:
            with _zf.ZipFile(_io.BytesIO(apk_blob)) as z:
                for n in z.namelist():
                    if n.startswith("assets/"):
                        try:
                            _scan_asset_blob(z.read(n))
                        except Exception:
                            pass
                    if n.startswith("classes") and n.endswith(".dex"):
                        try:
                            dex = z.read(n)
                        except Exception:
                            continue
                        for v in _dex_find_ans_constants(dex):
                            candidates.append(v)
        except Exception:
            pass

    if _looks_like_apks(blob):
        # feature-split .apks: walk every inner apk
        try:
            with _zf.ZipFile(_io.BytesIO(blob)) as outer:
                for inner in outer.namelist():
                    if inner.endswith(".apk"):
                        try:
                            _scan_apk(outer.read(inner))
                        except Exception:
                            continue
        except Exception:
            pass
    elif _looks_like_apk(blob):
        _scan_apk(blob)

    return sorted({c for c in candidates if ANS.match(c)})


# -------- Stdlib DEX class/method/code_item reader + Dalvik interpreter -------
# Port of the Dalvik subset interpreted by solve_dex.py (which needs androguard).
# Everything below is stdlib only: no androguard, no subprocess, no network. An opcode
# outside the supported set raises DexHeld carrying the opcode and code-unit offset
# (never a guess).

class DexHeld(ValueError):
    """Typed HELD for the DEX interpreter: carries reason / opcode / offset / method."""

    def __init__(self, reason, opcode=None, offset=None, method=None, partial=None):
        self.reason, self.opcode, self.offset, self.method = reason, opcode, offset, method
        self.partial = partial or {}
        bits = ["DEX HELD: " + reason]
        if opcode is not None:
            bits.append("opcode=0x%02X" % opcode)
        if offset is not None:
            bits.append("offset=0x%04X" % offset)
        if method:
            bits.append("method=%s" % method)
        ValueError.__init__(self, " ".join(bits))


class DexNoRelease(DexHeld):
    """No Release.code(Context) method exists in the supplied DEX files."""


class UnresolvedArtifactBinding(ValueError):
    """D29 P0-B typed HELD (2026-10-28): the answer_id does not resolve to a UNIQUE,
    GM-contract-anchored artifact / blob / puzzle. Replaces the former unsafe fallbacks
    (first-APK iter, flat[min(i, len-1)] positional, per_blob[idx][0] first-puzzle) that
    could attribute an answer to the WRONG delivery and still pass format validation.

    Carries the answer_id, the candidate blob indices, and a short human reason so the
    agent sees exactly what the GM contract failed to disambiguate.
    """

    def __init__(self, answer_id, candidates, reason):
        self.answer_id = answer_id
        self.candidates = list(candidates)
        self.reason = reason
        msg = ("MOBILE HELD: UNRESOLVED_ARTIFACT_BINDING %s - %s (candidates=%s)"
               % (answer_id, reason, candidates))
        ValueError.__init__(self, msg)


def _resolve_blob_binding(aid, question, start, names, candidate_idxs):
    """D29 P0-B artifact-association resolver (2026-10-28).

    Match an answer_id to a UNIQUE blob index. Preference order, all contract-anchored:
      1. Exact filename / basename / path from the question's `artifact` descriptor.
      2. SHA-256 or SHA-1 match from the question's `artifact_sha256` / `artifact_sha1`
         / `artifact_hash` field against `start.artifacts[i].sha256` (or _sha1).
      3. `delivery N` ordinal from the question's artifact text, matched against the
         GM-declared `start.artifacts[i].delivery` or 1-based blob position.
      4. `set_id` / `set` metadata matching the question's `set` or `set_id` field or
         the `setN.` id prefix.
      5. Singleton: EXACTLY one candidate exists under the current contract, no filename
         / hash / set tells it apart - accept.
    Anything else -> UnresolvedArtifactBinding.

    `candidate_idxs` is the set of blob indices eligible for this answer (e.g. only APK
    blobs for the APK scaffold; all blobs for compute()). Must have at least one item.
    """
    arts = start.get("artifacts") or []
    candidates = list(candidate_idxs)
    if not candidates:
        raise UnresolvedArtifactBinding(aid, candidates, "no eligible blob available")

    def _info(i):
        return arts[i] if 0 <= i < len(arts) else {}

    q = question or {}
    art_text = str(q.get("artifact") or "")
    q_sha256 = str(q.get("artifact_sha256") or q.get("artifact_hash") or "").lower()
    q_sha1 = str(q.get("artifact_sha1") or "").lower()
    q_set = str(q.get("set") or q.get("set_id") or "")
    aid_set = ""
    if "." in aid:
        head = aid.split(".", 1)[0]
        if head.startswith("set"):
            aid_set = head

    def _basename(p):
        """portable basename without an os import; matches both / and \\ separators."""
        if not p:
            return p
        for sep in ("/", "\\"):
            if sep in p:
                p = p.rsplit(sep, 1)[-1]
        return p

    # 1) filename / basename match (strict: substring of the question's artifact text)
    matched_names = []
    for i in candidates:
        nm = str(_info(i).get("filename") or (names[i] if i < len(names) else ""))
        if nm and art_text and (nm in art_text or art_text.endswith(nm) or _basename(nm) in art_text):
            matched_names.append(i)
    if len(matched_names) == 1:
        return matched_names[0]
    if len(matched_names) > 1:
        raise UnresolvedArtifactBinding(aid, matched_names,
            "multiple eligible blobs share the filename referenced by the question")

    # 2) SHA match
    if q_sha256 or q_sha1:
        matched_hash = []
        for i in candidates:
            h256 = str(_info(i).get("sha256") or "").lower()
            h1 = str(_info(i).get("sha1") or "").lower()
            if (q_sha256 and h256 and q_sha256 == h256) or (q_sha1 and h1 and q_sha1 == h1):
                matched_hash.append(i)
        if len(matched_hash) == 1:
            return matched_hash[0]
        if len(matched_hash) > 1:
            raise UnresolvedArtifactBinding(aid, matched_hash,
                "multiple eligible blobs have the hash referenced by the question")

    # 3) "delivery N" ordinal (1-based) - only valid if the GM declares a delivery index
    m = re.search(r"delivery\s+(\d+)", art_text)
    if m:
        n = int(m.group(1)) - 1
        matched_delivery = [i for i in candidates if (_info(i).get("delivery") == (n + 1)) or (i == n)]
        if len(matched_delivery) == 1:
            return matched_delivery[0]
        if len(matched_delivery) > 1:
            raise UnresolvedArtifactBinding(aid, matched_delivery,
                "multiple eligible blobs match delivery %d" % (n + 1))

    # 4) set_id tagging on the GM artifact record
    if q_set or aid_set:
        target_set = (q_set or aid_set).lower()
        matched_set = []
        for i in candidates:
            info_set = str(_info(i).get("set_id") or _info(i).get("set") or "").lower()
            if info_set and info_set == target_set:
                matched_set.append(i)
        if len(matched_set) == 1:
            return matched_set[0]
        if len(matched_set) > 1:
            raise UnresolvedArtifactBinding(aid, matched_set,
                "multiple eligible blobs share set_id %s" % target_set)

    # 5) Singleton: exactly one eligible blob under the current contract. Allowed only
    #    when the question does NOT point to a different artifact (so a wrong-artifact
    #    reference is not silently accepted). If the question text names an artifact
    #    different from the one blob available, HELD.
    if len(candidates) == 1:
        only = candidates[0]
        only_name = str(_info(only).get("filename") or (names[only] if only < len(names) else ""))
        if art_text and only_name and only_name not in art_text and art_text not in only_name and _basename(only_name) not in art_text:
            raise UnresolvedArtifactBinding(aid, candidates,
                "singleton blob %r does not match the question's artifact text %r" % (only_name, art_text[:80]))
        return only

    raise UnresolvedArtifactBinding(aid, candidates,
        "no filename / hash / delivery / set_id in the question matches a unique blob (D29 P0-B fail-closed)")


def _mutf8(b):
    b = b.replace(b"\xc0\x80", b"\x00")
    try:
        return b.decode("utf-8", "surrogatepass")
    except UnicodeDecodeError:
        return b.decode("latin1")


def _le(buf, off, n):
    if off < 0 or off + n > len(buf):
        raise DexHeld("read past end of DEX (off=0x%X n=%d)" % (off, n))
    return int.from_bytes(buf[off:off + n], "little")


class _DexFile:
    """Just enough of a DEX file: strings, types, protos, fields, methods, class_data code_items."""

    def __init__(self, raw):
        try:
            h = _dex_header(raw)
        except ValueError as e:
            raise DexHeld("bad DEX header: %s" % e)
        if h["endian"] != "little":
            raise DexHeld("big-endian DEX is not supported")
        self.raw = raw
        self.n_str, self.o_str = h["string_ids_size"], h["string_ids_off"]
        self.n_type, self.o_type = _le(raw, 0x40, 4), _le(raw, 0x44, 4)
        self.n_proto, self.o_proto = _le(raw, 0x48, 4), _le(raw, 0x4C, 4)
        self.n_field, self.o_field = _le(raw, 0x50, 4), _le(raw, 0x54, 4)
        self.n_meth, self.o_meth = _le(raw, 0x58, 4), _le(raw, 0x5C, 4)
        self.n_cls, self.o_cls = _le(raw, 0x60, 4), _le(raw, 0x64, 4)
        for n, o, w, nm in ((self.n_str, self.o_str, 4, "string_ids"), (self.n_type, self.o_type, 4, "type_ids"),
                            (self.n_proto, self.o_proto, 12, "proto_ids"), (self.n_field, self.o_field, 8, "field_ids"),
                            (self.n_meth, self.o_meth, 8, "method_ids"), (self.n_cls, self.o_cls, 32, "class_defs")):
            if n and o + n * w > len(raw):
                raise DexHeld("%s table extends past DEX end" % nm)
        self._s = {}

    def string(self, i):
        if i in self._s:
            return self._s[i]
        if not 0 <= i < self.n_str:
            raise DexHeld("string index %d out of range" % i)
        pos = _le(self.raw, self.o_str + 4 * i, 4)
        try:
            _n, pos = _uleb128(self.raw, pos)
        except ValueError as e:
            raise DexHeld("bad string entry %d: %s" % (i, e))
        end = self.raw.find(b"\x00", pos)
        if end < 0:
            raise DexHeld("unterminated string entry %d" % i)
        self._s[i] = _mutf8(self.raw[pos:end])
        return self._s[i]

    def type(self, i):
        if not 0 <= i < self.n_type:
            raise DexHeld("type index %d out of range" % i)
        return self.string(_le(self.raw, self.o_type + 4 * i, 4))

    def proto(self, i):
        """-> (param type descriptors, return type descriptor)"""
        if not 0 <= i < self.n_proto:
            raise DexHeld("proto index %d out of range" % i)
        o = self.o_proto + 12 * i
        ret = self.type(_le(self.raw, o + 4, 4))
        poff = _le(self.raw, o + 8, 4)
        params = []
        if poff:
            for k in range(_le(self.raw, poff, 4)):
                params.append(self.type(_le(self.raw, poff + 4 + 2 * k, 2)))
        return params, ret

    def method_ref(self, i):
        """-> (owner, name, param types, return type)"""
        if not 0 <= i < self.n_meth:
            raise DexHeld("method index %d out of range" % i)
        o = self.o_meth + 8 * i
        params, ret = self.proto(_le(self.raw, o + 2, 2))
        return self.type(_le(self.raw, o, 2)), self.string(_le(self.raw, o + 4, 4)), params, ret

    def field_ref(self, i):
        if not 0 <= i < self.n_field:
            raise DexHeld("field index %d out of range" % i)
        o = self.o_field + 8 * i
        return "%s->%s:%s" % (self.type(_le(self.raw, o, 2)), self.string(_le(self.raw, o + 4, 4)), self.type(_le(self.raw, o + 2, 2)))

    @staticmethod
    def sig(owner, name, params, ret):
        return "%s->%s(%s)%s" % (owner, name, "".join(params), ret)

    def methods(self):
        """yield _DexMethod for every method that has a code_item, in class_def / class_data order"""
        raw = self.raw
        for c in range(self.n_cls):
            cd = self.o_cls + 32 * c
            data_off = _le(raw, cd + 24, 4)
            if not data_off:
                continue
            try:
                pos = data_off
                sizes = []
                for _ in range(4):
                    v, pos = _uleb128(raw, pos)
                    sizes.append(v)
                for _ in range(sizes[0] + sizes[1]):          # static + instance fields: skip
                    _, pos = _uleb128(raw, pos)
                    _, pos = _uleb128(raw, pos)
                for group in (sizes[2], sizes[3]):             # direct, then virtual
                    midx = 0
                    for _ in range(group):
                        d, pos = _uleb128(raw, pos)
                        flags, pos = _uleb128(raw, pos)
                        code_off, pos = _uleb128(raw, pos)
                        midx += d
                        if code_off:
                            owner, name, params, ret = self.method_ref(midx)
                            yield _DexMethod(self, self.sig(owner, name, params, ret), params, ret, bool(flags & 0x8), code_off)
            except DexHeld:
                raise
            except ValueError as e:
                raise DexHeld("bad class_data for class_def %d: %s" % (c, e))


class _DexMethod:
    def __init__(self, dex, sig, params, ret, is_static, code_off):
        self.dex, self.sig, self.params, self.ret, self.is_static = dex, sig, params, ret, is_static
        raw = dex.raw
        self.regs = _le(raw, code_off, 2)
        self.ins = _le(raw, code_off + 2, 2)
        n = _le(raw, code_off + 12, 4)
        if code_off + 16 + 2 * n > len(raw):
            raise DexHeld("code_item insns extend past DEX end", method=sig)
        self.insns = [int.from_bytes(raw[code_off + 16 + 2 * k: code_off + 18 + 2 * k], "little") for k in range(n)]


def _S16(v):
    return v - 0x10000 if v & 0x8000 else v


def _S8(v):
    return v - 0x100 if v & 0x80 else v


def _S4(v):
    return v - 0x10 if v & 0x8 else v


def _wide_type(t):
    return t in ("J", "D")


class _VmLoader(object):
    """a ClassLoader value; an InMemoryDexClassLoader additionally owns the payload DEX it was built from"""
    __slots__ = ("payload",)

    def __init__(self):
        self.payload = None


class _VmByteBuffer(object):
    __slots__ = ("data",)

    def __init__(self, data):
        self.data = data


class _VmClass(object):
    """java.lang.Class by DEX type descriptor, e.g. 'Lcom/x/Module;'"""
    __slots__ = ("desc",)

    def __init__(self, desc):
        self.desc = desc


class _VmMethod(object):
    __slots__ = ("desc", "name", "nparams")

    def __init__(self, desc, name, nparams):
        self.desc, self.name, self.nparams = desc, name, nparams


# ------------------------------------------------------------------------------------
# D29 NATIVE-METHOD DISPATCH (ported from agent-5's D29 White Box Key Recovery clone,
# 2026-10-29). JNI-bound methods declared `native` in the DEX have no bytecode: their
# real body is in the APK's lib/<arch>/lib*.so. For the Java_<class>_<method> leaf
# functions these builds use, we statically read the exported symbol from the ELF64
# library (parse only, nothing is executed as the host CPU) and run its x86-64 straight
# -line body through a tiny emulator covering the opcode set those bodies use.
# ------------------------------------------------------------------------------------
_NATIVE_PREFIX = "::native::"


def _elf_symbol_code(so, symbol):
    """bytes of an exported function from an ELF64 shared object (static parse only, nothing is executed):
    from the symbol's address up to its size, or to the first ret if the size is 0."""
    import struct
    if so[:4] != b"\x7fELF" or so[4] != 2:
        raise DexHeld("native library is not an ELF64 object")
    shoff, = struct.unpack_from("<Q", so, 0x28)
    phoff, = struct.unpack_from("<Q", so, 0x20)
    phentsize, phnum, shentsize, shnum = struct.unpack_from("<HHHH", so, 0x36)
    loads = []
    for i in range(phnum):
        p_type, _fl, p_off, p_va, _pa, p_fsz, _msz, _al = struct.unpack_from("<IIQQQQQQ", so, phoff + i * phentsize)
        if p_type == 1:
            loads.append((p_va, p_off, p_fsz))
    secs = [struct.unpack_from("<IIQQQQIIQQ", so, shoff + i * shentsize) for i in range(shnum)]
    for sh in secs:
        if sh[1] in (2, 11):                                         # SHT_SYMTAB / SHT_DYNSYM
            strtab = secs[sh[6]]
            for k in range(sh[5] // 24):
                st_name, _info, _oth, _shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", so, sh[4] + k * 24)
                nm = so[strtab[4] + st_name:so.index(b"\0", strtab[4] + st_name)].decode("latin1")
                if nm != symbol or not st_value:
                    continue
                for va, off, fsz in loads:
                    if va <= st_value < va + fsz:
                        start = off + st_value - va
                        return so[start:start + (st_size or 256)]
    raise DexHeld("native symbol %s not found in the library" % symbol)


def _x86_run(code, args):
    """Tiny x86-64 straight-line emulator for the JNI leaf bodies the arena builds use: REX.W register-direct
    mov/movabs/xor/add/sub/imul/and/or/not/neg/shl/shr/sar/rol/ror then ret. SysV args rdi,rsi,rdx,rcx. Anything else -> DexHeld."""
    M = MASK64
    R = [0] * 16
    for r, v in zip((7, 6, 2, 1), args):
        R[r] = v & M
    i = 0
    _flags = None
    while i < len(code):
        rex = 0
        if 0x40 <= code[i] <= 0x4F:
            rex = code[i]
            i += 1
        op = code[i]
        i += 1
        rexw, rexr, rexb = rex & 8, (rex >> 2) & 1, rex & 1
        if op == 0xC3:
            return R[0]
        # --- D31 extension: guarded leaf bodies (cmp r32/r64, imm; jcc rel8; movzx r32, r16; 32-bit reg ops) ---
        if 0x70 <= op <= 0x7F:                                        # jcc rel8 on the last cmp
            rel = code[i]
            i += 1
            if rel >= 128:
                rel -= 256
            if _flags is None:
                raise DexHeld("native code: jcc without a preceding cmp")
            ua, ub, sa, sb = _flags
            cc = op & 15
            taken = {2: ua < ub, 3: ua >= ub, 4: ua == ub, 5: ua != ub, 6: ua <= ub, 7: ua > ub,
                     0xC: sa < sb, 0xD: sa >= sb, 0xE: sa <= sb, 0xF: sa > sb}.get(cc)
            if taken is None:
                raise DexHeld("native code: unsupported jcc condition 0x%x" % cc)
            if taken:
                i += rel
            continue
        if op in (0x81, 0x83, 0x39, 0x3B) and code[i] >> 6 == 3 and (op in (0x39, 0x3B) or (code[i] >> 3) & 7 == 7):
            W = 64 if rexw else 32
            MW = (1 << W) - 1
            modrm = code[i]
            i += 1
            if op in (0x81, 0x83):                                    # cmp r/m, imm32 / imm8 (sign-extended)
                rm = (modrm & 7) | (rexb << 3)
                if op == 0x81:
                    imm = int.from_bytes(code[i:i + 4], "little")
                    i += 4
                    if imm >> 31:
                        imm -= 1 << 32
                else:
                    imm = code[i]
                    i += 1
                    if imm >> 7:
                        imm -= 1 << 8
                a, b = R[rm] & MW, imm & MW
            else:                                                     # cmp r/m, r (0x39) / cmp r, r/m (0x3B)
                reg, rm = ((modrm >> 3) & 7) | (rexr << 3), (modrm & 7) | (rexb << 3)
                a, b = (R[rm] & MW, R[reg] & MW) if op == 0x39 else (R[reg] & MW, R[rm] & MW)
            sg = lambda v: v - (1 << W) if v >> (W - 1) else v
            _flags = (a, b, sg(a), sg(b))
            continue
        if op == 0x0F and not rexw and code[i] == 0xB7 and code[i + 1] >> 6 == 3:   # movzx r32, r/m16
            modrm = code[i + 1]
            i += 2
            R[((modrm >> 3) & 7) | (rexr << 3)] = R[(modrm & 7) | (rexb << 3)] & 0xFFFF
            continue
        if not rexw and 0xB8 <= op <= 0xBF:                           # mov r32, imm32 (zero-extends)
            R[(op - 0xB8) | (rexb << 3)] = int.from_bytes(code[i:i + 4], "little")
            i += 4
            continue
        if not rexw and op in (0x89, 0x8B, 0x31, 0x33, 0x01, 0x03, 0x29, 0x2B, 0x21, 0x23, 0x09, 0x0B) and code[i] >> 6 == 3:
            modrm = code[i]
            i += 1
            reg, rm = ((modrm >> 3) & 7) | (rexr << 3), (modrm & 7) | (rexb << 3)
            dst, src = (rm, reg) if op in (0x89, 0x31, 0x01, 0x29, 0x21, 0x09) else (reg, rm)
            a, b = R[dst] & 0xFFFFFFFF, R[src] & 0xFFFFFFFF
            R[dst] = (b if op in (0x89, 0x8B) else a ^ b if op in (0x31, 0x33) else a + b if op in (0x01, 0x03)
                      else a - b if op in (0x29, 0x2B) else a & b if op in (0x21, 0x23) else a | b) & 0xFFFFFFFF
            continue
        if not rexw:
            raise DexHeld("native code: unsupported non-64-bit instruction 0x%02x" % op)
        if 0xB8 <= op <= 0xBF:                                        # movabs r64, imm64
            R[(op - 0xB8) | (rexb << 3)] = int.from_bytes(code[i:i + 8], "little")
            i += 8
            continue
        if op == 0x0F:
            op2 = code[i]
            i += 1
            if op2 != 0xAF:
                raise DexHeld("native code: unsupported opcode 0f %02x" % op2)
            modrm = code[i]
            i += 1
            if modrm >> 6 != 3:
                raise DexHeld("native code: memory operand unsupported")
            d, s = ((modrm >> 3) & 7) | (rexr << 3), (modrm & 7) | (rexb << 3)
            R[d] = (R[d] * R[s]) & M                                  # imul r64, r/m64 (low 64 bits)
            continue
        modrm = code[i]
        i += 1
        if modrm >> 6 != 3:
            raise DexHeld("native code: memory operand unsupported (opcode 0x%02x)" % op)
        reg, rm = ((modrm >> 3) & 7) | (rexr << 3), (modrm & 7) | (rexb << 3)
        ext = (modrm >> 3) & 7
        if op in (0x89, 0x8B, 0x31, 0x33, 0x01, 0x03, 0x29, 0x2B, 0x21, 0x23, 0x09, 0x0B):
            dst, src = (rm, reg) if op in (0x89, 0x31, 0x01, 0x29, 0x21, 0x09) else (reg, rm)
            a, b = R[dst], R[src]
            R[dst] = (b if op in (0x89, 0x8B) else a ^ b if op in (0x31, 0x33) else a + b if op in (0x01, 0x03)
                      else a - b if op in (0x29, 0x2B) else a & b if op in (0x21, 0x23) else a | b) & M
        elif op == 0xC1:                                              # shift/rotate r/m64, imm8
            n = code[i] & 63
            i += 1
            v = R[rm]
            if ext == 0:
                v = ((v << n) | (v >> (64 - n))) & M if n else v
            elif ext == 1:
                v = ((v >> n) | (v << (64 - n))) & M if n else v
            elif ext == 4:
                v = (v << n) & M
            elif ext == 5:
                v = v >> n
            elif ext == 7:
                v = ((v - (1 << 64) if v >> 63 else v) >> n) & M
            else:
                raise DexHeld("native code: unsupported shift /%d" % ext)
            R[rm] = v
        elif op == 0xF7 and ext in (2, 3):                            # not / neg
            R[rm] = (~R[rm] if ext == 2 else -R[rm]) & M
        else:
            raise DexHeld("native code: unsupported opcode 0x%02x" % op)
    raise DexHeld("native code ran off the end without ret")


def _elf64_machine(so):
    """e_machine field for an ELF64 object. 0x3e == x86_64, 0xB7 == AArch64. Raises DexHeld on non-ELF64."""
    import struct
    if so[:4] != b"\x7fELF" or so[4] != 2:
        raise DexHeld("native library is not an ELF64 object")
    (mach,) = struct.unpack_from("<H", so, 0x12)
    return mach


def _arm64_run(code, args):
    """AArch64 straight-line emulator for the JNI leaf subset: movz/movk/movn, mov (reg alias), add, sub,
    and, orr, eor, mul, neg, mvn, lslv/lsrv/asrv/rorv, ret. Fixed-length 4-byte instructions, little-endian.
    JNI args come in x0..x7 (SysV AArch64). JNIEnv* and jobject fill x0, x1. Return value in x0."""
    M = MASK64
    R = [0] * 32   # x0..x30 real; x31 is XZR (reads 0, writes discarded)

    def rd(r):
        return 0 if r == 31 else R[r] & M

    def wr(r, v):
        if r != 31:
            R[r] = v & M

    for r, v in enumerate(args):
        if r < 31:
            R[r] = v & M
    i = 0
    while i + 4 <= len(code):
        w = int.from_bytes(code[i:i + 4], "little")
        i += 4
        if w == 0xD65F03C0:                                        # ret x30
            return R[0]
        top9 = (w >> 23) & 0x1FF
        if top9 in (0x1A5, 0x1E5, 0x125):                          # MOVZ / MOVK / MOVN (64-bit)
            hw = (w >> 21) & 3
            imm = (w >> 5) & 0xFFFF
            Rd = w & 0x1F
            shifted = imm << (hw * 16)
            if top9 == 0x1A5:                                       # MOVZ
                wr(Rd, shifted)
            elif top9 == 0x1E5:                                     # MOVK
                mask = 0xFFFF << (hw * 16)
                wr(Rd, (rd(Rd) & ~mask) | shifted)
            else:                                                   # MOVN
                wr(Rd, (~shifted) & M)
            continue
        top8 = (w >> 24) & 0xFF
        if top8 in (0x8B, 0xCB, 0x8A, 0xAA, 0xCA):                 # ADD/SUB/AND/ORR/EOR (shifted register, 64-bit)
            shift_type = (w >> 22) & 3
            N = (w >> 21) & 1                                       # bit 21 inverts the 2nd operand (ORN/BIC/EON/ADD-N etc.)
            imm6 = (w >> 10) & 0x3F
            Rm = (w >> 16) & 0x1F
            Rn = (w >> 5) & 0x1F
            Rd = w & 0x1F
            if shift_type:
                raise DexHeld("native code (arm64): shifted-register operand with shift_type=%d not supported at 0x%x" % (shift_type, i - 4))
            b = rd(Rm)
            if imm6:
                b = (b << imm6) & M                                 # only LSL supported here
            if N:
                b = (~b) & M                                        # ORN/BIC/EON encode the inverted-operand variants (incl. MVN alias)
            a = rd(Rn)
            if top8 == 0x8B:
                v = (a + b) & M
            elif top8 == 0xCB:                                      # SUB (and NEG = SUB from XZR)
                v = (a - b) & M
            elif top8 == 0x8A:
                v = a & b
            elif top8 == 0xAA:                                      # ORR (and MOV = ORR XZR; MVN = ORN XZR)
                v = a | b
            else:                                                   # 0xCA EOR
                v = a ^ b
            wr(Rd, v)
            continue
        # Data-processing (3-source): MADD/MSUB/UMADDL/... MUL == MADD with Ra=XZR.
        if (w & 0x7FE08000) == 0x1B000000 and (w >> 31) == 1:       # 1 00 11011 000 Rm 0 Ra Rn Rd (MADD 64)
            Ra = (w >> 10) & 0x1F
            o0 = (w >> 15) & 1
            Rm = (w >> 16) & 0x1F
            Rn = (w >> 5) & 0x1F
            Rd = w & 0x1F
            if o0 == 0 and Ra == 31:
                wr(Rd, (rd(Rn) * rd(Rm)) & M)                       # MUL alias
                continue
            if o0 == 0:
                wr(Rd, (rd(Ra) + rd(Rn) * rd(Rm)) & M)              # MADD
                continue
            if o0 == 1 and Ra == 31:
                wr(Rd, (- rd(Rn) * rd(Rm)) & M)
                continue
            if o0 == 1:
                wr(Rd, (rd(Ra) - rd(Rn) * rd(Rm)) & M)              # MSUB
                continue
        # Data-processing (2-source): LSLV/LSRV/ASRV/RORV. Mask 0xFFE0F000 == 0x9AC02000; bits 11-10 pick op.
        if (w & 0xFFE0F000) == 0x9AC02000:
            op = (w >> 10) & 3                                      # 0=LSLV 1=LSRV 2=ASRV 3=RORV
            Rm = (w >> 16) & 0x1F
            Rn = (w >> 5) & 0x1F
            Rd = w & 0x1F
            shift_amt = rd(Rm) & 63
            v = rd(Rn)
            if op == 0:                                             # LSLV
                v = (v << shift_amt) & M
            elif op == 1:                                           # LSRV
                v = v >> shift_amt
            elif op == 2:                                           # ASRV
                v = (v - (1 << 64) if v >> 63 else v) >> shift_amt
                v &= M
            else:                                                   # 3 == RORV
                shift_amt %= 64
                v = ((v >> shift_amt) | (v << (64 - shift_amt))) & M if shift_amt else v
            wr(Rd, v)
            continue
        raise DexHeld("native code (arm64): unsupported instruction 0x%08x at 0x%x" % (w, i - 4))
    raise DexHeld("native code (arm64) ran off the end without ret")


def _jni_symbol(owner, name):
    esc = lambda s: s.replace("_", "_1").replace(";", "_2").replace("[", "_3").replace("/", "_")
    return "Java_" + esc(owner[1:-1]) + "_" + esc(name)


class _DexVM:
    """Interprets the pure-Java release pipeline. Supported opcode set == solve_dex.py's set (see _DVM_OPS), plus the
    reflective in-APK module load some Day 24-26 builds use (InMemoryDexClassLoader over an asset DEX, then Method.invoke)."""
    STEP_CAP = 20000000
    DEPTH_CAP = 200

    def __init__(self, dex_blobs, assets):
        self.assets, self.fields, self.methods = assets, {}, {}
        self.steps = 0
        for raw in dex_blobs:
            dex = _DexFile(raw)
            for m in dex.methods():
                self.methods[m.sig] = m                     # later DEX overrides earlier (as solve_dex)

    @staticmethod
    def get_wide(regs, i):
        return _java_s64((int(regs[i + 1] or 0) & MASK32) << 32 | (int(regs[i] or 0) & MASK32))

    @staticmethod
    def set_wide(regs, i, v):
        v &= MASK64
        regs[i], regs[i + 1] = v & MASK32, (v >> 32) & MASK32

    def release_code(self):
        cands = [s for s in self.methods if s.endswith("/Release;->code(Landroid/content/Context;)Ljava/lang/String;")]
        if not cands:
            raise DexNoRelease("no Release.code(Context) method in the supplied DEX files")
        m = self.methods[cands[0]]
        return self.run(m, ([] if m.is_static else [None]) + [None], 0)

    def native(self, owner, name, args):
        """JNI-bound method with no bytecode: read the exported Java_* leaf from the APK's own native library and emulate it
        statically (env/class args are dummies). Tries x86_64 first (D30-F default), then arm64-v8a (D30 arm64 add-on,
        kill-switchable via HUNTRESS_MOBILE_ARM64=0). NotImplemented when no ABI ships a matching symbol."""
        import os as _os
        sym = _jni_symbol(owner, name)
        ints = [int(a) & MASK64 for a in args if not isinstance(a, (str, list)) and a is not None]
        # x86_64 first (SysV calling convention: rdi,rsi,rdx,rcx => [JNIEnv*, jobject, user args...])
        for key in sorted(self.assets):
            if key.startswith(_NATIVE_PREFIX) and "/x86_64/" in key:
                try:
                    code = _elf_symbol_code(self.assets[key], sym)
                except DexHeld:
                    continue
                return _java_s64(_x86_run(code, [0, 0] + ints))
        # arm64 fallback (AArch64 PCS: x0..x7 => [JNIEnv*, jobject, user args...])
        if _os.environ.get("HUNTRESS_MOBILE_ARM64") == "0":
            return NotImplemented
        for key in sorted(self.assets):
            if key.startswith(_NATIVE_PREFIX) and ("/arm64-v8a/" in key or "/arm64/" in key):
                try:
                    code = _elf_symbol_code(self.assets[key], sym)
                except DexHeld:
                    continue
                try:
                    mach = _elf64_machine(self.assets[key])
                except DexHeld:
                    continue
                if mach != 0xB7:                                     # not AArch64 bytes under an arm64 lib path -> skip, don't guess
                    continue
                return _java_s64(_arm64_run(code, [0, 0] + ints))
        return NotImplemented

    # ---- builtin (non-DEX) methods the pipeline may call ----
    def builtin(self, owner, name, ptypes, args):
        if owner.endswith("/Assets;") and name.startswith("read"):
            fn = next((a for a in args if isinstance(a, str)), None)
            if fn not in self.assets:
                raise DexHeld("APK asset not found: %r" % (fn,))
            return list(self.assets[fn])
        if owner == "Ljava/lang/StringBuilder;":
            if name == "<init>":
                return None
            if name == "append":
                tgt, val = args[0], args[1]
                if not isinstance(tgt, list):
                    raise DexHeld("StringBuilder receiver is not initialised")
                t = ptypes[0] if ptypes else ""
                if t == "C":
                    tgt.append(chr(int(val) & 0xFFFF))
                elif t == "I":
                    tgt.append(str(_java_s32(val)))
                elif t == "J":
                    tgt.append(str(int(val)))
                elif t == "Ljava/lang/String;":
                    tgt.append("null" if val is None else str(val))
                else:
                    raise DexHeld("StringBuilder.append(%s) unsupported" % t)
                return tgt
            if name == "toString":
                return "".join(args[0])
        if owner == "Ljava/lang/String;" and name == "charAt":
            return ord(args[0][_java_s32(args[1])])
        if owner == "Ljava/lang/Long;" and name == "toHexString":
            return format(args[0] & MASK64, "x")
        if owner == "Ljava/lang/String;" and name == "indexOf" and ptypes == ["I"]:
            s, ch = args[0], _java_s32(args[1])
            if not isinstance(s, str):
                raise DexHeld("String.indexOf on a non-string receiver")
            return s.find(chr(ch)) if 0 <= ch <= 0xFFFF else -1
        if owner == "Ljava/lang/String;" and name == "substring" and ptypes == ["I"]:
            s, b = args[0], _java_s32(args[1])
            if not isinstance(s, str) or not 0 <= b <= len(s):
                raise DexHeld("String.substring(%r) is out of range" % b)
            return s[b:]
        if owner == "Ljava/lang/String;" and name == "equalsIgnoreCase" and ptypes == ["Ljava/lang/String;"]:
            s, t = args[0], args[1]
            if not isinstance(s, str):
                raise DexHeld("String.equalsIgnoreCase on a non-string receiver")
            if not isinstance(t, str) or len(s) != len(t):
                return 0
            return int(all(a == b or a.upper() == b.upper() or a.lower() == b.lower() for a, b in zip(s, t)))
        # ---- reflective in-APK module load (payload.dex -> InMemoryDexClassLoader -> Method.invoke) ----
        if owner == "Ljava/lang/Long;" and name in ("valueOf", "longValue") and ptypes in (["J"], []):
            return int(args[0])
        if owner == "Ljava/nio/ByteBuffer;" and name == "wrap" and ptypes == ["[B", "I", "I"]:
            arr, off, ln = args[0], _java_s32(args[1]), _java_s32(args[2])
            if not isinstance(arr, list) or off < 0 or ln < 0 or off + ln > len(arr):
                raise DexHeld("ByteBuffer.wrap range %d+%d outside a %s" % (off, ln, "byte[%d]" % len(arr) if isinstance(arr, list) else type(arr).__name__))
            return _VmByteBuffer(bytes(int(x) & 0xFF for x in arr[off:off + ln]))
        if owner == "Ljava/util/Arrays;" and name == "copyOf" and ptypes == ["[B", "I"]:
            arr, n = args[0], _java_s32(args[1])
            if not isinstance(arr, list) or n < 0:
                raise DexHeld("Arrays.copyOf(byte[], %d) is not supported" % n)
            out = list(arr[:n])
            return out + [0] * (n - len(out))
        if owner == "Ljava/lang/Class;" and name == "getClassLoader":
            return _VmLoader()
        if owner == "Ldalvik/system/InMemoryDexClassLoader;" and name == "<init>":
            ld, bb = args[0], args[1]
            if not isinstance(ld, _VmLoader) or not isinstance(bb, _VmByteBuffer):
                raise DexHeld("InMemoryDexClassLoader.<init> needs a ByteBuffer built from an in-APK payload")
            try:
                payload = _DexFile(bb.data)
                found = list(payload.methods())
            except DexHeld:
                raise
            except Exception as e:
                raise DexHeld("in-memory payload is not a readable DEX (%s)" % type(e).__name__)
            for pm in found:
                self.methods[pm.sig] = pm                   # the loaded classes become callable, later DEX overrides earlier
            ld.payload = payload
            return None
        if owner == "Ljava/lang/ClassLoader;" and name == "loadClass":
            ld, cname = args[0], args[1]
            if not isinstance(ld, _VmLoader) or not isinstance(cname, str):
                raise DexHeld("ClassLoader.loadClass needs a loader and a class name")
            desc = "L" + cname.replace(".", "/") + ";"
            if not any(s.startswith(desc + "->") for s in self.methods):
                raise DexHeld("ClassNotFoundException %s (not defined by any DEX in the artifact)" % cname)
            return _VmClass(desc)
        if owner == "Ljava/lang/Class;" and name == "forName" and ptypes == ["Ljava/lang/String;"]:   # D31 reflection maze
            cname = args[0]
            if not isinstance(cname, str):
                raise DexHeld("Class.forName needs a String")
            desc = "L" + cname.replace(".", "/") + ";"
            if not any(s.startswith(desc + "->") for s in self.methods):
                raise DexHeld("ClassNotFoundException %s (not defined by any DEX in the artifact)" % cname)
            return _VmClass(desc)
        if owner == "Ljava/lang/Class;" and name in ("getDeclaredMethod", "getMethod"):
            cls, mname, classes = args[0], args[1], args[2]
            if not isinstance(cls, _VmClass) or not isinstance(mname, str) or not isinstance(classes, list):
                raise DexHeld("Class.getDeclaredMethod needs a class, a name and a Class[]")
            return _VmMethod(cls.desc, mname, len(classes))
        if owner == "Ljava/lang/reflect/Method;" and name == "invoke":
            meth, target, margs = args[0], args[1], args[2]
            if not isinstance(meth, _VmMethod) or not isinstance(margs, list):
                raise DexHeld("Method.invoke needs a resolved method and an Object[]")
            cands = [mm for sg, mm in self.methods.items()
                     if sg.startswith(meth.desc + "->" + meth.name + "(") and len(mm.params) == meth.nparams]
            if len(cands) != 1:
                raise DexHeld("Method.invoke: %d candidate(s) for %s.%s with %d parameter(s)" % (len(cands), meth.desc, meth.name, meth.nparams))
            mm = cands[0]
            r = self.run(mm, ([] if mm.is_static else [target]) + list(margs), 1)
            return r
        return NotImplemented

    # ---- the interpreter ----
    def run(self, m, args, depth):
        if depth > self.DEPTH_CAP:
            raise DexHeld("call depth cap exceeded", method=m.sig)
        regs = [0] * m.regs
        cur = m.regs - m.ins
        ai = 0
        if not m.is_static:
            regs[cur] = args[0] if args else None
            cur += 1
            ai = 1
        for t in m.params:
            v = args[ai] if ai < len(args) else None
            ai += 1
            if _wide_type(t):
                self.set_wide(regs, cur, int(v or 0))
                cur += 2
            else:
                regs[cur] = v
                cur += 1
        code, pc, pending = m.insns, 0, None
        dex = m.dex
        M32 = MASK32
        s32, s64 = _java_s32, _java_s64
        while True:
            if not 0 <= pc < len(code):
                raise DexHeld("pc ran outside the method", offset=pc, method=m.sig)
            self.steps += 1
            if self.steps > self.STEP_CAP:
                raise DexHeld("step cap exceeded (non-terminating?)", offset=pc, method=m.sig)
            u = code[pc]
            op = u & 0xFF
            hi = u >> 8
            nxt = pc + 1
            try:
                if op == 0x00 and u == 0:                                        # nop
                    pass
                elif op == 0x12:                                                 # const/4
                    regs[hi & 0xF] = _S4(hi >> 4) & M32
                elif op == 0x13:                                                 # const/16
                    regs[hi] = _S16(code[pc + 1]) & M32
                    nxt = pc + 2
                elif op == 0x14:                                                 # const
                    regs[hi] = (code[pc + 1] | code[pc + 2] << 16) & M32
                    nxt = pc + 3
                elif op == 0x15:                                                 # const/high16
                    regs[hi] = (code[pc + 1] << 16) & M32
                    nxt = pc + 2
                elif op == 0x16:                                                 # const-wide/16
                    self.set_wide(regs, hi, _S16(code[pc + 1]))
                    nxt = pc + 2
                elif op == 0x17:                                                 # const-wide/32
                    self.set_wide(regs, hi, s32(code[pc + 1] | code[pc + 2] << 16))
                    nxt = pc + 3
                elif op == 0x18:                                                 # const-wide
                    self.set_wide(regs, hi, s64(code[pc + 1] | code[pc + 2] << 16 | code[pc + 3] << 32 | code[pc + 4] << 48))
                    nxt = pc + 5
                elif op == 0x19:                                                 # const-wide/high16
                    self.set_wide(regs, hi, s64(code[pc + 1] << 48))
                    nxt = pc + 2
                elif op == 0x1A:                                                 # const-string
                    regs[hi] = dex.string(code[pc + 1])
                    nxt = pc + 2
                elif op == 0x1B:                                                 # const-string/jumbo
                    regs[hi] = dex.string(code[pc + 1] | code[pc + 2] << 16)
                    nxt = pc + 3
                elif op == 0x04:                                                 # move-wide
                    self.set_wide(regs, hi & 0xF, self.get_wide(regs, hi >> 4))
                elif op in (0x0A, 0x0C):                                         # move-result, move-result-object
                    regs[hi] = pending
                    pending = None
                elif op == 0x0B:                                                 # move-result-wide
                    self.set_wide(regs, hi, int(pending or 0))
                    pending = None
                elif op == 0x22:                                                 # new-instance
                    ty = dex.type(code[pc + 1])
                    regs[hi] = [] if ty == "Ljava/lang/StringBuilder;" else (_VmLoader() if ty == "Ldalvik/system/InMemoryDexClassLoader;" else None)
                    nxt = pc + 2
                elif op == 0x1C:                                                 # const-class
                    regs[hi] = _VmClass(dex.type(code[pc + 1]))
                    nxt = pc + 2
                elif op == 0x1F:                                                 # check-cast (the value is passed through unchanged)
                    dex.type(code[pc + 1])
                    nxt = pc + 2
                elif op == 0x23:                                                 # new-array
                    n = s32(regs[hi >> 4])
                    if n < 0:
                        raise DexHeld("NegativeArraySizeException", opcode=op, offset=pc, method=m.sig)
                    regs[hi & 0xF] = [0] * n
                    nxt = pc + 2
                elif op == 0x21:                                                 # array-length
                    regs[hi & 0xF] = len(regs[hi >> 4])
                elif op in (0x4B, 0x4D, 0x4F, 0x4C):                             # aput, aput-object, aput-byte, aput-wide
                    b, c = code[pc + 1] & 0xFF, code[pc + 1] >> 8
                    arr, idx = regs[b], s32(regs[c])
                    if not isinstance(arr, list) or not 0 <= idx < len(arr):
                        raise DexHeld("array index %r out of bounds" % idx, opcode=op, offset=pc, method=m.sig)
                    arr[idx] = self.get_wide(regs, hi) if op == 0x4C else ((s32(regs[hi]) & 0xFF) if op == 0x4F else regs[hi])
                    nxt = pc + 2
                elif op in (0x44, 0x46, 0x48, 0x45):                             # aget, aget-object, aget-byte, aget-wide
                    b, c = code[pc + 1] & 0xFF, code[pc + 1] >> 8
                    arr, idx = regs[b], s32(regs[c])
                    if not isinstance(arr, list) or not 0 <= idx < len(arr):
                        raise DexHeld("array index %r out of bounds" % idx, opcode=op, offset=pc, method=m.sig)
                    v = arr[idx]
                    if op == 0x45:
                        self.set_wide(regs, hi, int(v))
                    elif op == 0x48:                                             # Java byte: sign-extended int
                        regs[hi] = (((int(v) & 0xFF) ^ 0x80) - 0x80) & M32
                    elif op == 0x44:
                        regs[hi] = int(v) & M32
                    else:
                        regs[hi] = v
                    nxt = pc + 2
                elif op in (0x67, 0x69):                                         # sput, sput-object
                    self.fields[dex.field_ref(code[pc + 1])] = regs[hi]
                    nxt = pc + 2
                elif op in (0x60, 0x62):                                         # sget, sget-object
                    regs[hi] = self.fields.get(dex.field_ref(code[pc + 1]))
                    nxt = pc + 2
                elif op == 0x54:                                                 # iget-object (modelled as null, as solve_dex)
                    dex.field_ref(code[pc + 1])
                    regs[hi & 0xF] = None
                    nxt = pc + 2
                elif 0x6E <= op <= 0x72 or 0x74 <= op <= 0x78:                   # invoke-* / invoke-*/range
                    mi = code[pc + 1]
                    if op >= 0x74:
                        words = list(range(code[pc + 2], code[pc + 2] + hi))
                    else:
                        cnt, g, w = hi >> 4, hi & 0xF, code[pc + 2]
                        words = [w & 0xF, (w >> 4) & 0xF, (w >> 8) & 0xF, (w >> 12) & 0xF, g][:cnt]
                    nxt = pc + 3
                    owner, name, ptypes, ret = dex.method_ref(mi)
                    is_static = op in (0x71, 0x77)
                    vals, k = [], 0
                    if not is_static:
                        vals.append(regs[words[k]])
                        k += 1
                    for t in ptypes:
                        if k >= len(words):
                            raise DexHeld("invoke register mismatch for %s" % name, opcode=op, offset=pc, method=m.sig)
                        if _wide_type(t):
                            vals.append(self.get_wide(regs, words[k]))
                            k += 2
                        else:
                            vals.append(regs[words[k]])
                            k += 1
                    sig = dex.sig(owner, name, ptypes, ret)
                    r = self.builtin(owner, name, ptypes, vals)          # builtins first, as solve_dex.invoke
                    if r is NotImplemented:
                        if sig not in self.methods:
                            r = self.native(owner, name, vals)
                            if r is NotImplemented:
                                raise DexHeld("unsupported method invocation %s" % sig, opcode=op, offset=pc, method=m.sig)
                        else:
                            r = self.run(self.methods[sig], vals, depth + 1)
                    pending = r
                elif op == 0x81:                                                 # int-to-long
                    self.set_wide(regs, hi & 0xF, s32(regs[hi >> 4]))
                elif op == 0x84:                                                 # long-to-int
                    regs[hi & 0xF] = self.get_wide(regs, hi >> 4) & M32
                elif op == 0x8D:                                                 # int-to-byte (Java: sign-extended)
                    regs[hi & 0xF] = (((s32(regs[hi >> 4]) & 0xFF) ^ 0x80) - 0x80) & M32
                elif op == 0x8E:                                                 # int-to-char
                    regs[hi & 0xF] = s32(regs[hi >> 4]) & 0xFFFF
                elif op == 0x0E:                                                 # return-void
                    return None
                elif op == 0x10:                                                 # return-wide
                    return self.get_wide(regs, hi)
                elif op in (0x0F, 0x11):                                         # return, return-object
                    return regs[hi]
                elif op == 0x28:                                                 # goto
                    nxt = pc + _S8(hi)
                elif op in (0x2B, 0x2C):                                         # D31: packed-switch / sparse-switch (31t)
                    sv = s32(regs[hi])
                    poff = code[pc + 1] | (code[pc + 2] << 16)
                    if poff >> 31:
                        poff -= 1 << 32
                    pp = pc + poff
                    ident, size = code[pp], code[pp + 1]
                    nxt = pc + 3

                    def _w32(k):
                        x = code[k] | (code[k + 1] << 16)
                        return x - (1 << 32) if x >> 31 else x
                    if op == 0x2B:
                        if ident != 0x0100:
                            raise DexHeld("packed-switch payload ident 0x%04x" % ident, opcode=op, offset=pc, method=m.sig)
                        first = _w32(pp + 2)
                        if first <= sv < first + size:
                            nxt = pc + _w32(pp + 4 + 2 * (sv - first))
                    else:
                        if ident != 0x0200:
                            raise DexHeld("sparse-switch payload ident 0x%04x" % ident, opcode=op, offset=pc, method=m.sig)
                        for k in range(size):
                            if _w32(pp + 2 + 2 * k) == sv:
                                nxt = pc + _w32(pp + 2 + 2 * size + 2 * k)
                                break
                elif op == 0x31:                                                 # D31: cmp-long
                    b, c = code[pc + 1] & 0xFF, code[pc + 1] >> 8
                    x, y = s64(self.get_wide(regs, b)), s64(self.get_wide(regs, c))
                    regs[hi] = (0 if x == y else 1 if x > y else -1) & M32
                elif op in (0x7B, 0x7C):                                         # D31: neg-int / not-int
                    regs[hi & 0xF] = (-s32(regs[hi >> 4]) if op == 0x7B else ~s32(regs[hi >> 4])) & M32
                elif op in (0x7D, 0x7E):                                         # D31: neg-long / not-long
                    x = s64(self.get_wide(regs, hi >> 4))
                    self.set_wide(regs, hi & 0xF, (-x if op == 0x7D else ~x))
                elif 0x32 <= op <= 0x37:                                         # if-eq .. if-le
                    a, b = regs[hi & 0xF], regs[hi >> 4]
                    k = op - 0x32
                    if k < 2:
                        cond = (a == b) if k == 0 else (a != b)
                    else:
                        a, b = s32(a), s32(b)
                        cond = (a < b, a >= b, a > b, a <= b)[k - 2]
                    nxt = pc + _S16(code[pc + 1]) if cond else pc + 2
                elif 0x38 <= op <= 0x3D:                                         # if-eqz .. if-lez
                    a = regs[hi]
                    k = op - 0x38
                    if k < 2:
                        cond = (a == 0) if k == 0 else (a != 0)
                    else:
                        a = s32(a)
                        cond = (a < 0, a >= 0, a > 0, a <= 0)[k - 2]
                    nxt = pc + _S16(code[pc + 1]) if cond else pc + 2
                elif op in (0x9B, 0x9C, 0x9D, 0xA0, 0xA1, 0xA2):                 # add/sub/mul/and/or/xor-long (D30 WS 2026-10-30: +0x9C sub-long)
                    b, c = code[pc + 1] & 0xFF, code[pc + 1] >> 8
                    x, y = self.get_wide(regs, b), self.get_wide(regs, c)
                    self.set_wide(regs, hi, {0x9B: x + y, 0x9C: x - y, 0x9D: x * y, 0xA0: x & y, 0xA1: x | y, 0xA2: x ^ y}[op])
                    nxt = pc + 2
                elif op in (0xBB, 0xBC, 0xBD, 0xC0, 0xC1, 0xC2):                 # add/sub/mul/and/or/xor-long/2addr (D30 WS 2026-10-30: +0xBC sub-long/2addr, +0xC0 and-long/2addr)
                    a_, b_ = hi & 0xF, hi >> 4
                    x, y = self.get_wide(regs, a_), self.get_wide(regs, b_)
                    self.set_wide(regs, a_, {0xBB: x + y, 0xBC: x - y, 0xBD: x * y, 0xC0: x & y, 0xC1: x | y, 0xC2: x ^ y}[op])
                elif op in (0xA3, 0xA4, 0xA5):                                   # shl/shr/ushr-long
                    b, c = code[pc + 1] & 0xFF, code[pc + 1] >> 8
                    self.set_wide(regs, hi, self._lshift(op - 0xA3, self.get_wide(regs, b), s32(regs[c]) & 63))
                    nxt = pc + 2
                elif op in (0xC3, 0xC4, 0xC5):                                   # shl/shr/ushr-long/2addr
                    a_ = hi & 0xF
                    self.set_wide(regs, a_, self._lshift(op - 0xC3, self.get_wide(regs, a_), s32(regs[hi >> 4]) & 63))
                elif op == 0x98:                                                 # shl-int
                    b, c = code[pc + 1] & 0xFF, code[pc + 1] >> 8
                    regs[hi] = (s32(regs[b]) << (s32(regs[c]) & 31)) & M32
                    nxt = pc + 2
                elif op in (0xB9, 0xBA):                                         # shr-int/2addr, ushr-int/2addr
                    a_ = hi & 0xF
                    sh = s32(regs[hi >> 4]) & 31
                    regs[a_] = ((s32(regs[a_]) >> sh) if op == 0xB9 else ((regs[a_] & M32) >> sh)) & M32
                elif op in (0xE0, 0xE1, 0xE2):                                   # shl/shr/ushr-int/lit8
                    b, lit = code[pc + 1] & 0xFF, (code[pc + 1] >> 8) & 31
                    a = s32(regs[b])
                    regs[hi] = ((a << lit) if op == 0xE0 else (a >> lit) if op == 0xE1 else ((a & M32) >> lit)) & M32
                    nxt = pc + 2
                elif op in (0x90, 0x91, 0x92, 0x95, 0x96, 0x97):                 # int 3-reg
                    b, c = code[pc + 1] & 0xFF, code[pc + 1] >> 8
                    regs[hi] = self._ialu(op - 0x90, s32(regs[b]), s32(regs[c]))
                    nxt = pc + 2
                elif op in (0xB0, 0xB1, 0xB2, 0xB5, 0xB6, 0xB7):                 # int /2addr
                    a_ = hi & 0xF
                    regs[a_] = self._ialu(op - 0xB0, s32(regs[a_]), s32(regs[hi >> 4]))
                elif op in (0xD0, 0xD2, 0xD5, 0xD6, 0xD7):                       # int /lit16
                    regs[hi & 0xF] = self._ialu(op - 0xD0, s32(regs[hi >> 4]), _S16(code[pc + 1]))
                    nxt = pc + 2
                elif op in (0xD8, 0xDA, 0xDD, 0xDE, 0xDF):                       # int /lit8
                    b, lit = code[pc + 1] & 0xFF, _S8(code[pc + 1] >> 8)
                    regs[hi] = self._ialu(op - 0xD8, s32(regs[b]), lit)
                    nxt = pc + 2
                elif op in (0xD4, 0xDC):                                         # rem-int/lit16, rem-int/lit8
                    if op == 0xD4:
                        a_, b_, lit = hi & 0xF, hi >> 4, _S16(code[pc + 1])
                    else:
                        a_, b_, lit = hi, code[pc + 1] & 0xFF, _S8(code[pc + 1] >> 8)
                    if lit == 0:
                        raise DexHeld("ArithmeticException: / by zero", opcode=op, offset=pc, method=m.sig)
                    x = s32(regs[b_])
                    r = abs(x) % abs(lit)                                        # Java remainder: sign of the dividend
                    regs[a_] = (-r if x < 0 else r) & M32
                    nxt = pc + 2
                else:
                    raise DexHeld("unsupported opcode", opcode=op, offset=pc, method=m.sig)
            except DexHeld:
                raise
            except (IndexError, TypeError, KeyError, ValueError, AttributeError, OverflowError) as e:
                raise DexHeld("interpreter fault (%s: %s)" % (type(e).__name__, e), opcode=op, offset=pc, method=m.sig)
            pc = nxt

    @staticmethod
    def _lshift(kind, a, sh):
        if kind == 0:
            return (a << sh) & MASK64
        if kind == 1:
            return _java_s64(a) >> sh
        return (a & MASK64) >> sh

    @staticmethod
    def _ialu(kind, a, b):
        # kind = opcode offset inside its family: 0 add, 1 sub, 2 mul, 5 and, 6 or, 7 xor (all families line up)
        if kind == 0:
            r = a + b
        elif kind == 1:
            r = a - b
        elif kind == 2:
            r = a * b
        elif kind == 5:
            r = a & b
        elif kind == 6:
            r = a | b
        else:
            r = a ^ b
        return r & MASK32


# every opcode the interpreter executes (== the set solve_dex.py handles; anything else is a typed HELD)
# D30 Layered Protections (agent-5): 0x9C (sub-long), 0xBC (sub-long/2addr), 0xC0 (and-long/2addr) hit live;
# the three live in the closed arithmetic family 0x90..0xE2 and belong to the pre-scan hint set so an unsupported
# live opcode is called out structurally instead of discovered at runtime. These three are HINT entries only -
# the interpreter dispatch is a separate concern (HS mobile adapter) and these are harmless if unused.
_DVM_OPS = sorted({0x00, 0x04, 0x0A, 0x0B, 0x0C, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
                   0x1B, 0x1C, 0x1F, 0x21, 0x22, 0x23, 0x28, 0x44, 0x45, 0x46, 0x48, 0x4B, 0x4C, 0x4D, 0x4F, 0x54, 0x60, 0x62, 0x67, 0x69,
                   0x81, 0x84, 0x8D, 0x8E, 0x90, 0x91, 0x92, 0x95, 0x96, 0x97, 0x98, 0x9B, 0x9C, 0x9D, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4,
                   0xA5, 0xB0, 0xB1, 0xB2, 0xB5, 0xB6, 0xB7, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xD0, 0xD2,
                   0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xDA, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2}
                  | set(range(0x32, 0x3E)) | set(range(0x6E, 0x73)) | set(range(0x74, 0x79)))


def _apk_dex_and_assets(blob):
    """(dex blobs, {asset name: bytes}) for an APK or an .apks bundle (feature splits merged in archive order,
    later entries overriding earlier ones, as solve_dex.apk_contents)."""
    import zipfile as _zf, io as _io
    dexes, assets = [], {}

    def collect(apk_blob):
        with _zf.ZipFile(_io.BytesIO(apk_blob)) as z:
            for n in z.namelist():
                if re.fullmatch(r"classes(?:\d+)?\.dex", n):
                    dexes.append(z.read(n))
                elif n.startswith("assets/"):
                    assets[n[len("assets/"):]] = z.read(n)
                elif n.startswith("lib/") and n.endswith(".so"):
                    assets[_NATIVE_PREFIX + n] = z.read(n)

    try:
        if _looks_like_apks(blob):
            with _zf.ZipFile(_io.BytesIO(blob)) as outer:
                for n in outer.namelist():
                    if n.endswith(".apk"):
                        collect(outer.read(n))
        else:
            collect(blob)
    except _zf.BadZipFile as e:
        raise DexHeld("not a readable APK/APKS: %s" % e)
    return dexes, assets


def _apk_run_release(blob):
    """Execute Release.code(Context) from the artifact's own DEX; returns its String result.
    Raises DexNoRelease when the artifact has no such method, DexHeld for anything unsupported."""
    dexes, assets = _apk_dex_and_assets(blob)
    if not dexes:
        raise DexNoRelease("no classes*.dex in artifact")
    out = _DexVM(dexes, assets).release_code()
    if not isinstance(out, str):
        raise DexHeld("Release.code() returned %s, not a String" % type(out).__name__)
    return out


def _looks_like_protocol_recon(start, blobs):
    """Heuristic: this attempt is Day 28 Protocol Reconstruction (or a replay/mastery
    variant) if any question's `answer_format` is the ANS-16-hex shape AND the artifact
    is an .apk / .apks. Day 1-27 APK scaffolds answered OTHER fields (urls, perms,
    package); Protocol Reconstruction asks for the ANS code specifically."""
    qs = (start.get("questions") or [])
    wants_ans = False
    for q in qs:
        syn = json.dumps((q or {}).get("answer_format", "")).lower()
        if "ans-" in syn:
            wants_ans = True
            break
    if not wants_ans:
        return False
    return any(_looks_like_apk(b) or _looks_like_apks(b) for b in blobs)


def _protocol_recon_compute(start, blobs):
    """Day 28 Protocol Reconstruction answer map.

    Per artifact, the authority is Release.code(Context) EXECUTED from the artifact's own DEX by the stdlib
    interpreter above (_apk_run_release; .apks feature-split assets merged). Only when the artifact has no
    Release.code at all (DexNoRelease) does it fall back to a single unambiguous ANS-<16 hex> literal
    (HA-framed asset / DEX string pool). Any other DexHeld (unsupported opcode, bad DEX, non-ANS result)
    is raised, never guessed around. Nothing is hardcoded; every value derives from this attempt's bytes."""
    arts = start.get("artifacts") or []
    names = [a.get("filename", "") for a in arts]
    qs = {q.get("id"): q for q in (start.get("questions") or [])}

    result_by_idx, held_by_idx = {}, {}
    for i, b in enumerate(blobs):
        if not (_looks_like_apk(b) or _looks_like_apks(b)):
            continue
        try:
            v = _apk_run_release(b).strip()
            if not ANS.match(v):
                raise DexHeld("Release.code() result is not ANS-<16 upper hex>")
            result_by_idx[i] = v
        except DexNoRelease:
            lits = _apk_release_ans_candidates(b)
            if len(lits) == 1:
                result_by_idx[i] = lits[0]
            else:
                held_by_idx[i] = DexHeld("no Release.code() and %d ANS literal(s) %r" % (len(lits), lits[:4]))
        except DexHeld as e:
            held_by_idx[i] = e

    avail = sorted(set(result_by_idx) | set(held_by_idx))
    ans, unresolved = {}, []
    for aid in start["answer_ids"]:
        q = qs.get(aid) or {}
        if not avail:
            raise DexHeld("protocol_recon: no .apk/.apks blobs available for answer_id %r" % aid)
        try:                                                # contract-anchored unique blob or HELD; never a positional guess
            idx = _resolve_blob_binding(aid, q, start, names, avail)
        except UnresolvedArtifactBinding as e:
            unresolved.append((aid, e.reason))
            continue
        if idx in result_by_idx:
            ans[aid] = result_by_idx[idx]
        else:
            unresolved.append((aid, str(held_by_idx[idx])))
    if unresolved:
        raise DexHeld("protocol_recon: %d answer(s) unresolved: %s" % (len(unresolved), "; ".join("%s -> %s" % u for u in unresolved)),
                      partial=ans)
    return ans


def compute_puzzle(start, blobs):  # kept name reserved; alias to compute for forward-compat
    return compute(start, blobs)


def compute(start, blobs):
    ids = start["answer_ids"]
    arts = start.get("artifacts") or []
    names = [a.get("filename", "") for a in arts]
    per_blob = [_merge_split_fragments(puzzles_in(b)) for b in blobs]
    flat = [p for ps in per_blob for p in ps]
    if not flat:
        # Day 28 Protocol Reconstruction (2026-10-28 PORT): the artifact may be a .apk /
        # .apks (no huntress_puzzle.json). Try the DEX port FIRST when the question wants
        # an ANS-<16 hex> answer (that is the Protocol Reconstruction shape), then fall
        # back to the generic APK scaffold (urls/perms/package).
        if _looks_like_protocol_recon(start, blobs):
            try:
                return _protocol_recon_compute(start, blobs)
            except DexHeld:
                raise                                       # typed HELD (opcode/offset/method): never masked by the scaffold
            except ValueError:
                # fall through to the broader scaffold rather than hard-failing on the
                # ambiguous / Dalvik-required cases; the scaffold will raise with its own
                # precise message naming the unmatched answer_id if it has no handler.
                pass
        if any(_looks_like_apk(b) or _looks_like_apks(b) for b in blobs):
            return _apk_compute(start, blobs)
        raise ValueError("no huntress_puzzle.json found in %d artifact(s) %s" % (len(blobs), names))
    qs = {q.get("id"): q for q in (start.get("questions") or [])}
    ans = {}
    CODECS_USED.clear()
    # D29 P0-B (2026-10-28): the former fallback chain picked `flat[min(i,len-1)]` when the
    # filename / delivery hints did not resolve - a positional guess that recycled the last
    # puzzle across many questions. It also always picked `per_blob[idx][0]` (first puzzle in
    # a blob) when a blob held multiple puzzles. Both are replaced by _resolve_blob_binding
    # (contract-anchored unique match or HELD) and a unique-puzzle check inside the matched
    # blob. Preserved behavior: the former 1-1 case (one blob matches by filename and that
    # blob holds one puzzle) still resolves instantly.
    eligible = [k for k in range(len(per_blob)) if per_blob[k]]
    for i, aid in enumerate(ids):
        q = qs.get(aid) or {}
        idx = _resolve_blob_binding(aid, q, start, names, eligible)
        puzzles = per_blob[idx]
        if len(puzzles) == 1:
            p = puzzles[0]
        else:
            # multiple puzzles in one blob: look for a nested member identifier on the question
            member = str(q.get("member") or q.get("puzzle_id") or q.get("entry") or "")
            picked = None
            if member:
                for pz in puzzles:
                    pz_id = str((pz.get("id") if isinstance(pz, dict) else "") or "")
                    pz_path = str((pz.get("path") if isinstance(pz, dict) else "") or "")
                    if pz_id and (pz_id == member or pz_id in member):
                        picked = pz; break
                    if pz_path and (pz_path.endswith(member) or member in pz_path):
                        picked = pz; break
            if picked is None:
                raise UnresolvedArtifactBinding(aid, [idx],
                    "blob holds %d puzzles; question does not identify a unique nested member" % len(puzzles))
            p = picked
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
