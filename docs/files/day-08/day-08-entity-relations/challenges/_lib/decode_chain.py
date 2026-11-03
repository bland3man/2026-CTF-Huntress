#!/usr/bin/env python3
"""UNIVERSAL DECODE CHAIN (CyberChef 'Magic'-lite, pure stdlib, zero model usage): peel layered encodings automatically.

usage: python3 decode_chain.py <file | -> [--text "STRING"] [--depth 6] [--top 3] [--slug] [--quiet]
  --slug   also print the answer-slug candidates (three lowercase words + hyphen + 2 digits, ANS-<16 hex>, flag{...}) found in the best outputs
Library: best_chains(data: bytes, depth=6, top=3) -> [(score, [decoder names], bytes)]    find_answers(text) -> [str]

Decoders (the well-known set incl. the 2025 'Cover All Your Bases' family): base64, base64url, base32, hex, base85, ascii85 (Adobe, with or
without <~ ~>), base58, base62, base45, base65536 (optional: only if `pip install base65536` is present; UTF-8 multi-byte text, degrades
silently if missing), binary (8-bit and 7-bit), octal, decimal byte lists, url-encoding, rot13, rot47, caesar (brute), atbash, reverse, zlib,
gzip, bz2, lzma, and single-byte XOR (brute, scored). A beam search keeps the best candidates per layer; the score rewards printable text,
common words and answer-shaped strings. Never executes anything. ASCII only (output decoding may surface non-ASCII source text, shown as-is).
"""
import argparse, base64, binascii, bz2, collections, gzip, hashlib, lzma, quopri, re, string, sys, urllib.parse, zlib

SLUG = re.compile(r"\b[a-z]+(?:-[a-z]+){2}-\d{2}\b")
ANS = re.compile(r"\bANS-[0-9A-F]{16}\b")
FLAG = re.compile(r"\b(?:flag|huntress|ctf)\{[^}\s]{3,80}\}", re.I)
WORDS = ("the ", " and ", "flag", "submit", "answer", "decode", "nice", "work", "congrat", "http", "password", "this ", "your ", "exact", "slug")
PRINT = set(range(32, 127)) | {9, 10, 13}


def printable_ratio(b):
    return (sum(c in PRINT for c in b) / len(b)) if b else 0.0


def rate(b):
    if not b:
        return -1.0
    t = b.decode("latin-1", "ignore")
    s = printable_ratio(b)
    low = t.lower()
    s += 0.5 * min(sum(w in low for w in WORDS), 4)
    if SLUG.search(t) or ANS.search(t) or FLAG.search(t):
        s += 2.0
    return s


def _txt(b):
    try:
        return b.decode("ascii")
    except UnicodeDecodeError:
        return None


# D32: every codec primitive below is the ONE definition in codec_registry.py (shared with autosolve_warmups and the warmups table
# readers); these names stay so existing importers (autosolve_warmups, autosolve_mobile, peel_any, triage) keep working.
import os as _os  # noqa: E402
sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import codec_registry as CR  # noqa: E402

_int_to_bytes = CR.int_to_bytes
_b58 = CR.b58
_b62 = CR.b62
_b45 = CR.b45
_bits = CR.bits
_rot = CR.rot
_rot47 = CR.rot47
_rot_printable = CR.rot_printable
_atbash = CR.atbash
_uudecode = CR.uudecode
MORSE = CR.MORSE
_morse = CR.morse_lenient                                  # '/', '|' or 2+ spaces separate words; unknown codes dropped; upper case


def expand(b):
    """Yield (decoder_name, decoded_bytes) candidates for one layer."""
    t = _txt(b)
    st = t.strip() if t else None
    out = []

    def add(name, fn):
        try:
            r = fn()
            if r and r != b:
                out.append((name, r))
        except Exception:
            pass
    if st is not None and len(st) >= 4:
        c = re.sub(r"\s", "", st)
        if re.fullmatch(r"[A-Za-z0-9+/=]+", c) and len(c) >= 8:
            add("base64", lambda: CR.UNITS["base64"](c.encode()))
        if re.fullmatch(r"[A-Za-z0-9_\-=]+", c) and len(c) >= 8:
            add("base64url", lambda: base64.urlsafe_b64decode(c + "=" * (-len(c) % 4)))
        if re.fullmatch(r"[A-Z2-7=]+", c) and len(c) >= 8:
            add("base32", lambda: CR.UNITS["base32"](c.encode()))
        if re.fullmatch(r"[0-9a-fA-F]+", c) and len(c) % 2 == 0:
            add("hex", lambda: CR.UNITS["hex"](c.encode()))
        if len(st) >= 5:
            core = st[2:-2] if st.startswith("<~") and st.endswith("~>") else st
            add("ascii85", lambda: base64.a85decode(core.encode("ascii")))
            add("base85", lambda: base64.b85decode(core.encode("ascii")))
        if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", c) and len(c) >= 8:
            add("base58", lambda: _b58(c))
        if re.fullmatch(r"[0-9A-Za-z]+", c) and len(c) >= 8:
            add("base62", lambda: _b62(c, string.digits + string.ascii_uppercase + string.ascii_lowercase))
            add("base62(alt)", lambda: _b62(c, string.ascii_uppercase + string.ascii_lowercase + string.digits))
        if re.fullmatch(r"[0-9A-Z $%*+\-./:]+", st) and len(st) >= 6:
            add("base45", lambda: _b45(st))
        if re.fullmatch(r"[01\s]+", st) and len(c) >= 8:
            if len(c) % 8 == 0:
                add("binary8", lambda: _bits(st, 8))
            if len(c) % 7 == 0:
                add("binary7", lambda: _bits(st, 7))
        if re.fullmatch(r"[0-7\s]+", st) and len(c) >= 6:
            add("octal", lambda: bytes(int(x, 8) for x in (st.split() if " " in st else [c[i:i + 3] for i in range(0, len(c), 3)])))
        if re.fullmatch(r"[\d,\s]+", st) and re.search(r"\d\D+\d", st):
            nums = [int(x) for x in re.split(r"[,\s]+", st) if x]
            if nums and max(nums) < 256:
                add("decimal-bytes", lambda: bytes(nums))
        if re.search(r"%[0-9A-Fa-f]{2}", st):
            add("url", lambda: urllib.parse.unquote_to_bytes(st))
        if st.lower().startswith("begin ") and re.search(r"(?mi)^\s*end\s*$", t):
            add("uuencode", lambda: _uudecode(t))
        if re.search(r"=[0-9A-Fa-f]{2}", st) or re.search(r"=\r?\n", t):
            add("quoted-printable", lambda: quopri.decodestring(t.encode("latin-1")))
        if re.fullmatch(r"[.\-/|\s]+", st) and ("." in st or "-" in st) and len(re.sub(r"\s", "", st)) >= 3:
            add("morse", lambda: _morse(st).encode())
        add("rot13", lambda: _rot(t, 13).encode())
        add("rot47", lambda: _rot47(t).encode())
        add("atbash", lambda: _atbash(t).encode())
        add("reverse", lambda: t[::-1].encode())
        base = rate(b)
        for sc, n in sorted(((rate(_rot(t, n).encode()), n) for n in range(1, 26)), reverse=True)[:2]:   # caesar: brute ALL 25 letter shifts, keep the best (any ROT-N, not a fixed few)
            if sc > base:
                add("caesar+%d" % n, lambda n=n: _rot(t, n).encode())
        for sc, n in sorted(((rate(_rot_printable(t, n).encode()), n) for n in range(1, 94)), reverse=True)[:2]:   # printable-ASCII rotation, ALL 93 shifts (catches an odd high-number ROT over 33..126)
            if sc > base + 0.2:
                add("rot-printable+%d" % n, lambda n=n: _rot_printable(t, n).encode())
    for name, fn in (("zlib", zlib.decompress), ("gzip", gzip.decompress), ("bz2", bz2.decompress), ("lzma", lzma.decompress)):
        add(name, lambda fn=fn: fn(b))
    try:                                                   # modern compressors (optional deps, guarded like base65536)
        import zstandard
        add("zstd", lambda: zstandard.ZstdDecompressor().decompress(b))
    except Exception:
        pass
    try:
        import lz4.frame
        add("lz4", lambda: lz4.frame.decompress(b))
    except Exception:
        pass
    try:
        import brotli
        add("brotli", lambda: brotli.decompress(b))
    except Exception:
        pass
    if 4 <= len(b) <= 200000 and printable_ratio(b) < 0.85:   # EBCDIC (cp037): mainframe/malware text, only when not already readable ASCII
        try:
            dec = b.decode("cp037")
            if dec and sum(ch in string.printable for ch in dec) / len(dec) > 0.92:
                add("ebcdic(cp037)", lambda: dec.encode("latin-1"))
        except Exception:
            pass
    try:                                                   # base65536 (2025 "Cover All Your Bases" family): optional dep, UTF-8 text, not ASCII
        import base65536
        u = b.decode("utf-8")
        if u.strip() and len(u.strip()) >= 2:
            add("base65536", lambda: base65536.decode(re.sub(r"\s", "", u)))
    except Exception:
        pass
    if 4 <= len(b) <= 20000 and rate(b) < 1.3:          # not yet readable English: try single-byte XOR (many keys keep text mostly printable)
        best = sorted(((rate(bytes(x ^ k for x in b)), k) for k in range(1, 256)), reverse=True)[:2]
        for sc, k in best:
            if sc > 1.3:
                add("xor-0x%02x" % k, lambda k=k: bytes(x ^ k for x in b))
    return out


def best_chains(data, depth=6, top=3, beam=14):
    start = (rate(data), [], data)
    frontier, seen, allstates = [start], {hashlib.sha1(data).hexdigest()}, [start]
    for _ in range(depth):
        nxt = []
        for sc, chain, b in frontier:
            for name, nb in expand(b):
                h = hashlib.sha1(nb).hexdigest()
                if h in seen:
                    continue
                seen.add(h)
                st = (rate(nb) + (0.0 if printable_ratio(nb) > 0.85 else -0.35), chain + [name], nb)
                nxt.append(st)
        if not nxt:
            break
        nxt.sort(key=lambda s: -s[0])
        frontier = nxt[:beam]
        allstates += frontier
    allstates.sort(key=lambda s: (-round(s[0], 3), len(s[1])))
    out, shown = [], set()
    for sc, chain, b in allstates:
        k = hashlib.sha1(b).hexdigest()
        if k in shown:
            continue
        shown.add(k); out.append((sc, chain, b))
        if len(out) >= top:
            break
    return out


def find_answers(text):
    return list(dict.fromkeys(SLUG.findall(text) + ANS.findall(text) + FLAG.findall(text)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?"); ap.add_argument("--text"); ap.add_argument("--depth", type=int, default=6)
    ap.add_argument("--top", type=int, default=3); ap.add_argument("--slug", action="store_true"); ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    data = a.text.encode() if a.text is not None else (sys.stdin.buffer.read() if a.path in (None, "-") else open(a.path, "rb").read())
    res = best_chains(data, a.depth, a.top)
    for i, (sc, chain, b) in enumerate(res, 1):
        prev = "".join(chr(c) if c in PRINT and c not in (10, 13) else ("|" if c in (10, 13) else ".") for c in b[:240])
        print("#%d score %.2f chain: %s" % (i, sc, " > ".join(chain) if chain else "(none: input as-is)"))
        if not a.quiet:
            print("   -> %s" % prev)
    if a.slug:
        ans = []
        for _, _, b in res:
            ans += find_answers(b.decode("latin-1", "ignore"))
        print("ANSWER_CANDIDATES: %s" % (", ".join(dict.fromkeys(ans)) or "none"))


if __name__ == "__main__":
    main()
