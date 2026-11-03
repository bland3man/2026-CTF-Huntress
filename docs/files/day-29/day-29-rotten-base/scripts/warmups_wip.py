#!/usr/bin/env python3
"""AUTOSOLVE - warmups lane (warmup_decode family). Zero model usage, generic across days (no hardcoded ids).

compute(start, blobs) -> {answer_id: answer}   (the ctf_gm.solve_mode contract; works for single, time_trial and mastery)

Evidence the shapes are built from (Days 01-07):
  single / time_trial : ONE blob, one or more nested layers of the day's encoding
                        (D1 base64, D2 rot13, D3 hex, D4 8-bit binary, D5 decimal bytes, D6 octal, D7 percent-encoding);
                        decodes to "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: <slug>"
  mastery             : N artifacts (D04: 18 separate blob.txt) or ONE zip of blob-NN.txt (D07: 33 members). Each blob is
                        "NN<TAB>fragment" lines, every fragment in a DIFFERENT encoding of the cumulative set; the decoded fragments
                        concatenate (whitespace is significant) into the same sentence. Question i -> artifact "blob-0i.txt" / set i.
Answer: the slug on the final non-empty decoded line (answer_format "three lowercase words separated by hyphens, followed by a hyphen
and a two-digit number"); falls back to ANS-<hex> / flag{...} / the whole final line for older answer shapes (D01 was flag{...}).
Disambiguation is deterministic: every fragment is decoded by every decoder whose charset fits, and a depth-first search keeps only
combinations whose running text stays a prefix of the known sentence (or, if the sentence ever changes, the highest-scoring readable
combination ending in an answer). Falls back to decode_chain.best_chains for anything new. ASCII only. Never executes artifact content.
"""
import ast, base64, binascii, codecs, hashlib, heapq, html, io, json, os, quopri, re, string, sys, time, unicodedata, urllib.parse, zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decode_chain as DC  # noqa: E402

# Pre-handled likely NEXT warmup layers (2026-10-07; every past title punned its encoding: Half a Turn=rot13, Hex Appeal=hex,
# Eight Is Enough=octal, Percent Chance=percent): morse, quoted-printable, \u/\x escapes, HTML entities, uuencode, base58/62/45
# (decode_chain's decoders, now also usable per mastery fragment), base91, and every caesar shift (decode_chain brute covers only 6).
MORSE = {".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g", "....": "h", "..": "i", ".---": "j",
         "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t",
         "..-": "u", "...-": "v", ".--": "w", "-..-": "x", "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2",
         "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9", ".-.-.-": ".",
         "--..--": ",", "..--..": "?", ".----.": "'", "-.-.--": "!", "-..-.": "/", "-.--.": "(", "-.--.-": ")", ".-...": "&",
         "---...": ":", "-.-.-.": ";", "-...-": "=", ".-.-.": "+", "-....-": "-", "..--.-": "_", ".-..-.": '"', "...-..-": "$",
         ".--.-.": "@"}
NATO = {"alfa": "a", "alpha": "a", "bravo": "b", "charlie": "c", "delta": "d", "echo": "e", "foxtrot": "f", "golf": "g", "hotel": "h", "india": "i", "juliett": "j", "juliet": "j",
        "kilo": "k", "lima": "l", "mike": "m", "november": "n", "oscar": "o", "papa": "p", "quebec": "q", "romeo": "r", "sierra": "s", "tango": "t", "uniform": "u", "victor": "v",
        "whiskey": "w", "whisky": "w", "xray": "x", "x-ray": "x", "yankee": "y", "zulu": "z", "zero": "0", "one": "1", "two": "2", "three": "3", "tree": "3", "four": "4", "fower": "4",
        "five": "5", "fife": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9", "niner": "9", "dash": "-", "hyphen": "-", "minus": "-"}
B91 = string.ascii_uppercase + string.ascii_lowercase + string.digits + '!#$%&()*+,./:;<=>?@[]^_`{|}~"'


Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"


def _z85(t):
    """ZeroMQ base85: 5 characters -> 4 bytes, big endian (RFC 32/Z85)."""
    out = bytearray()
    for i in range(0, len(t), 5):
        v = 0
        for ch in t[i:i + 5]:
            v = v * 85 + Z85.index(ch)
        out += v.to_bytes(4, "big")
    return bytes(out).rstrip(b"\x00")


def _nato(t):
    """ICAO/NATO phonetic words -> letters/digits ('/' or a blank separates words). Only if EVERY token is a known word."""
    out = []
    for tok in re.split(r"\s+", t.strip().lower()):
        if tok in ("/", "|", ""):
            out.append(" ")
        elif tok in NATO:
            out.append(NATO[tok])
        else:
            raise ValueError("not NATO")
    return "".join(out)


def _hexdump(t):
    """`hexdump -C` / `xxd` output -> the bytes (the hex columns only: the text gutter holds plaintext FRAGMENTS split across lines and must never be used)."""
    out = bytearray()
    for line in t.splitlines():
        m = re.match(r"^\s*[0-9a-fA-F]{4,8}(:?)\s+(.*)$", line)
        if not m:
            continue
        body = m.group(2)
        if "|" in body:                                   # hexdump -C: the gutter is |...|
            body = body.split("|")[0]
        elif m.group(1):                                  # xxd: groups end at the first run of two spaces, then the text column
            body = re.split(r"\s{2,}", body)[0]
        for tok in body.split():
            if re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,2}", tok):
                out += bytes.fromhex(tok)
    if not out:
        raise ValueError("not a hexdump")
    return bytes(out)


def _json_strings(t, limit=6):
    """Every string value of a JSON document (depth-first), longest first: a payload is often wrapped as {"data": "<encoded>"}."""
    doc = json.loads(t)
    found = []

    def walk(v):
        if isinstance(v, str):
            found.append(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    walk(doc)
    return sorted({s for s in found if len(s) >= 8}, key=len, reverse=True)[:limit]
BIGINT_MAX = 4000          # base58/62/91 are O(n^2) big-int decodes: skip them on huge layers (those are hex/base64 anyway)


def _morse(t):
    # a mastery fragment can start/end on a word gap ("/"): keep that space, whitespace is significant there
    lead = " " if re.match(r"\s*[/|]", t) or re.match(r"\s{3,}", t) else ""           # a word gap is '/', '|' or (2026-10-15) a run of 3+ spaces
    trail = " " if re.search(r"[/|]\s*$", t) or re.search(r"\s{3,}$", t) else ""
    words = re.split(r"\s*[/|]\s*|\s{3,}|\n", t.strip().strip("/|").strip())
    return lead + " ".join("".join(MORSE[c] for c in w.split()) for w in words if w.strip()) + trail


def _uu(t):
    lines = t.strip("\r\n").splitlines()
    if lines and lines[0].startswith("begin "):
        lines = lines[1:lines.index("end")] if "end" in lines else lines[1:]
    elif not lines or any(len(l) != 1 + 4 * ((((ord(l[0]) - 32) & 63) + 2) // 3) for l in lines if l not in ("`", "")):     # 2026-10-15: the old line (1 + 4*(n+2)//3) was only right when n+2 was a multiple of 3, so a full 45-byte line failed the check
        raise ValueError("not uuencode")
    return b"".join(binascii.a2b_uu(l) for l in lines if l not in ("`", ""))


def _b91(t):
    v, b, n, out = -1, 0, 0, bytearray()
    for ch in t:
        c = B91.index(ch)
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while True:
                out.append(b & 255); b >>= 8; n -= 8
                if n <= 7:
                    break
            v = -1
    if v + 1:
        out.append((b | v << n) & 255)
    return bytes(out)


_BF_CHARS = frozenset("><+-.,[]")                     # the eight brainfuck commands (every other character is a no-op / comment)


def _brainfuck(code, max_steps=2_000_000, max_out=100_000):
    """Brainfuck (title pun 'a very small language', 2026-10-26 Day 26). A standard 30000-cell wrapping byte tape; ',' reads 0 (no input); loops honoured, but BOUNDED by a step and output
    cap (the artifact is untrusted). -> the emitted bytes (the caller decodes/validates them). Only reached when every non-whitespace character is a brainfuck command (see the guard in candidates)."""
    prog = [ch for ch in code if ch in _BF_CHARS]
    jump, stack = {}, []
    for i, ch in enumerate(prog):
        if ch == "[":
            stack.append(i)
        elif ch == "]":
            if not stack:
                raise ValueError("unbalanced brackets")
            j = stack.pop()
            jump[i] = j
            jump[j] = i
    if stack:
        raise ValueError("unbalanced brackets")
    tape = bytearray(30000)
    ptr = pc = steps = 0
    out = bytearray()
    n = len(prog)
    while pc < n:
        steps += 1
        if steps > max_steps:
            raise ValueError("step cap exceeded")
        ch = prog[pc]
        if ch == ">":
            ptr = (ptr + 1) % len(tape)
        elif ch == "<":
            ptr = (ptr - 1) % len(tape)
        elif ch == "+":
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif ch == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif ch == ".":
            out.append(tape[ptr])
            if len(out) > max_out:
                raise ValueError("output cap exceeded")
        elif ch == ",":
            tape[ptr] = 0                              # no input stream: EOF reads as 0
        elif ch == "[":
            if tape[ptr] == 0:
                pc = jump[pc]
        elif ch == "]":
            if tape[ptr] != 0:
                pc = jump[pc]
        pc += 1
    if not out:
        raise ValueError("no brainfuck output")
    return bytes(out)


# D27 audit §7 (user directive 2026-10-27): shared Ook! decoder.
# Ook! is a Brainfuck skin where every token is `Ook.`, `Ook?` or `Ook!`; consecutive token
# PAIRS map 1:1 onto the eight brainfuck commands. Agent-3 added this to the per-CID working
# copy for D27 Monkey Business (Single blob was 3393 pure Ook pairs → 108-char output).
# ONE canonical mapping lives here so the whole-blob path (decode_blob below) and the
# per-fragment path (candidates list, see `add("ook", ...)` above) call the SAME function.
# Static only; the Ook stream is parsed and interpreted by our bounded `_brainfuck`, never exec'd.
_OOK_BF = {".?": ">", "?.": "<", "..": "+", "!!": "-", "!.": ".", ".!": ",", "!?": "[", "?!": "]"}


def _ook(text):
    """-> decoded bytes (via _brainfuck), or None if text is not pure Ook! (not raised).
    Pure Ook means: only `Ook.` / `Ook?` / `Ook!` tokens plus whitespace, at least 2 tokens
    (one pair = one BF command). An odd final token is dropped (same as agent-3's working
    copy behavior). Caller handles decode to text."""
    if isinstance(text, bytes):
        try:
            text = text.decode("latin-1")
        except Exception:
            return None
    if re.sub(r"Ook[.?!]|\s+", "", text):
        return None  # non-Ook chars present
    toks = re.findall(r"Ook([.?!])", text)
    if len(toks) < 2:
        return None
    prog = "".join(_OOK_BF["".join(toks[i:i + 2])] for i in range(0, len(toks) - 1, 2))
    try:
        return _brainfuck(prog)
    except Exception:
        return None


KNOWN = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
SLUG = re.compile(r"[a-z]+-[a-z]+-[a-z]+-\d{2}")
FRAG_LINE = re.compile(r"^(\d{1,3})\t(.*)$")
WORDS = ("the", "this", "and", "work", "decod", "warm", "solve", "submit", "answer", "exact", "game", "master", "nice", "to ")


# =====================================================================================================================
# UNIVERSE EXTENSIONS (2026-10-15). The author adds one new encoding per day; every miss cost 160-350 s. These decoders cover
# the keyless / tiny-key-space encodings a puzzle author could pick next, so the NEXT one is already built. Rules kept:
#  * a result is accepted only if it forms the KNOWN sentence or a valid slug (callers check) - nothing here is trusted alone;
#  * lossy encodings with merged letters (tap code c/k, Polybius i/j, 24-letter Baconian i/j u/v) decode only when no merged
#    letter lies in the slug (else HELD - the true letter cannot be known);
#  * known-plaintext (crib) attacks use the fixed KNOWN sentence and demand an exact KNOWN + slug result.
# Every non-ASCII character here is written as chr()/escape so the source stays ASCII.
# =====================================================================================================================
_B32_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B32_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_B32_Z = "ybndrfg8ejkmcpqxot1uwisza345h769"
_B58_FLICKR = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
_B58_RIPPLE = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
_B64_STD = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
_B64_BCRYPT = "./" + string.ascii_uppercase + string.ascii_lowercase + string.digits
_B64_ITOA = "./" + string.digits + string.ascii_uppercase + string.ascii_lowercase
_XXALPHA = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_ZW = tuple(chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E))
_DOT_CHARS = "".join(chr(x) for x in (0x2022, 0xB7, 0x2219, 0x25CF, 0xFF0E, 0x30FB))
_DASH_CHARS = "".join(chr(x) for x in (0x2013, 0x2014, 0x2212, 0x2012, 0x2015, 0x2010, 0x2011, 0xFF0D, 0x2500)) + "_"
_BR_CODES = (0x01, 0x03, 0x09, 0x19, 0x11, 0x0B, 0x1B, 0x13, 0x0A, 0x1A, 0x05, 0x07, 0x0D, 0x1D, 0x15, 0x0F, 0x1F, 0x17, 0x0E, 0x1E, 0x25, 0x27, 0x3A, 0x2D, 0x3D, 0x35)
_BR_LETTER = {v: string.ascii_lowercase[i] for i, v in enumerate(_BR_CODES)}
_BR_PUNCT = {0x24: "-", 0x02: ",", 0x32: ".", 0x16: "!", 0x12: ":", 0x06: ";", 0x26: "?", 0x04: "'"}
_POLY = "abcdefghiklmnopqrstuvwxyz"                  # 5x5 square, i/j merged (decoded as i)
_TAP = "abcdefghijlmnopqrstuvwxyz"                   # 5x5 tap square, c/k merged (decoded as c)
_BACON24 = "abcdefghiklmnopqrstuwxyz"                # 24-letter Baconian: i/j and u/v merged (decoded as i, u)
_T9 = {"2": "abc", "3": "def", "4": "ghi", "5": "jkl", "6": "mno", "7": "pqrs", "8": "tuv", "9": "wxyz"}


def _bigbase(c, alpha):
    n = 0
    for ch in c:
        n = n * len(alpha) + alpha.index(ch)
    pad = len(c) - len(c.lstrip(alpha[0]))
    return b"\x00" * pad + (n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"")


def _b32_alpha(c, alpha):
    c = c.rstrip("=")
    if any(ch not in alpha for ch in c):
        raise ValueError("outside alphabet")
    c = c.translate(str.maketrans(alpha, _B32_STD))
    return base64.b32decode(c + "=" * (-len(c) % 8))


def _b64_alpha(c, alpha):
    c = c.rstrip("=")
    if any(ch not in alpha for ch in c):
        raise ValueError("outside alphabet")
    c = c.translate(str.maketrans(alpha, _B64_STD))
    return base64.b64decode(c + "=" * (-len(c) % 4), validate=True)


def _b92_val(ch):
    o = ord(ch)
    if ch == "!":
        return 0
    if 35 <= o <= 95:
        return o - 34
    if 97 <= o <= 125:
        return o - 35
    raise ValueError("not base92")


def _b92(t):
    """basE92 (thenoviceoof): 13 bits -> 2 characters, a trailing character carries 6 bits; '~' alone is the empty string."""
    if t == "~":
        return b""
    bits = []
    for i in range(0, len(t) - 1, 2):
        v = _b92_val(t[i]) * 91 + _b92_val(t[i + 1])
        if v >= 8192:
            raise ValueError("bad base92 pair")
        bits.append(format(v, "013b"))
    if len(t) % 2:
        bits.append(format(_b92_val(t[-1]), "06b"))
    s = "".join(bits)
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s) - 7, 8))


def _xx(t):
    """xxencode (uuencode with the +-0-9A-Za-z alphabet): header/trailer optional."""
    lines = t.strip("\r\n").splitlines()
    if lines and lines[0].startswith("begin "):
        lines = lines[1:lines.index("end")] if "end" in lines else lines[1:]
    out = bytearray()
    for l in lines:
        if not l:
            continue
        n = _XXALPHA.index(l[0])
        if n == 0:
            continue
        if len(l) != 1 + 4 * ((n + 2) // 3):
            raise ValueError("bad xx line")
        v = [_XXALPHA.index(ch) for ch in l[1:]]
        raw = bytearray()
        for i in range(0, len(v), 4):
            q = v[i:i + 4]
            raw += bytes([(q[0] << 2 | q[1] >> 4) & 255, (q[1] << 4 | q[2] >> 2) & 255, (q[2] << 6 | q[3]) & 255])
        out += raw[:n]
    if not out:
        raise ValueError("empty")
    return bytes(out)


def _bytes_options(opts):
    """Several byte readings -> an _XorSet of the printable-ASCII ones (the caller's lookahead / slug check settles which is right)."""
    got = []
    for b in opts:
        try:
            s = b.decode("ascii")
        except UnicodeDecodeError:
            continue
        if _printable(s) and s not in got:
            got.append(s)
    if not got:
        raise ValueError("no printable reading")
    return _XorSet(got)


def _bits_ws(s):
    opts = []
    for one in (" ", "\t"):
        bits = "".join("1" if ch == one else "0" for ch in s)
        if len(bits) % 8 == 0:
            opts.append(bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)))
    return _bytes_options(opts)


def _zw(s):
    z = [ch for ch in s if ch in _ZW]
    kinds = sorted(set(z))
    if len(z) < 16 or not 2 <= len(kinds) <= 3:
        raise ValueError("not zero-width binary")
    opts = []
    if len(kinds) == 2:
        for zero, one in ((kinds[0], kinds[1]), (kinds[1], kinds[0])):
            bits = "".join("1" if ch == one else "0" for ch in z)
            if len(bits) % 8 == 0:
                opts.append(bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)))
    else:
        for sep in kinds:
            rest = [k for k in kinds if k != sep]
            for zero, one in ((rest[0], rest[1]), (rest[1], rest[0])):
                groups = [g for g in "".join("S" if ch == sep else ("1" if ch == one else "0") for ch in z).split("S") if g]
                if groups and all(len(g) <= 8 for g in groups):
                    opts.append(bytes(int(g, 2) for g in groups))
    return _bytes_options(opts)


def _braille_text(s):
    """English braille (a-z, number sign + a-j for digits, capital sign, basic punctuation) -> text."""
    out, num, cap = [], False, False
    for ch in s:
        o = ord(ch)
        if not 0x2800 <= o <= 0x28FF:
            if ch in "\r\n":
                out.append(ch); num = False
                continue
            raise ValueError("not braille")
        v = o - 0x2800
        if v == 0x3C:
            num = True
        elif v == 0x20:
            cap = True
        elif v == 0:
            out.append(" "); num = False
        elif v in _BR_PUNCT:
            out.append(_BR_PUNCT[v]); num = False
        elif v in _BR_LETTER:
            letter = _BR_LETTER[v]
            if num and letter in "abcdefghij":
                out.append(str((string.ascii_lowercase.index(letter) + 1) % 10))
            else:
                num = False
                out.append(letter.upper() if cap else letter)
            cap = False
        else:
            raise ValueError("unknown braille cell")
    return "".join(out)


def _tok_split(t):
    return [x for x in re.split(r"[\s,;]+", t.strip()) if x]


def _tok_decode(t, fn, need=3):
    """Token-per-character codes (A1Z26, Polybius, multitap, Baconian): fn(token) -> a character or None (= a literal token, e.g. '-' or '!'). '/' is a word gap and the LAST token, if
    it is two digits, is the slug's number (kept literal). Needs `need` recognised code tokens."""
    toks = _tok_split(t)
    if len(toks) < need:
        raise ValueError("too few tokens")
    out, hit = [], 0
    for i, tok in enumerate(toks):
        if tok in ("/", "|", "//"):
            out.append(" ")
        elif i == len(toks) - 1 and re.fullmatch(r"\d\d", tok):
            out.append(tok)
        else:
            r = fn(tok)
            if r is None:
                out.append(tok)
            else:
                out.append(r); hit += 1
    if hit < need:
        raise ValueError("no codes")
    return "".join(out)


def _a1z26(t):
    return _tok_decode(t, lambda k: chr(96 + int(k)) if re.fullmatch(r"\d{1,2}", k) and 1 <= int(k) <= 26 else None)


def _polybius(t):
    return _tok_decode(t, lambda k: _POLY[(int(k[0]) - 1) * 5 + int(k[1]) - 1] if re.fullmatch(r"[1-5]{2}", k) else None)


def _bacon(t, table):
    def f(k):
        if re.fullmatch(r"[abAB]{5}", k):
            v = int(k.lower().replace("a", "0").replace("b", "1"), 2)
            return table[v] if v < len(table) else None
        return None
    return _tok_decode(t, f)


def _t9(t):
    def f(k):
        if k == "0":
            return " "
        if re.fullmatch(r"([2-9])\1*", k) and len(k) <= len(_T9[k[0]]):
            return _T9[k[0]][len(k) - 1]
        return None
    return _tok_decode(t, f)


def _tap(t):
    toks = _tok_split(t)
    out, i, hit = [], 0, 0
    dots = r"(?:\.{1,5}|\*{1,5}|[xX]{1,5})"
    while i < len(toks):
        tok = toks[i]
        if tok in ("/", "|", "//"):
            out.append(" ")
        elif i == len(toks) - 1 and re.fullmatch(r"\d\d", tok):
            out.append(tok)
        elif re.fullmatch(dots, tok) and i + 1 < len(toks) and re.fullmatch(dots, toks[i + 1]):
            out.append(_TAP[(len(tok) - 1) * 5 + len(toks[i + 1]) - 1]); hit += 1
            i += 1
        else:
            out.append(tok)
        i += 1
    if hit < 3:
        raise ValueError("no tap codes")
    return "".join(out)


def _merge_fix(dec, groups):
    """A merged-letter code decoded to canonical letters (first letter of each group). Verify against the KNOWN sentence modulo the merge, then return KNOWN + slug - but ONLY if the slug holds
    no canonical-merged letter (the true letter could be either one: HELD, never a guess)."""
    canon = {}
    for g in groups:
        for ch in g:
            canon[ch] = g[0]
    kl = [canon.get(ch, ch) for ch in KNOWN.lower() if ch.isalpha()]
    k, pos = 0, 0
    while k < len(kl) and pos < len(dec):
        ch = dec[pos]
        if ch.isalpha():
            if canon.get(ch.lower(), ch.lower()) != kl[k]:
                raise ValueError("does not match the known sentence")
            k += 1
        pos += 1
    if k < len(kl):
        raise ValueError("short")
    rem = dec[pos:].strip(" :.,!")
    if not SLUG.fullmatch(rem):
        raise ValueError("no slug")
    if any(ch in {g[0] for g in groups} for ch in rem if ch.isalpha()):
        raise ValueError("merged letter in the slug: ambiguous")
    return KNOWN + rem


_PIG_VSUF = ("way", "yay", "ay", "hay")


def _pig_word(w, cluster, vsuf, whole):
    """Forward pig latin of one token. whole=True moves letters of the WHOLE token ('sunny-castle-opal-96' -> 'unny-castle-opal-96say'), whole=False only the leading run of letters
    ('unnysay-castle-opal-96'). cluster=True moves the whole leading consonant cluster, else only the first letter."""
    if not w:
        return w
    if whole:
        core, tail = w, ""
    else:
        m = re.match(r"([A-Za-z]*)(.*)", w, re.S)
        core, tail = m.group(1), m.group(2)
        if not core:
            return w
    if core[0].lower() in "aeiou":
        return core + vsuf + tail
    i = 1
    if cluster:
        i = 0
        while i < len(core) and core[i].lower() not in "aeiou":
            i += 1
    return core[i:] + core[:i] + "ay" + tail


def _pig_latin(t):
    """Pig latin verified by FORWARD-encoding the known sentence (style, cluster rule and vowel suffix are all read off it); the slug token is inverted only where that is unambiguous (the
    moved letters are delimited by the slug's digits, or exactly one letter moves) and re-encoded to prove it. A clustered leading-run style is ambiguous in the slug -> HELD."""
    toks, kt = t.split(), KNOWN.split()
    if len(toks) != len(kt) + 1:
        raise ValueError("token count")
    last = toks[-1]
    found = set()
    for whole in (True, False):
        for cluster in (True, False):
            for vs in _PIG_VSUF:
                if not all(_pig_word(a, cluster, vs, whole).lower() == b.lower() for a, b in zip(kt, toks[:-1])):
                    continue
                plains = []
                if last.endswith(vs) and whole:
                    plains.append(last[:-len(vs)])
                if whole and last.endswith("ay"):
                    m = re.fullmatch(r"(.*\d\d)([a-z]+)", last[:-2])
                    if m:
                        plains.append(m.group(2) + m.group(1))
                if not whole:
                    m = re.fullmatch(r"([a-z]+)(-.*)", last)
                    if m:
                        seg, rest = m.groups()
                        if seg.endswith(vs):
                            plains.append(seg[:-len(vs)] + rest)
                        if not cluster and seg.endswith("ay") and len(seg) >= 4:
                            plains.append(seg[-3] + seg[:-3] + rest)
                for p in plains:
                    if SLUG.fullmatch(p) and _pig_word(p, cluster, vs, whole) == last:
                        found.add(p)
    if len(found) != 1:
        raise ValueError("not pig latin / ambiguous")
    return KNOWN + found.pop()


def _morse_norm(t):
    """Morse written with other glyphs: unicode dots/dashes, '_' for dash, or 'dit'/'dah'/'di' words. -> dot/dash text, or None."""
    if re.fullmatch(r"(?i)(?:dit|dah|di|[\s/|\-])+", t) and re.search(r"(?i)dah|dit|di", t):
        u = re.sub(r"(?i)(?<=[a-z])-(?=[a-z])", "", t)
        u = re.sub(r"(?i)dah", "-", u)
        u = re.sub(r"(?i)dit", ".", u)
        return re.sub(r"(?i)di", ".", u)
    if re.fullmatch("[.\\-/|\\s%s%s]+" % (_DOT_CHARS, _DASH_CHARS), t):
        u = t
        for ch in _DOT_CHARS:
            u = u.replace(ch, ".")
        for ch in _DASH_CHARS:
            u = u.replace(ch, "-")
        return u if u != t else None
    return None


def _json_chars(t):
    """A JSON / Python list of single characters or of code points -> the text."""
    try:
        v = json.loads(t)
    except Exception:
        v = ast.literal_eval(t)
    if not isinstance(v, (list, tuple)) or len(v) < 4:
        raise ValueError("not a char list")
    if all(isinstance(x, str) and len(x) == 1 for x in v):
        return "".join(v)
    if all(isinstance(x, int) and 0 <= x < 0x110000 for x in v):
        return "".join(chr(x) for x in v)
    raise ValueError("mixed list")


def _more_candidates(add, s, t, c):
    """The extra decoders for one fragment/layer. `s` keeps its whitespace, `t` is stripped, `c` has all whitespace removed."""
    if re.fullmatch(r"[ \t]{64,}", s):
        add("whitespace-binary", lambda: _bits_ws(s))
    if any(ch in _ZW for ch in s):
        add("zero-width", lambda: _zw(s))
    if any(ord(ch) > 127 for ch in s):
        if any(0x2800 <= ord(ch) <= 0x28FF for ch in s):
            add("braille-bytes", lambda: bytes(ord(ch) - 0x2800 for ch in s if 0x2800 <= ord(ch) <= 0x28FF))
            add("braille-text", lambda: _braille_text(s.strip()))
        if any(0x1F1E6 <= ord(ch) <= 0x1F1FF for ch in s):
            add("regional-indicators", lambda: "".join(chr(97 + ord(ch) - 0x1F1E6) if 0x1F1E6 <= ord(ch) <= 0x1F1FF else ch for ch in s))
        if all(0x1F3F7 <= ord(ch) <= 0x1F3F7 + 255 for ch in c) and c:
            add("base100", lambda: bytes(ord(ch) - 0x1F3F7 for ch in c))
        add("nfkc", lambda: unicodedata.normalize("NFKC", s))
        add("nomarks", lambda: "".join(ch for ch in unicodedata.normalize("NFKD", s) if not unicodedata.category(ch).startswith("M")))
    if _sentence_like(s):
        if s != s.lower():
            add("lower", lambda: s.lower())
        if s != s.swapcase():
            add("swapcase", lambda: s.swapcase())
    if not t:
        return
    toks = _tok_split(t)
    if len(toks) >= 4 and not re.search(r"[^0-9a-zA-Z\s,;]", t) and all(len(x) <= 9 for x in toks):
        md = max(int(ch, 36) for x in toks for ch in x)             # the smallest base that can hold every digit; every larger base up to 36 is tried too
        for base in range(max(2, md + 1), 37):
            if base in (10, 16):
                continue                                              # decimal / hex lists are the 'decimal' / 'hex' decoders above
            vals = [int(x, base) for x in toks]
            if max(vals) < 256:
                add("base%d-codes" % base, lambda v=vals: bytes(v))
    if re.fullmatch(r"\d+", c):
        if len(c) % 3 == 0 and len(c) >= 9:
            add("decimal3-joined", lambda: bytes(int(c[i:i + 3]) for i in range(0, len(c), 3)))
            if re.fullmatch(r"[0-7]+", c):
                add("octal3-joined", lambda: bytes(int(c[i:i + 3], 8) for i in range(0, len(c), 3)))
        if 8 <= len(c) <= 3000:
            add("bigint-decimal", lambda: (lambda n: n.to_bytes((n.bit_length() + 7) // 8, "big"))(int(c)))
    if re.fullmatch(r"[01]{4}(?:\s+[01]{4}){5,}", t) and len(t.split()) % 2 == 0:
        add("binary4", lambda: bytes(int(a + b, 2) for a, b in zip(t.split()[0::2], t.split()[1::2])))
    if re.fullmatch(r"[01]{7,8}(?:[\s,;|.\-/]+[01]{7,8}){3,}", t):
        bt = re.findall(r"[01]+", t)
        if len({len(x) for x in bt}) == 1:
            add("binary(sep)", lambda: bytes(int(x, 2) for x in bt))
    if re.search(r"(?i)\b0x[0-9a-f]{2}\b", t) and re.fullmatch(r"[0-9a-fA-FxX\s,;:{}\[\]()\-.]+", t):
        hb = re.sub(r"(?i)0x|[^0-9a-f]", "", t)
        if len(hb) % 2 == 0 and len(hb) >= 8:
            add("hex(0x-list)", lambda: binascii.unhexlify(hb))
    mn = _morse_norm(t)
    if mn is not None:
        add("morse(alt)", lambda: _morse(mn))
    if re.fullmatch(r"[0-9/|\-!,:.;?\s]+", t):
        add("a1z26", lambda: _a1z26(t))
        add("polybius", lambda: _merge_fix(_polybius(t), ("ij",)))
        add("multitap", lambda: _t9(t))
    if re.fullmatch(r"[abAB/|\-!,:.;?\s0-9]+", t):
        add("baconian", lambda: _bacon(t, string.ascii_lowercase))
        add("baconian24", lambda: _merge_fix(_bacon(t, _BACON24), ("ij", "uv")))
    if re.fullmatch(r"[A-Pa-p]+", c) and len(c) % 2 == 0 and len(c) >= 8:       # Day 17: nibble alphabet A..P = 0..15, two letters per byte (Baconian -> this)
        add("nibble-AP", lambda: bytes((ord(c[i].upper()) - 65) * 16 + ord(c[i + 1].upper()) - 65 for i in range(0, len(c), 2)))
    if re.fullmatch(r"[.*xX/|\-!,:;?\s0-9]+", t) and re.search(r"[.*xX]", t):
        add("tap-code", lambda: _merge_fix(_tap(t), ("ck",)))
    if len(re.findall(r"(?i)[a-z]ay\b", t)) >= 6 and len(t.split()) == len(KNOWN.split()) + 1:
        add("pig-latin", lambda: _pig_latin(t))
    if re.fullmatch(r"(?:\\[0-9a-fA-F]{1,6}\s?)+", t):
        add("css-escape", lambda: re.sub(r"\\([0-9a-fA-F]{1,6})\s?", lambda m: chr(int(m.group(1), 16)), t))
    if "+" in t and re.search(r"%[0-9A-Fa-f]{2}", t):
        add("percent(+)", lambda: urllib.parse.unquote_plus(t, errors="strict"))
    if "-" in t and re.fullmatch(r"(?:xn--)?[ -~]+", t):
        add("punycode", lambda: codecs.decode(re.sub(r"^xn--", "", t).encode("ascii"), "punycode"))
    if "+" in t and re.fullmatch(r"[ -~]+", t):
        add("utf-7", lambda: t.encode("ascii").decode("utf-7"))
    if t[:1] in "[(" and len(t) >= 16:
        add("char-list", lambda: _json_chars(t))
    cm = re.fullmatch(r"(?s)<!\[CDATA\[(.*)\]\]>", t)
    if cm:
        add("cdata", lambda: cm.group(1))
    if "<" in t and ">" in t and re.search(r"<[A-Za-z/!][^>]*>", t):
        add("untag", lambda: re.sub(r"<[^>]*>", "", t).strip())
    lm = re.fullmatch(r"(?s)[A-Za-z][A-Za-z _\-]{0,23}\s*[:=]\s*(\S.*)", t)
    if lm and len(lm.group(1)) >= 8 and "\n" not in t:
        add("label", lambda: lm.group(1).strip())
    wm = re.fullmatch(r"(?s)[A-Za-z_]{0,12}[{\[(<](.{8,})[}\])>]", t)
    if wm and "\n" not in t:
        add("brackets", lambda: wm.group(1))
    if t.startswith("```"):
        add("unfence", lambda: re.sub(r"(?m)^```\w*\s*$", "", t).strip())
    if t.startswith("-----BEGIN"):                                          # PEM / PGP armor: the base64 body between the BEGIN and END lines
        add("armor", lambda: "".join(l.strip() for l in t.splitlines() if l.strip() and not l.startswith("-----") and ":" not in l))
    if len(c) >= 8 and len(c) <= BIGINT_MAX:
        if re.fullmatch(r"[0-9A-Za-z=]+", c):
            c32 = c.rstrip("=")
            add("base32(crockford)", lambda: _b32_alpha(c32.upper(), _B32_CROCKFORD))
            add("base32(z)", lambda: _b32_alpha(c32, _B32_Z))
        if re.fullmatch(r"[1-9a-zA-Z]+", c):
            add("base58(flickr)", lambda: _bigbase(c, _B58_FLICKR))
            add("base58(ripple)", lambda: _bigbase(c, _B58_RIPPLE))
        if re.fullmatch(r"[0-9A-Za-z]+", c):
            add("base62(lower-first)", lambda: _bigbase(c, string.digits + string.ascii_lowercase + string.ascii_uppercase))
        c64 = c.rstrip("=")
        if len(c64) % 4 != 1:
            if re.fullmatch(r"[./A-Za-z0-9]+", c64):
                add("base64(bcrypt)", lambda: _b64_alpha(c64, _B64_BCRYPT))
                add("base64(itoa)", lambda: _b64_alpha(c64, _B64_ITOA))
            if re.fullmatch(r"[A-Za-z0-9+/]+", c64):
                add("base64(swapcase)", lambda: _b64_alpha(c64.swapcase(), _B64_STD))
        if all(ch in _XXALPHA for ch in c) and not t.startswith("begin "):
            add("xxencode", lambda: _xx(s))
        elif t.startswith("begin ") and "end" in t:
            add("xxencode", lambda: _xx(s))
        if all(ch in "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}~" for ch in c):
            add("base92", lambda: _b92(c))


# ---- known-plaintext (crib) attacks: the fixed KNOWN sentence is the crib; the answer must be exactly KNOWN + slug --------------------------------------------------------------------
_AFFINE = []


def _affine_tables():
    if not _AFFINE:
        lo, up = string.ascii_lowercase, string.ascii_uppercase
        for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
            ai = pow(a, -1, 26)
            for b in range(26):
                if a == 1 and b == 0:
                    continue
                dl = "".join(chr(97 + (ai * (i - b)) % 26) for i in range(26))
                _AFFINE.append(((a, b), str.maketrans(lo + up, dl + dl.upper())))
    return _AFFINE


def _accept_sentence(o):
    """-> KNOWN + slug iff `o` is the known sentence (any letter case: a morse / NATO / lower-casing layer outside the cipher drops case) followed by a slug, else None."""
    o = o.strip()
    return KNOWN + o[len(KNOWN):].lower() if o.lower().startswith(KNOWN.lower()) and SLUG.fullmatch(o[len(KNOWN):].lower()) else None


def _vig_variants(s):
    """Vigenere / Beaufort / autokey (key length 1..16, key advancing on letters or on every character), the key read off the KNOWN sentence."""
    res = []
    pos = [i for i, ch in enumerate(s) if ch.isascii() and ch.isalpha()]
    kpos = [i for i, ch in enumerate(KNOWN) if ch.isalpha()]
    nk = len(kpos)
    if len(pos) < nk + 5 or len(s) < len(KNOWN) + 9:
        return res
    ct = [ord(s[i].lower()) - 97 for i in pos]
    pt = [ord(KNOWN[i].lower()) - 97 for i in kpos]

    def build(shift_of):                                  # shift_of(j, i) -> plaintext letter index for ciphertext letter j (char position i)
        out = list(s)
        for j, i in enumerate(pos):
            p = shift_of(j, i)
            if p is None:
                return None
            out[i] = chr(97 + p) if s[i].islower() else chr(65 + p)
        return "".join(out)
    for mode in (0, 1):                                    # 0: key index = letter index, 1: key index = character index
        kidx = [j if mode == 0 else i for j, i in enumerate(pos)]
        for kind in ("vig", "beau"):
            d = [(ct[j] - pt[j]) % 26 if kind == "vig" else (ct[j] + pt[j]) % 26 for j in range(nk)]
            for L in range(1, 17):
                if nk < 3 * L:
                    break
                key = {}
                if any(key.setdefault(kidx[j] % L, d[j]) != d[j] for j in range(nk)) or len(key) != L:
                    continue
                if kind == "vig":
                    r = build(lambda j, i: (ct[j] - key[kidx[j] % L]) % 26 if kidx[j] % L in key else None)
                else:
                    r = build(lambda j, i: (key[kidx[j] % L] - ct[j]) % 26 if kidx[j] % L in key else None)
                if r:
                    res.append(r)
                break
    d = [(ct[j] - pt[j]) % 26 for j in range(nk)]          # autokey: key = primer + plaintext
    for L in range(1, 17):
        if nk < L + 12:
            break
        if all(d[j] == pt[j - L] for j in range(L, nk)):
            plain = []
            for j in range(len(ct)):
                plain.append((ct[j] - (d[j] if j < L else plain[j - L])) % 26)
            r = build(lambda j, i: plain[j])
            if r:
                res.append(r)
            break
    return res


def _rail_order(n, k):
    rails, r, dr = [[] for _ in range(k)], 0, 1
    for i in range(n):
        rails[r].append(i)
        if k > 1:
            dr = 1 if r == 0 else (-1 if r == k - 1 else dr)
            r += dr
    return [i for rail in rails for i in rail]


def _rail_dec(ct, k):
    out = [""] * len(ct)
    for ch, i in zip(ct, _rail_order(len(ct), k)):
        out[i] = ch
    return "".join(out)


def _scytale_dec(ct, k):                                    # ct = "".join(pt[i::k] for i in range(k))
    out, p = [""] * len(ct), 0
    for i in range(k):
        for j in range(i, len(ct), k):
            out[j] = ct[p]
            p += 1
    return "".join(out)


def _transposed_variants(s):
    yield "reverse-words", " ".join(s.split()[::-1])
    yield "reverse-each-word", " ".join(w[::-1] for w in s.split(" "))
    yield "swap-pairs", "".join((s[i + 1] + s[i]) if i + 1 < len(s) else s[i] for i in range(0, len(s), 2))
    for k in range(2, 17):
        yield "railfence%d" % k, _rail_dec(s, k)
        yield "scytale%d" % k, _scytale_dec(s, k)


def _crib_subst(t):
    """Monoalphabetic substitution of any kind (leet, keyboard, atbash, caesar, case folding, symbol maps) learned from the KNOWN sentence. Letters the crib never showed (f j q z...) in the slug make
    it HELD; the last two characters are the slug's digits and stay literal when they are digits."""
    n = len(KNOWN)
    if len(t) < n + 9:
        return None
    enc = {}                                              # plain character -> cipher character; it must be a FUNCTION over the whole crib (a deterministic substitution)
    for ch, p in zip(t[:n], KNOWN):
        if enc.setdefault(p, ch) != ch:
            return None
    if all(ch == p for p, ch in enc.items()):
        return None
    inv = {}                                              # cipher character -> the slug-charset plain characters that produce it (several = ambiguous: '!' is both 'i' and itself in some leet tables)
    for p, ch in enc.items():
        if p in _SLUGCH:
            inv.setdefault(ch, set()).add(p)
    for p in {q for q in enc if q.lower() in _SLUGCH and q.isalpha()}:
        inv.setdefault(enc[p], set()).add(p.lower())
    leet_class = all(ch.lower() == p.lower() or not ch.isalpha() for p, ch in enc.items() if p.isalpha())   # the cipher never moves a letter onto another letter (leet, case changes): letters the crib did not show stay themselves
    seen_plain = {p.lower() for p in enc}
    tail, out = t[n:], []
    for i, ch in enumerate(tail):
        if i >= len(tail) - 2 and ch in string.digits:
            out.append(ch)
        elif ch in inv:
            if len(inv[ch]) != 1:
                return None
            out.append(next(iter(inv[ch])))
        elif ch == "-":
            out.append(ch)
        elif leet_class and ch.isascii() and ch.isalpha() and ch.lower() not in seen_plain:
            out.append(ch.lower())
        else:
            return None
    r = "".join(out)
    return KNOWN + r if SLUG.fullmatch(r) else None


_ROTTABS = []


def _rot_tables():
    """Cyclic shifts over the 94 printable characters and over the 62 alphanumerics (two orders): the rot47 family generalised to every shift."""
    if not _ROTTABS:
        pr = "".join(chr(c) for c in range(33, 127))
        for alpha in (pr, string.digits + string.ascii_uppercase + string.ascii_lowercase, string.ascii_uppercase + string.ascii_lowercase + string.digits):
            for n in range(1, len(alpha)):
                _ROTTABS.append(str.maketrans(alpha, alpha[-n:] + alpha[:-n]))              # decode = shift back by n
    return _ROTTABS


def _crib_decode(t):
    s = t.strip()
    if not len(KNOWN) + 9 <= len(s) <= 260:
        return None
    kl = KNOWN.lower()
    for _key, tab in _affine_tables():
        o = s.translate(tab)
        if o.lower().startswith(kl):
            r = _accept_sentence(o)
            if r:
                return r
    for tab in _rot_tables():
        o = s.translate(tab)
        if o.lower().startswith(kl):
            r = _accept_sentence(o)
            if r:
                return r
    for o in _vig_variants(s):
        r = _accept_sentence(o)
        if r:
            return r
    for _name, o in _transposed_variants(s):
        if o.lower().startswith(kl):
            r = _accept_sentence(o)
            if r:
                return r
    for cand in (s, s[::-1]):
        r = _crib_subst(cand)
        if r:
            return r
    if len(re.findall(r"(?i)[a-z]ay\b", s)) >= 6:
        try:
            return _pig_latin(s)
        except Exception:
            pass
    return None


_PRINTABLE_RE = re.compile(r"[\x20-\x7e\t\r\n]+")


def _printable(s):
    return _PRINTABLE_RE.fullmatch(s) is not None


def _rot13(s):
    return s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                     "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))


class _XorSet(list):
    """Several plaintext readings of ONE binary layer under different single-byte XOR keys (the caller keeps them all; the answer-format check at the end decides)."""


_ENCODED_LOOKING = re.compile(r"[A-Za-z0-9+/=_\-\s]+")
# the characters real text encodings are made of: letters/digits and the separators of percent, HTML entities, \x / \u escapes, 0x/0b prefixes, decimal/octal lists, base64/32/58/62
# alphabets, Python/JS literals (quotes, parentheses, brackets, + for chr(..)+chr(..)). A WRONG xor key turns an encoded layer into text with symbols outside this set (< ? $ ^ * | ~ ` { } @ !).
_ENCODING_ALPHABET = re.compile(r"[A-Za-z0-9 \t\r\n%&#;\\,:.\-_+/=()\[\]'\"]+")


_ALPHABET_BYTES = frozenset(ord(c) for c in (string.ascii_letters + string.digits + " \t\r\n%&#;\\,:.-_+/=()[]'\""))     # the same characters as _ENCODING_ALPHABET above


def _sentence_like(s):
    """Plain English-looking text: at least two spaces and 80% letters/spaces (a legitimate decoded sentence must never be re-read as an XOR layer)."""
    return s.count(" ") >= 2 and sum(c.isalpha() or c == " " for c in s) >= 0.8 * len(s)


def _bitrev8(x):
    return int(format(x, "08b")[::-1], 2)


_BYTE_MAPS = [("bitrev", [_bitrev8(x) for x in range(256)]), ("nibswap", [((x & 15) << 4) | (x >> 4) for x in range(256)])] + \
    [("rol%d" % n, [((x << n) | (x >> (8 - n))) & 255 for x in range(256)]) for n in range(1, 8)] + \
    [("add%d" % k, [(x + k) & 255 for x in range(256)]) for k in range(1, 256)]


def _xor_text(b):
    """Single-byte XOR layer: -> an _XorSet of every key in 1..255 whose result is printable text made ONLY of encoding-alphabet characters, else None. More than one key can qualify
    (flipping a low bit keeps base64 letters printable), so uniqueness cannot be the test (measured 2026-10-10: the unique-key version never fired); the survivors are tried in turn
    and the final slug format settles which one is right. Capped at 8, len >= 16.
    2026-10-15 universe: the same byte-layer test also covers the other keyless byte tricks (bit reversal, nibble swap, rotate-left 1..7, add/subtract a constant, EBCDIC cp037) and a
    repeating-key XOR (period 2..16) read off the KNOWN sentence."""
    if len(b) < 16:
        return None
    distinct = set(b)                                  # a key works iff EVERY distinct byte value maps into the alphabet: test the (few) distinct values, not every byte
    if len(distinct) > len(_ALPHABET_BYTES):           # more distinct bytes than the alphabet has characters: no key can work (this rejects nearly all garbage at once)
        return None
    hits = []
    kb = KNOWN.encode("ascii")
    if len(b) >= len(kb) + 4:                          # KNOWN-prefix crib: the final sentence itself contains characters ('!') outside the encoded-layer alphabet below, so test the keyless byte tricks against the known sentence directly
        tabs = [(k, [x ^ k for x in range(256)]) for k in ((b[0] ^ kb[0]),)] + [(k, [(x + k) & 255 for x in range(256)]) for k in (((kb[0] - b[0]) & 255),)] + [(n, tr) for n, tr in _BYTE_MAPS if not n.startswith("add")]
        for _n, tr in tabs:
            if all(tr[b[i]] == kb[i] for i in range(len(kb))):
                try:
                    hits.append(bytes(tr[x] for x in b).decode("ascii"))
                except UnicodeDecodeError:
                    pass
        try:                                           # EBCDIC (cp037) text
            eb = b.decode("cp037")
            if eb.startswith(KNOWN):
                hits.append(eb)
        except Exception:
            pass
    if len(b) >= len(KNOWN) + 4:                       # repeating-key XOR: the key stream under the KNOWN prefix must repeat with a short period
        stream = [b[i] ^ ord(KNOWN[i]) for i in range(len(KNOWN))]
        for L in range(2, 17):
            if len(set(stream[:L])) > 1 and all(stream[i] == stream[i % L] for i in range(len(stream))):
                try:
                    hits.append(bytes(x ^ stream[i % L] for i, x in enumerate(b)).decode("ascii"))
                except UnicodeDecodeError:
                    pass
                break
    for k in range(1, 256):
        if all((x ^ k) in _ALPHABET_BYTES for x in distinct):
            hits.append(bytes(x ^ k for x in b).decode("ascii"))
    return _XorSet(hits[:64]) if hits else None


_XOR_BUSY = [False]      # set while ranking XOR options, so the lookahead below can never start another XOR scan (no recursion, no blow-up)


def _decodable(s):
    """Can any real decoder (not a letter shift / reversal / plain) turn `s` into printable text? Used to decide whether a printable layer is a genuine encoded layer or XOR junk:
    XOR 0x5a turns the characters 0, 1 and space into j, k and z, which looks like clean letters but no decoder can read it (measured 2026-10-10: the alphabet test alone missed
    spaced-binary / decimal-list / octal text under XOR). Runs with XOR disabled, so it cannot recurse."""
    was = _XOR_BUSY[0]
    _XOR_BUSY[0] = True
    try:
        for name, _out in candidates(s):
            if name == "plain" or name in ("reverse", "rot13", "rot47", "atbash") or name.startswith("caesar"):
                continue
            return True
        return False
    finally:
        _XOR_BUSY[0] = was


def _rank_xor(opts):
    """Several keys keep an encoded layer inside the encoding alphabet (the characters alone cannot tell them apart: XOR is a bijection), so rank the options by a ONE-STEP LOOKAHEAD:
    does a real decoder turn the option into text with known words / a slug? Best 8 returned; options with no signal keep key order (a deeper stack is settled by the final slug check)."""
    if len(opts) <= 1 or _XOR_BUSY[0]:
        return list(opts)[:8]
    _XOR_BUSY[0] = True
    try:
        scored = []
        for i, o in enumerate(opts):
            q = 0
            if KNOWN.lower() in o.lower():            # the option already IS the known sentence (a keyless byte trick / repeating-key XOR read off the crib): decisive
                scored.append((-20, i, o))
                break
            for name, out in candidates(o):
                if name == "plain" or name in ("reverse", "rot13", "rot47", "atbash") or name.startswith("caesar"):
                    continue
                q = max(q, _score(out) + (2 if KNOWN in out else 0))
            scored.append((-q, i, o))
            if q >= 10:                      # an option that decodes to the known sentence is decisive: stop scanning the remaining keys
                break
        scored.sort()
        return [o for _, _, o in scored[:8]]
    finally:
        _XOR_BUSY[0] = False


def _magic(b):
    """Compression container magic: gzip, zlib (all levels), bzip2, xz."""
    return (b[:2] == b"\x1f\x8b" or b[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda") or b[:3] == b"BZh" or b[:6] == b"\xfd7zXZ\x00"
            or b[:4] == b"\x28\xb5\x2f\xfd" or b[:4] == b"\x04\x22\x4d\x18")           # + zstd and lz4-frame magic


_EXTRA_DECOMP = None


def _extra_decompressors():
    """zstd / lz4 / brotli, only the ones installed (all optional). Probed once per process: a failed import is not cached by Python,
    so probing on every call re-searched sys.path ~400 times per Time Trial (1.65 s of 1.82 s on /mnt/c). Callers only concatenate."""
    global _EXTRA_DECOMP
    if _EXTRA_DECOMP is None:
        _EXTRA_DECOMP = _probe_extra_decompressors()
    return list(_EXTRA_DECOMP)


def _probe_extra_decompressors():
    fns = []
    try:
        import zstandard
        fns.append(lambda b: zstandard.ZstdDecompressor().decompress(b))
    except Exception:
        pass
    try:
        import lz4.frame
        fns.append(lambda b: lz4.frame.decompress(b))
    except Exception:
        pass
    try:
        import brotli
        fns.append(lambda b: brotli.decompress(b))
    except Exception:
        pass
    return fns


def _decompress(text, blind=False):
    """-> decompressed text (or None) for a layer whose bytes (latin-1 view) start with a compression magic. blind=True also tries the magic-less raw deflate and brotli streams, but only
    accepts a result that is clean printable text (a magic-less guess must never turn junk into a layer)."""
    import bz2, gzip, lzma, zlib
    try:
        b = text.encode("latin-1")
    except UnicodeEncodeError:
        return None
    # Dispatch by the container signature. Trying gzip/zlib/bzip2/xz in
    # sequence on every compressed layer is wasted work and can dominate tiny
    # Warmups payloads.
    if b[:2] == b"\x1f\x8b":
        fns = [gzip.decompress]
    elif b[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
        fns = [zlib.decompress]
    elif b[:3] == b"BZh":
        fns = [bz2.decompress]
    elif b[:6] == b"\xfd7zXZ\x00":
        fns = [lzma.decompress]
    elif b[:4] in (b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18"):
        fns = _extra_decompressors()[:2]
    else:
        fns = []
    if not fns and blind and len(b) >= 8 and not _printable(text):
        fns = [lambda x: zlib.decompress(x, -15)] + _extra_decompressors()
    for fn in fns:
        try:
            out = fn(b)
        except Exception:
            continue
        for enc in ("utf-8", "latin-1"):
            try:
                o = out.decode(enc)
            except UnicodeDecodeError:
                continue
            if not blind or _printable(o):
                return o
            break
    return None


def _try(fn):
    try:
        r = fn()
        if isinstance(r, _XorSet):                                     # several byte readings already (zero-width / whitespace binary): the caller ranks them
            return r
        raw = r if isinstance(r, bytes) else None                      # kept: a binary layer that is valid ASCII but not printable can still be a single-byte XOR over encoded text
        if isinstance(r, bytes):
            # UTF-16 text (a BOM, or an ASCII sentence with a NUL between every character) is a common wrapper around base64 / hex. NUL is itself valid ASCII, so this MUST be tried
            # before the ASCII decode (found 2026-10-10: the ASCII decode 'succeeded' with NULs and the printable check then threw the text away).
            if len(r) >= 8 and len(r) % 4 == 0 and r.count(0) * 4 >= len(r) * 3 - 3 and (r[1:4] == b"\x00\x00\x00" or r[:3] == b"\x00\x00\x00"):
                r = r.decode("utf-32-le" if r[1:4] == b"\x00\x00\x00" else "utf-32-be")              # UTF-32 (3 of every 4 bytes are NUL)
            elif r[:2] in (b"\xff\xfe", b"\xfe\xff"):
                r = r.decode("utf-16")
            elif len(r) >= 4 and r.count(0) * 3 >= len(r):
                r = r.decode("utf-16-le" if r[1:2] == b"\x00" else "utf-16-be")
            else:
                try:
                    r = r.decode("ascii")
                except UnicodeDecodeError:
                    # a COMPRESSED layer (gzip / zlib / bzip2 / xz) is binary but is still a layer: keep it (as latin-1, lossless) so peel() can decompress it next
                    if _magic(r):
                        return r.decode("latin-1")
                    dz = _decompress(r.decode("latin-1"), blind=True)        # magic-less raw deflate / brotli (accepted only as clean printable text)
                    if dz is not None:
                        return dz
                    return _xor_text(r)            # a single-byte XOR layer: the only key that turns binary into clean printable text
        if raw is not None and isinstance(r, str) and len(raw) >= 16 and not _XOR_BUSY[0] and not _sentence_like(r) and not _decodable(r):
            # decoded as ASCII but it is neither clean encoded text nor a sentence: control bytes, OR printable junk (hex text XORed with 0x5a is still printable): the XOR reading
            x = _xor_text(raw)
            if x is not None:
                # ADD the XOR readings, never substitute them for the direct reading: a fragment that decodes straight to the answer slug is 'not decodable further' too, and replacing
                # it with key candidates lost the answer (D04 / D07 mastery regression, found 2026-10-10 by _test_autosolve_warmups.py)
                return _XorSet(([r] if _printable(r) else []) + list(x))
        return r if _printable(r) else None
    except Exception:
        return None


def candidates(frag):
    """All plausible decodings of one fragment (most charset-specific first). Whitespace inside the fragment is preserved."""
    s = frag.strip("\r\n")
    t = s.strip()
    c = re.sub(r"\s", "", t)
    out = []

    def add(name, fn):
        r = _try(fn)
        if isinstance(r, _XorSet):
            for i, x in enumerate(_rank_xor(r)):
                if (name + "+xor", x) not in out:
                    out.append((name + "+xor", x))
        elif r is not None and (name, r) not in out:
            out.append((name, r))
    if t:
        rl = _runlength_pairs(t)
        if rl:
            add("runlength", lambda: rl)
        if "%" in t and re.search(r"%[0-9A-Fa-f]{2}", t):
            add("percent", lambda: urllib.parse.unquote(t, errors="strict"))
            if "%25" in t:                                                     # double URL encoding (%2570 -> %70 -> p)
                add("percent-twice", lambda: urllib.parse.unquote(urllib.parse.unquote(t, errors="strict"), errors="strict"))
        tb = re.sub(r"(?i)0b|_", "", t)            # 0b-prefixed and underscore-grouped binary are the same encoding
        if re.fullmatch(r"[01]+(?:\s+[01]+)*", tb):
            cb = re.sub(r"\s", "", tb)
            toks = tb.split() if " " in tb else [cb[i:i + 8] for i in range(0, len(cb), 8)]
            if all(len(x) == 8 for x in toks):
                add("binary", lambda: bytes(int(x, 2) for x in toks))
                if len(toks) <= 24:                                                              # short fragments only: a long blob gets the same readings from the byte-layer test (_xor_text)
                    add("binary(inverted)", lambda: bytes(int(x, 2) ^ 255 for x in toks))       # NOT of every byte
                    add("binary(lsb-first)", lambda: bytes(int(x[::-1], 2) for x in toks))     # bits written least-significant first
            elif len(toks) >= 4 and all(len(x) == 7 for x in toks):          # 7-bit ASCII groups
                add("binary7", lambda: bytes(int(x, 2) for x in toks))
        if re.fullmatch(r"[0-7]{3}(?:\s+[0-7]{3})*", t):
            add("octal", lambda: bytes(int(x, 8) for x in t.split()))
        if re.search(r"(?i)\b0o[0-7]{1,3}\b", t):                          # 0o116 0o151 ... (Python style prefix)
            add("octal(0o)", lambda: bytes(int(x, 8) for x in re.findall(r"(?i)0o([0-7]{1,3})", t)))
        if re.search(r"(?m)^\s*[0-9a-fA-F]{4,8}:?\s+[0-9a-fA-F]{2}", t):  # hexdump -C / xxd
            add("hexdump", lambda: _hexdump(t))
        tn = t.strip("[](){};")                    # a bracketed list of byte values ([78, 105, ...]) is the same encoding
        if re.fullmatch(r"\d{1,3}(?:[\s,;|/.\-]+\d{1,3})*", tn):       # + the other common separators (semicolon, pipe, slash, dot, hyphen)
            nums = [int(x) for x in re.split(r"[\s,;|/.\-]+", tn)]
            if max(nums) < 256:
                add("decimal", lambda: bytes(nums))
        if re.fullmatch(r"[0-9a-fA-F]+", c) and len(c) % 2 == 0:
            add("hex", lambda: binascii.unhexlify(c))
        hs = re.sub(r"(?i)0x|\\x|[\s,:;\-.|/]", "", t)  # 0x4e,0x69 / \x4e\x69 / 4e:69 / 4e-69 / 4e.69 / 4e|69 / 4e/69: hex with separators or prefixes
        if hs != c and re.fullmatch(r"[0-9a-fA-F]+", hs) and len(hs) % 2 == 0 and re.search(r"[,:;\-.|/]|0x|\\x", t, re.I):
            add("hex(sep)", lambda: binascii.unhexlify(hs))
        c64 = c.rstrip("=")                                                 # padding is optional: base64 without '=' is as common as with it
        if len(c64) >= 4 and len(c64) % 4 != 1:
            padded = c64 + "=" * (-len(c64) % 4)
            if re.fullmatch(r"[A-Za-z0-9+/]+", c64):
                add("base64", lambda: base64.b64decode(padded, validate=True))
            if re.fullmatch(r"[A-Za-z0-9_\-]+", c64):
                add("base64url", lambda: base64.urlsafe_b64decode(padded))
        qm = re.fullmatch(r"(?s)[bBrRuU]?(['\"])(.*)\1", t)                # 'text' / b'text' / "text": the quotes are a wrapper, the content is the next layer
        if qm and len(qm.group(2)) >= 4:
            add("unquote", lambda: qm.group(2))
        if len(c) % 5 == 0 and len(c) >= 10 and all(ch in Z85 for ch in c):
            add("z85", lambda: _z85(c))
        if re.fullmatch(r"[A-Za-z2-7]+=*", c) and len(c) >= 8:          # any case, with or without padding (Day 10 shipped the padded uppercase form)
            cu = c.upper().rstrip("=")
            cu += "=" * (-len(cu) % 8)
            add("base32", lambda: base64.b32decode(cu))
        if re.fullmatch(r"[0-9A-Va-v]+=*", c) and len(c) >= 8 and hasattr(base64, "b32hexdecode"):   # RFC 4648 extended-hex alphabet
            cv = c.upper().rstrip("=")
            cv += "=" * (-len(cv) % 8)
            add("base32hex", lambda: base64.b32hexdecode(cv))
        for name, fn in (("ascii85", lambda: base64.a85decode(t[2:-2] if t.startswith("<~") else t)), ("base85", lambda: base64.b85decode(t))):
            if len(t) >= 5:
                add(name, fn)
        if len(c) >= 8 and set(c) <= _BF_CHARS and "." in c and any(ch in c for ch in "+<>[]"):   # brainfuck: every non-whitespace char is a command, output exists, and a '+'/'<'/'>'/'[' rules out pure morse (.-/)
            add("brainfuck", lambda: _brainfuck(s))
        # D27 audit §7 (user directive 2026-10-27): Ook! esolang per-fragment candidate.
        # Agent-3 added this to the per-CID working copy for Day 27 Monkey Business and the
        # Mastery blobs' line 27 is pure Ook; porting it into the shared adapter so the
        # NEXT Ook-family warmup lands with the decoder already in place (not another HELD).
        # Full doc on the pair-mapping lives next to _ook() below. Cheap predicate: tokens
        # are only Ook./Ook?/Ook! and whitespace, with at least 4 tokens so a single stray
        # 'Ook' word in prose doesn't trigger.
        if "Ook" in t and re.fullmatch(r"(?:Ook[.?!]|\s)+", t) and len(re.findall(r"Ook[.?!]", t)) >= 4:
            add("ook", lambda: _ook(s))
        if re.fullmatch(r"[.\-/|\s]+", t) and re.search(r"[.\-]", t):
            add("morse", lambda: _morse(s))
        if re.search(r"=[0-9A-Fa-f]{2}", t):
            add("quoted-printable", lambda: quopri.decodestring(t.encode("latin-1")))
        if re.search(r"\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}|\\[0-7]{3}|\\U[0-9A-Fa-f]{8}|\\N\{", t):
            # D09: each \u fragment is a JSON-quoted string ("c..."): drop the wrapping quotes
            u = t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'" else t
            add("unicode-escape", lambda: u.encode("latin-1").decode("unicode_escape"))
        if re.search(r"\\u\{[0-9A-Fa-f]+\}", t):                           # ES6 code-point escapes
            add("u-brace", lambda: re.sub(r"\\u\{([0-9A-Fa-f]+)\}", lambda m: chr(int(m.group(1), 16)), t))
        if re.search(r"U\+[0-9A-Fa-f]{4,6}", t):                            # U+004E notation
            add("U+", lambda: "".join(chr(int(h, 16)) for h in re.findall(r"U\+([0-9A-Fa-f]{4,6})", t)))
        if re.search(r"fromCharCode|\bchr\s*\(|\bord\s*\(|\bbytes\s*\(\s*\[", t):   # String.fromCharCode(78,105,...) / chr(78)+chr(105)+...
            add("charcode-call", lambda: "".join(chr(n) for n in [int(x) for x in re.findall(r"(?<![\w.])\d{1,6}(?![\w.])", t)]))
        if re.fullmatch(r"[A-Za-z/|\s\-]+", t) and len(t.split()) >= 6:      # NATO phonetic words
            add("nato", lambda: _nato(t))
        if t[:1] in "{[" and len(t) >= 12:                                   # {"data": "<encoded>"}: each long string value is a new layer
            try:
                for i, sv in enumerate(_json_strings(t)):
                    add("json-string%d" % i, lambda sv=sv: sv)
            except Exception:
                pass
        dm = re.match(r"(?is)data:[^,;]*(;base64)?,(.*)", t)               # data:text/plain;base64,<payload> / data:,<percent-encoded>
        if dm:
            add("data-uri", (lambda: base64.b64decode(re.sub(r"\s", "", dm.group(2)) + "=" * (-len(re.sub(r"\s", "", dm.group(2))) % 4))) if dm.group(1)
                else (lambda: urllib.parse.unquote(dm.group(2))))
        if re.search(r"&#\d+;|&#[xX][0-9A-Fa-f]+;|&[a-zA-Z]+;", t):
            add("html-entities", lambda: html.unescape(t).replace("\xa0", " "))      # &nbsp; is a space; the printable check would otherwise reject the whole layer
        if t.startswith("begin ") or re.fullmatch(r"[ -`]+(?:\n[ -`]+)*", s.strip("\r\n")):
            add("uuencode", lambda: _uu(s))
        if len(c) >= 8 and len(c) <= BIGINT_MAX:
            if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", c):
                add("base58", lambda: DC._b58(c))
            if re.fullmatch(r"[0-9A-Za-z]+", c):
                add("base36", lambda: (lambda n: n.to_bytes((n.bit_length() + 7) // 8, "big"))(int(c, 36)))
                add("base62", lambda: DC._b62(c, string.digits + string.ascii_uppercase + string.ascii_lowercase))
                add("base62(alt)", lambda: DC._b62(c, string.ascii_uppercase + string.ascii_lowercase + string.digits))
            if all(ch in B91 for ch in c):
                add("base91", lambda: _b91(c))
        if re.fullmatch(r"[0-9A-Z $%*+\-./:]+", t) and len(t) >= 6:
            add("base45", lambda: DC._b45(t))
    if not _XOR_BUSY[0]:      # the 2026-10-15 universe extensions (see _more_candidates); skipped inside the XOR lookahead so the XOR-junk test above is unchanged
        _more_candidates(add, s, t, c)
    if not _XOR_BUSY[0] and not _NOROT[0]:      # the XOR lookahead ignores letter shifts and reversals anyway (see _decodable/_rank_xor), and they are ~30 of the ~45 decoders: skipping them is a 3x speedup there
        add("rot13", lambda: _rot13(s))
        add("atbash", lambda: DC._atbash(s))
        add("rot47", lambda: DC._rot47(s))
        for k in range(1, 26):
            if k != 13:
                add("caesar%d" % k, lambda k=k: DC._rot(s, k))
    add("plain", lambda: s)
    if not _XOR_BUSY[0] and not _NOROT[0]:
        add("reverse", lambda: s[::-1])
    return out


_NOROT = [False]        # set by _decodes_better: its lookahead discards every letter-shift / reversal reading anyway, so computing them (about 30 of ~70 decoders) is pure waste


def _known_ok(text):
    # case-insensitive: morse cannot carry letter case, so a morse fragment decodes the sentence in lowercase
    low, kl = text.lower(), KNOWN.lower()
    if len(text) <= len(KNOWN):
        return kl.startswith(low)
    return low.startswith(kl) and re.fullmatch(r"[a-z0-9-]*", low[len(KNOWN):]) is not None


def _words(text):
    low = text.lower()
    return sum(w in low for w in WORDS)


def _score(text):
    return _words(text) + (3 if SLUG.search(text) else 0)


def _decodes_better(r, base):
    """One-step lookahead for a letter-shift / reversal: does any real decoder turn `r` into text that reads better than `base` (known words, or a slug)?"""
    if len(r) < 8:
        return False
    was = _NOROT[0]
    _NOROT[0] = True
    try:
        for name, out in candidates(r):
            if name in ("plain", "reverse", "rot13", "rot47", "atbash", "lower", "swapcase") or name.startswith("caesar"):
                continue
            if _score(out) > base or KNOWN in out:
                return True
    finally:
        _NOROT[0] = was
    return False


def decode_fragments(lines, strict_tail=False):
    """lines: list of fragment strings in line-number order -> best concatenated plaintext.
    strict_tail=True (decode_blob's numbered-line fallback, 2026-10-15): in the slug region the known sentence no longer constrains a fragment, and every letter shift / reversal / case change keeps it
    slug-shaped, so the first one tried would be returned as a confidently WRONG slug (measured: an unknown Caesar+3 on a new last line came back as 'suhhs-wustle-ofqb-96'). Those readings are skipped there."""
    cands = [candidates(f) for f in lines]
    res = []

    def dfs(i, acc):
        if res:
            return
        if i == len(cands):
            low = acc.lower()
            if low.startswith(KNOWN.lower()) and SLUG.search(low[len(KNOWN):]):
                res.append(acc)
            return
        for nm, r in cands[i]:
            if strict_tail and len(acc) >= len(KNOWN) and (nm in _SUBST_NAMES or nm.startswith("caesar")):
                continue
            nxt = acc + r
            if _known_ok(nxt):
                dfs(i + 1, nxt)
    dfs(0, "")
    if res:
        return res[0]
    # the sentence changed: greedy best-readable per fragment, preferring the most specific decoder that reads well
    best = ""
    for cs in cands:
        if not cs:
            return None
        best += max(cs, key=lambda nr: (_score(best + nr[1]) - _score(best), -cs.index(nr)))[1]
    return best


def _runlength_pairs(t):
    """Day 24 String Theory: '<count>:<char>' tokens joined by commas, where <char> may itself be a comma ('1:,'), so a plain split(',') misreads it. Parsed token by token; the WHOLE text must parse, else None."""
    if not re.match(r"\d+:", t):
        return None
    pos, parts = 0, []
    while pos < len(t):
        m = re.compile(r"(\d+):(.)", re.S).match(t, pos)
        if not m:
            return None
        parts.append(m.group(2) * int(m.group(1)))
        pos = m.end()
        if pos < len(t):
            if t[pos] != ",":
                return None
            pos += 1
    return "".join(parts)


def _direct_layers(text):
    """Cheap, strict one-layer decoders ahead of the broad transformation catalog."""
    t = text.strip()
    out = []
    raw = t.encode("latin-1", "ignore")
    if _magic(raw):
        dz = _decompress(t)
        if dz is not None:
            out.append(("magic", dz))
    rl = _runlength_pairs(t)
    if rl:
        out.append(("runlength", rl))
    if re.fullmatch(r"[abAB]{5}(?:\s+[abAB]{5}){3,}", t):          # D17 single message: only a/b 5-letter groups; a/b are also hex digits, so this must run before the hex layer
        try:
            out.append(("baconhex", _baconhex(t)))
        except Exception:
            pass
    compact = re.sub(r"\s", "", t)
    if len(compact) >= 4 and len(compact) % 4 != 1 and re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        try:
            out.append(("base64", _as_text(base64.b64decode(compact + "=" * (-len(compact) % 4), altchars=b"-_", validate=True))))
        except Exception:
            pass
    if len(compact) >= 2 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
        try:
            out.append(("hex", _as_text(bytes.fromhex(compact))))
        except Exception:
            pass
    if re.search(r"%[0-9A-Fa-f]{2}", t):
        try:
            out.append(("percent", urllib.parse.unquote(t, errors="strict")))
        except Exception:
            pass
    if re.search(r"&#\d+;|&#[xX][0-9A-Fa-f]+;|&[a-zA-Z]+;", t):
        out.append(("html", html.unescape(t).replace("\xa0", " ")))
    unique, seen = [], set()
    for name, value in out:
        if value and value != text and value not in seen:
            seen.add(value)
            unique.append((name, value))
    return unique


def _answer_shaped(text):
    t = text.strip()
    return bool(SLUG.fullmatch(t) or re.fullmatch(r"ANS-[0-9A-F]{16}", t) or re.fullmatch(r"(?:flag|huntress|ctf)\{[^}\s]{3,80}\}", t, re.I))


def peel(data, depth=14):
    """Bounded best-first layer search with content-hash deduplication."""
    t_start = time.monotonic()
    text = _as_text(data)

    def key(value):
        return hashlib.sha256(value.encode("utf-8", "surrogatepass")).digest()

    for _name, direct in _direct_layers(text):
        if _answer_shaped(direct):
            return direct.strip()
        if KNOWN.lower() in direct.lower():
            return direct

    readable = []
    seen = {key(text)}
    serial = 0
    queue = [(-_score(text), 0, serial, text)]
    frontier = [text]
    expanded = 0
    max_nodes = max(24, min(192, max(1, depth) * 12))
    while queue and expanded < max_nodes and time.monotonic() - t_start < 1.25:
        _rank, level, _seq, t = heapq.heappop(queue)
        frontier.append(t)
        if level >= depth:
            continue
        expanded += 1
        if KNOWN in t:
            return t
        cr = _crib_decode(t)
        if cr:
            return cr
        if SLUG.search(_final_line(t)) and _words(t) >= 2:
            if _spells_known(t):
                return t
            if _wwords(t) >= 4:
                readable.append(t)
        dz = _decompress(t)
        if dz is None and not _magic(t.encode("latin-1", "ignore")):
            dz = _decompress(t, blind=True)
        children = [("compressed", dz)] if dz is not None and dz != t else []
        for name, child in candidates(t):
            if name == "plain" or child == t:
                continue
            rotlike = name in ("reverse", "rot13", "rot47", "atbash") or name.startswith("caesar")
            if rotlike and _score(child) <= _score(t) and not _decodes_better(child, _score(t)):
                continue
            children.append((name, child))
        children.sort(key=lambda pair: (KNOWN.lower() in pair[1].lower(), _score(pair[1]), SLUG.search(pair[1]) is not None), reverse=True)
        for _name, child in children[:12]:
            fingerprint = key(child)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            if _answer_shaped(child):
                return child.strip()
            serial += 1
            heapq.heappush(queue, (-_score(child), level + 1, serial, child))
    frontier = sorted({node[3] for node in queue} | set(frontier[-12:]), key=_score, reverse=True)[:12]
    for t in frontier:
        if SLUG.search(t) and (SLUG.fullmatch(t.strip()) or _wwords(t) >= (1 if t == text else 2)):
            return t
    if time.monotonic() - t_start < 1.25:
        w = _wrapped_lookahead(text)
        if w:
            return w
    if readable:
        return readable[0]
    if time.monotonic() - t_start < 1.25 and len(data) <= 6000:
        for _, _, b in DC.best_chains(data if isinstance(data, bytes) else data.encode("utf-8", "replace"), depth=8, top=5):
            t = b.decode("latin-1", "ignore")
            if (SLUG.search(t) and (SLUG.fullmatch(t.strip()) or _wwords(t) >= 2)) or DC.ANS.fullmatch(t.strip()) or DC.FLAG.fullmatch(t.strip()):
                return t
    return None


_KNOWN_LETTERS = re.sub(r"[^a-z]", "", KNOWN.lower())
_WHOLE_WORDS = frozenset(("the", "this", "and", "work", "warmup", "solve", "submit", "answer", "exact", "game", "master", "nice", "to", "decoding", "decode", "your", "you", "for", "is", "of", "congratulations"))


def _wwords(t):
    """How many distinct known/common words occur as WHOLE words (not substrings): real English scores, 'answerway' / 'decod1ng' do not."""
    return len(_WHOLE_WORDS & set(re.findall(r"[a-z]+", t.lower())))


def _spells_known(t):
    """Does the text spell the known sentence, ignoring case, punctuation and spacing? (morse / NATO / tap-code style decodes drop exactly those.)"""
    return re.sub(r"[^a-z]", "", t.lower()).startswith(_KNOWN_LETTERS)


def _as_text(data):
    """The layer text of a blob: UTF-8 if it is valid non-ASCII UTF-8 (base100, braille, fullwidth ...), UTF-8-BOM / UTF-16 / UTF-32 text files, else latin-1 (lossless for binary)."""
    if not isinstance(data, bytes):
        return data
    if data[:3] == b"\xef\xbb\xbf":
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError:
            pass
    if data[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff") or data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        for enc in ("utf-32", "utf-16"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
    if any(b > 127 for b in data):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1")


def _wrapped_lookahead(text):
    """Last resort before the generic beam: an affine / rail-fence / scytale / word-reversal layer around an encoded blob cannot be recognised by its own output (every permutation of a base64 string
    is base64-shaped), so test each candidate by whether a REAL decoder then turns it into the KNOWN sentence. Cheap (XOR-busy mode skips the letter-shift decoders) and only reached on a miss."""
    s = text.strip()
    if len(s) < 16 or len(s) > 6000 or _XOR_BUSY[0]:
        return None
    if len(s) / max(1, len(s.split())) < 12 and "\n" not in s:                  # only a BLOB-shaped layer (long unbroken tokens: base64 / hex / base32 ...) is worth it; words, spaced lists and morse are not
        return None
    variants = ((("affine", k), s.translate(tab)) for k, tab in _affine_tables())
    _XOR_BUSY[0] = True
    try:
        for _name, r in list(variants) + [(n, v) for n, v in _transposed_variants(s)]:
            if r == s:
                continue
            for name, out in candidates(r):
                if name == "plain":
                    continue
                if KNOWN in out or (SLUG.fullmatch(out.strip()) is not None and _words(out) >= 2):
                    return out
                for n2, o2 in candidates(out):                                 # one more layer (base64 of hex ...) is common enough to try
                    if n2 != "plain" and KNOWN in o2:
                        return o2
    finally:
        _XOR_BUSY[0] = False
    return None


def _final_line(text):
    lines = [l for l in (text or "").splitlines() if l.strip()]
    return lines[-1] if lines else ""


def _pad(s, n):
    s = s.strip()
    return s + "=" * (-len(s) % n)


# Day 13 (Opposite Day mastery, 2026-10-13): 13 numbered lines per blob, the encoding FIXED BY LINE NUMBER. The search in decode_fragments missed it, fell to the greedy guess and submitted a
# half-decoded slug twice (+10.8 s, +64.8 s; the agent solved it from the bytes at +177 s). Tried FIRST, accepted ONLY when the whole text passes the sentence oracle, so a different layout is untouched.
_ATB = str.maketrans(string.ascii_lowercase + string.ascii_uppercase, string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1])
POSITIONAL_D13 = (
    lambda s: base64.b64decode(_pad(s, 4)).decode("ascii"),
    lambda s: s.translate(str.maketrans(string.ascii_lowercase + string.ascii_uppercase,
                                        string.ascii_lowercase[13:] + string.ascii_lowercase[:13] + string.ascii_uppercase[13:] + string.ascii_uppercase[:13])),
    lambda s: bytes.fromhex(s.strip()).decode("ascii"),
    lambda s: "".join(chr(int(t, 2)) for t in s.split()),
    lambda s: "".join(chr(int(t)) for t in s.split()),
    lambda s: "".join(chr(int(t, 8)) for t in s.split()),
    lambda s: urllib.parse.unquote(s),
    lambda s: html.unescape(s),
    lambda s: json.loads(s.strip()),
    lambda s: base64.b32decode(_pad(s.upper(), 8)).decode("ascii"),
    lambda s: base64.urlsafe_b64decode(_pad(s, 4)).decode("ascii"),
    lambda s: s[::-1],
    lambda s: s.translate(_ATB),
)


# Day 14 (Seven Steps mastery, 2026-10-14): the Day 13 thirteen lines plus a 14th = Caesar shift of 7 (encoded +7, decode -7). Found from the real bytes after the generic search
# picked wrong shifts and submitted gibberish slugs.
def _caesar_back7(s):
    lo, up = string.ascii_lowercase, string.ascii_uppercase
    return s.translate(str.maketrans(lo + up, lo[-7:] + lo[:-7] + up[-7:] + up[:-7]))


POSITIONAL_D14 = POSITIONAL_D13 + (_caesar_back7,)


# SELF-EXTENDING positional decode (2026-10-14): the mastery family is N numbered lines, one fixed encoding per line, concatenating to the KNOWN sentence + slug. The ladder only GROWS (D13 13 lines, D14 +caesar7 = 14),
# and hardcoding the exact length is why Day 14's 14-line blobs fell through to the generic search and a GIBBERISH slug got submitted. Instead, decode GUIDED by the known target: for each line try every decoder in the
# pool and keep the chunk that keeps the running text a prefix of KNOWN (slug-charset once past it). A new encoding appended on any line then solves with NO code change, as long as its decoder is in the pool. Accept
# ONLY a result that starts with KNOWN and ends in a slug - never a shape-only guess.
def _caesar_dec(n):                                    # decode a Caesar encoded by +n (shift letters back by n)
    lo, up = string.ascii_lowercase, string.ascii_uppercase
    return lambda s: s.translate(str.maketrans(lo + up, lo[-n % 26:] + lo[:-n % 26] + up[-n % 26:] + up[:-n % 26]))


def _jsonu_dec(s):
    t = s.strip()
    return json.loads(t) if t[:1] == '"' else json.loads('"' + t + '"')


LINE_DECODERS = {                                      # name -> callable(str)->str, tried per line and chosen by the known-target guide
    "base64": lambda s: base64.b64decode(_pad(s, 4)).decode("ascii"),
    "rot13": _caesar_dec(13),
    "hex": lambda s: bytes.fromhex(s.strip()).decode("ascii"),
    "binary": lambda s: "".join(chr(int(t, 2)) for t in s.split()),
    "decimal": lambda s: "".join(chr(int(t)) for t in s.split()),
    "octal": lambda s: "".join(chr(int(t, 8)) for t in s.split()),
    "percent": lambda s: urllib.parse.unquote(s),
    "html": lambda s: html.unescape(s),
    "jsonu": _jsonu_dec,
    "base32": lambda s: base64.b32decode(_pad(s.upper(), 8)).decode("ascii"),
    "base64url": lambda s: base64.urlsafe_b64decode(_pad(s, 4)).decode("ascii"),
    "reverse": lambda s: s[::-1],
    "atbash": lambda s: s.translate(_ATB),
    "base85": lambda s: base64.b85decode(s.strip()).decode("ascii"),
    "ascii85": lambda s: base64.a85decode(s.strip()).decode("ascii"),
}
LINE_DECODERS.update({"caesar%d" % n: _caesar_dec(n) for n in range(1, 26)})   # caesar+1..+25 (covers the Day 14 caesar+7 and any future shift)


def _as_str(fn):                                       # wrap a bytes-returning module decoder for the per-line string pool
    def g(s):
        r = fn(s)
        return r.decode("ascii") if isinstance(r, (bytes, bytearray)) else r
    return g


LINE_DECODERS.update({                                 # the rest of the warmups encoding family, so a numbered blob mixing ANY of these decodes under the known-sentence guide (2026-10-14: be ready for the whole family, not just the ladder)
    "morse": _morse, "nato": _nato, "z85": _as_str(_z85), "b91": _as_str(_b91), "uuencode": _as_str(_uu),
    "quopri": lambda s: quopri.decodestring(s.encode()).decode("ascii"),
    "xesc": lambda s: s.encode().decode("unicode_escape"),
})
try:                                                   # TARGETED PRE-BUILD (2026-10-14): the predictive flagged base58/62/45 as warmups candidates and they were the only real gaps; REUSE decode_chain's vetted decoders
    _B62A = string.digits + string.ascii_uppercase + string.ascii_lowercase
    LINE_DECODERS.update({
        "base58": lambda s: DC._b58(s).decode("ascii"),
        "base62": lambda s: DC._b62(s, _B62A).decode("ascii"),
        "base62alt": lambda s: DC._b62(s, string.ascii_uppercase + string.ascii_lowercase + string.digits).decode("ascii"),
        "base45": lambda s: DC._b45(s).decode("ascii"),
    })
except Exception:                                      # decode_chain shape changed: skip the extras, the core pool still works
    pass
LINE_DECODERS["rot47"] = lambda s: "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)   # D15 (Room Forty-Seven mastery): 15th line = ROT47 appended to the D14 ladder
LINE_DECODERS["morsehex"] = lambda s: bytes.fromhex(re.sub(r"\s+", "", _morse(s))).decode("ascii")   # D16 (Dot Com mastery): 16th line = Morse spelling hex bytes; lines 1-15 are the D15 ladder (line 14 caesar7)
def _baconhex(s):                                      # D17 (Bacon Bits): 5-letter a/b groups -> 0..15 nibbles (Baconian value, letters A..P) -> two nibbles per byte
    v = [int(g.lower().replace("a", "0").replace("b", "1"), 2) for g in s.split()]
    if len(v) % 2 or any(x > 15 for x in v):
        raise ValueError("not baconhex")
    return bytes(v[i] * 16 + v[i + 1] for i in range(0, len(v), 2)).decode("ascii")


LINE_DECODERS["baconhex"] = _baconhex                  # D17 (Bacon Bits mastery): 17th line = Baconian a/b groups spelling hex nibbles; lines 1-16 are the D16 ladder
LINE_DECODERS["rail3"] = lambda s: _rail_dec(s, 3)         # D18 (Off the Rails mastery): 18th line = 3-rail rail-fence on the final slug tail; lines 1-17 are the D17 ladder
def _utf16hex(s):                                      # D21 (Under Pressure mastery): lines 19/20 = hex of UTF-16 text led by a BOM (fffe = LE, feff = BE); the BOM picks the byte order
    b = bytes.fromhex(re.sub(r"\s+", "", s))
    if b[:2] not in (b"\xff\xfe", b"\xfe\xff"):
        raise ValueError("no UTF-16 BOM")
    return b.decode("utf-16")


def _gzipb64(s):                                       # D21: line 21 = base64 of a gzip stream holding the slug tail
    import base64 as _b64, gzip as _gz
    return _gz.decompress(_b64.b64decode(s.split()[0])).decode("ascii")


# D28 (Back in Sixteen mastery, 2026-10-28): rows 22-28 add zlib-b64, Adobe ASCII85, RLE "N:C,", U+hex, Brainfuck, Ook!, reversed-hex;
# row 18 in this specific blob is literal plaintext (an identity decoder) rather than the Day 18 rail3. Each helper is pure, bounded,
# raises on malformed input (never returns silent garbage). ASCII-only source (chr()/escapes); never executes bytes from an artifact.
def _zlibb64(s):                                       # base64 of a zlib stream; mirrors _gzipb64 for zlib (header starts 0x78... = "eN..." / "eJ..." in b64)
    import base64 as _b64, zlib as _zl
    return _zl.decompress(_b64.b64decode(s.split()[0])).decode("ascii")


def _ascii85adobe(s):                                  # Adobe ASCII85 with <~...~> framing optional; whitespace tolerated
    return base64.a85decode(s.strip().encode("ascii"), adobe=True).decode("ascii")


_RLE_PAIR = re.compile(r"(\d+):([^,]),")


def _rle_colon(s):                                     # D28 row 24: "N:C," runs. 'count:character,' repeated. Must match the WHOLE string.
    pairs = _RLE_PAIR.findall(s)
    if not pairs:
        raise ValueError("not RLE N:C,")
    # verify the whole string is covered (every match consumed contiguously); a stray trailing comma is OK but junk is not
    joined = "".join("%s:%s," % p for p in pairs)
    if joined != s and joined.rstrip(",") != s.rstrip(","):
        raise ValueError("RLE N:C, has stray content")
    return "".join(ch * int(n) for n, ch in pairs)


_UHEX = re.compile(r"U\+([0-9a-fA-F]+)")


def _codepoints_u(s):                                  # D28 row 25: "U+hhhh" codepoints joined (any separator); must have at least one match
    out = []
    for v in _UHEX.findall(s):
        cp = int(v, 16)
        if cp > 0x10FFFF:
            raise ValueError("codepoint out of range")
        out.append(chr(cp))
    if not out:
        raise ValueError("no U+hex codepoints")
    return "".join(out)


_BF_CHARS = set("+-<>.,[]")


def _run_brainfuck(source):                            # bounded BF interpreter (<=2,000,000 ticks). Returns raw bytes.
    code = "".join(ch for ch in source if ch in _BF_CHARS)
    if not code:
        raise ValueError("not brainfuck")
    jumps = {}
    stack = []
    for idx, ch in enumerate(code):
        if ch == "[":
            stack.append(idx)
        elif ch == "]":
            if not stack:
                raise ValueError("unmatched ']' in brainfuck")
            opening = stack.pop()
            jumps[idx] = opening
            jumps[opening] = idx
    if stack:
        raise ValueError("unmatched '[' in brainfuck")
    tape = [0] * 30000
    ptr = ip = steps = 0
    out = bytearray()
    LIMIT = 2_000_000
    while ip < len(code):
        steps += 1
        if steps > LIMIT:
            raise ValueError("brainfuck step limit exceeded")
        ch = code[ip]
        if ch == ">":
            ptr += 1
            if ptr == len(tape):
                tape.append(0)
        elif ch == "<":
            ptr -= 1
            if ptr < 0:
                tape.insert(0, 0)
                ptr = 0
        elif ch == "+":
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif ch == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif ch == ".":
            out.append(tape[ptr])
        elif ch == "[" and tape[ptr] == 0:
            ip = jumps[ip]
        elif ch == "]" and tape[ptr] != 0:
            ip = jumps[ip]
        ip += 1
    return bytes(out)


def _brainfuck_text(s):                                # D28 row 26: Brainfuck source -> decoded output as ASCII text
    return _run_brainfuck(s).decode("ascii")


_OOK_TOKEN = re.compile(r"Ook[.!?]")
_OOK_XLATE = {
    "Ook. Ook?": ">",
    "Ook? Ook.": "<",
    "Ook. Ook.": "+",
    "Ook! Ook!": "-",
    "Ook! Ook.": ".",
    "Ook. Ook!": ",",
    "Ook! Ook?": "[",
    "Ook? Ook!": "]",
}


def _ook_text(s):                                      # D28 row 27: Ook! tokens -> Brainfuck -> run -> ASCII
    toks = _OOK_TOKEN.findall(s)
    if not toks:
        raise ValueError("not Ook!")
    if len(toks) % 2:
        raise ValueError("Ook! program has an unmatched token")
    try:
        bf = "".join(_OOK_XLATE[toks[i] + " " + toks[i + 1]] for i in range(0, len(toks), 2))
    except KeyError as exc:
        raise ValueError("unknown Ook! pair: " + repr(exc.args[0]))
    return _run_brainfuck(bf).decode("ascii")


_HEX_PAIRS = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def _revhex(s):                                        # D28 row 28: hex text written backwards. Reverse the hex digits first, then decode as ASCII.
    rev = s.strip()[::-1]
    if not _HEX_PAIRS.fullmatch(rev):
        raise ValueError("row is not reversible byte-hex")
    return bytes.fromhex(rev).decode("ascii")


def _literal(s):                                       # D28 row 18 in Back in Sixteen: the fragment is literal plaintext (identity, strip only leading/trailing whitespace within the row text)
    # The caller supplies the raw fragment text (already split from the "NN<TAB>..." line). Return it verbatim.
    if not isinstance(s, str):
        raise ValueError("literal expects str")
    return s


LINE_DECODERS["utf16lehex"] = _utf16hex
LINE_DECODERS["utf16behex"] = _utf16hex
LINE_DECODERS["gzipb64"] = _gzipb64
LINE_DECODERS["zlibb64"] = _zlibb64
LINE_DECODERS["ascii85adobe"] = _ascii85adobe
LINE_DECODERS["rle_colon"] = _rle_colon
LINE_DECODERS["codepoints_u"] = _codepoints_u
LINE_DECODERS["brainfuck"] = _brainfuck_text
LINE_DECODERS["ook"] = _ook_text
LINE_DECODERS["revhex"] = _revhex
LINE_DECODERS["literal"] = _literal


def _rot13_b64(s):                                     # D29 row 29 (Rotten Base): ROT13 applied over a base64 string; undo the ROT13 first, then base64-decode to ASCII
    t = codecs.encode(s.strip(), "rot13")
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t) or len(t) % 4:
        raise ValueError("row is not rot13-over-base64")
    return base64.b64decode(t, validate=True).decode("ascii")


LINE_DECODERS["rot13b64"] = _rot13_b64
LADDER_NAMES = ["base64", "rot13", "hex", "binary", "decimal", "octal", "percent", "html", "jsonu", "base32", "base64url", "reverse", "atbash", "caesar7", "rot47", "morsehex", "baconhex", "rail3", "utf16lehex", "utf16behex", "gzipb64"]   # the known positional order; a disambiguator, not a hard requirement
# D28 (Back in Sixteen) 28-row ladder: rows 1-17 unchanged, row 18 becomes LITERAL (vs rail3 historically), rows 19-21 unchanged, rows 22-28 new. Selected per frag count in _guided_positional.
LADDER_NAMES_D28 = ["base64", "rot13", "hex", "binary", "decimal", "octal", "percent", "html", "jsonu", "base32", "base64url", "reverse", "atbash", "caesar7", "rot47", "morsehex", "baconhex", "literal", "utf16lehex", "utf16behex", "gzipb64", "zlibb64", "ascii85adobe", "rle_colon", "codepoints_u", "brainfuck", "ook", "revhex"]
LADDER_NAMES_D29 = LADDER_NAMES_D28 + ["rot13b64"]   # D29 (Rotten Base) 29-row ladder: rows 1-28 as Day 28, row 29 = ROT13 over base64
_SLUGCH = set(string.ascii_lowercase + "0123456789-")


LAYER_LOG = []                                         # provenance: (sha256[:10] of the numbered line's text, "codec > layer") for every magic-layer reading that was ACCEPTED as a candidate; bounded, in memory only


def _note_layer(frag, chain):
    if len(LAYER_LOG) < 500:
        LAYER_LOG.append((hashlib.sha256(frag.encode("utf-8", "replace")).hexdigest()[:10], " > ".join(chain)))


def _container_texts(frag):
    """[(chain, text)] for a numbered line that is a text codec + a magic-announced layer (layer_magic.py, shared). Never raises; a missing module just means no extra readings.
    SCOPING (2026-10-21): _container_texts is intentionally called ONLY from the slug-tail paths (_guided_positional's slug region at line ~1685 and _structural_unique at ~1761).
    The main single-blob path peel() already handles 'base64 of gzip' and similar through its own beam search + _decompress on every candidate, so wiring layer_magic there too would
    duplicate work without adding reach. The slug-tail paths apply the strict 'slug characters only, exactly one distinct reading' rule, which layer_magic's chain-tagged output supports natively."""
    try:
        import layer_magic
        return layer_magic.peel_to_text(frag)
    except Exception:
        return []


def _guided_positional(frags):
    """Decode numbered fragments guided by the KNOWN target sentence. Idempotent and pure. Two regions:
    - the KNOWN-prefix region (the fixed sentence): the target CONSTRAINS the decode, so ANY encoding whose decoder is in the pool self-solves here with no code change, picked because it keeps the running text a prefix of KNOWN.
    - the slug tail (unconstrained text): a letter-substitution is ambiguous there, so ONLY the known ladder decoder for that position is trusted. A NEW/unknown encoding on a pure-slug line returns None (HELD) - never a wrong slug guess (that was the Day 14 bug).
    Returns the full validated sentence, or None."""
    # D28 LADDER SELECTION: if the blob has 28 numbered fragments, prefer the Day 28 "Back in Sixteen" layout; otherwise keep the historical D13-D21 ladder.
    # Selection is strict (len == 28) so unrelated blob sizes never pick the D28 decoders unless the whole shape matches.
    ladder = LADDER_NAMES_D29 if len(frags) == 29 else LADDER_NAMES_D28 if len(frags) == 28 else LADDER_NAMES
    acc = ""
    for i, frag in enumerate(frags):
        if len(acc) >= len(KNOWN):                     # SLUG REGION: unconstrained -> trust only the known ladder decoder for this position; an unknown encoding here is HELD, not guessed
            name = ladder[i] if i < len(ladder) else None
            if name is None:                           # a line NUMBER beyond the known ladder (tomorrow's new line): an UNAMBIGUOUS structural decode is accepted; a letter SUBSTITUTION only on the final line and only when exactly one reading makes a slug whose words are all in the accepted-slug lexicon
                c = _structural_unique(frag)
                if c is None and i == len(frags) - 1:
                    c = _lexicon_tail(acc[len(KNOWN):], frag)
                if c is None:
                    return None
                acc += c
                continue
            try:
                c = LINE_DECODERS[name](frag)
            except Exception:
                c = None
            if not isinstance(c, str) or any(ch not in _SLUGCH for ch in c):   # slug charset only; an empty fragment legitimately decodes to "" (append nothing)
                # the position's trusted decoder did not read this line (a day may CHANGE the encoding of an existing line): accept only an UNAMBIGUOUS structural reading (the same rule as a brand-new
                # line), never a letter substitution; none or several readings = HELD, exactly as before
                c = _structural_unique(frag)
                if c is None:
                    return None
            acc += c
            continue
        best = None                                    # PREFIX REGION: the known target constrains it, so a guided pool search is safe and self-extending
        for name, dec in LINE_DECODERS.items():
            try:
                c = dec(frag)
            except Exception:
                continue
            if not isinstance(c, str) or c == "":
                continue
            nxt = (acc + c).lower(); kl = KNOWN.lower()      # case-insensitive: morse/NATO and similar cannot carry case, yet still decode the sentence
            ok = kl.startswith(nxt) or (len(nxt) >= len(kl) and nxt.startswith(kl) and all(ch in _SLUGCH for ch in nxt[len(kl):]))
            if not ok:
                continue
            if best is None or (i < len(ladder) and name == ladder[i]):   # prefer the ladder decoder for this position when it also fits
                best = c
                if i < len(ladder) and name == ladder[i]:
                    break
        if best is None:                               # the pool had nothing: the second pool (every affine / rot-N key and bit tricks), then any encoding the generic candidate set reads - still constrained by the KNOWN prefix
            kl = KNOWN.lower()
            for _name, dec in _line_pool2().items():
                try:
                    c = dec(frag)
                except Exception:
                    continue
                if not isinstance(c, str) or c == "":
                    continue
                nxt = (acc + c).lower()
                if kl.startswith(nxt) or (len(nxt) >= len(kl) and nxt.startswith(kl) and all(ch in _SLUGCH for ch in nxt[len(kl):])):
                    best = c
                    break
        if best is None:
            kl = KNOWN.lower()
            for _name, c in candidates(frag):
                if not isinstance(c, str) or c == "":
                    continue
                nxt = (acc + c).lower()
                if kl.startswith(nxt) or (len(nxt) >= len(kl) and nxt.startswith(kl) and all(ch in _SLUGCH for ch in nxt[len(kl):])):
                    best = c
                    break
        if best is None:                               # two layers inside ONE line (base64 of hex, a bytes literal of \x escapes ...): one more candidate step, still constrained by the KNOWN prefix
            kl = KNOWN.lower()
            for n1, c1 in candidates(frag):
                if n1 == "plain" or not isinstance(c1, str) or c1 == "":
                    continue
                for n2, c2 in candidates(c1):
                    if n2 == "plain" or not isinstance(c2, str) or c2 == "":
                        continue
                    nxt = (acc + c2).lower()
                    if kl.startswith(nxt) or (len(nxt) >= len(kl) and nxt.startswith(kl) and all(ch in _SLUGCH for ch in nxt[len(kl):])):
                        best = c2
                        break
                if best is not None:
                    break
        if best is None:                               # a text codec + a magic-announced container/BOM layer (gzip, zlib, bzip2, xz, UTF-16/32): still constrained by the KNOWN prefix
            kl = KNOWN.lower()
            for _chain, c in _container_texts(frag):
                nxt = (acc + c).lower()
                if kl.startswith(nxt) or (len(nxt) >= len(kl) and nxt.startswith(kl) and all(ch in _SLUGCH for ch in nxt[len(kl):])):
                    best = c
                    _note_layer(frag, _chain)
                    break
        if best is None:
            return None
        acc += best
    return acc if acc.lower().startswith(KNOWN.lower()) and SLUG.search(acc[len(KNOWN):].lower()) else None


_POOL2 = {}


def _line_pool2():
    """Per-line decoders tried only AFTER the main LINE_DECODERS pool: every affine key (caesar 1..25 and atbash included), every rotate-N over the printable / alphanumeric characters, and the bit-level
    variants of the binary line (inverted, least-significant-bit first). Safe in the KNOWN-prefix region only (the sentence constrains it); never used for the slug tail."""
    if not _POOL2:
        for (a, b), tab in _affine_tables():
            _POOL2["affine%d_%d" % (a, b)] = lambda s, tab=tab: s.translate(tab)
        for i, tab in enumerate(_rot_tables()):
            _POOL2["rotN%d" % i] = lambda s, tab=tab: s.translate(tab)
        _POOL2["binary_inverted"] = lambda s: "".join(chr(int(x, 2) ^ 255) for x in s.split())
        _POOL2["binary_lsb_first"] = lambda s: "".join(chr(int(x[::-1], 2)) for x in s.split())
        _POOL2["percent_twice"] = lambda s: urllib.parse.unquote(urllib.parse.unquote(s))
        _POOL2["lowercase"] = lambda s: s.lower()                     # UPPER / Title / aLtErNaTiNg / swapped case all fold to the case-insensitive known prefix
        _POOL2["reverse_each_word"] = lambda s: " ".join(w[::-1] for w in s.split(" "))
        _POOL2["reverse_word_order"] = lambda s: " ".join(s.split(" ")[::-1])
        _POOL2["swap_adjacent_pairs"] = lambda s: "".join((s[i + 1] + s[i]) if i + 1 < len(s) else s[i] for i in range(0, len(s), 2))
        for nm, table in (("leet_digits", "4a 3e 1i 0o 5s 7t"), ("leet_digits_il", "4a 3e 1l 0o 5s 7t"), ("leet_wide", "4a 8b 3e 6g 1i 0o 5s 7t"), ("leet_symbols", "@a 3e !i 0o $s +t")):
            _POOL2[nm] = (lambda s, tr=str.maketrans({p[0]: p[1] for p in table.split()}): s.translate(tr))     # the usual leet tables read back (the KNOWN prefix settles which one)
    return _POOL2


def _lexicon_tail(slug_so_far, frag):
    """The FINAL numbered line has no known decoder and is not a structural encoding (so likely a letter substitution: caesar / atbash / rot / affine / reversal ...). Try every per-line reading we have and keep the ones
    that complete a slug (three words, hyphen, two digits) whose three words are ALL in the lexicon of ACCEPTED slugs (slug_lexicon.py, 157 words, 99% leave-one-out coverage). Exactly ONE distinct reading = accept;
    none or several = None (HELD). The evidence is the vocabulary of the generator, not the letters' shape. Never raises."""
    try:
        import slug_lexicon
        if not slug_lexicon.words():
            return None
        pools = [LINE_DECODERS, _line_pool2()]
        ok = set()
        for pool in pools:
            for dec in pool.values():
                try:
                    c = dec(frag)
                except Exception:
                    continue
                if isinstance(c, str) and c and all(ch in _SLUGCH for ch in c) and slug_lexicon.valid_slug(slug_so_far + c):
                    ok.add(c)
        for _n, c in candidates(frag):
            if isinstance(c, str) and c and all(ch in _SLUGCH for ch in c) and slug_lexicon.valid_slug(slug_so_far + c):
                ok.add(c)
        return ok.pop() if len(ok) == 1 else None
    except Exception:
        return None


_SUBST_NAMES = ("plain", "reverse", "rot13", "rot47", "atbash", "lower", "swapcase")


def _structural_unique(frag):
    """The decoded text of a slug-region line whose line number has no known decoder: accepted ONLY if exactly one distinct structural (non-substitution) decoder reading is made of slug characters.
    Letter shifts / reversals / case changes are excluded (every slug-shaped string has many readings under them); two different structural readings = ambiguous = None (HELD)."""
    outs = set()
    for name, c in candidates(frag):
        if name in _SUBST_NAMES or name.startswith("caesar") or name.endswith("+xor") or not isinstance(c, str) or c == "":
            continue
        if all(ch in _SLUGCH for ch in c):
            outs.add(c)
    # MAGIC-ANNOUNCED LAYERS (2026-10-21, Day 21 Mastery line 21 = base64 of a gzip stream, the one line this reader could not compose; lines 19-20 hex of BOM-led UTF-16 it already read): a text codec
    # followed by a layer that names itself by its magic bytes (gzip / zlib / bzip2 / xz signature, or a UTF-16/32 BOM) is as structural as any other reading and has exactly one meaning. Shared with
    # every lane (layer_magic.py). Same acceptance rule as above: slug characters only, exactly one distinct reading.
    for _chain, c in _container_texts(frag):
        c = c.strip()
        if c and all(ch in _SLUGCH for ch in c):
            outs.add(c)
            _note_layer(frag, _chain)
    # TWO-LAYER structural readings (2026-10-16, Day 16 Dot Com line 16 = Morse spelling HEX bytes): a reading that is itself an even-length hex string whose bytes read as slug text is the FIRST layer of a
    # longer chain; the deeper reading replaces it. Still structural (no letter substitution) and still validated by the caller (the whole sentence must end in a slug).
    for c in list(outs):
        if len(c) >= 4 and len(c) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", c):
            try:
                d = bytes.fromhex(c).decode("ascii")
            except Exception:
                continue
            if d and all(ch in _SLUGCH for ch in d):
                outs.discard(c)
                outs.add(d)
    return outs.pop() if len(outs) == 1 else None


def decode_positional(frags):
    """frags: the fragment strings in line-number order. -> the full KNOWN sentence+slug, or None. Fast path: the exact known ladder (D13/D14); then the self-extending guided decode; never a partial or shape-only guess."""
    for layout in (POSITIONAL_D14, POSITIONAL_D13):    # fast exact-ladder path for the known lengths
        if len(frags) == len(layout):
            try:
                out = "".join(f(s) for f, s in zip(layout, frags))
                if out.startswith(KNOWN) and SLUG.search(out[len(KNOWN):]):
                    return out
            except Exception:
                pass
    return _guided_positional(frags)                   # self-extends to any line count / a newly appended encoding


def decode_blob(data):
    text = _as_text(data)
    # D27 audit §7 (user directive 2026-10-27): pure-Ook whole-blob fast path. If the entire
    # blob is pure Ook! tokens + whitespace, decode via _ook (shared with the per-fragment
    # path) and recurse so a layered Ook payload (Ook output that is itself another codec)
    # still peels. Returns the decoded text (bytes->latin-1->str), optionally re-decoded.
    # Only runs when the blob has a plausible Ook signature to keep the common path cheap.
    try:
        if "Ook" in text and re.fullmatch(r"(?:Ook[.?!]|\s)+", text):
            o = _ook(text)
            if o:
                try:
                    s = o.decode("latin-1")
                except Exception:
                    s = None
                if s is not None:
                    # Peel any further encoding layer sitting on top of the Ook output.
                    inner = decode_blob(o) if not SLUG.search(s) else None
                    return inner or s
    except Exception:
        pass
    rows = [FRAG_LINE.match(l) for l in text.splitlines() if l.strip()]
    if rows and all(rows):
        frags = [m.group(2) for m in sorted(rows, key=lambda m: int(m.group(1)))]
        # NO-GIBBERISH INVARIANT (2026-10-14): a numbered-line (positional multi-codec) blob is only ever returned when the WHOLE KNOWN sentence validates. The generic search is still tried, but its output is
        # accepted only if it too starts with KNOWN - otherwise return None so the mode is HELD (the Commander/agent builds the extractor) rather than a shape-matching gibberish slug being submitted (the Day 14 bug).
        out = decode_positional(frags)
        if out:
            return out
        alt = decode_fragments(frags, strict_tail=True)
        if alt and alt.lower().startswith(KNOWN.lower()) and SLUG.search(alt[len(KNOWN):].lower()):   # case-insensitive: a morse fragment legitimately decodes the sentence lowercase; still rejects gibberish that never forms KNOWN
            return alt
        return None
    return peel(data)


def answer_from(text):
    if not text:
        return None
    last = _final_line(text)
    m = SLUG.findall(last) or SLUG.findall(text)
    if m:
        return m[-1]
    other = DC.ANS.findall(text) + DC.FLAG.findall(text)
    return other[-1] if other else last.strip() or None


def _natural_key(name):
    return [(0, int(t), "") if t.isdigit() else (1, 0, t) for t in re.split(r"(\d+)", name)]


def _files(blobs):
    out = []
    for b in blobs:
        if isinstance(b, (bytes, bytearray)) and b[:2] == b"PK":
            z = zipfile.ZipFile(io.BytesIO(b))
            for pw in (None, b"infected"):
                try:
                    # NATURAL order (2026-10-21): the positional fallback (no per-question artifact name) maps member i to answer id i. A plain sorted() put blob-100..103 BEFORE blob-11 and shifted
                    # every answer from set11 on by four (found in the Day 21 audit; production was unaffected only because the GM names each question's artifact).
                    out += [(os.path.basename(n), z.read(n, pwd=pw)) for n in sorted(z.namelist(), key=_natural_key) if not n.endswith("/")]
                    break
                except RuntimeError:
                    continue
        else:
            out.append((None, b))
    return out


def compute(start, blobs):
    qs = start.get("questions") or []
    ids = start.get("answer_ids") or [q["id"] for q in qs] or ["message"]
    byq = {q.get("id"): q for q in qs}
    files = _files(blobs)
    if len(ids) > 1:                                   # D15 (2026-10-15): keep the real mastery bytes on disk (timed artifacts are not cached) so the extractor can be built offline from them
        try:
            dd = os.environ.get("HUNTRESS_WARMUPS_DUMP_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_pool", "_dump_warmups")
            os.makedirs(dd, exist_ok=True)
            for k, b in enumerate(blobs):
                if isinstance(b, (bytes, bytearray)):         # one file PER ATTEMPT (content hash in the name): a later rehearsal or retry must never overwrite the bytes of an accepted attempt (Day 21: it did)
                    open(os.path.join(dd, "mastery_%s_blob%d.bin" % (hashlib.sha256(b).hexdigest()[:12], k)), "wb").write(b)
        except OSError:
            pass
    names = {}
    for n, b in files:
        if n:
            names.setdefault(n, b)
    arts = [a.get("filename") for a in (start.get("artifacts") or []) if isinstance(a, dict)]
    ans = {}
    for i, aid in enumerate(ids):
        want = (byq.get(aid) or {}).get("artifact")
        if want and want in names and list(n for n, _ in files).count(want) == 1:
            data = names[want]
        elif len(files) == len(ids):
            data = files[i][1]
        elif len(files) == 1:
            data = files[0][1]
        else:
            raise ValueError("cannot map answer %s to an artifact (%d files, %d ids, artifacts %s)" % (aid, len(files), len(ids), arts[:3]))
        t = decode_blob(data)
        if len(ids) > 1 and not (t and KNOWN.lower() in t.lower()):   # NO-GIBBERISH (D15): a multi-set blob is only submitted when the WHOLE known sentence validated
            raise ValueError("mastery blob for %s did not validate against the known sentence (not submitted)" % aid)
        a = answer_from(t)
        if not a:
            raise ValueError("no answer decoded for %s" % aid)
        ans[aid] = a
    return ans


if __name__ == "__main__":
    # offline: python3 autosolve_warmups.py <file> [file...]   (prints decoded final line + answer per file/zip member)
    for p in sys.argv[1:]:
        for n, b in _files([open(p, "rb").read()]):
            t = decode_blob(b)
            print("%s%s -> %s | %r" % (p, ("::" + n) if n else "", answer_from(t), _final_line(t)[-110:]))
