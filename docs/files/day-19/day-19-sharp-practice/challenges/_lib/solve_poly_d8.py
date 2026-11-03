"""Day 08 Lost in Translation: decode HUNTRESS_ANALYSIS_V1:<KIND>-payload v=3 descriptors (php polyglot + host files).
Usage (from framework root): python3 'challenges/Day 08/Lost_in_Translation/scripts/solve_poly.py' <dir_with_extracted_files> <task_or_start.json>
Importable: poly_answers(dir, question_ids) -> {id: value}"""
import re, base64, os, sys, json, collections

MARK = re.compile(r'HUNTRESS_ANALYSIS_V1:([A-Z0-9]+)-([^\r\n\'"]+)')
SUF = {'role': 'role', 'attack': 'attack', 'adapter': 'adapter', 'campaign': 'campaign_id', 'url': 'url',
       'stage-count': 'stage_count', 'steps': 'steps', 'host-profile': 'host_profile',
       'obfuscation': 'obfuscation_profile', 'stage-profile': 'stage_profile', 'next-language': 'next_language',
       'file-path': 'file_path'}


def b64(s):
    s = s.strip()
    return base64.b64decode(s + '=' * (-len(s) % 4))


def _peel(p):
    """Fallback for unseen marker kinds: peel hex / base64 / reversal layers until a 'v=N|' descriptor appears."""
    cur = p.replace('.', '')
    for _ in range(6):
        for cand in (cur, cur[::-1]):
            if re.match(r'^v=\d+\|', cand):
                return cand
        try:
            if re.fullmatch(r'[0-9a-fA-F]+', cur) and len(cur) % 2 == 0:
                cur = bytes.fromhex(cur).decode()
            else:
                try:
                    cur = b64(cur).decode()
                except Exception:
                    cur = b64(cur[::-1]).decode()
        except Exception:
            break
    raise ValueError('unpeelable')


def _peel2(p, depth=4):
    """Universe fallback (2026-10-15 night, script_universe): an unseen kind token whose payload is gzip / zlib / raw deflate, percent-encoded, urlsafe
    base64, ROT13 text, a reversed hex string or a single-byte XOR. Breadth-first over byte layers; accepts ONLY a printable 'v=N|' descriptor, so an
    unrecognised payload stays undecoded (HELD) and can never produce a guess."""
    import zlib, urllib.parse, codecs
    ok = re.compile(rb'^v=\d+\|[\x20-\x7e]+$')
    start = p.strip().replace('.', '').encode('latin-1', 'ignore')
    layer, seen = [start], {start}
    for _ in range(depth):
        nxt = []
        for b in layer:
            outs = []
            s = b.decode('latin-1')
            outs.append(b[::-1])
            if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0:
                outs.append(bytes.fromhex(s))
            if '%' in s:
                outs.append(urllib.parse.unquote_to_bytes(s))
            outs.append(codecs.encode(s, 'rot13').encode('latin-1', 'ignore'))
            for urlsafe in (False, True):
                try:
                    t = s.strip() + '=' * (-len(s.strip()) % 4)
                    outs.append(base64.urlsafe_b64decode(t) if urlsafe else base64.b64decode(t))
                except Exception:
                    pass
            for wb in (47, 15, -15):                       # gzip (auto header) / zlib / raw deflate
                try:
                    outs.append(zlib.decompress(b, wb if wb > 0 else wb))
                except Exception:
                    pass
            for k in range(1, 256):
                if len(b) > 4 and bytes([b[0] ^ k, b[1] ^ k]) == b'v=':
                    outs.append(bytes(x ^ k for x in b))
            for o in outs:
                if not o or o in seen:
                    continue
                if ok.match(o):
                    return o.decode('latin-1')
                seen.add(o); nxt.append(o)
        layer = nxt[:64]
    raise ValueError('unpeelable')


def decode_payload(kind, p):
    try:
        t = _decode_known(kind, p)
        if re.match(r'^v=\d+\|', t):
            return t
    except Exception:
        pass
    try:
        return _peel(p)
    except Exception:
        return _peel2(p)


def _decode_known(kind, p):
    if kind == 'B64':
        return b64(p).decode()
    if kind == 'HEX':
        return bytes.fromhex(p).decode()
    if kind == 'FRAG':
        return bytes.fromhex(p.replace('.', '')).decode()
    if kind == 'HB64':
        return b64(bytes.fromhex(p).decode()).decode()
    if kind == 'LYR':
        # Day 23: layered carrier - the payload is '<layer1>_<layer2>_..._<layerN>-<data>' where
        # the layer names list the transforms applied in the given order to produce <data>; decoding
        # applies them in reverse. Known layers: hex, b64, b32, b85, b16, rev, zlib, gzip.
        import base64 as _b64, binascii, zlib, gzip, io
        head, _, body = p.partition('-')
        if not head or not body:
            raise ValueError('LYR no header')
        layers = head.split('_')
        buf = body
        for layer in reversed(layers):
            if isinstance(buf, bytes):
                try:
                    buf_s = buf.decode('utf-8')
                except Exception:
                    buf_s = buf.decode('latin-1')
            else:
                buf_s = buf
            if layer == 'hex':
                buf = bytes.fromhex(buf_s)
            elif layer == 'b64':
                buf = _b64.b64decode(buf_s + '=' * (-len(buf_s) % 4))
            elif layer == 'b32':
                buf = _b64.b32decode(buf_s + '=' * (-len(buf_s) % 8))
            elif layer == 'b85':
                buf = _b64.b85decode(buf_s)
            elif layer == 'b16':
                buf = _b64.b16decode(buf_s.upper())
            elif layer == 'rev':
                buf = buf_s[::-1] if isinstance(buf, str) else buf[::-1]
            elif layer == 'frag':
                # fragments joined by '.'; stripping the dots undoes the fragmenting step.
                buf = buf_s.replace('.', '')
            elif layer == 'zlib':
                buf = zlib.decompress(buf if isinstance(buf, bytes) else buf_s.encode('latin-1'))
            elif layer == 'gzip':
                b = buf if isinstance(buf, bytes) else buf_s.encode('latin-1')
                buf = gzip.decompress(b)
            else:
                raise ValueError('LYR unknown layer ' + layer)
        if isinstance(buf, bytes):
            buf = buf.decode('utf-8', 'replace')
        return buf
    raise ValueError('kind ' + kind)


# A marker that sits inside a HOST-LANGUAGE COMMENT keeps that comment's terminator in MARK's capture (Day 14 msbuild
# .proj: '<!-- HUNTRESS_ANALYSIS_V1:HB64-<hex> -->'). Base64 payloads survive it (decoding stops at the padding) but
# hex ones do not, so cut the payload at the first whitespace and shed any trailing comment close.
CLOSE = ('-->', ']]>', '*/', '?>', '#>', '--')


def clean_payload(p):
    p = p.strip().split()[0] if p.strip().split() else p.strip()
    for _ in range(3):
        for c in CLOSE:
            if p.endswith(c):
                p = p[:-len(c)].strip()
                break
        else:
            break
    return p


# ---- TRUNCATION GUARD (2026-10-18, generalization suite). A host container can cut a payload; the decodable prefix then yields a SHORTENED value for the field the cut
# fell in ('file_path=/op'), a plausible but wrong answer. A descriptor whose payload cannot be whole loses its LAST key (the only field a cut can shorten) and that
# field stays unanswered. Evidence for the two signals: all 1170 archived Day 15-18 literal markers are encoding-aligned (base64 length % 4 == 0, hex even) and all 1170 v=3
# descriptors share ONE key order and end with file_path (SCHEMA_ORDER). An aligned cut that falls inside the final value is indistinguishable from a short complete value: that residual is measured by
# _test_script_variation.py (reported, not hidden) and never occurs when a second complete copy exists (the most complete copy wins).
SCHEMA_ORDER = {'3': ('v', 'language', 'role', 'verdict', 'attack', 'adapter', 'host_profile', 'obfuscation_profile', 'stage_profile', 'next_language',
                      'stage_count', 'steps', 'campaign_id', 'url', 'file_path')}      # the key order of all 1170 archived Day 15-18 v=3 descriptors


def _aligned(kind, p):
    """True / False when the payload's encoding shows it whole / cut; None when the kind carries no alignment rule (unseen kinds)."""
    s = p.strip()
    if kind == 'B64':
        return len(s) % 4 == 0
    if kind == 'HB64':                      # hex of a base64 text: the hex is even AND the inner base64 text is a whole number of 4-character groups
        if len(s) % 2:
            return False
        try:
            return len(bytes.fromhex(s).decode('latin-1').strip()) % 4 == 0
        except ValueError:
            return False
    if kind == 'HEX':
        return len(s) % 2 == 0
    if kind == 'FRAG':
        return len(s.replace('.', '')) % 2 == 0
    return None


def _trim_incomplete(kind, p, kv):
    """-> kv, without its last key when the payload cannot be proven whole (see TRUNCATION GUARD)."""
    if len(kv) < 2:
        return kv
    keys = list(kv)
    order = SCHEMA_ORDER.get(kv.get('v'))
    # a descriptor in the known v=3 order that stops before its terminal key is what a cut payload looks like; one in any other key order is not recognised as that
    # schema (author-made or future shapes), so only the encoding checks speak for it
    schema_cut = order is not None and len(keys) < len(order) and tuple(keys) == tuple(order[:len(keys)])
    cut = (_aligned(kind, p) is False) or schema_cut
    return {k: kv[k] for k in keys[:-1]} if cut else kv


# MSBuild carries the same payload in a <PropertyGroup> property; prefer it when the comment copy will not decode
# ('follow its properties into its targets'). Any single-element carrier of the same shape works here.
PROP = re.compile(r'<(?:HuntressDescriptor|HuntressMaterial)>\s*([^<>\s]+)\s*</(?:HuntressDescriptor|HuntressMaterial)>')


# ---- LITERAL RECONSTRUCTION (2026-10-18, H1). Used ONLY when the marker is not present as one literal in the file: a
# descriptor that a script joins at run time from string literals ([lit, lit].join(sep), ''.join([lit, ...]) and lit + lit
# chains). Only literal elements are accepted. A computed element, a template interpolation, an unknown escape, a nested
# array, a join whose receiver or argument is not a literal, a concatenation with a computed neighbour, an undecodable
# marker or two DIFFERENT descriptors make the file yield NO candidate (ValueError, which desc_of turns into (None, None)).
# Identical duplicate copies are accepted. Nothing here executes the artifact.
_LIT = r'''"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`'''
_ESC = {'\\': '\\', "'": "'", '"': '"', '`': '`', 'n': '\n', 'r': '\r', 't': '\t'}
_ARR_A = re.compile(r'\[\s*((?:(?:' + _LIT + r')\s*,\s*)*(?:' + _LIT + r')\s*,?)\s*\]\s*\.\s*join\s*\(\s*(' + _LIT + r'|)\s*\)')
_ARR_B = re.compile(r'(' + _LIT + r')\s*\.\s*join\s*\(\s*\[\s*((?:(?:' + _LIT + r')\s*,\s*)*(?:' + _LIT + r')\s*,?)\s*\]\s*\)')
_CAT = re.compile(r'(?:' + _LIT + r')(?:\s*\+\s*(?:' + _LIT + r'))+')
_ELEM = re.compile(_LIT)
_JOIN_RECV = re.compile(r'\.\s*join\s*\(')     # every join call: a join on a computed receiver is a rejection, not an ignore


# ---- BOUNDED CONSTANT PROPAGATION (2026-10-18, generalization suite). 'var parts = [lit, lit]; ... parts.join(sep)' and 'parts = [lit, lit]; ''.join(parts)' are as constant
# as an inline literal array IF the name is bound exactly once to a pure literal array and every other occurrence of the name (outside string literals) is that join. Any other
# use (a push or other method, an index, a reassignment, a second binding, being passed to a call, a property of another object) means the final content is not the
# literal, and the file is rejected like any other computed construct. Nothing is executed.
_ID = r'[A-Za-z_$][\w$]*'
_ARRAY_LIT = r'\[\s*(?:(?:' + _LIT + r')\s*,\s*)*(?:' + _LIT + r')\s*,?\s*\]'
_BIND = re.compile(r'(?<![\w$.])(?:(?:var|let|const)\s+)?(' + _ID + r')\s*=(?!=)\s*(' + _ARRAY_LIT + r')')
_USE_RECV = re.compile(r'(?<![\w$.])(' + _ID + r')\s*\.\s*join\s*\(')
_USE_ARG = re.compile(r'\.\s*join\s*\(\s*(' + _ID + r')\s*\)')


def _inline_bound_arrays(s):
    binds = {}
    for m in _BIND.finditer(s):
        binds.setdefault(m.group(1), []).append(m)
    uses = [(m, 'recv') for m in _USE_RECV.finditer(s) if m.group(1) in binds] + [(m, 'arg') for m in _USE_ARG.finditer(s) if m.group(1) in binds]
    if not uses:
        return s
    bare = re.sub(_LIT, '""', s)
    edits = []
    for name in sorted({m.group(1) for m, _ in uses}):
        if len(binds[name]) != 1:
            raise ValueError('ambiguous array binding')
        n_uses = sum(1 for m, _ in uses if m.group(1) == name)
        if len(re.findall(r'(?<![\w$.])' + re.escape(name) + r'(?![\w$])', bare)) != 1 + n_uses:
            raise ValueError('bound array is used other than by its join')
        lit = binds[name][0].group(2)
        for m, how in uses:
            if m.group(1) == name:
                edits.append((m.start(), m.end(), lit + '.join(' if how == 'recv' else '.join(' + lit + ')'))
    for a, b, r in sorted(edits, reverse=True):
        s = s[:a] + r + s[b:]
    return s


def _unlit(tok):
    """decode one literal token (JS / Python / PHP style quotes); raises ValueError on anything it does not know"""
    q, body = tok[0], tok[1:-1]
    if q == '`' and '${' in body:
        raise ValueError('template interpolation')
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c != '\\':
            out.append(c)
            i += 1
            continue
        n = body[i + 1:i + 2]
        if n in _ESC:
            out.append(_ESC[n])
            i += 2
        elif n == 'x' and re.fullmatch(r'[0-9a-fA-F]{2}', body[i + 2:i + 4]):
            out.append(chr(int(body[i + 2:i + 4], 16)))
            i += 4
        elif n == 'u' and re.fullmatch(r'[0-9a-fA-F]{4}', body[i + 2:i + 6]):
            out.append(chr(int(body[i + 2:i + 6], 16)))
            i += 6
        else:
            raise ValueError('unsupported escape')
    return ''.join(out)


_BR = re.compile(_LIT + r'|\[|\]')


def _bracket_index(s):
    """one linear pass: the positions of the square brackets outside string literals, with the depth after each one"""
    pos, depth, d = [], [], 0
    for m in _BR.finditer(s):
        t = m.group(0)
        if t == '[':
            d += 1
        elif t == ']':
            d -= 1
        else:
            continue
        pos.append(m.start())
        depth.append(d)
    return pos, depth


def _nested_at(index, p):
    """True when position p sits inside an open square bracket: a nested construct"""
    import bisect
    pos, depth = index
    i = bisect.bisect_left(pos, p)
    return i > 0 and depth[i - 1] > 0


def _prev_char(s, i):
    j = i - 1
    while j >= 0 and s[j].isspace():
        j -= 1
    return s[j] if j >= 0 else ''


def _next_char(s, i):
    j = i
    while j < len(s) and s[j].isspace():
        j += 1
    return s[j] if j < len(s) else ''


def _literal_chains(s):
    """-> the reconstructed text of every accepted literal chain in s; raises ValueError on any rejected construct.
    Linear in the file size: one bracket index per file, bounded neighbour lookups."""
    texts, spans = [], []
    s = _inline_bound_arrays(s)
    index = _bracket_index(s)
    for m in _ARR_A.finditer(s):
        if _nested_at(index, m.start()):
            raise ValueError('nested array')
        sep = _unlit(m.group(2)) if m.group(2) else ''
        texts.append(sep.join(_unlit(t.group(0)) for t in _ELEM.finditer(m.group(1))))
        spans.append(m.span())
    for m in _ARR_B.finditer(s):
        if _nested_at(index, m.start()):
            raise ValueError('nested array')
        sep = _unlit(m.group(1))
        texts.append(sep.join(_unlit(t.group(0)) for t in _ELEM.finditer(m.group(2))))
        spans.append(m.span())
    if len(_JOIN_RECV.findall(s)) != len(spans):
        raise ValueError('join with a computed receiver or argument')
    import bisect
    spans.sort()
    starts = [a for a, _ in spans]
    for m in _CAT.finditer(s):
        k = bisect.bisect_right(starts, m.start()) - 1
        if k >= 0 and spans[k][0] <= m.start() < spans[k][1]:
            continue
        if _prev_char(s, m.start()) == '+' or _next_char(s, m.end()) == '+':
            raise ValueError('computed concatenation')
        texts.append(''.join(_unlit(t.group(0)) for t in _ELEM.finditer(m.group(0))))
    return texts


def _kv_best(kind, raw):
    best = None
    for p in (clean_payload(raw), raw):
        try:
            t = decode_payload(kind, p)
        except Exception:
            continue
        kv = dict(x.split('=', 1) for x in t.split('|') if '=' in x)
        if not kv.get('v'):
            continue
        kv = _trim_incomplete(kind, p, kv)
        if best is None or len(kv) > len(best):
            best = kv
    return best


SPLIT_MARK = re.compile(r'HUNTRESS_ANALYSIS_V1:SPLIT\b')      # Day 18 Apps Script carrier: the marker sits in a comment, the payload is a joined literal chain
SPLIT_CHAIN = re.compile(r'^([A-Z0-9]+)-(.+)$', re.S)           # a joined chain: KIND-payload (KIND as _decode_known knows it)
_SPLIT_KINDS = ('B64', 'HEX', 'FRAG', 'HB64', 'LYR')


def _split_desc(s):
    """-> (kind, descriptor dict) for a descriptor reconstructed from literal chains, (None, None) if there is none;
    raises ValueError when the reconstruction is rejected (computed parts, competing or undecodable payloads).
    Day 18 SPLIT carrier (Google Apps Script, 2026-10-18): a file marked HUNTRESS_ANALYSIS_V1:SPLIT whose joined chain is 'KIND-payload' (KIND one of
    B64, HEX, FRAG, HB64) is a descriptor of that kind. The rebuilt chain carries no HUNTRESS_ANALYSIS_V1 marker of its own, so it is decoded here, never guessed."""
    found = []
    split_marked = bool(SPLIT_MARK.search(s))
    for t in _literal_chains(s):
        km = SPLIT_CHAIN.match(t) if split_marked else None
        if km and km.group(1) in _SPLIT_KINDS:          # a joined chain 'KIND-payload' in a SPLIT file: the same kinds _decode_known knows
            kv = _kv_best(km.group(1), km.group(2))
            if kv is None:
                raise ValueError('undecodable split descriptor')
            found.append((km.group(1), tuple(kv.items())))      # key ORDER is kept: the truncation guard needs to know which key is last
            continue
        marked = False
        for mm in MARK.finditer(t):
            marked = True
            kv = _kv_best(mm.group(1), mm.group(2))
            if kv is None:
                raise ValueError('undecodable split descriptor')
            found.append((mm.group(1), tuple(kv.items())))
        if split_marked and not marked and len(t) >= 16:
            # BARE chain in a SPLIT file (no inner 'KIND-' prefix; the live Day 18 hot fix handled it, its test pins it): the generic peel (hex / base64 / reversal, dots dropped, then gzip / zlib /
            # deflate / percent / urlsafe / rot13 / 1-byte XOR) decodes it, and ONLY a printable 'v=N|' descriptor counts. A chain that is not a descriptor is ignored, never an error: a SPLIT
            # file may hold unrelated joins. Competing descriptors are rejected below like every other candidate.
            kv = _kv_best('SPLIT', t)
            if kv is not None:
                found.append(('SPLIT', tuple(kv.items())))
    if not found:
        return None, None
    # copies of ONE descriptor agree (the kind label of a copy is irrelevant: a 'FRAG-' copy and a bare copy of the same descriptor are the real Day 18 shape); a copy that is a strict
    # prefix of another is a truncated duplicate and yields to the fuller one; anything else is two different descriptors
    descs = sorted({items for _k, items in found}, key=len)
    longest = descs[-1]
    if any(longest[:len(d)] != d for d in descs):
        raise ValueError('competing payloads')
    kind = next(k for k, items in found if items == longest)
    return kind, dict(longest)


def _marked_desc(s, m):
    """the original single-marker path (unchanged logic): raises ValueError when the raw marker does not decode"""
    kind = m.group(1)
    tries = [clean_payload(m.group(2)), m.group(2)]
    mp = PROP.search(s)
    if mp:
        tries.insert(1, mp.group(1))
    # Take the MOST COMPLETE descriptor, not the first that parses: a payload truncated by the host container still
    # decodes to a leading 'v=3|language=...' fragment, so a field count is what separates a whole copy from a partial one.
    best, last = None, None
    for p in tries:
        try:
            t = decode_payload(kind, p)
        except Exception as e:
            last = e
            continue
        kv = dict(x.split('=', 1) for x in t.split('|') if '=' in x)
        if not kv.get('v'):
            last = ValueError('no v= in descriptor')
            continue
        kv = _trim_incomplete(kind, p, kv)
        if best is None or len(kv) > len(best):
            best = kv
    if best is None:
        raise last if last else ValueError('undecodable descriptor')
    return kind, best


def _unescaped(s):
    """Day 19 (Sharp Practice): an ASPX inline-C# host carries the WHOLE specimen as one escaped string literal, so the
    real line breaks are two-character \\n sequences and MARK's `[^\\r\\n'\"]+` capture runs past the payload into the
    host's own code. Expanding the escapes restores the embedded source. Returns None when there is nothing to expand,
    so this is additive: it is only consulted after the literal source has already failed to decode."""
    if '\\n' not in s or 'HUNTRESS_ANALYSIS_V1' not in s:
        return None
    out = s.replace('\\r\\n', '\n').replace('\\n', '\n').replace('\\r', '\n')
    out = out.replace('\\"', '"').replace("\\'", "'").replace('\\\\', '\\')
    return out if out != s else None


def _desc_of_text(s):
    m = MARK.search(s)
    if not m:
        return _split_desc(s)                      # raises ValueError when there is no split descriptor either
    try:
        return _marked_desc(s, m)
    except ValueError as e:
        # the raw marker did not give a decodable descriptor (a backtick or a join separator cut its capture): a split
        # reconstruction may still carry the descriptor; when it does not, the original error stands (no candidate)
        try:
            k, v = _split_desc(s)
        except ValueError:
            raise e
        if v is None:
            raise e
        return k, v


def desc_of(path):
    s = open(path, encoding='utf-8', errors='replace').read()
    had_mark = MARK.search(s) is not None
    best = None
    err = None
    for cand in (s, _unescaped(s)):
        if cand is None:
            continue
        try:
            k, v = _desc_of_text(cand)
        except ValueError as e:
            err = err or e
            continue
        if v and (best is None or len(v) > len(best[1])):   # the most COMPLETE descriptor wins, as in _marked_desc
            best = (k, v)
    if best is not None:
        return best
    if had_mark and err is not None:
        raise err
    return None, None


def poly_answers(d, ids):
    kv = {}
    kinds = collections.Counter()
    for f in sorted(os.listdir(d)):             # DETERMINISM (independent review 2026-10-23, finding #9): by_hash below keeps the LAST-visited same-stem file; os.listdir() order is filesystem-dependent, sorted() makes it reproducible
        try:
            k, v = desc_of(os.path.join(d, f))
        except Exception as e:
            print('ERR', f, e, file=sys.stderr); continue
        if v:
            kv[f] = v; kinds[k] += 1
    # Day 23 (Press Start to Decode) renames the fixtures to '{hash}.{ext}' - the file no longer carries
    # the 'polyglot-{lang}-' prefix in its name, so stem-prefix lookups miss. Build a hash index as a
    # fallback: the id's trailing hash segment finds the file whose basename-without-ext matches it.
    by_hash = {}
    for f in kv:
        stem_f = os.path.splitext(f)[0]
        if re.fullmatch(r'[0-9a-f]{4,16}', stem_f):
            by_hash[stem_f] = f
    A = {}
    for i in ids:
        m = re.match(r'^(polyglot|host)-(.+)-(' + '|'.join(SUF) + r')$', i)
        if not m:
            continue
        stem = m.group(2)
        cands = [f for f in kv if os.path.splitext(f)[0] == m.group(1) + '-' + stem]
        if not cands:
            # Fallback: try the trailing hex-hash segment as a filename stem (Day 23).
            tail = stem.rsplit('-', 1)[-1]
            if tail in by_hash:
                cands = [by_hash[tail]]
        if len(cands) != 1:
            print('no file for', i, cands, file=sys.stderr); continue
        v = kv[cands[0]].get(SUF[m.group(3)])
        if v is None:
            continue
        A[i] = v.replace(',', '>') if m.group(3) == 'steps' else v
    return A, kinds


def bash_adv_decode(material, codec):
    """Decode a bash-advanced fixture's Material per its Codec string.
    Codecs seen on Day 08: xor_hex|<key>, percent_hex, reversed_base64, base64_literal,
    hex_compact, plus an optional trailing reverse_bytes step. Returns decoded text or None.
    Day 23 adds: decimal_colon as a loader, and repeating_key_xor|<csv-hex-key> as a secondary transform."""
    import base64 as _b64
    import urllib.parse as _up
    steps = codec.split('|')
    c = steps[0]
    try:
        if c == 'xor_hex':
            k = int(steps[1], 16)
            data = bytes(x ^ k for x in bytes.fromhex(material))
        elif c == 'percent_hex':
            data = _up.unquote(material).encode('utf-8', 'replace')
        elif c == 'reversed_base64':
            data = _b64.b64decode(material[::-1])
        elif c == 'base64_literal':
            data = _b64.b64decode(material)
        elif c == 'hex_compact':
            data = bytes.fromhex(material)
        elif c == 'decimal_csv':   # Day 09
            data = bytes(int(x) for x in material.split(',') if x.strip())
        elif c == 'decimal_colon':   # Day 23 (Press Start to Decode): colon-separated decimals
            data = bytes(int(x) for x in material.split(':') if x.strip())
        elif c == 'reversed_decimal':
            data = bytes(int(x) for x in material.split(',') if x.strip())[::-1]
        elif c == 'decimal':
            data = bytes(int(x) for x in material.split(',') if x.strip())
        elif c == 'hex_literal':
            data = bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', material))
        elif c == 'hex_colon':
            data = bytes(int(x, 16) for x in material.split(':') if x)
        else:
            # Unknown codec: fall back to the legacy base64 / reversed-base64 guesses.
            for cand in (material, material[::-1]):
                try:
                    t = b64(cand).decode()
                    if t.startswith('v='):
                        return t
                except Exception:
                    pass
            return None
    except Exception:
        return None
    # Day 23 secondary transforms: repeating_key_xor|<csv-hex-key> is applied over the loaded bytes.
    rest = steps[1:]
    k = 0
    while k < len(rest):
        step = rest[k]
        k += 1
        if not step:
            continue
        if step == 'reverse_bytes':
            data = data[::-1]
            continue
        if step == 'single_byte_xor':
            if k < len(rest):
                try:
                    xk = int(rest[k], 16)
                    data = bytes(b ^ xk for b in data)
                    k += 1
                except Exception:
                    return None
            continue
        if step == 'add_modulo_256':
            if k < len(rest):
                try:
                    ak = int(rest[k], 16) if any(c in rest[k].lower() for c in 'abcdef') else int(rest[k])
                    data = bytes((b - ak) % 256 for b in data)
                    k += 1
                except Exception:
                    pass
            continue
        if step.startswith('repeating_key_xor'):
            try:
                # the key may be in the same step after a comma, or on the following codec segment (we split by |)
                _, csvkey = step.split(',', 1) if ',' in step else (step, '')
            except Exception:
                csvkey = ''
            if not csvkey and k < len(rest):
                csvkey = rest[k]
                k += 1
            if not csvkey:
                continue
            try:
                key = bytes(int(x, 16) for x in csvkey.split(','))
            except Exception:
                try:
                    key = bytes(int(x) for x in csvkey.split(','))
                except Exception:
                    return None
            if not key:
                return None
            data = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        elif ',' in step and all(part.strip() for part in step.split(',')):
            # bare csv-hex key as a trailing segment (produced by naive codec.split('|') on
            # 'repeating_key_xor|9e,7a,91,0d,82'): treat as the repeating_key_xor key.
            try:
                key = bytes(int(x, 16) for x in step.split(','))
            except Exception:
                continue
            if key:
                data = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return data.decode('utf-8', 'replace')


def bash_adv_desc(path):
    s = open(path, encoding='utf-8', errors='replace').read()
    # Day 23 variants: MATERIAL_/CODEC_ in upper or lower / title case, single or double quotes.
    m = re.search(r"(?i)Material_\w+\s*=\s*['\"]([^'\"]*)['\"]", s)
    c = re.search(r"(?i)Codec_\w+\s*=\s*['\"]([^'\"]*)['\"]", s)
    if not m or not c:
        return None
    t = bash_adv_decode(m.group(1), c.group(1))
    if t and t.startswith('v='):
        kv = dict(x.split('=', 1) for x in t.split('|') if '=' in x)
        # Only accept a well-formed descriptor; a wrong codec can decode to garbage that still starts with 'v='.
        if _d23_valid_kv(kv):
            return kv
    return None


# ---------- Day 23 (Press Start to Decode) universal post-processor -----------
# Many Day 23 ids ask for derived fields (host, leaf, token, indicator, style, secondary, tertiary, ...)
# on top of the base descriptor, OR for ordinary url/campaign/steps/role fields on languages whose per-
# language build branch does not know these new field names. One pass computes the file -> KV descriptor
# map once (bash_adv_desc / desc_of fallbacks), then derives every answerable field.

_D23_VRE = re.compile(r'v=\d\|[\x20-\x7e]*')


def _d23_valid_kv(kv):
    """A descriptor kv is accepted only if it is well-formed: 'v' is a single digit, there are at least two
    more key=value pairs, every key is a lowercase identifier, and every value is printable ASCII with no
    control bytes. This rejects a false-positive decode (a wrong XOR that happens to contain 'v=1|' followed
    by garbage), which otherwise poisons the whole batch."""
    if not isinstance(kv, dict):
        return False
    v = kv.get('v')
    if not (isinstance(v, str) and len(v) == 1 and v.isdigit()):
        return False
    other = [k for k in kv if k != 'v']
    if len(other) < 2:
        return False
    for k, val in kv.items():
        if not re.fullmatch(r'[a-z][a-z0-9_]*', str(k)):
            return False
        sv = str(val)
        if not sv or any(ord(c) < 0x20 or ord(c) > 0x7e for c in sv):
            return False
    return True


def _d23_cmd_joined(src):
    """Day 23 batch/cmd/vbs/wsf fixtures spread the v=1| descriptor across concatenated set statements
    ('set v_a0=v=1^|...' / 'set fragment0=v=1^|...'). Reassemble by stripping ^ continuation then joining
    the <name><N>= assignments in order. Returns the joined descriptor string or ''."""
    s2 = src.replace('^|', '|').replace('^"', '"').replace('^&', '&')
    # discover a family of ordered variable assignments whose first value starts with 'v=1|' or 'v=2|'
    all_sets = list(re.finditer(r'set\s+"?([A-Za-z_][A-Za-z_0-9]*?)(\d+)\s*=\s*([^\r\n"]*)"?', s2, flags=re.IGNORECASE))
    # group by family name
    fams = {}
    for m in all_sets:
        fam = m.group(1).lower()
        idx = int(m.group(2))
        val = m.group(3)
        fams.setdefault(fam, []).append((idx, val))
    # pick the family whose smallest-index value starts with 'v=1|' or 'v=2|'
    for fam, lst in fams.items():
        lst.sort()
        if lst and (lst[0][1].startswith('v=1|') or lst[0][1].startswith('v=2|')):
            joined = ''.join(v for _, v in lst)
            m = re.search(r'v=\d\|[^"\r\n<>%!]+', joined)
            if m:
                return m.group(0)
    return ''


def _d23_descriptor_bruteforce(path):
    """Last resort: hunt a 'v=N|k=v|...' descriptor in the file bytes - direct, after a single-byte XOR of a
    colon/space/comma-separated hex payload, or after base64 decoding of any long printable-base64 run. Returns the
    best (most-fields) descriptor as a kv-dict, or None."""
    try:
        s = open(path, encoding='utf-8', errors='replace').read()
    except Exception:
        return None
    best = None
    aux = {}
    def _consider(txt):
        nonlocal best
        if not isinstance(txt, str):
            return
        # Day 23 regex fallback: `"steps":["a","b",...]` present but outer JSON brace unmatched.
        sm = re.search(r'"steps"\s*:\s*\[\s*((?:"[^"]+"\s*,?\s*)+)\]', txt)
        if sm:
            steps_list = re.findall(r'"([^"]+)"', sm.group(1))
            if steps_list:
                aux.setdefault('steps', ','.join(steps_list))
                am = re.search(r'"adapter"\s*:\s*"([^"]+)"', txt)
                if am:
                    aux.setdefault('adapter', am.group(1))
                cm = re.search(r'"stageCount"\s*:\s*(\d+)', txt)
                if cm:
                    aux.setdefault('stage_count', cm.group(1))
        for m in _D23_VRE.finditer(txt):
            raw = m.group(0)
            # trim at the first run of chars that cannot be part of a k=v|... descriptor
            kv = {}
            for part in raw.split('|'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    kv[k] = v
                elif part == '':
                    continue
                else:
                    break  # a bare segment (not k=v) ends the descriptor
            if _d23_valid_kv(kv) and len(kv) > (len(best) if best else 1):
                best = kv
        # Day 23 jscript/batch/vbs variant: the decoded payload is a JSON object with 'steps', 'adapter',
        # 'values' (containing campaign_id/url/file_path/...), 'stageCount', etc. Flatten it to the same kv shape.
        try:
            import json as _json
            # find JSON objects with proper brace matching
            i = 0
            while i < len(txt):
                if txt[i] != '{':
                    i += 1
                    continue
                depth = 0
                in_str = False
                esc = False
                for j in range(i, min(len(txt), i + 100000)):
                    ch = txt[j]
                    if esc:
                        esc = False
                        continue
                    if ch == '\\' and in_str:
                        esc = True
                        continue
                    if ch == '"':
                        in_str = not in_str
                        continue
                    if in_str:
                        continue
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            raw = txt[i:j+1]
                            try:
                                obj = _json.loads(raw)
                                if isinstance(obj, dict) and len(obj) >= 3:
                                    kv = {}
                                    for k, v in obj.items():
                                        if isinstance(v, (list, tuple)):
                                            kv[k] = ','.join(str(x) for x in v)
                                        elif isinstance(v, dict):
                                            for kk, vv in v.items():
                                                if isinstance(vv, (list, tuple)):
                                                    kv[kk] = ','.join(str(x) for x in vv)
                                                else:
                                                    kv[kk] = str(vv)
                                        else:
                                            kv[k] = str(v)
                                    if 'stageCount' in kv and 'stage_count' not in kv:
                                        kv['stage_count'] = kv['stageCount']
                                    if 'steps' in kv and isinstance(obj.get('steps'), list):
                                        kv['steps'] = ','.join(obj['steps'])
                                    if ('url' in kv or 'file_path' in kv or 'campaign_id' in kv or 'steps' in kv) and len(kv) > (len(best) if best else 1):
                                        best = kv
                                    # Day 23 PowerShell composite: JSON uses single-letter keys. The specimen
                                    # type is detected from the shape:
                                    # resource-hijacking: has g (int) and h (mutex, 'Global\\...'); c = wallet (scalar);
                                    #                     b = url; d = update/next_stage; e = registry/persistence; f = user_agent
                                    # collection:         no g/h; c = list of files; b = url; d = staged archive (zip);
                                    #                     e = mutex; f = user_agent
                                    # impact:             b = extension; c = note; d = url
                                    if 'a' in kv and 'b' in kv and 'c' in kv:
                                        has_g = 'g' in kv
                                        has_h = 'h' in kv
                                        c_raw = obj.get('c') if isinstance(obj, dict) else kv.get('c')
                                        if has_g or has_h:
                                            # resource-hijacking
                                            ps = {
                                                'specimen_type': 'resource-hijacking',
                                                'campaign_id': 'campaign-' + str(kv['a']) if not str(kv['a']).startswith('campaign-') else str(kv['a']),
                                                'url': str(kv['b']),
                                                'wallet_address': str(kv['c']),
                                                'wallet': str(kv['c']),
                                                'next_stage': str(kv.get('d', '')),
                                                'mutex': str(kv.get('h', kv.get('e', ''))),
                                                'mutex_name': str(kv.get('h', kv.get('e', ''))),
                                                'user_agent': str(kv.get('f', '')),
                                                'host_id': 'host-' + str(kv['a']),
                                            }
                                        elif isinstance(c_raw, (list, tuple)):
                                            # collection
                                            first = str(c_raw[0]) if c_raw else ''
                                            ps = {
                                                'specimen_type': 'collection',
                                                'campaign_id': 'campaign-' + str(kv['a']) if not str(kv['a']).startswith('campaign-') else str(kv['a']),
                                                'url': str(kv['b']),
                                                'staged_file': first,
                                                'next_stage_file': first,
                                                'mutex': str(kv.get('e', '')),
                                                'user_agent': str(kv.get('f', '')),
                                                'host_id': 'host-' + str(kv['a']),
                                            }
                                        else:
                                            # impact (or unknown)
                                            ps = {
                                                'specimen_type': 'impact',
                                                'campaign_id': 'campaign-' + str(kv['a']) if not str(kv['a']).startswith('campaign-') else str(kv['a']),
                                                'extension': str(kv['b']),
                                                'recovery_note_name': str(kv['c']),
                                                'note_name': str(kv['c']),
                                                'url': str(kv.get('d', '')),
                                                'host_id': 'host-' + str(kv['a']),
                                            }
                                        ps.update({k: str(v) for k, v in kv.items() if k not in ps})
                                        if best is None or len(ps) > len(best):
                                            best = ps
                            except Exception:
                                pass
                            i = j + 1
                            break
                else:
                    i += 1
                    continue
        except Exception:
            pass
    _consider(s)
    # Day 23 batch/cmd: the descriptor is concatenated across `set v_aN=...` statements with ^| escapes.
    joined = _d23_cmd_joined(s)
    if joined:
        _consider(joined)
    if best is not None and len(best) >= 4:
        return best
    # UNIFIED byte-sequence sweep (Day 23): gather every candidate material - separated number runs (decimal OR
    # hex, ANY separator: colon, dash, comma, space, pipe), bracket arrays, percent-hex, and base64 runs - and every
    # candidate repeating key (short 2..32 number array). For each material (and its byte-reverse) try identity,
    # single-byte XOR/add/sub, rolling XOR (seed 0..255), and repeating-key XOR with each candidate key. _consider
    # accepts only a printable descriptor, so a wrong transform never wins.
    import base64 as _b64

    def _emit(b):
        """try every bounded transform of byte-string b and feed each to _consider; stop early once best is solid."""
        if not b or len(b) < 20 or len(b) > 200000:
            return
        for bv in (b, b[::-1]):
            try:
                _consider(bv.decode('utf-8', 'replace'))
            except Exception:
                pass
            for k in range(1, 256):
                for op in (0, 1, 2):
                    try:
                        if op == 0:
                            out = bytes(x ^ k for x in bv)
                        elif op == 1:
                            out = bytes((x - k) % 256 for x in bv)
                        else:
                            out = bytes((x + k) % 256 for x in bv)
                        _consider(out.decode('utf-8', 'replace'))
                    except Exception:
                        continue
                    if best is not None and len(best) >= 8:
                        return
            for seed in range(256):
                try:
                    out = bytearray(len(bv))
                    prev = seed
                    for i, x in enumerate(bv):
                        out[i] = x ^ prev
                        prev = x
                    _consider(bytes(out).decode('utf-8', 'replace'))
                except Exception:
                    continue
                if best is not None and len(best) >= 8:
                    return
            for key in _KEYS:
                try:
                    _consider(bytes(x ^ key[i % len(key)] for i, x in enumerate(bv)).decode('utf-8', 'replace'))
                except Exception:
                    continue
                if best is not None and len(best) >= 8:
                    return

    # candidate repeating keys: short number arrays [a,b,c] (decimal or 0x hex), 2..32 elements
    _KEYS = []
    for mm in re.finditer(r'\[\s*((?:0x[0-9a-fA-F]{1,2}|\d{1,3})(?:\s*,\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3})){1,31})\s*\]', s):
        try:
            vals = [int(x, 0) & 0xff for x in mm.group(1).split(',')]
        except Exception:
            continue
        if 2 <= len(vals) <= 32:
            _KEYS.append(bytes(vals))

    # 1) separated number runs inside string literals (decimal or hex, any separator)
    for qm in re.finditer(r'"([0-9a-fA-F]{1,3}(?:[:\-,\s|][0-9a-fA-F]{1,3}){39,})"', s):
        body = qm.group(1)
        toks = re.split(r'[:\-,\s|]+', body)
        toks = [t for t in toks if t]
        # decimal reading
        try:
            if all(t.isdigit() and int(t) < 256 for t in toks):
                _emit(bytes(int(t) for t in toks))
        except Exception:
            pass
        if best is not None and len(best) >= 8:
            break
        # hex reading (2-digit pairs)
        try:
            if all(re.fullmatch(r'[0-9a-fA-F]{1,2}', t) for t in toks):
                _emit(bytes(int(t, 16) for t in toks))
        except Exception:
            pass
        if best is not None and len(best) >= 8:
            break
    # 2) bracket arrays (both key-length and payload-length, decimal/hex), each alone AND all concatenated in order
    if not (best is not None and len(best) >= 8):
        _arr_all = []
        for mm in re.finditer(r'\[\s*((?:0x[0-9a-fA-F]{1,2}|\d{1,3})(?:\s*,\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3}))*)\s*\]', s):
            try:
                vals = [int(x, 0) & 0xff for x in mm.group(1).split(',')]
            except Exception:
                continue
            if len(vals) >= 40:
                _emit(bytes(vals))
                if best is not None and len(best) >= 8:
                    break
            if 2 <= len(vals) <= 20000:
                _arr_all.append(vals)
        # the material may be split across firstPart.concat(secondPart) etc: try the concatenation of all arrays
        if not (best is not None and len(best) >= 8) and len(_arr_all) >= 2:
            cat = []
            for vv in _arr_all:
                cat.extend(vv)
            if 40 <= len(cat) <= 200000:
                _emit(bytes(cat))
    # 3) percent-hex
    if not (best is not None and len(best) >= 8):
        for mm in re.finditer(r'(?:%[0-9a-fA-F]{2}){20,}', s):
            try:
                _emit(bytes.fromhex(mm.group(0).replace('%', '')))
            except Exception:
                pass
            if best is not None and len(best) >= 8:
                break
    # 4) base64 runs: single long runs AND multi-piece concatenations joined by '+' (jscript multi-line base64)
    if not (best is not None and len(best) >= 8):
        cands = [m.group(0) for m in re.finditer(r'[A-Za-z0-9+/_-]{100,}={0,2}', s)]
        # Each '"..." + "..." + "..."' chain is one logical base64 payload.
        for cm in re.finditer(r'((?:"[A-Za-z0-9+/=_-]*"\s*\+\s*)+"[A-Za-z0-9+/=_-]*")', s):
            parts = re.findall(r'"([A-Za-z0-9+/=_-]*)"', cm.group(1))
            full = ''.join(parts)
            if 40 <= len(full) <= 200000:
                cands.append(full)
        for txt in cands:
            for c in (txt, txt[::-1]):
                try:
                    _emit(_b64.b64decode(c + '=' * (-len(c) % 4), validate=False))
                except Exception:
                    continue
                if best is not None and len(best) >= 8:
                    break
            if best is not None and len(best) >= 8:
                break
    # Merge any auxiliary values collected by regex fallbacks (steps, adapter, stage_count).
    if aux:
        if isinstance(best, dict):
            for k, v in aux.items():
                best.setdefault(k, v)
        else:
            best = None if _strict() else dict(aux)      # regex-only crumbs (steps / adapter / stage_count) are not a descriptor
    return best


def _d23_detect_style_js(src):
    """jscript style = function-style|invocation-style|property-style, via the canonical
    solve_script_inventory.jsstyle (tested against GM-accepted labels on earlier days)."""
    try:
        import solve_script_inventory as _SI
        fs, inv, ps = _SI.jsstyle(src)
        return '%s|%s|%s' % (fs, inv, ps)
    except Exception:
        return None


def _d23_detect_style_vbs(src, kv):
    """vbscript style = descriptor-representation|byte-transform|control-flow-wrapper. representation and
    transform are the first two Codec_ tokens verbatim; control is the canonical solve_dim_dimmer.vbs_ctl."""
    cm = re.search(r"(?i)Const\s+Codec_\w+\s*=\s*\"([^\"]*)\"", src) or re.search(r"(?i)Codec_\w+\s*=\s*['\"]([^'\"]*)['\"]", src)
    if not cm:
        return None
    parts = cm.group(1).split('|')
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    rep, tr = parts[0], parts[1]
    try:
        import solve_dim_dimmer as _DD
        ctl = _DD.vbs_ctl(src)
    except Exception:
        ctl = None
    if rep and tr and ctl:
        return '%s|%s|%s' % (rep, tr, ctl)
    return None


def _d23_detect_style_bat(src, kv):
    """batch style = behavior-graph-topology|control-flow-wrapper|variable-expansion-form, via the descriptor
    graph plus the canonical solve_script_inventory.bctl (control) and .expform (expansion)."""
    g = (kv.get('graph') if isinstance(kv, dict) else None)
    try:
        import solve_script_inventory as _SI
        ctl = _SI.bctl(src)
        exp = _SI.expform(_SI.region(src), src)
    except Exception:
        return None
    if g and ctl and exp:
        return '%s|%s|%s' % (g, ctl, exp)
    return None


def _d23_file_kv(d):
    """{basename: kv-dict} for every file whose descriptor we can decode.
    DETERMINISM (independent review 2026-10-23, finding #9): _d23_fill's by_hash lookup keeps whichever same-stem file
    this function visited LAST. os.listdir() order is filesystem-dependent, not insertion order, so a hypothetical
    stem collision would resolve non-deterministically across two copies of the same zip. Sorted here once, at zero
    cost (no real collision was found scanning every preserved Day 15-23 real evidence.zip, 2,543 files - this closes
    the latent hazard without changing any observed answer)."""
    import os as _os
    out = {}
    for f in sorted(_os.listdir(d)):
        p = _os.path.join(d, f)
        kv = None
        try:
            kv = bash_adv_desc(p)
        except Exception:
            kv = None
        if not kv:
            try:
                _k, _v = desc_of(p)
                if _v:
                    kv = _v
            except Exception:
                pass
        if not kv:
            try:
                import autosolve_script as _AS
                kv = _AS.generic_decode(p)
            except Exception:
                kv = None
        if not isinstance(kv, dict) or not kv:
            kv = _d23_descriptor_bruteforce(p)
        if isinstance(kv, dict):
            # Day 23 style enrichment per language extension
            try:
                src = open(p, encoding='utf-8', errors='replace').read()
                ext = _os.path.splitext(f)[1].lower()
                if ext in ('.js', '.mjs', '.cjs'):
                    st = _d23_detect_style_js(src)
                    if st and 'style' not in kv:
                        kv['style'] = st
                elif ext in ('.vbs', '.vbe'):
                    st = _d23_detect_style_vbs(src, kv)
                    if st and 'style' not in kv:
                        kv['style'] = st
                elif ext in ('.bat', '.cmd'):
                    st = _d23_detect_style_bat(src, kv)
                    if st and 'style' not in kv:
                        kv['style'] = st
            except Exception:
                pass
            out[f] = kv
    return out


# STRICT MODE (2026-10-23, independent review + coverage proof). On a TIMED route (time_trial / mastery: ONE complete submit, graded all-or-nothing) a derivation that no GM-ACCEPTED batch has
# ever exercised returns None, so the field stays unresolved and the lane HELDs with the id listed, instead of returning a plausible guess (the "complete but wrong batch" class). "Exercised"
# was MEASURED: a line trace over every preserved GM-accepted script batch (Days 15-23, 16 batches) - the branches below never ran in any of them. The Single and other untimed routes keep
# the old behaviour. Set from start['mode'] by autosolve_script.solve_fields_ext; HUNTRESS_POLY_LENIENT=1 switches it off (a Commander decision, not an agent default).
_STRICT = [False]


def set_strict_for_mode(mode):
    _STRICT[0] = str(mode or '').strip().lower() in ('time_trial', 'mastery')


def _strict():
    return _STRICT[0] and os.environ.get('HUNTRESS_POLY_LENIENT') != '1'


_D23_ATT_BY_LANG = {
    'ps1': 'T1059.001', 'powershell': 'T1059.001',
    'py': 'T1059.006', 'python': 'T1059.006',
    'bat': 'T1059.003', 'cmd': 'T1059.003', 'batch': 'T1059.003',
    'vbs': 'T1059.005', 'vbscript': 'T1059.005',
    'js': 'T1059.007', 'jscript': 'T1059.007', 'javascript': 'T1059.007',
    'mjs': 'T1059.007', 'nodejs': 'T1059.007', 'typescript': 'T1059.007', 'ts': 'T1059.007',
    'sh': 'T1059.004', 'bash': 'T1059.004',
    'php': 'T1059.004', 'perl': 'T1059.004', 'pl': 'T1059.004',
    'ruby': 'T1059.006', 'rb': 'T1059.006',
    'lua': 'T1059.004', 'applescript': 'T1059.002', 'autoit': 'T1059',
    'auto_hotkey': 'T1059', 'groovy': 'T1059', 'csharp_script': 'T1059',
    'wmi_mof': 'T1047', 'msbuild_xml': 'T1127.001', 'nsis': 'T1218',
    'github_actions': 'T1053', 'google_apps_script': 'T1059',
    'gdscript': 'T1059',
}


# MEASURED 2026-10-23 (line trace over the 16 preserved GM-accepted script batches, Days 15-23): of the 34 keys above only these five were ever looked up while producing an accepted answer.
# The other 29 (php, perl, lua, ruby, nsis, github_actions, msbuild_xml, ...) are unvalidated and are not returned on a timed route.
_D23_ATT_PROVEN = frozenset({'batch', 'jscript', 'nodejs', 'python', 'vbscript'})


def _d23_role(kv):
    r = kv.get('role')
    if r:
        return r
    steps = kv.get('steps', '')
    return _sh_role_from_steps(steps)


def _d23_lang_ext(fname):
    _, ext = os.path.splitext(fname)
    return (ext.lstrip('.').lower()) if ext else ''


def _d23_derive(kv, suffix, lang_hint='', is_polyglot=False):
    """Compute the value for one answer suffix from the descriptor kv-dict. Returns None if not derivable."""
    import urllib.parse as _up
    s = suffix
    def _first_indicator():
        for key in _SH_INDICATOR_ORDER:
            v = kv.get(key)
            if v:
                return v
        return None
    if s == 'role':
        return _d23_role(kv)
    if s == 'attack':
        role = _d23_role(kv)
        if role == 'benign_utility':
            return 'none'
        if role == 'persistence_descriptor':
            return 'T1053'
        if role == 'impact':
            return 'T1486'
        if role == 'uploader':
            return 'T1041'
        if role == 'downloader' or role == 'stager':
            return 'T1105'
        if role == 'dropper':
            return 'T1140'
        # Day 23: polyglot-{lang} launcher/staged_chain/relay use plain T1059 (no language sub-technique);
        # plain-language launcher/staged_chain/relay keep the language-specific T1059.X.
        if is_polyglot:
            return 'T1059'
        lh = lang_hint.lower()
        if _strict() and lh not in _D23_ATT_PROVEN:
            return None                                   # a language/technique pairing no GM-accepted batch has ever contained: unresolved, never a table guess
        return _D23_ATT_BY_LANG.get(lh)
    if s == 'steps':
        v = kv.get('steps')
        return v.replace(',', '>') if v else None
    if s == 'campaign':
        return kv.get('campaign_id')
    if s in ('campaign-token', 'token'):
        v = kv.get('campaign_id')
        if v and '-' in v:
            return v.split('-', 1)[1]
        return None
    if s == 'url':
        return kv.get('url')
    if s == 'upload-url':
        return kv.get('upload_url')
    if s == 'host' or s == 'url-host':
        v = kv.get('url')
        if v:
            try:
                h = _up.urlparse(v).hostname
                if h:
                    return h
            except Exception:
                pass
        return None if _strict() else kv.get('host_id')
    if s == 'host-id':
        return kv.get('host_id')
    if s == 'path' or s == 'file-path':
        return kv.get('file_path')
    if s == 'leaf' or s == 'path-leaf':
        v = kv.get('file_path') or kv.get('schedule_path') or kv.get('next_stage_file') or ''
        if v:
            # split by / or \
            seg = re.split(r'[\\/]', v)[-1]
            return seg or v
        return None
    if s == 'count' or s == 'stage-count':
        v = kv.get('stage_count')
        return str(int(v)) if v is not None else None
    if s == 'profile' or s == 'stage-profile':
        return kv.get('stage_profile')
    if s == 'language' or s == 'next-language':
        return kv.get('next_language')
    if s == 'obfuscation':
        v1 = kv.get('syntax') or kv.get('syntax_profile')
        v2 = kv.get('obfuscation') or kv.get('obfuscation_profile')
        if v1 and v2:
            return v1 + '|' + v2
        return None if _strict() else (v2 or v1)
    if s == 'carrier':
        v1 = kv.get('carrier') or kv.get('carrier_profile')
        v2 = kv.get('windows_chain') or kv.get('execution_chain') or kv.get('windows_execution_chain')
        if v1 and v2:
            return v1 + '|' + v2
        return None if _strict() else v1
    if s == 'style':
        parts = []
        for k in ('function_style', 'invocation_style', 'property_style', 'property_access_style',
                  'descriptor_property_access_style', 'descriptor_property_style'):
            if kv.get(k):
                parts.append(kv[k])
        if parts and not _strict():
            return '|'.join(parts)
        return kv.get('style')
    if s == 'indicator':
        return _first_indicator()
    if s == 'secondary':
        # Day 23 PowerShell: by specimen type - wallet (resource-hijacking), staged file (collection), note name (impact).
        st = kv.get('specimen_type')
        if st == 'resource-hijacking':
            return kv.get('wallet_address') or kv.get('wallet')
        if st == 'collection':
            return kv.get('staged_file') or kv.get('next_stage_file')
        if st == 'impact':
            return kv.get('note_name') or kv.get('recovery_note_name')
        if _strict():
            return None                               # no specimen_type: do not pick whichever field happens to be non-empty
        return kv.get('wallet_address') or kv.get('wallet') or kv.get('staged_file') or kv.get('note_name') or kv.get('recovery_note_name')
    if s == 'tertiary':
        st = kv.get('specimen_type')
        if st == 'resource-hijacking':
            return kv.get('mutex_name') or kv.get('mutex')
        if st == 'collection':
            return kv.get('user_agent')
        if st == 'impact':
            return kv.get('extension')
        if _strict():
            return None
        return kv.get('mutex') or kv.get('mutex_name') or kv.get('user_agent') or kv.get('extension')
    if s == 'adapter':
        return kv.get('adapter')
    if s == 'feature':
        return kv.get('feature')
    if s == 'primitive':
        return kv.get('primitive')
    if s == 'id':
        return kv.get('handoff_id') or kv.get('id')
    return None


_D23_SUFFIX_RE = re.compile(r'^(?P<lang>[a-z_]+(?:-advanced)?|polyglot-[a-z_]+|host-[a-z_]+)-(?P<hash>[0-9a-f]{4,16})-(?P<suf>[A-Za-z][-A-Za-z]*)$')


def _d23_fill(d, ids):
    """Derive answers for every supported Day 23 id. Non-destructive: returns {id: value}.
    Mastery ids carry a 'setN.' prefix on top of the single/time-trial shape; the derivation is identical,
    so the prefix is stripped for matching and the original id is used as the output key."""
    kvs = _d23_file_kv(d)
    by_hash = {}
    for f, kv in kvs.items():
        stem = os.path.splitext(f)[0]
        if re.fullmatch(r'[0-9a-f]{4,16}', stem):
            by_hash[stem] = (f, kv)
    out = {}
    for i in ids:
        base = re.sub(r'^set\d+\.', '', i)
        m = _D23_SUFFIX_RE.match(base)
        if not m:
            continue
        h = m.group('hash')
        suf = m.group('suf')
        lang = m.group('lang')
        is_poly = False
        if lang.startswith('polyglot-'):
            lang_hint = lang[len('polyglot-'):]
            is_poly = True
        elif lang.startswith('host-'):
            lang_hint = lang[len('host-'):]
        else:
            lang_hint = lang
        if h not in by_hash:
            continue
        _, kv = by_hash[h]
        try:
            v = _d23_derive(kv, suf, lang_hint, is_polyglot=is_poly)
        except Exception:
            v = None
        if v is not None and v != '':
            out[i] = v
    return out


BASH_SUF = {'feature': 'feature', 'primitive': 'primitive', 'campaign': 'campaign_id', 'stage-count': 'stage_count',
            'steps': 'steps'}

# Day 23 plain-bash fixtures (Press Start to Decode): same Material_/Codec_ descriptor,
# but new per-file 'role'/'indicator'/'campaign-token' derivations and a wider set of codecs.
_SH_ROLE_BY_STEPS = {
    'decode_configuration,return_configuration': 'benign_utility',
    'acquire_remote,dispatch_pipe': 'stager',
    'acquire_remote,dispatch_memory': 'stager',
    'decode_embedded,write_file': 'dropper',
    'acquire_remote,write_file': 'downloader',
    'locate_local,dispatch_process': 'launcher',
    'profile_host,acquire_remote,write_file,change_mode,dispatch_process': 'staged_chain',
    'profile_host,acquire_remote,decode_embedded,write_file,dispatch_process': 'staged_chain',
    'acquire_remote,write_file,dispatch_process,handoff_script': 'staged_chain',
    'decode_configuration,locate_interpreter,dispatch_next_stage': 'relay',
    'build_schedule,register_descriptor': 'persistence_descriptor',
    'collect_local,encode_archive,transmit_remote': 'uploader',
    'collect_local,upload_remote': 'uploader',
    'select_fixture_files,transform_copy,write_recovery_note': 'impact',
    'transform_content,write_recovery_note': 'impact',
}


def _sh_role_from_steps(steps):
    if not steps:
        return None
    if steps in _SH_ROLE_BY_STEPS:
        return _SH_ROLE_BY_STEPS[steps]
    st = steps.split(',')
    if any(s == 'handoff_script' for s in st) or any(s == 'dispatch_next_stage' for s in st):
        if _strict():
            return None
        if 'locate_interpreter' in st and 'decode_configuration' in st:
            return 'relay'
        return 'staged_chain'
    if 'write_recovery_note' in st:
        return 'impact'
    if 'register_descriptor' in st and 'build_schedule' in st:
        return None if _strict() else 'persistence_descriptor'
    if 'upload_remote' in st or 'transmit_remote' in st:
        return 'uploader'
    if _strict():
        return None                                   # every table hit and every heuristic above ran in an accepted batch; the guesses below never did
    if len(st) >= 3:
        return 'staged_chain'
    if 'return_configuration' in st or st[0] == 'decode_configuration':
        return 'benign_utility'
    if 'decode_embedded' in st:
        return 'dropper'
    if 'acquire_remote' in st and 'write_file' in st:
        return 'downloader'
    if 'acquire_remote' in st:
        return 'stager'
    if any(s.startswith('dispatch') for s in st):
        return 'launcher'
    return 'staged_chain'


# Exact priority from the GM question: URL, upload URL, next-stage file, file path, schedule path,
# recovery-note name, host id. Each level has one canonical descriptor key (with a known alias).
_SH_INDICATOR_ORDER = ('url', 'upload_url', 'next_stage_file', 'next_stage',
                       'file_path', 'schedule_path',
                       'recovery_note_name', 'note_name', 'host_id')


def extra_answers(d, ids):
    """ids may carry a 'setN.' prefix. -> answers for polyglot-/host- (v=3 descriptors) and bash-advanced- fixtures."""
    plain = {i: re.sub(r'^set\d+\.', '', i) for i in ids}
    A, _ = poly_answers(d, list(plain.values()))
    out = {i: A[p] for i, p in plain.items() if p in A}
    for i, p in plain.items():
        # advanced-bash fixtures (Day 08+): keeps the historical role/attack labels.
        m = re.match(r'^bash-advanced-(.+)-(role|attack|feature|primitive|campaign|campaign-token|stage-count|steps|indicator)$', p)
        if m:
            fn = [f for f in os.listdir(d) if os.path.splitext(f)[0] == m.group(1) and f.endswith('.sh')]
            kv = bash_adv_desc(os.path.join(d, fn[0])) if fn else None
            if not kv:
                continue
            k = m.group(2)
            if k == 'role':
                out[i] = 'advanced_syntax'
            elif k == 'attack':
                out[i] = 'T1059.004'
            elif k == 'campaign-token':
                v = kv.get('campaign_id')
                if v and '-' in v:
                    out[i] = v.split('-', 1)[1]
            elif k == 'indicator':
                for key in _SH_INDICATOR_ORDER:
                    if kv.get(key):
                        out[i] = kv[key]
                        break
            else:
                v = kv.get(BASH_SUF[k])
                if v is not None:
                    out[i] = v.replace(',', '>') if k == 'steps' else v
            continue
        # Day 23 plain-bash fixtures: bash-<hex>-<suffix>
        m = re.match(r'^bash-([0-9a-f]{4,10})-(role|steps|campaign|campaign-token|indicator|attack)$', p)
        if not m:
            continue
        fn = [f for f in os.listdir(d) if os.path.splitext(f)[0] == m.group(1) and f.endswith('.sh')]
        kv = bash_adv_desc(os.path.join(d, fn[0])) if fn else None
        if not kv:
            continue
        k = m.group(2)
        if k == 'role':
            r = _sh_role_from_steps(kv.get('steps', ''))
            if r:
                out[i] = r
        elif k == 'attack':
            out[i] = 'T1059.004'
        elif k == 'steps':
            v = kv.get('steps')
            if v:
                out[i] = v.replace(',', '>')
        elif k == 'campaign':
            v = kv.get('campaign_id')
            if v:
                out[i] = v
        elif k == 'campaign-token':
            v = kv.get('campaign_id')
            if v and '-' in v:
                out[i] = v.split('-', 1)[1]
        elif k == 'indicator':
            for key in _SH_INDICATOR_ORDER:
                if kv.get(key):
                    out[i] = kv[key]
                    break
    # Day 23 universal post-processor for any field type/language not covered above.
    try:
        for _k, _v in _d23_fill(d, [i for i in ids if i not in out]).items():
            out.setdefault(_k, _v)
    except Exception as _e:
        print('d23 fill failed:', _e, file=sys.stderr)
    return out


if __name__ == '__main__':
    d = sys.argv[1]
    st = json.load(open(sys.argv[2])); st = st.get('start', st)
    ids = [q['id'] for q in st['questions']]
    A, kinds = poly_answers(d, ids)
    print(len(A), dict(kinds))
