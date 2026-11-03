#!/usr/bin/env python3
"""Autosolve adapter for the script-analysis lane (script_inventory family), generic across days.

Entry points:
  run(gm, challenge_id) -> result dict    PREFERRED for the dispatcher. One attempt: full batch submit; if it is not
                                          CORRECT, grouped then per-field submits in the SAME attempt (the GM rejects a
                                          whole batch if any field is wrong but banks accepted individual submits), so
                                          one unknown/wrong field never sinks the attempt.
  compute(start, blobs) -> answers dict   ctf_gm.solve_mode contract (all-or-nothing batch; use only if run() is unusable).

Reuses the Day 07 unified solver (solve_node_by_node.analyze/build: ps1/js/cmd/bat/vbs/py/sh/mjs). Files that no known
decoder handles (a NEW language, or a mutated codec) go through a generic self-decoding Material_<id>/Codec_<id> decoder;
what still cannot be resolved is reported in result['unresolved'] instead of crashing.
Must be run with the framework root as the working directory (solve_node_by_node resolves paths from os.getcwd()).

CLI (from framework root, WSL): python3 challenges/_lib/autosolve_script.py <challenge id> [--dry]
"""
import json, os, re, shutil, sys, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import solve_node_by_node as SN
import decode_bash as DB
import decode_node as DN
from ctf_gm import unzip
import ctf_gm as _cg  # TIMED WINDOW BUDGET (2026-10-11, same pattern as ctf_gm.GM.start / autosolve_binary): this adapter
# calls gm._post directly instead of GM.start, so it must open/check the window itself - a 429 backoff here used to be
# able to sleep past a ranked attempt's deadline exactly like the D-Day incident (see ctf_gm.py's WindowExpired doc).

# ---- LANGUAGE REGISTRY: a new script language next day = ONE appended row in kb/script_tables.json ("interpreters") ------------------------
# ext -> label, attack (interpreter ATT&CK sub-technique when it is CERTAIN, else None), cand (ordered candidates the per-field fallback in run()
# probes when attack is None), plus the syntax the generic Material_/Codec_ extractor needs (syn, a name in _SYN):
#   strs   regexes of string literals (first match group, or the literal minus its delimiters, is the content)
#   assign assignment tokens (regex alternation) and concat operators (regex alternation)
# D32: the rows moved from code to the append-only data file (re-read when its mtime changes, one stat per call); the row text and order are
# byte-for-byte the former in-code table (generated from it), so no carrier changed. The per-row rationale is the row's "note".
_DQ, _SQ, _BQ = r'"(?:[^"\\]|\\.)*"', r"'(?:[^'\\]|\\.)*'", r'`(?:[^`\\]|\\.)*`'
_C = {'strs': (_DQ, _SQ, _BQ), 'assign': r':=|=|:', 'concat': r'\+|&|\.|,'}          # C-like / shell / VB / Python default
_SYN = {'c': _C, 'autoit': dict(_C, concat=r'\.|&'),
        'lua': {'strs': (r'\[(?P<eq>=*)\[.*?\](?P=eq)\]', _DQ, _SQ), 'assign': r'=', 'concat': r'\.\.'},
        'applescript': {'strs': (_DQ,), 'assign': r'\bto\b|=', 'concat': r'&'},
        'perl': dict(_C, concat=r'\.|,'), 'ruby': dict(_C, strs=(_DQ, _SQ), concat=r'\+'),
        'php': dict(_C, strs=(_DQ, _SQ), concat=r'\.')}
TABLES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kb', 'script_tables.json')
LANGS = {}
TABLES = {'role_attack': [], 'aliases': {}}
_TABLES_MTIME = [None]


def tables():
    """The kb/script_tables.json data (interpreters -> LANGS in place, role_attack, aliases). Re-read only when the file's mtime changed;
    a missing or broken file keeps the last good tables (never raises)."""
    try:
        mt = os.stat(TABLES_PATH).st_mtime_ns
    except OSError:
        return TABLES
    if mt == _TABLES_MTIME[0]:
        return TABLES
    try:
        doc = json.load(open(TABLES_PATH, encoding='utf-8'))
        langs = {}
        for row in doc.get('interpreters') or []:
            ent = {'label': row['label'], 'attack': row.get('attack'), 'cand': tuple(row.get('cand') or ()), 'syn': _SYN[row.get('syn') or 'c']}
            for e in row['ext']:
                langs.setdefault(e.lower(), ent)          # append-only: an earlier row for an extension is never overridden
        LANGS.clear(); LANGS.update(langs)
        TABLES['role_attack'] = [r for r in (doc.get('role_attack') or []) if r.get('role') and r.get('attack')]
        TABLES['aliases'] = {k: list(v) for k, v in (doc.get('aliases') or {}).items()}
        EXT_LANG.clear(); EXT_LANG.update({e: v['label'] for e, v in LANGS.items()})
        _TABLES_MTIME[0] = mt
    except Exception as e:
        print('autosolve_script: kb/script_tables.json unreadable (%s); keeping the last tables' % type(e).__name__, file=sys.stderr)
    return TABLES


EXT_LANG = {}                                                            # kept for callers of the old name
tables()
CONTRACT_REJECTED = {}                                                   # {answer id: reason} of the LAST solve_fields_ext: derived values that violated their answer_format
MODEL_SUFFIX = ('-scenario', '-role', '-attack', '-control', '-expansion')


def _lang(path):
    tables()                                                             # one stat: picks up an appended kb/script_tables.json row at once
    return LANGS.get(os.path.splitext(path)[1].lower(), {'label': '', 'attack': None, 'cand': (), 'syn': _C})


_LUA_LONG = re.compile(r'\[(=*)\[(.*)\]\1\]$', re.S)


def _inner(lit):
    """the content of one string literal: a Lua long string as is (no escapes inside), any quoted literal JS-unescaped. The ONE unescaper
    for every literal reader in this module (D32: the former _inner_lit duplicate is gone)."""
    lb = _LUA_LONG.match(lit)
    return lb.group(2) if lb else DN._js_unescape(lit[1:-1])


_SYN_RX = {}


def _syn_rx(syn):
    """compiled (string, Material_ assignment) regexes of one syntax, built once per syntax (D32: was rebuilt on every call)"""
    key = (tuple(syn['strs']), syn['assign'], syn['concat'])
    rx = _SYN_RX.get(key)
    if rx is None:
        s = '(?:' + '|'.join(syn['strs']) + ')'       # string regexes may carry their own named groups (Lua long strings)
        rx = _SYN_RX[key] = (s, re.compile(s, re.S),
                             re.compile(r'(?i)\bmaterial_(?P<hid>\w+)\s*(?:' + syn['assign'] + r')\s*\(?\s*(?P<body>(?:' + s + r'\s*(?:' +
                                        syn['concat'] + r')?\s*)+)', re.S))
    return rx


def _generic_material(src, syn=_C):
    """Material_<id> / MATERIAL_<id> assigned a (possibly concatenated) string literal, using the language's syntax."""
    s, s_rx, mat_rx = _syn_rx(syn)
    m = mat_rx.search(src)
    if not m:
        raise RuntimeError('no Material_')
    hid = m.group('hid')
    mat = ''.join(_inner(p.group(0)) for p in s_rx.finditer(m.group('body')))
    c = re.search(r'(?i)\bcodec_' + re.escape(hid) + r'\s*(?:' + syn['assign'] + r')\s*(?P<lit>' + s + ')', src, re.S)
    if not c:
        raise RuntimeError('no Codec_')
    return mat, _inner(c.group('lit'))


# ---- UNIVERSE FALLBACK (2026-10-15 night, _test_script_universe.py) ---------------------------------------------------------------------
# Carriers whose idiom the per-language string regexes do not see (bat `set "Material_x=..."`, reg `"Material_x"="..."`, XML element/attribute,
# here-strings, heredocs, Rust `: &str =`, Go `:=`, bare INI/env values, PHP define(...)) and one extra byte layer (gzip / zlib / raw deflate).
# Liberal on EXTRACTION (many candidate materials), strict on VALIDATION (the decode must be a printable 'v=1|' descriptor), so an
# unrecognised sample stays undecoded and HELD - this path can add answers, never guess one.
_LIT = r'''(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)'''
_CONT_END = ('+', '&', '_', '\\', ',', '.', '^', '(')


def _stmt_after(src, pos, limit=200000):
    """the text of the logical statement that starts at pos: to the end of the line, continued while the line ends with a concat/continuation
    token or the next line starts with one (or with a quote); here-strings / heredocs / Lua long brackets run to their own terminator"""
    rest = src[pos:pos + limit]
    h = re.match(r'''[\s"':=,\]>]*?(?:@['"]|<<<\s*['"]?(?P<tag>\w+)['"]?|\[(?P<eq>=*)\[)[ \t]*\r?\n?(?P<body>.*?)(?:\r?\n[ \t]*(?:['"]@|(?P=tag);?|\](?P=eq)\])|\](?P=eq)\])''', rest, re.S) \
        if re.match(r'''[\s"':=,\]>]*?(?:@['"]|<<<|\[=*\[)''', rest) else None
    if h:
        return '\x00HERE\x00' + h.group('body')
    lines, out = rest.splitlines(), []
    for i, ln in enumerate(lines):
        out.append(ln)
        s = ln.rstrip()
        nxt = lines[i + 1].lstrip() if i + 1 < len(lines) else ''
        if s.endswith(_CONT_END) or nxt.startswith(('+', '&', '..', '. ')):       # NOT a leading quote: the next line may be the Codec_ assignment
            if i < 400:
                continue
        break
    return '\n'.join(out)


def _tok_candidates(seg):
    """ordered distinct candidate strings that could be the value that follows an identifier"""
    c = []
    if seg.startswith('\x00HERE\x00'):
        body = seg[6:]
        c.append(''.join(body.split()))
        c.append(body.strip())
        return c
    seg = re.sub(r'''^["']\s*(?=[:=])''', '', seg)                                  # key"="value  /  "key": "value"
    seg = re.sub(r'''^["']\s+\w+\s*=\s*''', '', seg)                              # Name="Material_x" Value="v"
    lm = list(re.finditer(_LIT, seg))
    lits = [m.group(0) for m in lm]
    if lits:
        chain = [lm[0]]                       # only literals JOINED by a concat operator / line continuation belong to one value
        for m in lm[1:]:
            if re.fullmatch(r'\s*(?:\+|&|\.\.|\.|,)?\s*(?:_\s*)?', seg[chain[-1].end():m.start()]):
                chain.append(m)
            else:
                break
        c.append(''.join(_inner(m.group(0)) for m in chain))
        c.extend(_inner(x) for x in lits[:3])
    m = re.search(r'>\s*([^<>]+?)\s*<', seg)                                        # <Material_x>value</Material_x>
    if m:
        c.append(m.group(1))
    line = seg.split('\n', 1)[0]
    line = re.sub(r'''^[\s"':=,\]>\[]*(?:string|&str|str|String)?[\s"':=,]*''', '', line) if not lits else line
    line = line.strip().rstrip(';,)"\'>').strip()
    if line:
        c.append(line)
        c.append(re.split(r'[\s;"\'<]', line, 1)[0])
    out = []
    for x in c:
        for y in (x.strip(), x.strip().strip('\'"`').strip()):
            if y and y not in out:
                out.append(y)
    return out


def _decompressed(bl):
    """gzip / zlib / raw deflate readings of a byte list, each capped at script_descriptor.MAX_INFLATE (S8: no unbounded inflate of challenge bytes)"""
    import script_descriptor as _SD
    outs = []
    b = bytes(bl)
    for kind in ('gzip', 'zlib', 'deflate'):
        try:
            d = _SD.bounded_decompress(b, kind)
            if d:
                outs.append(list(d))
        except Exception:
            pass
    return outs


def _layered_decode(mat, codec):
    """DN.robust_decode, plus one optional gzip/zlib/deflate layer between the representation and the declared transform"""
    try:       # the DECLARED representation first (an octal list also parses as decimal, and a wrong reading can still start with 'v=1|')
        t, how = DB.decode_codec(mat, codec, valid=DN._lenient)
        if how == 'declared':
            return t
    except Exception:
        pass
    try:
        return DN.robust_decode(mat, codec)[0]
    except Exception:
        pass
    for bl in DN._candidate_byte_lists(mat):
        for v in _decompressed(bl):
            for cd in (codec, ''):
                try:
                    return DB.decode_codec(v, cd, valid=DN._lenient)[0]
                except Exception:
                    pass
        # compression applied AFTER the transform: transform the stored bytes first, then decompress, then validate
        try:
            for tr in DB.apply_transform(bl, ((codec.split('|') + ['', ''])[1]).strip().lower(), (codec.split('|') + ['', '', ''])[2].strip()):
                for v in _decompressed(tr):
                    if DN._lenient(v):
                        return bytes(v).decode('latin-1')
        except Exception:
            pass
    raise RuntimeError('undecodable layered')


def _raw_decode(src):
    for m in re.finditer(r'(?i)\bmaterial_(\w+)', src):
        hid = m.group(1)
        mats = _tok_candidates(_stmt_after(src, m.end()))
        codecs = ['']
        for cm in re.finditer(r'(?i)\bcodec_' + re.escape(hid) + r'(?!\w)', src):
            cc = [x for x in _tok_candidates(_stmt_after(src, cm.end())) if x.count('|') >= 1 or re.fullmatch(r'[\w]+', x)]
            codecs = (cc[:6] or ['']) + ['']
            break
        for mat in mats[:8]:
            for codec in codecs:
                try:
                    text = _layered_decode(mat, codec)
                    # a descriptor is 'key=value|key=value|...': a piece without '=' means a stray tail was decoded with the material
                    if text and re.match(r'^v=\d+\|', text) and all('=' in x for x in text.strip().split('|')):
                        return text
                except Exception:
                    continue
    raise RuntimeError('no raw material')


_CONCAT_RX = re.compile(r'(?i)\bmaterial_\w+\s*(?::=|=|:)\s*\(?\s*' + _LIT + r'\s*(?:\+|&|\.\.|\.)\s*(?:_\s*)?' + _LIT, re.S)


def _concat_material(src):
    """True when a Material_<id> value is a CONCATENATION of literals (a native single-literal extractor would see only the first piece)"""
    return bool(_CONCAT_RX.search(src))


_GD_CACHE = {}                      # (sha256 of the file BYTES, extension) -> kv dict or the error text. Never keyed by file name: a Mastery
_GD_CACHE_MAX = 20000               # reuses one name with different bytes in every set (D31), and solve_poly_d8._d23_file_kv calls generic_decode again
                                    # for every file solve_fields_ext already decoded (measured: half the generic decode time on D16 TT).


def generic_decode(path):
    """Try every known Material_/Codec_ extractor, then the generic one; validate the result is a v=1| descriptor.
    The language's own result stays the answer unless another extractor recovers STRICTLY MORE descriptor fields (a native extractor that saw only
    the first piece of a concatenated literal returns a truncated 'v=1|' prefix, which must never beat the whole descriptor).
    D32: memoised by CONTENT (sha256 of the bytes + extension); a copy of the kv is returned, so a caller may enrich it."""
    import hashlib
    try:
        key = (hashlib.sha256(open(path, 'rb').read()).hexdigest(), os.path.splitext(path)[1].lower())
    except OSError:
        key = None
    hit = _GD_CACHE.get(key) if key else None
    if hit is not None:
        if isinstance(hit, str):
            raise RuntimeError(hit)
        return dict(hit)
    try:
        kv = _generic_decode_uncached(path)
    except Exception as e:
        if key:
            _GD_CACHE[key] = str(e) or type(e).__name__
        raise
    if key:
        if len(_GD_CACHE) >= _GD_CACHE_MAX:
            _GD_CACHE.clear()
        _GD_CACHE[key] = dict(kv)
    return dict(kv)


def _prefix_brute(b, extra_keys=()):
    """decode_bash.brute restricted to the candidates whose FIRST output byte is 'v' (KNOWN-PREFIX key recovery, D32 item 2), yielded in
    brute's own order (identity, then key 0..255 x xor/add/sub/rolling-a/rolling-b, then the extra keys; then the reversed bytes). Every
    validator generic_decode hands to decode_codec (decode_bash._ok_desc, decode_node._lenient) rejects a first byte other than 'v', so the
    FIRST valid candidate is identical to brute's: the key is fixed by the first byte instead of tried 256 ways (5 transforms instead of
    1280 per byte reading). Proven equal by _test_d32_script_prefix_brute.py. Kill switch HUNTRESS_SCRIPT_PREFIX_BRUTE=0."""
    v = 0x76
    for base in (b, b[::-1]):
        yield base
        if base:
            b0 = base[0]
            kx = b0 ^ v
            for k, op in sorted(((kx, 0), ((v - b0) % 256, 1), ((b0 - v) % 256, 2), (kx, 3), (kx, 4))):
                if op == 0:
                    yield [x ^ k for x in base]
                elif op == 1:
                    yield [(x + k) % 256 for x in base]
                elif op == 2:
                    yield [(x - k) % 256 for x in base]
                else:
                    yield DB._rolling(base, k)[op - 3]
        for key in extra_keys:
            out = [x ^ key[i % len(key)] for i, x in enumerate(base)]
            yield out
            yield out[::-1]


class _PrefixBrute(object):
    """scope in which decode_bash.decode_codec uses _prefix_brute (only around generic_decode, whose validators all require a leading 'v';
    decode_bash.decode_js validates JSON and is never inside this scope)"""
    depth = 0
    saved = None

    def __enter__(self):
        if os.environ.get('HUNTRESS_SCRIPT_PREFIX_BRUTE', '1') != '0':
            if _PrefixBrute.depth == 0:
                _PrefixBrute.saved = DB.brute
                DB.brute = _prefix_brute
            _PrefixBrute.depth += 1
        return self

    def __exit__(self, *a):
        if _PrefixBrute.depth:
            _PrefixBrute.depth -= 1
            if _PrefixBrute.depth == 0:
                DB.brute = _PrefixBrute.saved
        return False


def _generic_decode_uncached(path):
    with _PrefixBrute():
        return _generic_decode_body(path)


def _generic_decode_body(path):
    src = open(path, encoding='utf-8', errors='replace').read()
    first = _generic_decode_classic(path, src)
    if first is not None and not _concat_material(src):
        return first
    best = first
    for fb in (lambda: _raw_decode(src),):
        try:
            text = fb()
            kv = DB.kv_of(text)
            if best is None or len(kv) > len(best):
                best = kv
        except Exception:
            continue
    if best is None:
        # D32 DESCRIPTOR SEARCH, last tiers (plaintext 'v=' fragment, every literal under every representation with known-prefix key
        # recovery, bare runs): only where every older path found nothing, so they can add an answer but never change one.
        try:
            import script_descriptor as _SD
            return _SD.find(src, tiers=('plain', 'literal', 'bare'))[0]
        except Exception as e:
            raise RuntimeError('undecodable (%s: %s)' % (type(e).__name__, str(e)[:160]))
    return best


def _generic_decode_classic(path, src):
    native = {'js': lambda: DN.decode_node(path)['text'], 'sh': lambda: DB.decode_bash(path)['text'],
              'py': lambda: DB.decode_py(path)['text']}
    lg = _lang(path)

    def gen(syn):
        mat, codec = _generic_material(src, syn)
        return DN.robust_decode(mat, codec)[0]
    # The language's own decoder (or its registered syntax) goes FIRST: a foreign decoder can match just the first
    # fragment of a concatenated literal and still produce a plausible-looking truncated 'v=1|' descriptor.
    tries = [native[lg['label']]] if lg['label'] in native else [lambda: gen(lg['syn'])]
    tries += [f for k, f in native.items() if k != lg['label']]
    if lg['label'] in native or lg['syn'] is not _C:
        tries.append(lambda: gen(_C))
    # 2026-10-21 (hs-unique-21): collect every candidate and pick the one with MOST kv fields; a per-literal regex can return a truncated prefix.
    _candidates = []
    for t in tries:
        try:
            text = t()
            if text and re.match(r'^v=\d+\|', text):
                _candidates.append(DB.kv_of(text))
        except Exception:
            continue
    try:
        import script_constprop as _CP
        _d = _CP.find_descriptor(src)
        if _d and re.match(r'^v=\d+\|', _d):
            _candidates.append(DB.kv_of(_d))
    except Exception:
        pass
    if _candidates:
        return max(_candidates, key=lambda kv: len(kv) if isinstance(kv, dict) else 0)
    # D32 DESCRIPTOR SEARCH, tier 1 (script_descriptor.tier_marker: a raw HUNTRESS_ANALYSIS_V1 marker, LYR headers included, also inside XML
    # comments). It runs BEFORE the two cross-lane peels below, which cost ~1 s per file (measured: 70 of 102 files on the D16 Time Trial
    # reached peel_any = 70 s of profile time). Only for a file with NO Material_ token (Material_/Codec_ keeps its own path untouched); an
    # undecodable or ambiguous marker leaves the old fallbacks exactly as they were. The looser tiers run last (see _generic_decode_body).
    if not re.search(r'(?i)\bmaterial_', src):
        try:
            import script_descriptor as _SD
            return _SD.find(src, tiers=('marker',))[0]
        except Exception:
            pass
    # 2026-10-21: cross-lane fallback - layer_magic.peel_to_text (bounded; nothing is executed).
    try:
        import layer_magic as _LM
        for _chain, _peeled in _LM.peel_to_text(src):
            if _peeled and re.match(r'^v=\d+\|', _peeled):
                return DB.kv_of(_peeled)
    except Exception:
        pass
    # 2026-10-21: cross-lane fallback #2 - peel_any single-member leaf.
    try:
        import peel_any as _PA
        _buf = src.encode('utf-8', 'replace') if isinstance(src, str) else bytes(src)
        _r = _PA.peel(_buf, 'autosolve_script')
        _leaf = _r.get('leaf') if isinstance(_r, dict) else None
        if _leaf and _r.get('members') is None and isinstance(_leaf, (bytes, bytearray)) and len(_leaf) <= 2 * 1024 * 1024:
            try:
                _t2 = bytes(_leaf).decode('utf-8', 'ignore')
                if re.match(r'^v=\d+\|', _t2):
                    return DB.kv_of(_t2)
            except Exception:
                pass
    except Exception:
        pass
    return None


def _enum_values(q):
    af = q.get('answer_format') if isinstance(q, dict) else None
    if isinstance(af, dict) and str(af.get('kind', '')).lower() == 'enum' and isinstance(af.get('accepted_values'), list):
        return [str(v) for v in af['accepted_values']]
    return None


def _enum_ok(q, value):
    """True unless the question lists its allowed values and `value` is not one of them"""
    ev = _enum_values(q)
    return ev is None or value in ev


def _enum_by_steps(q, steps):
    """the ONE enum value sharing a word with the descriptor's steps (words split on ',' '_' '>'); a tie or no overlap -> None (never guessed)"""
    ev = _enum_values(q)
    if not ev or not steps:
        return None
    words = set(w for w in re.split(r'[,_>\s]+', str(steps).lower()) if w)
    hits = [v for v in ev if words & set(w for w in re.split(r'[_\-\s]+', v.lower()) if w)]
    return hits[0] if len(hits) == 1 else None


def _role_rows(role):
    """kb/script_tables.json role_attack rows for this role: the NEWEST confirmed row (an accepted answer backs it) is a default; unconfirmed
    rows are ordered candidates only (newest first)"""
    rows = [r for r in tables()['role_attack'] if r.get('role') == role]
    conf = [r['attack'] for r in rows if r.get('confirmed') is True]
    return {'confirmed': conf[-1] if conf else None,
            'candidates': list(dict.fromkeys(r['attack'] for r in reversed(rows) if r.get('confirmed') is not True))}


def _generic_build(F, questions, A, cand=None):
    """Second pass for ids the Day 07 builder could not resolve, over files decoded generically. An interpreter-type
    attack for a language with no certain sub-technique is left out of A and its ordered candidates go into cand."""
    un = []
    cand = {} if cand is None else cand
    for q in questions:
        rawid = q['id']
        if rawid in A:
            continue
        rid = re.sub(r'^set\d+\.', '', rawid)
        art = q['artifact'].split('->')[-1].strip()
        fe = F.get(art)
        val = None
        try:
            if fe and fe['lang'] == 'generic':
                b = fe['kv']; parts = rid.split('-'); field = '-'.join(parts[2:])
                # STATED VALUES WIN (D32, blog day 8 / D31 'the full transform'): a descriptor that states its role / technique is answered
                # verbatim; the step graph and the language tables are consulted only when it does not.
                role = b.get('role') or (SN.role_of(b['steps'], parts[1]) if 'steps' in b else None)
                if field == 'role':
                    val = role if (role and _enum_ok(q, role)) else _enum_by_steps(q, b.get('steps'))
                elif field == 'attack' and b.get('attack'):
                    val = b['attack']
                elif field == 'attack' and role:
                    rows = _role_rows(role)
                    if role == 'persistence_descriptor' or role in SN.ATT_ROLE:
                        val = SN.attack_of(role, None)                # role-derived: independent of the language
                    elif rows['confirmed']:
                        val = rows['confirmed']                       # an appended kb/script_tables.json row an accepted answer backs
                    elif fe['lang_attack']:
                        val = fe['lang_attack']                       # interpreter technique, certain for this language
                    elif fe['lang_cand'] or rows['candidates']:
                        cand[rawid] = list(dict.fromkeys(rows['candidates'] + list(fe['lang_cand'])))   # run() probes these one field at a time
                elif field == 'campaign': val = b.get('campaign_id')
                elif field == 'stage-count': val = str(int(b['stage_count']))
                elif field == 'steps': val = '>'.join(b['steps'].split(','))
                else:
                    val = b.get(field.replace('-', '_'))
                    for k in (tables()['aliases'].get(field) or ()) if val is None else ():
                        if b.get(k) is not None:                      # explicit alias (campaign -> campaign_id, obfuscation -> obfuscation_profile ...)
                            val = b[k]
                            break
        except Exception:
            val = None
        if val is None:
            un.append(rawid)
        else:
            A[rawid] = val
    return un


_ZIP_SIGS = (bytes([0x50, 0x4B, 0x03, 0x04]), bytes([0x50, 0x4B, 0x05, 0x06]))   # zip local-file / end-of-central-directory


def _set_blobs(blobs, nsets, bad):
    # An archive (zip signature) that does not open is NOT payload: its raw outer bytes are never substituted. It is recorded in bad
    # (the undecodable channel) and its slot is None, so solve_fields_ext leaves that set's fields unresolved (HELD). Other blobs are kept as before.
    out = []
    for bi, blob in enumerate(blobs):
        try:
            members = _unzip(blob)
        except Exception:
            if blob[:4] in _ZIP_SIGS:
                bad.append('artifact_%d' % bi)
                out.append(None); continue
            out.append(blob); continue
        inner = sorted((n, d) for n, d in members if n.lower().endswith('.zip'))   # Mastery: outer zip of per-set zips
        out.extend(d for _, d in inner) if inner else out.append(blob)
    return out


_UNZIP_MEMO = {}


def _unzip(blob):
    """ctf_gm.unzip memoised on the archive BYTES (sha256; the last 8 archives): one solve used to open (and AES-decrypt) the same evidence
    zip three times (_set_blobs, the archive-name index, the member extraction). Raises exactly what unzip raises."""
    import hashlib
    key = hashlib.sha256(bytes(blob)).hexdigest() if isinstance(blob, (bytes, bytearray)) else None
    if key is not None and key in _UNZIP_MEMO:
        hit = _UNZIP_MEMO[key]
        if isinstance(hit, Exception):
            raise hit
        return hit
    try:
        out = list(unzip(blob))
    except Exception as e:
        out = e
    if key is not None:
        if len(_UNZIP_MEMO) >= 8:
            _UNZIP_MEMO.clear()
        _UNZIP_MEMO[key] = out
    if isinstance(out, Exception):
        raise out
    return out


def _extract_members(blob, d, bad):
    """Write the archive members into d by BASENAME (questions name files by basename). S7 (D32): two members with one basename and
    DIFFERENT bytes are ambiguous - neither is written (their fields are HELD) and 'ambiguous:<name>' goes to bad; identical copies are
    fine. Only the path components '', '.' and '..' are refused (the old "'..' anywhere in the path" test dropped names like a..b.js)."""
    seen, clash = {}, set()
    for n, data in _unzip(blob):
        bn = os.path.basename(n.replace('\\', '/'))
        if bn in ('', '.', '..'):
            continue
        if bn in seen and seen[bn] != data:
            clash.add(bn)
        seen.setdefault(bn, data)
    for bn, data in seen.items():
        if bn in clash:
            bad.append('ambiguous:' + bn)
            continue
        with open(os.path.join(d, bn), 'wb') as fh:
            fh.write(data)


def _solve_one_dir(d, blob, qs, sp, A, cand, bad, grader='form'):
    """one set: extract its archive into d, run the Day 07 builder, the polyglot / Day 23 fillers and the generic pass. -> unresolved ids
    grader: the batch-expansion grader revision of this attempt (script_expansion_grader.revision); 'legacy' relabels the batch
    *-expansion ids with the pre-D15-TT rule, read from the same reconstruction statement."""
    _extract_members(blob, d, bad)
    grp = [q for q in qs if (q['id'].startswith(sp + '.') if sp else True)]
    arts = SN.artifact_set(grp)
    devnull = open(os.devnull, 'w'); old = sys.stderr; sys.stderr = devnull   # the Day 07 builder is chatty on stderr
    try:
        # the Day 07 decoders of every non-JScript carrier validate a leading 'v' (decode_bash._ok_desc / decode_node._lenient), so they run in
        # the known-prefix scope; decode_bash.decode_js validates JSON and keeps the full brute (D32 speed, exactness: _test_d32_script_prefix_brute)
        js_arts = [f for f in arts if f.endswith('.js')]
        with _PrefixBrute():
            F = SN.analyze(d, [f for f in arts if f not in js_arts])
        F.update(SN.analyze(d, js_arts))
        for f in list(F):       # a Day 07-style extractor sees only the FIRST piece of a concatenated Material_ literal: hand that file to the generic path
            try:
                if f in arts and F[f].get('lang') != 'generic' and _concat_material(open(os.path.join(d, f), encoding='utf-8', errors='replace').read()):
                    del F[f]
            except Exception:
                pass
        for f in arts:
            if f not in F and os.path.exists(os.path.join(d, f)):
                try:
                    lg = _lang(f)
                    F[f] = {'lang': 'generic', 'ext_lang': lg['label'], 'lang_attack': lg['attack'],
                            'lang_cand': lg['cand'], 'kv': generic_decode(os.path.join(d, f))}
                except Exception:
                    bad.append(f)
        a, _ = SN.build(F, grp)
    finally:
        sys.stderr = old; devnull.close()
    if grader == 'legacy':
        try:
            import script_expansion_grader as _XG
            a.update(_XG.relabel(d, grp))
        except Exception as e:
            print('expansion grader relabel failed:', e, file=sys.__stderr__)
    A.update(a)
    try:   # Day 08: php polyglot / host-container v=3 descriptors + advanced-bash fixtures
        import solve_poly_d8 as _P8
        for k, v in _P8.extra_answers(d, [q['id'] for q in grp if q['id'] not in A]).items():
            A.setdefault(k, v)
    except Exception as e:
        print('poly_d8 failed:', e, file=sys.__stderr__)
    try:   # Day 25: a question asking for "two labels joined by |" must get the joined pair, never the single label an earlier builder set
        import solve_poly_d8 as _P8p
        _pipe = [q['id'] for q in grp if 'two labels joined by |' in q.get('question', '')]
        for k, v in (_P8p._d23_fill(d, _pipe).items() if _pipe else ()):
            if v and str(v).count('|') == 1:
                A[k] = v
    except Exception as e:
        print('pipe-pair fill failed:', e, file=sys.__stderr__)
    return _generic_build(F, grp, A, cand)


def solve_fields(start, blobs):
    """-> (answers for the attempt, unresolved ids, files no decoder could read)."""
    A, un, bad, _ = solve_fields_ext(start, blobs)
    return A, un, bad


def solve_fields_ext(start, blobs):
    """-> (answers, unresolved ids, undecodable files, {unresolved id: ordered candidate values to probe}).

    D27 fix (Mixed Signals D26 postmortem): the set-prefix sort used to be lexical, which placed `set10` before
    `set2` and misaligned 9 of 10 sets against their inner evidence archives (85% wrong answers). Day 11 had 2 sets
    so the bug was dormant until a double-digit set count appeared. Fix 1: numeric-key sort. Fix 2: map each set's
    blob by matching the question's own `artifact` evidence-name, not by positional index."""
    qs = start.get('questions') or []
    sets = sorted({(re.match(r'^(set\d+)\.', q['id']).group(1) if re.match(r'^set\d+\.', q['id']) else '') for q in qs},
                  key=lambda s: int(re.sub(r'\D', '', s) or 0))
    bad = []
    sb = _set_blobs(blobs, len(sets), bad)
    # Fix 2 (S1 corrected D32): index every inner evidence archive of every blob by its member path AND basename. A question names its set's
    # archive as 'evidence-01.zip -> member', so the archive is the part BEFORE '->' (the old check looked at the whole string, which ends
    # with the member name, so the name match never fired and every set fell back to position).
    _blob_by_name = {}
    for _b in blobs or ():
        try:
            for n, data in _unzip(_b):
                if n.lower().endswith('.zip'):
                    for _k in (n, os.path.basename(n)):
                        if _k in _blob_by_name and _blob_by_name[_k] is not data and _blob_by_name[_k] != data:
                            _blob_by_name[_k] = None              # one name, two different archives: never pick one silently
                        else:
                            _blob_by_name[_k] = data
        except Exception:
            continue
    A, un, cand = {}, [], {}
    try:
        import script_expansion_grader as _XG
        grader = _XG.revision(start, blobs)
    except Exception:
        grader = 'form'
    for i, sp in enumerate(sets):
        _grp_qs = [q for q in qs if (q.get('id', '').startswith(sp + '.') if sp else True)]
        _by_name = None
        for _q in _grp_qs:
            _af = str(_q.get('artifact') or _q.get('artifact_file') or '').split('->')[0].strip()
            if _af.lower().endswith('.zip'):
                _by_name = _blob_by_name.get(_af, _blob_by_name.get(os.path.basename(_af)))
                if _by_name is not None:
                    break
        if _by_name is not None:
            blob = _by_name
        elif len(sets) == 1 or len(sb) == len(sets) or (len(sb) == 1 and not _blob_by_name):
            # positional only when it is unambiguous: one set, one archive per set, or ONE flat evidence archive (no inner archives at all)
            # that every set shares - each set then reads only the members its own questions name (D28 'Out of Order' synthetic Mastery).
            blob = sb[min(i, len(sb) - 1)] if sb else None
        else:
            # S1: more sets than archives used to reuse the LAST archive for every extra set (confident, wrong answers). Now HELD.
            print('AUTOSOLVE script: %s has no archive of its own (%d sets, %d archives): its fields are HELD' % (sp or 'set', len(sets), len(sb)),
                  file=sys.__stderr__)
            blob = None
        if blob is None:   # undecodable / missing / ambiguous archive: this set's fields stay unresolved, so they are HELD
            continue
        d = tempfile.mkdtemp(prefix='autoscript_')
        try:
            un += _solve_one_dir(d, blob, qs, sp, A, cand, bad, grader)
        finally:
            shutil.rmtree(d, ignore_errors=True)               # S9: the per-set copy of the challenge samples is never left behind
    ids = start.get('answer_ids') or [q['id'] for q in qs]
    # ANSWER CONTRACT (2026-10-18): a derived value that violates its own question's answer_format (a truncated enum, a non-numeric integer, a malformed technique id)
    # is removed and reported in CONTRACT_REJECTED, so it is HELD, never submitted. Zero of 24,935 GM-accepted archived answers fail this check (_test_answer_contract.py).
    import answer_contract as _AC
    kept, rejected = _AC.filter_answers({k: A[k] for k in ids if k in A}, qs)
    CONTRACT_REJECTED.clear()
    CONTRACT_REJECTED.update(rejected)
    return (kept, [i for i in ids if i not in kept], sorted(set(bad)),
            {k: v for k, v in cand.items() if k in ids and k not in kept})


def compute(start, blobs):
    """ctf_gm.solve_mode contract: {answer id: value}. D32: the SAME solve path as run() (_solve), so a fix lands once."""
    return _solve(start, blobs)[0]


def format_candidates(start, answers):
    """D33: {answer id: ranked renderings} for every answered id whose RENDERING the per-family rule
    store (script_render, fed by GM-accepted answers) does not settle - hex 0x prefix / case / width,
    list order (sorted vs insertion), hash-set ordering, arrow-sequence ordering, GUID case/braces,
    zero padding. Read-only: compute() answers are never changed here; the submit / probe owner
    decides how to use the ranked list (untimed only, never a blind pick)."""
    try:
        import script_render
        return script_render.candidates_for(start, answers)
    except Exception:
        return {}


def _solve(st, blobs, challenge_id=None):
    """THE one solve path of compute() and run() (D32: the two used to carry their own copies of the shape / multiset / stock dispatch, with
    different validation). -> (answers, unresolved, undecodable files, {id: candidates}, shape_first_used).
      1. advisory mastery-shape fingerprint (one print; HUNTRESS_SCRIPT_SHAPE_FINGERPRINT=0 silences it);
      2. the D30 shape-first dispatcher, only through _shape_first (every id answered and shape-checked; benched / proven per challenge);
      3. the multi-set family solver (script_multiset: per-set archive by name, parallel sets, spill sanitiser), else the stock solve_fields_ext;
      4. a value still carrying control bytes is dropped (HELD), never submitted."""
    try:
        if os.environ.get('HUNTRESS_SCRIPT_SHAPE_FINGERPRINT', '1').strip() != '0':
            import mastery_shape as _ms
            _ms.recognize_mastery(st)
    except Exception:
        pass
    sf = _shape_first(st, blobs, challenge_id)
    if sf is not None:
        A, un, bad, cand = sf
        print('AUTOSOLVE script: shape-first dispatch answered %d id(s); stock solver skipped' % len(A), flush=True)
    else:
        A, un, bad, cand = _multiset_or_stock(st, blobs)
    n0 = len(A)
    A = _drop_control_bytes(A)
    if len(A) < n0:
        un = list(un) + [k for k in (st.get('answer_ids') or []) if k not in A and k not in un]
    return A, un, bad, cand, sf is not None


# -----------------------------------------------------------------------------------------------
# D30 shape-first fast dispatcher (DEFAULT OFF). HS commander + operator review required before enable.
# -----------------------------------------------------------------------------------------------
# Why: HS reported Day 29 Make It Make Sense MM 271s on a 2.3MB artifact in the stock solve_fields path.
# The multiset family already short-circuits via recognize(). This adds a lean fast path for 3 common
# text-script shapes seen Day 20-29. Without profile data from HS's actual Day 29 MM artifact bytes we
# cannot confirm the 271s MM hits any of these three; the dispatcher is DEFAULT OFF so a false fit never
# ships a wrong answer. Operator enables per-shape after reviewing byte-identity evidence vs. live bytes.
# -----------------------------------------------------------------------------------------------

# A whitelist mapping normalised answer_id -> compiled regex. The regex_table shape solver walks the
# whole blob text once and runs each known pattern. The set is deliberately small; adding patterns is
# cheap but each one risks a false-positive HELD on an unrelated challenge, so growth requires evidence.
_SCRIPT_FIELD_REGEX = {
    "md5":      r"\b[0-9a-f]{32}\b",
    "sha1":     r"\b[0-9a-f]{40}\b",
    "sha256":   r"\b[0-9a-f]{64}\b",
    "ipv4":     r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
    "email":    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "url":      r"https?://[^\s\"'<>]+",
    "port":     r"\bport\s*[:=]\s*(\d{1,5})\b",
}


def _shape_solve_polyglot_base64(start, blob):
    """Each line is base64; decode in one pass, map decoded line K to answer_ids[K]. Returns a dict or
    None on any mismatch (counts off, decode failure, question count differs)."""
    import base64 as _b64
    try:
        text = blob.decode("ascii", errors="strict") if isinstance(blob, (bytes, bytearray)) else str(blob)
    except Exception:
        return None
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    ids = list(start.get("answer_ids") or [q.get("id") for q in (start.get("questions") or []) if q.get("id")])
    if len(lines) != len(ids):
        return None
    out = {}
    for i, line in enumerate(lines):
        try:
            dec = _b64.b64decode(line + "=" * (-len(line) % 4), validate=True).decode("utf-8", errors="strict").strip()
        except Exception:
            return None
        out[ids[i]] = dec
    return out if out else None


def _shape_solve_json_field(start, blob):
    """blob is a JSON doc; answer_ids match top-level or dotted key paths. Returns {aid: value} or None."""
    import json as _json
    try:
        text = blob.decode("utf-8", errors="strict") if isinstance(blob, (bytes, bytearray)) else str(blob)
        doc = _json.loads(text)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    ids = list(start.get("answer_ids") or [q.get("id") for q in (start.get("questions") or []) if q.get("id")])

    def _walk(d, path):
        cur = d
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur

    out = {}
    for aid in ids:
        v = _walk(doc, aid)
        if v is None:
            return None  # a single missing key => fall through, do not ship a partial answer
        out[aid] = v if isinstance(v, str) else str(v)
    return out if out else None


def _shape_solve_regex_table(start, blob):
    """Match each answer_id's name against the whitelist regex table; apply to the whole blob text.
    Returns a dict or None if any id's regex is missing OR any pattern finds 0 OR >1 UNIQUE matches.

    D30-29-fix: HS Verdict 2 flagged that re.search returns the FIRST match. If an artifact has
    multiple sha256/md5/ipv4/email in a log file and the GM wants a specific one (e.g. "the second
    ipv4"), returning the first would silently commit a wrong answer and burn a ranked attempt. The
    fix: for every requested pattern, enumerate ALL matches, dedupe, and only accept when EXACTLY
    ONE unique match exists in the whole blob. Multi-match cases fall through to the general path.
    """
    import re as _re
    try:
        text = blob.decode("utf-8", errors="replace") if isinstance(blob, (bytes, bytearray)) else str(blob)
    except Exception:
        return None
    ids = list(start.get("answer_ids") or [q.get("id") for q in (start.get("questions") or []) if q.get("id")])
    out = {}
    for aid in ids:
        last = str(aid).lower().split(".")[-1]
        candidates = [last, _re.sub(r"[_-]?\d+$", "", last)]
        pat = next((_SCRIPT_FIELD_REGEX[k] for k in candidates if k in _SCRIPT_FIELD_REGEX), None)
        if pat is None:
            return None
        all_matches = _re.findall(pat, text)
        # findall() returns a list of groups when the pattern has groups, otherwise the full match string.
        # Normalise: a tuple-of-groups (multiple groups) collapses to the first group; a bare string stays.
        normalised = []
        for m in all_matches:
            normalised.append(m if isinstance(m, str) else (m[0] if isinstance(m, tuple) and m else ""))
        unique = list(dict.fromkeys(normalised))  # dedupe preserving order
        if len(unique) == 0:
            return None  # no match -> fall through
        if len(unique) > 1:
            return None  # ambiguous -> fall through; general path or agent disambiguates
        out[aid] = unique[0]
    return out if out else None


_SCRIPT_SHAPE_SOLVERS = {
    "polyglot_base64": _shape_solve_polyglot_base64,
    "json_field":      _shape_solve_json_field,
    "regex_table":     _shape_solve_regex_table,
}


def _detect_script_shape(start, blob):
    """Fast content-level recognition. Returns (shape_name, confidence_0_to_1) or (None, 0.0).
    HIGH-confidence only (>= 0.8) will dispatch; anything else falls through."""
    import re as _re
    if not blob:
        return None, 0.0
    sample = blob[:4096] if isinstance(blob, (bytes, bytearray)) else bytes(str(blob)[:4096], "utf-8", "ignore")
    try:
        text = sample.decode("ascii", errors="strict")
    except Exception:
        return None, 0.0

    # json_field: whole blob parses as a JSON object; its keys cover at least one answer_id
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}") or stripped.startswith("{"):
        try:
            import json as _json
            whole = blob.decode("utf-8", errors="strict") if isinstance(blob, (bytes, bytearray)) else str(blob)
            doc = _json.loads(whole)
            if isinstance(doc, dict):
                ids = [q.get("id") for q in (start.get("questions") or []) if q.get("id")] + list(start.get("answer_ids") or [])
                top_keys = set(doc.keys())
                hits = sum(1 for aid in ids if aid.split(".")[0] in top_keys)
                if hits >= max(1, len(ids) // 2):
                    return "json_field", 0.9
        except Exception:
            pass

    # polyglot_base64: >= 3 lines, each line is >= 16 b64 chars (D30-29-fix: raised from 8 to filter UUIDs,
    # short JWT headers, hex tokens that pass the alnum+/= regex), >=80% decode cleanly, AND decoded content
    # on the first 2 sample lines must be mostly printable ASCII (ratio >= 0.9, counting 0x20-0x7e + \t\n\r).
    # The printable-ratio check kills the hex-string collision (hex decodes to random bytes, not printable).
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) >= 3:
        import base64 as _b64
        b64chars = _re.compile(r"^[A-Za-z0-9+/=]{16,}$")
        matching = [ln for ln in lines if b64chars.match(ln)]
        if len(matching) >= max(3, int(0.8 * len(lines))):
            def _printable_ratio(data):
                if not data:
                    return 0.0
                good = sum(1 for b in data if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
                return good / len(data)
            try:
                sample_decoded = []
                for sample_line in matching[:2]:
                    sample_decoded.append(_b64.b64decode(sample_line + "=" * (-len(sample_line) % 4), validate=True))
                # D30-29-fix: every sample line's decoded bytes must be printable-ratio >= 0.9.
                # Short-circuits hex-token false-positive (decodes to high-entropy bytes).
                if all(_printable_ratio(d) >= 0.9 for d in sample_decoded):
                    return "polyglot_base64", 0.85
            except Exception:
                pass

    # regex_table: at least one answer_id's name maps to a known field pattern AND the full blob contains at least one match
    ids = [q.get("id") for q in (start.get("questions") or []) if q.get("id")] + list(start.get("answer_ids") or [])
    whole_text = blob.decode("utf-8", errors="replace") if isinstance(blob, (bytes, bytearray)) else str(blob)
    recognized_ids = 0
    for aid in ids:
        last = str(aid).lower().split(".")[-1]
        candidates = [last, _re.sub(r"[_-]?\d+$", "", last)]
        pat = next((_SCRIPT_FIELD_REGEX[k] for k in candidates if k in _SCRIPT_FIELD_REGEX), None)
        if pat and _re.search(pat, whole_text):
            recognized_ids += 1
    if ids and recognized_ids == len(ids):
        return "regex_table", 0.8

    return None, 0.0


def _try_script_shape_dispatch(start, blobs):
    """Entry point from compute(). Default OFF via env; returns dict of answers or None (fall through).

    D30 Option C (2026-10-29): emits a 'shape_probe' observability line to stderr whenever the
    dispatcher runs. Format: 'shape_probe: lane=script result=<shape|none> conf=<f>'. Agents reading
    runner_status.py / autosolve logs discover shape-dispatch exists through this line without a
    prompt change. Silent when env disabled.
    """
    import os as _os
    import sys as _sys
    if _os.environ.get("HUNTRESS_SCRIPT_SHAPE_DISPATCH") != "1":
        return None
    if not blobs or len(blobs) != 1:
        _sys.stderr.write("shape_probe: lane=script result=none reason=multi_blob\n")
        return None
    shape, confidence = _detect_script_shape(start, blobs[0])
    if not shape or confidence < 0.8:
        _sys.stderr.write("shape_probe: lane=script result=none conf=%.2f\n" % (confidence or 0.0))
        return None
    # D30 (2026-10-29, post-operator-GO): per-shape kill switch, mirrors the binary dispatcher.
    # HUNTRESS_SCRIPT_SHAPE_<NAME>=0 disables the shape even when the master dispatcher is on.
    # Operator's conservative GO is "json_field only"; Go.ps1 sets POLYGLOT_BASE64=0 + REGEX_TABLE=0.
    if _os.environ.get("HUNTRESS_SCRIPT_SHAPE_" + shape.upper()) == "0":
        _sys.stderr.write("shape_probe: lane=script result=none reason=shape_disabled:%s\n" % shape)
        return None
    solver = _SCRIPT_SHAPE_SOLVERS.get(shape)
    if solver is None:
        _sys.stderr.write("shape_probe: lane=script result=none reason=unknown_shape:%s\n" % shape)
        return None
    try:
        out = solver(start, blobs[0])
        if out is None:
            _sys.stderr.write("shape_probe: lane=script result=none reason=solver_rejected:%s\n" % shape)
            return None
        _sys.stderr.write("shape_probe: lane=script result=matched shape=%s conf=%.2f answers=%d\n" %
                          (shape, confidence, len(out)))
        return out
    except Exception as _e:
        _sys.stderr.write("shape_probe: lane=script result=none reason=solver_error:%s:%s\n" %
                          (shape, type(_e).__name__))
        return None


_SHAPE_PROVEN_ENV = 'HUNTRESS_SHAPE_FIRST_PROVEN'   # base challenge ids whose Single the GM accepted via shape-first (process-wide: survives an adapter reload)
_SHAPE_BAD_ENV = 'HUNTRESS_SHAPE_FIRST_BAD'          # base challenge ids where a shape-first submit was NOT accepted: never use shape-first for them again


def _shape_ids(env):
    return set(x for x in os.environ.get(env, '').split(',') if x)


def _shape_mark(challenge_id, r):
    """Record how a shape-first submit went. CORRECT on the untimed Single PROVES the shape solver for this challenge; any other result
    benches it. WS hardening (D31 review): most script fields have no per-class shape regex, so a wrong-but-plausible shape answer must
    never reach a one-shot ranked TT/MM unproven. Never raises."""
    try:
        base = challenge_id.split('/')[0]
        ok = str((r or {}).get('result', '')).upper() == 'CORRECT'
        if ok and challenge_id == base:
            os.environ[_SHAPE_PROVEN_ENV] = ','.join(sorted(_shape_ids(_SHAPE_PROVEN_ENV) | {base}))
        elif not ok:
            os.environ[_SHAPE_BAD_ENV] = ','.join(sorted(_shape_ids(_SHAPE_BAD_ENV) | {base}))
    except Exception:
        pass


def _shape_first(st, blobs, challenge_id=None):
    """D31 reopen (WS + user directive: every built fastpath must be reachable in production). run() never reaches compute(), so the
    D30 shape dispatcher was unreachable. -> (A, [], [], {}) ONLY when it answers EVERY expected id with a non-empty string that also
    passes mastery_shape's per-class shape check; otherwise None and the stock solve_fields_ext runs exactly as before. On a ONE-SHOT
    timed route (TT/MM) it is used only if this challenge's Single was already accepted via shape-first; a shape-first answer the GM
    rejected benches it for that challenge. It never submits anything itself: _one_considered_submit still decides (HELD, never a
    guess). Never raises."""
    try:
        if challenge_id:
            base = challenge_id.split('/')[0]
            if base in _shape_ids(_SHAPE_BAD_ENV):
                return None
            if challenge_id != base and base not in _shape_ids(_SHAPE_PROVEN_ENV):
                return None
        out = _try_script_shape_dispatch(st, blobs)
        if not isinstance(out, dict) or not out:
            return None
        expect = st.get('answer_ids') or [q.get('id') for q in (st.get('questions') or []) if isinstance(q, dict) and q.get('id')]
        if not expect:
            return None
        import mastery_shape as _ms
        for i in expect:
            v = out.get(i)
            if not isinstance(v, str) or not v.strip() or not _ms.value_matches_shape(i, v):
                return None
        return {i: out[i] for i in expect}, [], [], {}
    except Exception:
        return None


def scan(task, blobs):
    """The shared per-lane scan (release_scan.py): resolved answers, ordered candidates for the ids we cannot name (the LANGS carrier table's ordered ATT&CK lists
    for interpreter-derived fields; an empty list = nothing known), and which part answered. Never raises on an unknown language. No GM call."""
    ids = list(task.get('answer_ids') or [q.get('id') for q in (task.get('questions') or []) if q.get('id')])
    A, _un, _bad, cand = solve_fields_ext(task, blobs)
    resolved = {i: A[i] for i in ids if i in A}
    ex = {i: 'autosolve_script.solve_fields_ext' for i in resolved}
    # A candidate list whose winner the GM already ACCEPTED (this process - e.g. the Single just before this Time Trial - or the accepted-values store from an earlier
    # day) is answered locally, not a gap: the gate must not hold a mode whose answer we already know (R2a, agreed with the workstation 2026-10-11). Read-only.
    real = _RealGMMarker()
    for i in ids:
        if i not in resolved and cand.get(i):
            w = known_winner(real, tuple(cand[i]))
            if w is not None:
                resolved[i] = w
                ex[i] = 'autosolve_script.known_winner'
    unresolved = {i: list(cand.get(i, [])) for i in ids if i not in resolved}
    ex.update({i: 'autosolve_script.LANGS.cand' for i, c in unresolved.items() if c})
    return {'resolved': resolved, 'unresolved': unresolved, 'extractor': ex}


class _RealGMMarker:
    """lets known_winner read the accepted-values store (it only trusts values the REAL GM accepted); it makes no GM call"""
    @property
    def host(self):
        import ctf_gm
        return ctf_gm.PUB_HOST


def _clean(r):
    return {k: v for k, v in (r or {}).items() if k not in ('questions', 'guidance', 'prompt')}


def _done(r):
    return str(r.get('result', '')).upper() == 'CORRECT'


def start(gm, challenge_id, for_time=False):
    """HOF gate (2026-10-16, homestation): ctf_gm lets run_for_time reach the wire ONLY when the user's HOF switch is ON and the caller asked for a ranked start (GM.start sets _hof_ok). This adapter
    starts timed modes with gm._post (it bypasses GM.start), so without this the ranked request was silently stripped: a regular attempt, no Hall of Fame, no message. Same rule, same switch: the
    permission exists only for the duration of this start and only for a timed route; the rollback (HUNTRESS_HOF=0 / kb/hof_policy.json enabled:false) puts nothing ranked on the wire."""
    timed = challenge_id.endswith("/time_trial") or challenge_id.endswith("/mastery")
    try:
        gm._hof_ok = bool(for_time and timed) and _cg._hof_switch_on()
        return _start_body(gm, challenge_id, for_time)
    finally:
        gm._hof_ok = False


def _start_body(gm, challenge_id, for_time=False):
    """Like GM.start but safe on an already-solved mode: the GM then answers start with result=CORRECT, the questions,
    and NO answer_ids/artifacts, and GM.start's automatic retry gets HTTP 405. Returns None when already solved.
    Dual-pool fix (Day 08, self-fix not blind-retry): a timed route (/time_trial, /mastery) can 503
    training_rotation_invalid when its untimed training pool is exhausted; opt into the ranked pool with
    run_for_time=True on the SAME call (mirrors GM.start's fix) instead of looping the same failing request."""
    timed = challenge_id.endswith("/time_trial") or challenge_id.endswith("/mastery")
    # for_time=True opens a RANKED (Hall-of-Fame) attempt instead of the default untimed pool. Measured safe for
    # this lane: the 695-field Day-09 analysis takes ~1.1s offline (challenges/_lib/time_lanes.py).
    extra = {'run_for_time': True} if (for_time and timed) else {}
    _cg.close_window()           # a stale window from an earlier attempt must not govern this one
    for i in range(10):
        try:
            st = gm._post(op='start', challenge=challenge_id, **extra)
            break
        except RuntimeError as e:
            if timed and 'training_rotation_invalid' in str(e):
                st = gm._post(op='start', challenge=challenge_id, run_for_time=True); break
            if timed and extra and 'timed_intent_not_available' in str(e):
                # LEGACY (SINGLE-POOL) TIMED ROUTE - measured live on this very challenge
                # (Day 10 wmi-persistence-reconstruction/{time_trial,mastery}): run_for_time is
                # REJECTED outright (true OR false -> 409 timed_intent_not_available), while the
                # same start with the property OMITTED opens a normal attempt that is itself
                # hall_of_fame_eligible. Drop the ranked property and take that single pool
                # instead of raising. See the matching note in ctf_gm.GM.start.
                extra = {}; continue
            if '429' in str(e) and i < 9:
                wait = 1.0 + i
                _cg._check_window(wait)   # D-Day pattern: never sleep past a ranked attempt's deadline (raises WindowExpired instead)
                time.sleep(wait); continue
            raise
    else:
        # S9 (D32): every try ended in 'continue' (429 backoffs and the one legacy-route downgrade): say so instead of an UnboundLocalError
        raise RuntimeError('start %s: no attempt after 10 tries (429 backoff / legacy timed route)' % challenge_id)
    if str(st.get('result', '')).upper() == 'CORRECT' and not st.get('answer_ids'):
        return None
    # PORTED from workstation main (2026-10-21, verified live): timed pool empty (remaining 0) and the GM names practice as the next op ->
    # take the untimed practice continuation, never a variant-spending retry. Only when the resumed attempt is unusable.
    _low = (str(st.get('result', '')) + ' ' + str(st.get('status', ''))).lower()
    _rem = st.get('unique_attempts_remaining')
    if isinstance(_rem, int) and not isinstance(_rem, bool) and _rem == 0 and str(st.get('next_op') or '').lower() == 'practice' and ('expired' in _low or not st.get('answer_ids')):
        gm._post(op='practice', challenge=challenge_id); st = gm._post(op='start', challenge=challenge_id)
    low = _state_words(st)              # the GM's own state fields ONLY: the prompt / question text can contain 'expired' and must never trigger a variant-spending retry
    if 'training_rotation_invalid' in low and timed:
        st = gm._post(op='start', challenge=challenge_id, run_for_time=True); low = _state_words(st)
    if 'expired' in low or 'flag_unavailable' in low or not st.get('answer_ids'):
        if os.environ.get('HUNTRESS_NO_RETRY') == '1':
            raise RuntimeError('REFUSED: the resumed attempt is %s and HUNTRESS_NO_RETRY=1, so no fresh variant was spent' % (low or 'unusable'))
        gm.retry(challenge_id); st = gm._post(op='start', challenge=challenge_id)
    if timed and isinstance(st, dict) and st.get('deadline') and str(st.get('result', '')).lower() != 'expired':
        # this adapter bypasses GM.start, so it opens the budget itself. S6 (D32): opened on the FINAL attempt (after any rotation fix or
        # retry), so a replaced attempt never runs on the deadline of the one it replaced.
        _cg.open_window(st.get('deadline'))
    if timed and isinstance(st, dict):
        # TIMED CORPUS (Day 15): this adapter bypasses GM.start, so GM.start's record of {start, blobs} was never
        # created and ctf_gm could not save the attempt's real bytes. Register it here - that is what makes an
        # INCORRECT timed attempt diagnosable offline afterwards.
        try:
            gm._ctx()[challenge_id] = {'start': st, 'blobs': {}}
        except Exception:
            pass
    return st


def _contract_questions(challenge_id, st):
    # A resumed start returns answer_ids but no questions; take the question text from the saved free contract when the ids match exactly.
    import glob
    base, _, mode = challenge_id.partition('/')
    want = list(st.get('answer_ids') or [])
    for p in glob.glob(os.path.join('challenges', 'Day *', '_board', base + '.assignment.json')):
        try:
            for m in json.load(open(p, encoding='utf-8')).get('mode_entries') or []:
                if m.get('mode') == mode and m.get('questions') and [q.get('id') for q in m['questions']] == want:
                    return m['questions']
        except Exception:
            continue
    return None


def _multiset_or_stock(st, blobs):
    # run() bypassed compute(), so multi-set Mastery missed script_multiset's decode-spill sanitiser (D31: 4 beanshell path fields sank a 29250-id batch).
    try:
        import script_multiset
        if script_multiset.recognize(st).get('is_multiset'):
            ans, un, bad = script_multiset.solve(st, blobs)
            if ans:
                print('AUTOSOLVE script: multiset path answered %d id(s), %d unresolved' % (len(ans), len(un)), flush=True)
                return ans, list(un), list(bad), {}
    except Exception as e:
        print('AUTOSOLVE script: multiset path failed (%s); stock solver' % type(e).__name__, flush=True)
    return solve_fields_ext(st, blobs)


_CONTROL_BYTES = re.compile('[\x00-\x1f\x7f\ufffd]')


def _drop_control_bytes(A):
    # exact_text never legitimately carries control bytes: trim a decode spill, else drop the value so the id is HELD, never submitted.
    try:
        import script_multiset
        fix = script_multiset.sanitize_field
    except Exception:
        fix = lambda k, v: v
    out, dropped = {}, []
    for k, v in A.items():
        if isinstance(v, str) and _CONTROL_BYTES.search(v):
            v = fix(k, v)
            if _CONTROL_BYTES.search(v):
                dropped.append(k)
                continue
        out[k] = v
    if dropped:
        print('AUTOSOLVE script: %d value(s) still carry control bytes after sanitising -> HELD: %s' % (len(dropped), dropped[:4]), flush=True)
    return out


def _state_words(d):
    """lower-cased result / status / error / state of a GM response - never the prompt, guidance or question text"""
    if not isinstance(d, dict):
        return ''
    parts = [str(d.get(k) or '') for k in ('result', 'status', 'error', 'state', 'code')]
    if isinstance(d.get('attempt'), dict):         # a resumed attempt may carry its own state one level down
        parts += [str(d['attempt'].get(k) or '') for k in ('result', 'status', 'state')]
    return ' '.join(parts).lower()


# ---- candidate probing, made cheap (2026-10-10, homestation) -------------------------------------------------------------------------
# A probe is a full GM round trip (~0.2-0.4 s) and the old loop paid one per field per candidate. Three layers now remove almost all of it:
#   1. KNOWN winner - a value the GM already accepted for this candidate list (earlier in this process, or in an earlier run via the
#                     accepted-values store) goes into the FIRST batch with everything else: ZERO probes.
#   2. LEARN once   - otherwise probe on the FIRST field of each group only, in the candidate list's own order.
#   3. ONE batch    - then submit that winner for ALL the remaining fields of the group in a single call (the GM banks it only if every field is
#                     right); only a MIXED group falls back to per-field probing, exactly as before.
# The final answers are identical to the old loop's (checked against it on random truths in _test_script_probe.py); only the call count drops.
_LEARNED = {}                       # tuple(candidate list) -> accepted value; one process runs single, time trial and mastery, so it carries over


def _ok(rr):
    return str(rr.get('result')) in ('accepted', 'CORRECT')


# Values the GM REJECTED for a list in this process live in the SAME dict as the winners (under ('~rejected', key)), so there is one memory: clearing it clears both.
def _rejected(key):
    return _LEARNED.get(('~rejected', key), ())


def _enc(s):
    """Percent-encode the characters that would blur two different candidate lists into one token, or make accepted_values add a shared cross-day
    key ('-' generalises to '*-suffix'): '%' first, then '+' (the list separator) and '-'."""
    return str(s).replace('%', '%25').replace('+', '%2B').replace('-', '%2D')


def _lang_token(key, value=None):
    """The store token for a candidate list. With a value, ONE counter per (list, value): a confirmation of A1 never mixes into B2's count, so one
    early disagreement can no longer disable a list for good (the reviewer's defect 4). No hyphen anywhere (see _enc)."""
    t = 'langattack:' + '+'.join(_enc(c) for c in key)
    return t if value is None else t + '=' + _enc(value)


def _rej_token(key, value):
    return 'langrej:' + '+'.join(_enc(c) for c in key) + '=' + _enc(value)


def _is_real_gm(gm):
    try:
        import ctf_gm
        return getattr(gm, 'host', None) == ctf_gm.PUB_HOST
    except Exception:
        return False


def _persist(gm, key, winner):
    """Bank the winner for LATER runs through the accepted-values store (background thread, off the solve path). Real Game Master only, so an
    offline test can never write to the real store."""
    try:
        if _is_real_gm(gm):
            import accepted_values
            accepted_values.record_async({_lang_token(key, winner): winner}, {'result': 'accepted'})
    except Exception:
        pass


def _note_rejected(gm, key, value):
    """A remembered winner was shown WRONG: evict it from the in-process memory at once and record the rejection in the store, so a stale value that two earlier
    runs had confirmed stops being trusted (the reviewer's defects 2 and 3). The corrected winner is then learned under the SAME key (see probe_candidates)."""
    if _LEARNED.get(key) == value:
        del _LEARNED[key]
    _LEARNED.setdefault(('~rejected', key), set()).add(value)
    try:
        if _is_real_gm(gm):
            import accepted_values
            accepted_values.record_async({_rej_token(key, value): value}, {'result': 'accepted'})
    except Exception:
        pass


def _count(keys, token):
    return int((keys.get(token) or {}).get('n', 0))


def known_winner(gm, key, keys=None):
    """The accepted value for this candidate list, or None. In-process memory first (unless it was rejected), then the store. A stored value is trusted when it
    has >= 2 confirmations of ITS OWN, at least 2 more than twice the rejections recorded against it, and no other value of the list is trusted too (or it
    has 3x the confirmations of the runner-up). Counters are per (list, value), so one early disagreement never disables a list for good."""
    rej = _rejected(key)
    w = _LEARNED.get(key)
    if w is not None and w in key and w not in rej:
        return w
    try:
        if _is_real_gm(gm):
            import accepted_values
            ks = keys if keys is not None else accepted_values.load_cached().get('keys', {})
            ok = []
            for v in dict.fromkeys(key):
                if v in rej:
                    continue
                conf, nrej = _count(ks, _lang_token(key, v)), _count(ks, _rej_token(key, v))
                if conf >= 2 and conf >= 2 * nrej + 2:
                    ok.append((conf, v))
            ok.sort(reverse=True)
            if len(ok) == 1 or (len(ok) > 1 and ok[0][0] >= 3 * ok[1][0]):
                return ok[0][1]
    except Exception:
        pass
    return None


def _field_key(scope, qid):
    """the in-process memory key of ONE field of ONE challenge (set prefix dropped: every set of a Mastery asks the same field)"""
    return ('~field', str(scope).split('/')[0], re.sub(r'^set\d+\.', '', str(qid)))


_GUESS_ONLY = set()                 # candidate-list keys whose in-process winner is only a top-ranked GUESS one Single accepted (S4)


def prefill_known(gm, A, cand, scope=None, timed=False):
    """Move every field whose candidate list has a KNOWN winner out of `cand` and into A, so it rides in the first submit. -> {qid: its candidates}.
    scope / timed (D32, S4): a top-ranked GUESS the GM accepted on an untimed Single is remembered under the candidate-list key (as before) AND
    per (challenge, field). On a one-shot timed route a guess-only key is NOT trusted for other fields/challenges (that bypassed the
    no-guess-on-timed hold); only the same field of the same challenge (scope) or the confirmed store may prefill it."""
    out, memo, ks = {}, {}, None
    if scope is not None:
        for qid, cands in list(cand.items()):
            w = _LEARNED.get(_field_key(scope, qid))
            if w is not None and w in cands and w not in _rejected(tuple(cands)) and qid not in A:
                out[qid] = list(cands); A[qid] = w; del cand[qid]
    try:
        if _is_real_gm(gm):
            import accepted_values
            ks = accepted_values.load_cached().get('keys', {})
    except Exception:
        ks = None
    for qid, cands in list(cand.items()):
        key = tuple(cands)
        if key not in memo:
            if timed and key in _GUESS_ONLY:
                saved = _LEARNED.pop(key, None)          # the store may still vouch for it (>= 2 confirmations); the guess alone may not
                memo[key] = known_winner(gm, key, ks)
                if saved is not None:
                    _LEARNED[key] = saved
            else:
                memo[key] = known_winner(gm, key, ks)
        w = memo[key]
        if w is not None and qid not in A:
            out[qid] = list(cands); A[qid] = w; del cand[qid]
    return out


def restore_rejected(prefilled, wrong, A, cand, gm=None, batch=False):
    """A remembered winner this fixture REJECTED goes back to probing, and the rejection is recorded (memory evicted, store told). An id listed twice in
    `wrong` is harmless (defect 8).
      batch=False: the field itself was shown wrong, so the value leaves its candidate list (other fields of the group may still be right).
      batch=True : a whole BATCH of fields was rejected, so which of them were wrong is unknown - some may well be right with that value (a mixed group).
                   The value stays in every list, but LAST, so probing reaches for it only after the other candidates."""
    noted = set()
    for q in dict.fromkeys(w for w in wrong if w in prefilled):
        bad_value = A.pop(q, None)
        if batch:
            cand[q] = [c for c in prefilled[q] if c != bad_value] + ([bad_value] if bad_value in prefilled[q] else [])
        else:
            cand[q] = [c for c in prefilled[q] if c != bad_value]
        if bad_value is not None and (tuple(prefilled[q]), bad_value) not in noted:
            noted.add((tuple(prefilled[q]), bad_value))
            _note_rejected(gm, tuple(prefilled[q]), bad_value)


def _remaining(rr):
    v = (rr or {}).get('remaining')
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _banked(before, rr, n):
    """Did a batch of n fields bank ALL n? True: the attempt is CORRECT, or the GM's `remaining` count fell by exactly n. False: it fell by less (some fields were
    wrong although the result said 'accepted': the reviewer's defect (b)). None: the GM gave no counts, so it cannot be checked."""
    if str((rr or {}).get('result')) == 'CORRECT':
        return True
    after = _remaining(rr)
    if before is None or after is None:
        return None
    return (before - after) == n


def probe_candidates(gm, cand, sub, done, A, r, origin=None):
    """Resolve the remaining `cand` fields (see the block comment). `sub(answers)` submits; `done(result)` says the attempt is complete.
    `origin` maps a field id to its ORIGINAL candidate list when a remembered winner was rejected and the list was reduced, so the corrected winner is
    remembered under the original key (the old reduced key left the stale entry in place). -> (probed {qid: value or None}, last result)."""
    probed, groups = {}, {}
    for qid, cands in cand.items():
        if qid not in A:
            groups.setdefault(tuple(cands), []).append(qid)

    def one(q, key):                                  # per-field probe in the list's own order, exactly like the old loop
        # (A learned-first reorder was tried and REMOVED: on groups whose fields disagree it cost up to +1 submit per field, measured +9 on random
        # instances, and it is redundant - once a winner is known prefill_known sends it in the FIRST submit, so this loop never sees that group.)
        nonlocal r
        for v in key:
            rr = sub({q: v})
            if _ok(rr):
                probed[q] = v; A[q] = v; r = rr
                return v
        probed[q] = None
        return None

    for key, qids in groups.items():
        if done(r):
            break
        todo, winner = list(qids), None
        while todo and winner is None and not done(r):          # LEARN: the first field that accepts a candidate fixes the winner
            winner = one(todo.pop(0), key)
        if winner is None:
            continue
        uniform = not todo                                      # a one-field group has nothing that could disagree with its winner
        if todo and not done(r):
            before = _remaining(r)
            rr = sub({q: winner for q in todo})                 # ONE batch for the rest: banked only if every field is right
            if _ok(rr) and _banked(before, rr, len(todo)) is not False:
                for q in todo:
                    probed[q] = winner; A[q] = winner
                r = rr; uniform = True
            else:                                               # a mixed group, or an 'accepted' that banked fewer fields than sent: per-field, exactly as before
                for q in todo:
                    if done(r):
                        break
                    one(q, key)
        if uniform:                                             # remembered only when the winner held for the WHOLE group (a mixed group teaches nothing)
            mem = (origin or {}).get(qids[0], key)
            _LEARNED[mem] = winner
            _GUESS_ONLY.discard(mem)                            # verified by the GM for a whole uniform group: no longer a mere guess
            _persist(gm, mem, winner)
    return probed, r


def _localize(sub, ids, A, say, budget=12, stop_at=8):
    """WHICH locally computed answers does the GM reject? Subset submits on an ALREADY-SPENT, DEADLINE-FREE timed
    attempt (HUNTRESS_TT_BISECT=1): no variant is spent, no window can be lost, and every accepted subset is BANKED by
    the GM, so this both narrows the defect and advances the attempt.

    Day 15 rationale: a full-batch timed submit is graded all-or-nothing ('incorrect', no accepted/remaining counts), so
    an adapter that is wrong on ONE of 1026 fields learns nothing from it and the next variant fails the same way. A
    halving search over subsets turns that single bit into the id of the broken extractor.

    Descends only while a group is larger than `stop_at` (naming the family is enough to fix the extractor) and never
    makes more than `budget` submits. -> (suspect ids, banked ids, last result).
    """
    suspects, banked, calls = [], [], [0]

    def shot(g):
        r = sub({k: A[k] for k in g})
        calls[0] += 1
        say('localize: %4d field(s) -> %s (remaining=%s) [%d/%d]'
            % (len(g), r.get('result'), _remaining(r), calls[0], budget))
        return r

    def rec(g, last):
        """g is known to hold at least one rejected answer"""
        if len(g) <= stop_at or calls[0] >= budget:
            suspects.extend(g)
            return last
        h = len(g) // 2
        left, right = g[:h], g[h:]
        r = shot(left)
        if _ok(r):
            banked.extend(left)
            return rec(right, r)
        last = rec(left, r)
        if calls[0] >= budget:
            return last
        r2 = shot(right)                       # the right half is still unknown: it may hold a second defect
        if _ok(r2):
            banked.extend(right)
            return r2
        return rec(right, r2)

    last = rec(list(ids), {'result': 'incorrect'})
    return suspects, banked, last


def _one_considered_submit(gm, challenge_id, sub, A, cand, prefilled, ids, bad, t0):
    """ONE complete submit computed locally, or none. A candidate-only field takes its top-ranked candidate (the LANGS order is the
    considered choice); a field with no answer at all means nothing is submitted (HELD: a partial batch would use the GM as an oracle)."""
    # DECIDED 2026-10-18 (Commander): on a Time Trial a candidate-only field is NEVER sent as a top-ranked guess. It stays unresolved, so the attempt
    # is HELD with the field list (one ranked attempt is not spent on a guess). Untimed routes keep the guess exactly as before.
    hold_guess = challenge_id.endswith(('/time_trial', '/mastery'))   # one-shot routes: decided 2026-10-18 (Commander) - mastery is a single complete submit too
    guessed = {}
    for q, cands in list(cand.items()):
        if cands and q not in A and not hold_guess:
            A[q] = cands[0]
            guessed[q] = tuple(cands)
    held_guess = [q for q, cands in cand.items() if cands and q not in A] if hold_guess else []
    missing = [i for i in ids if i not in A]
    if held_guess:
        missing = list(dict.fromkeys(missing + held_guess))
    extra = dict(answered=len(A), undecodable_files=bad, wrong=[], probed={}, guessed=sorted(guessed), seconds=round(time.time() - t0, 1))
    if missing:
        r = {'result': 'HELD', 'why': '%d answer id(s) have no locally computed answer, e.g. %s: nothing submitted (solve locally first)'
             % (len(missing), ', '.join(sorted(map(str, missing))[:3]))}
        if held_guess:
            r['why'] = ('%d candidate-only field(s) not guessed on a Time Trial (decided 2026-10-18: no top-ranked guess in a timed route), e.g. %s: '
                        'nothing submitted' % (len(held_guess), ', '.join(sorted(map(str, held_guess))[:3])))
            r['guess_held'] = sorted(held_guess)
        r.update(extra, unresolved=missing)
        return r
    if hold_guess:
        # S6 (D32): a timed submit is never sent after the attempt's own deadline (a slow Mastery solve took up to 271 s): HELD instead.
        left = _cg.window_left()
        if left is not None and left <= 0:
            r = {'result': 'HELD', 'why': 'the timed window closed %.1f s ago before the solve finished: nothing submitted' % -left}
            r.update(extra, unresolved=[])
            return r
    r = sub(A)
    _res_upper = str(r.get('result', '')).upper()
    if _res_upper == 'CORRECT':
        for q, key in guessed.items():                    # a top-ranked candidate the GM accepted is a known winner from now on: no guess next time
            # this process runs Single, then Time Trial, then Mastery: the next mode of THIS challenge prefills it. S4 (D32): also remembered
            # per (challenge, field); the bare candidate-list key is marked guess-only, so a timed route of another field never trusts it.
            _LEARNED[key] = A[q]
            _GUESS_ONLY.add(key)
            _LEARNED[_field_key(challenge_id, q)] = A[q]
            _persist(gm, key, A[q])
        for q, cands in prefilled.items():
            _LEARNED[_field_key(challenge_id, q)] = A[q]
            _persist(gm, tuple(cands), A[q])
    elif prefilled:
        # S5 (D32): a remembered winner in a rejected submit must not be resent blindly by the next run in this process. With per-field
        # grading (accepted_ids) the ones the GM did not accept are recorded as rejected (memory + store); without it the winners are only
        # evicted from the in-process memory (no store write: which field was wrong is unknown).
        acc = r.get('accepted_ids')
        if isinstance(acc, list):
            restore_rejected(prefilled, [q for q in prefilled if q not in set(acc)], dict(A), {}, gm, batch=False)
        else:
            for q, cands in prefilled.items():
                if _LEARNED.get(tuple(cands)) == A.get(q):
                    del _LEARNED[tuple(cands)]
                _LEARNED.pop(_field_key(challenge_id, q), None)
    # ACCUMULATE-ON-CORRECT HOOK (B, 2026-10-15): on every GM CORRECT or accepted-partial, bank every GM-accepted
    # (token, raw, accepted) via field_formats.confirm_all. The field_id IS the token for script (ids like
    # 'jscript-launcher-url' are the parser key). Additive-only, no-guess (accepted_ids governs partial submits).
    if A and _res_upper in ('CORRECT', 'ACCEPTED'):
        # D31 HS 2026-10-30 (fork 1 D16-engineering-state item: confirm_all banking cost 3.67 s on
        # the D16 Single, scales with field count; ~55 s SS->TT and 44 s TT->MM gaps on D30 agent-1
        # per fork 4). The GM already said CORRECT by this point - banking is a learning write that
        # does not need to block the mode loop before the next TT/MM start.
        # Env HUNTRESS_SCRIPT_CONFIRM_ALL_ASYNC=0 restores synchronous banking (unchanged behaviour).
        import os as _os_ca, threading as _th_ca
        _async = _os_ca.environ.get("HUNTRESS_SCRIPT_CONFIRM_ALL_ASYNC", "1").strip() != "0"
        def _bank_now():
            try:
                import field_formats as _ff
                if _res_upper == 'CORRECT':
                    _pairs = [(q, A[q], A[q]) for q in A]
                else:
                    _acc = set(r.get('accepted_ids') or [])
                    _pairs = [(q, A[q], A[q]) for q in A if q in _acc]
                if _pairs:
                    _n = _ff.confirm_all(_pairs, day=None)
                    try: print("AUTOSOLVE script: field_formats.confirm_all banked %d new token(s)" % _n, flush=True)
                    except Exception: pass
            except Exception:
                pass
        if _async:
            # Daemon thread so a Python exit never waits on the banking write.
            _t = _th_ca.Thread(target=_bank_now, name="script-confirm-all-bank", daemon=True)
            _t.start()
        else:
            _bank_now()
    r.update(extra, unresolved=[])
    if _res_upper != 'CORRECT' and challenge_id.endswith(('/time_trial', '/mastery')):
        # FAIL FAST (2026-10-15, Day 15: a wrong Time Trial was followed by 800 s of silence and then 13 improvised probes). A timed route is ONE complete
        # submit: no retry, no probe loop, no oracle. Say so in the result NOW so the Commander sees the verdict at T+seconds and can start the explicit,
        # bounded diagnostic (HUNTRESS_TT_BISECT=1, <= 12 subset submits, deadline-free attempts only) instead of discovering it minutes later.
        r['fail_fast'] = ('timed one-shot %s: no automatic retry or probe loop. Next step is the bounded diagnostic: HUNTRESS_TT_BISECT=1 '
                          '(<= %d subset submits, only on a deadline-free attempt), or fix the extractor offline.' % (r.get('result'), _TT_BISECT_MAX))
        try:
            print('AUTOSOLVE script: FAIL-FAST %s -> %s' % (challenge_id, r.get('result')), flush=True)
        except Exception:
            pass
    return r


_TT_BISECT_MAX = 12            # hard ceiling for the diagnostic localisation on a timed route, whatever the environment says


def _cpm(event, **kw):
    """critical-path event through ctf_gm._cp (critical_path.py); a no-op when unavailable; never raises"""
    try:
        sys.modules["ctf_gm"]._cp(event, **kw)
    except Exception:
        pass


def run(gm, challenge_id, retries=1, for_time=False):
    """One automated shot at challenge_id (single, X/time_trial or X/mastery). Returns the last GM result (cleaned) plus
    'answered', 'unresolved', 'undecodable_files', 'wrong', 'seconds'.
    DEFAULT (user 2026-10-11: solve locally first, ONE considered attempt, never the GM as an oracle): exactly one complete submit, or none
    (HELD) when a field has no locally computed answer. The old regroup / single-field / candidate-probe loop runs only with
    HUNTRESS_ORACLE=lab on an UNTIMED route. A timed route is never retried automatically (a retry spends a fresh variant)."""
    t0 = time.time()
    timed = challenge_id.endswith('/time_trial') or challenge_id.endswith('/mastery')
    oracle = os.environ.get('HUNTRESS_ORACLE') == 'lab' and not timed
    if timed:
        retries = 0

    def sub(p):
        for _ in range(8):
            try:
                return _clean(gm.submit(challenge_id, p))
            except RuntimeError as e:
                if '429' in str(e):
                    _cg._check_window(0.5)   # same budget rule as start(): a submit retry must not outlive the ranked window either
                    time.sleep(0.5); continue
                raise
        return {'result': 'ratelimited'}

    for attempt in range(retries + 1):
        # only the FIRST attempt is ranked; a retry drops to the untimed pool so a lost window never burns a
        # second ranked rotation (same rule as the binary adapter)
        st = start(gm, challenge_id, for_time and attempt == 0)
        if st is None:
            return {'result': 'CORRECT', 'already_solved': True, 'answered': 0, 'unresolved': [],
                    'undecodable_files': [], 'wrong': [], 'seconds': round(time.time() - t0, 1)}
        blobs = [gm.download(challenge_id, e, i) for i, e in enumerate(gm.artifacts(st))]
        if not st.get('questions') and st.get('answer_ids'):
            _cq = _contract_questions(challenge_id, st)
            if _cq:
                st = dict(st, questions=_cq)
                print('AUTOSOLVE script: resumed start had no questions; %d taken from the saved contract (ids match)' % len(_cq), flush=True)
        _cpm('execute_begin', by='script', blobs=len(blobs))
        A, un, bad, cand, _sf = _solve(st, blobs, challenge_id)   # D32: the one solve path compute() uses too
        _cpm('execute_end', by='script', answered=len(A), unresolved=len(un))
        # S4 (D32): a guess accepted earlier rides in the first submit only for the same field of the same challenge (see prefill_known)
        prefilled = prefill_known(gm, A, cand, scope=challenge_id, timed=timed)
        origin = {q: tuple(c) for q, c in prefilled.items()}
        pre = set(prefilled)
        # D31 reopen: an empty answer_ids used to fall back to list(A), which makes 'missing' always empty and lets a partial batch through.
        ids = st.get('answer_ids') or [q.get('id') for q in (st.get('questions') or []) if isinstance(q, dict) and q.get('id')] or list(A)
        if timed and os.environ.get('HUNTRESS_TT_BISECT') == '1' and not st.get('deadline'):
            # DIAGNOSTIC MODE (Day 15, explicit opt-in): the attempt is already spent and carries NO deadline, so
            # subset submits cost no variant and can lose no window. See _localize.
            say = lambda m: print(m, flush=True)
            missing = [i for i in ids if i not in A]
            if missing:
                return {'result': 'HELD', 'why': '%d id(s) have no local answer: %s' % (len(missing), missing[:3]),
                        'unresolved': missing, 'answered': len(A), 'undecodable_files': bad,
                        'seconds': round(time.time() - t0, 1)}
            canary = next((i for i in ids if i.endswith('-campaign')), ids[0])
            rc = sub({canary: A[canary]})
            say('localize: canary %s -> %s (remaining=%s)' % (canary, rc.get('result'), _remaining(rc)))
            if not _ok(rc):
                return {'result': 'HELD', 'why': 'canary field %s was rejected too: this attempt no longer accepts '
                        'answers (dead or late), so a subset search would only mis-blame fields' % canary,
                        'unresolved': [], 'answered': len(A), 'undecodable_files': bad, 'suspects': [],
                        'seconds': round(time.time() - t0, 1)}
            pf = os.environ.get('HUNTRESS_TT_PROBE')
            if pf:
                # ENUM PROBE: {answer id: [candidate, ...]} for fields whose allowed values the GM lists. The whole
                # set goes first as ONE batch (the top candidate of each); only if that is rejected does each field
                # get its own single-field submit, which the GM grades independently.
                plan = json.load(open(pf, encoding='utf-8'))
                first = {q: c[0] for q, c in plan.items() if c}
                rg = sub(first)
                say('probe: top candidates as one batch (%d) -> %s (remaining=%s)' % (len(first), rg.get('result'), _remaining(rg)))
                won, last = {}, rg
                if _ok(rg):
                    won = dict(first)
                else:
                    for q, cands in plan.items():
                        for c in cands:
                            rr = sub({q: c})
                            last = rr
                            say('probe: %-28s %-14s -> %s (remaining=%s)' % (q, c, rr.get('result'), _remaining(rr)))
                            if _ok(rr):
                                won[q] = c
                                break
                say('probe: WINNERS %s' % json.dumps(won, sort_keys=True))
                # keep the GM's OWN result (a probe that completes the mode must still report CORRECT and its flag,
                # or the board records a solved mode as unsolved and loses the flag)
                r = dict(last or {})
                r.update(winners=won, answered=len(A), unresolved=[], undecodable_files=bad,
                         seconds=round(time.time() - t0, 1))
                return r
            gf = os.environ.get('HUNTRESS_TT_GROUPS')
            if gf:
                # EXPLICIT GROUPS: {label: [answer id, ...]} - one submit per group, so one call answers
                # "is this whole field family right?" instead of a blind halving.
                out = {}
                for lbl, gids in json.load(open(gf, encoding='utf-8')).items():
                    g = [i for i in gids if i in A]
                    if not g:
                        continue
                    rg = sub({k: A[k] for k in g})
                    out[lbl] = rg.get('result')
                    say('group %-28s %4d field(s) -> %s (remaining=%s)' % (lbl, len(g), rg.get('result'), _remaining(rg)))
                r = {'result': 'groups-probed', 'groups': out, 'answered': len(A), 'unresolved': [],
                     'undecodable_files': bad, 'seconds': round(time.time() - t0, 1)}
                return r
            rest = [i for i in ids if i != canary]
            susp, bk, last = _localize(sub, rest, A, say,
                                       budget=min(int(os.environ.get('HUNTRESS_TT_BISECT_CALLS') or _TT_BISECT_MAX), _TT_BISECT_MAX),
                                       stop_at=int(os.environ.get('HUNTRESS_TT_BISECT_STOP') or 8))
            say('localize: SUSPECTS (%d): %s' % (len(susp), ', '.join(susp)))
            r = dict(last or {})
            r.update(answered=len(A), unresolved=[], undecodable_files=bad, suspects=susp,
                     banked=len(bk) + 1, seconds=round(time.time() - t0, 1))
            return r
        if not oracle:
            _r1 = _one_considered_submit(gm, challenge_id, sub, A, cand, prefilled, ids, bad, t0)
            if _sf:
                _shape_mark(challenge_id, _r1)           # CORRECT on the Single proves the shape solver here; anything else benches it
            return _r1
        wrong, pre_wrong, probed = [], [], {}
        r = sub(A) if A else {'result': 'nothing-to-submit'}
        # Every field of the first batch banked (the GM's own remaining count says so): nothing below needs re-checking. Without counts the old, safe
        # path runs (re-submit by group), so a GM that banks only part of a rejected batch can never leave a wrong answer standing in A.
        first_ok = _ok(r) and _banked(len(ids), r, len(A)) is True
        if not _done(r) and A and not first_ok:
            sure = [i for i in ids if i in A and i not in pre]

            def grp(pick):
                nonlocal r
                if not pick:
                    return
                rr = sub({k: A[k] for k in pick})
                if str(rr.get('result')) not in ('accepted', 'CORRECT'):
                    for qid in pick:
                        rr = sub({qid: A[qid]})
                        if str(rr.get('result')) not in ('accepted', 'CORRECT'):
                            wrong.append(qid)
                        if _done(rr):
                            break
                r = rr
            if pre and sure:                              # who made the first batch fail? try the CERTAIN fields alone: one submit
                rs = sub({k: A[k] for k in sure})
                if _ok(rs):
                    r = rs
                else:
                    grp([i for i in sure if not i.endswith(MODEL_SUFFIX)])
                    for suf in MODEL_SUFFIX:
                        if _done(r):
                            break
                        grp([i for i in sure if i.endswith(suf)])
            elif sure:
                grp([i for i in sure if not i.endswith(MODEL_SUFFIX)])
                for suf in MODEL_SUFFIX:
                    if _done(r):
                        break
                    grp([i for i in sure if i.endswith(suf)])
            # the remembered winners get their OWN batch per candidate list: a stale one costs one rejected submit, not one per field (defect 1)
            by_key = {}
            for q in prefilled:
                by_key.setdefault(origin[q], []).append(q)
            for k, qs in by_key.items():
                if _done(r):
                    break
                rp = sub({q: A[q] for q in qs})
                if _ok(rp):
                    r = rp
                else:
                    pre_wrong.extend(qs); r = rp
        # Candidate probing (e.g. the interpreter technique of a language with no dedicated T1059 sub-technique): one
        # field per submit AFTER everything certain is banked. The GM banks accepted individual submits and a rejected
        # single-field submit changes nothing else, so this never risks fields already accepted.
        restore_rejected(prefilled, pre_wrong, A, cand, gm, batch=True)
        pr, r = probe_candidates(gm, cand, sub, _done, A, r, origin)
        probed.update(pr)
        held = set()
        for q, cands in prefilled.items():               # a remembered winner that HELD is one more confirmation for the store
            k = tuple(cands)
            if q in A and q not in pre_wrong and k not in held:
                held.add(k); _persist(gm, k, A[q])
        if 'expired' in _state_words(r) and attempt < retries:
            gm.retry(challenge_id); continue
        break
    r.update(answered=len(A), unresolved=[i for i in un if i not in A], undecodable_files=bad, wrong=wrong,
             probed=probed, seconds=round(time.time() - t0, 1))
    return r


if __name__ == '__main__':
    from ctf_gm import GM
    cid = sys.argv[1]
    gm = GM()
    if '--dry' in sys.argv:
        st = start(gm, cid)
        if st is None:
            print(json.dumps({'result': 'CORRECT', 'already_solved': True})); sys.exit(0)
        blobs = [gm.download(cid, e, i) for i, e in enumerate(gm.artifacts(st))]
        t = time.time(); A, un, bad, _c, _s = _solve(st, blobs, cid)   # the same path run() takes (multiset family included)
        print(json.dumps({'ids': len(st.get('answer_ids') or []), 'answered': len(A), 'unresolved': un[:40],
                          'undecodable_files': bad, 'compute_s': round(time.time() - t, 2)}))
    else:
        r = run(gm, cid)
        print(json.dumps({k: r.get(k) for k in ('result', 'remaining', 'answered', 'unresolved', 'undecodable_files',
                                                'wrong', 'probed', 'seconds')}))
