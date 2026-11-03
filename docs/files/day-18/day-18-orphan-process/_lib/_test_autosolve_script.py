#!/usr/bin/env python3
"""Offline regression for autosolve_script.compute: replays saved attempts (task.json + artifact) and diffs the answers
against answer sets from GM-confirmed runs. No GM calls. Run from the framework root (WSL):
  python3 challenges/_lib/_test_autosolve_script.py"""
import io, json, os, sys, time, zipfile
sys.path.insert(0, os.path.join(os.getcwd(), 'challenges', '_lib'))
import autosolve_script as AS

H = os.path.expanduser('~')
C = os.path.join(os.getcwd(), 'challenges')


def res(name):
    try:
        r = json.load(open(os.path.join(H, name)))
        return '%s/%s' % (r.get('result'), r.get('remaining'))
    except Exception:
        return 'n/a'


def zipdir(d):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w') as z:
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if os.path.isfile(p):
                z.write(p, f)
    return b.getvalue()


_CASES = []


def _allowed(i, got, want):
    """A difference the GM itself has shown to be no difference.

    batch-*-expansion: until Day 15 the solver answered 'delayed' for EVERY batch fixture and Days 02-07 were graded
    CORRECT, so 'delayed' is an accepted value on those days' attempts. The Day 15 grader is stricter: all 9
    'delayed' labels of one time_trial attempt were rejected, and the form-derived labels (percent / call_double /
    delayed / for_indirect, read from the descriptor reconstruction statement exactly as the GM question describes)
    were accepted in one submit -> CORRECT. So a form-derived label that only differs from an old 'delayed'
    reference is the better answer, not a regression; anything else is still a failure."""
    return i.endswith('-expansion') and want == 'delayed' and got in (
        'percent', 'delayed', 'call_double', 'for_indirect')


def case(label, task, blobs, ref, ref_note):
    t = time.time()
    A, un, bad = AS.solve_fields(task, blobs)
    ids = task['answer_ids']
    diff = [i for i in ids if i in ref and i in A and str(A[i]) != str(ref[i])
            and not _allowed(i, str(A[i]), str(ref[i]))]
    missing = [i for i in ids if i not in A]
    ok = not diff and not missing
    print('%-34s %s  answered %d/%d  diffs %d  unresolved %d  undecodable %s  %.2fs  [ref: %s]' % (
        label, 'PASS' if ok else 'FAIL', len(A), len(ids), len(diff), len(missing), bad, time.time() - t, ref_note))
    for i in diff[:5]:
        print('   diff', i, repr(A[i])[:60], '!=', repr(ref[i])[:60])
    if missing:
        print('   unresolved', missing[:8])
    _CASES.append(ok)
    return ok


def _bytes_or_none(rel):
    """D32: a staged artifact that is not on this machine SKIPS its cases (printed), instead of crashing the whole suite"""
    p = os.path.join(C, rel)
    if os.path.exists(p):
        return open(p, 'rb').read()
    print('SKIP (fixture bytes absent on this machine): %s' % rel)
    return None


ok = True
t7 = json.load(open(os.path.join(C, 'Day 07/_stage/Node_by_Node/task.json'), encoding='utf-8'))
a7 = _bytes_or_none('Day 07/_stage/Node_by_Node/artifact_0.bin')
# reference = the agent's final answers (staged_chain role mapping, GM-confirmed CORRECT per the writeup). [home path]
# is NOT used: it is the batch the GM rejected (node_result_single = incorrect) before relay-handoff -> staged_chain was learned.
ok &= a7 is None or case('Day07 single (staged attempt)', t7, [a7],
           json.load(open(os.path.join(C, 'Day 07/Node by Node/scripts/local_answers.json'))),
           'Day07 local_answers.json (final, GM-confirmed mapping)')
t6 = json.load(open(os.path.join(C, 'Day 06/_stage/Shell_We_Begin/task.json'), encoding='utf-8'))
a6 = _bytes_or_none('Day 06/_stage/Shell_We_Begin/artifact_0.bin')
ok &= a6 is None or case('Day06 single (staged attempt)', t6, [a6],
           json.load(open(os.path.join(C, 'Day 06/Shell_We_Begin/scripts/local_answers.json'))),
           'Day06 local_answers.json, GM ' + res('shell_result_single.json'))
for tt in ('tt1', 'tt2'):
    d = os.path.join(C, 'Day 06/Shell_We_Begin/fixtures_' + tt)
    ref = os.path.join(C, 'Day 06/Shell_We_Begin/scripts/answers_fixtures_%s.json' % tt)
    if os.path.isdir(d) and os.path.exists(ref):
        ok &= case('Day06 time_trial fixtures_' + tt, t6, [zipdir(d)], json.load(open(ref)),
                   'answers_fixtures_%s.json (solver output; GM tt %s)' % (tt, res('shell_result_time_trial.json')))
# Day 15 Crumb Trail TIME TRIAL: the real bytes of a timed attempt (saved by the timed corpus) against the answers the
# GM accepted for it -> mode CORRECT. It is the one case in this suite whose batch expansion labels are GM-confirmed as
# form-derived (percent x4, call_double x4, delayed x1), so it must stay EXACT, with no allowance.
# The real timed bytes come from the local _timed_corpus OR the shared git fixtures (archive_pack.corpus_dirs, bytes through archived_blobs): the old hard-coded WSL path
# ([local path]) does not exist under Windows python, so this case was silently SKIPPED there (24 cases instead of 25, found 2026-10-16 when the results record flipped between the two Pythons).
try:
    import archive_pack as _AP
    import archived_blobs as _AB
    _d15dir = next((d for d in _AP.corpus_dirs('script-analysis-day-15-credential-store-clues_time_trial') if _AB.has_blobs(d)), None)
except Exception:
    _d15dir = None
_D15_REF = os.path.join(C, 'Day 15/Crumb Trail/scripts/tt_accepted_answers.json')
if _d15dir and os.path.exists(_D15_REF):
    t15 = json.load(open(os.path.join(C, 'Day 15/_stage/Crumb_Trail/task.json'), encoding='utf-8'))
    ok &= case('Day15 time_trial (real bytes)', t15, [_AB.blobs(_d15dir)[0]], json.load(open(_D15_REF)),
               'Day15 tt_accepted_answers.json (GM-confirmed CORRECT)')
else:
    print('Day15 time_trial (real bytes)  NOT RUN: no archived attempt or no accepted-answers file on this machine')
    ok = False        # a missing real-bytes case is a coverage loss, never a silent pass

# NEW-LANGUAGE cases: present the Day 07 .mjs fixtures as a language the Day 07 solver has no branch for. Decoding must
# go through the LANGS registry; every descriptor field must match the GM-confirmed answers; the interpreter ATT&CK field
# must be the certain sub-technique when one exists (.lua -> T1059.011) or be offered as ordered probe candidates
# (.ts -> T1059.007, T1059 / .rb -> T1059) and NOT hard-coded; role-derived attack values (T1105, T1041...) stay exact.
import ctf_gm
members = dict(ctf_gm.unzip(a7)) if a7 is not None else {}
mjs = sorted(n for n in members if n.endswith('.mjs'))
ref7 = json.load(open(os.path.join(C, 'Day 07/Node by Node/scripts/local_answers.json')))
mjs_ids = [q['id'] for q in t7['questions'] if q['artifact'].strip().endswith('.mjs')]
INTERP = 'T1059.007'                                   # what the .mjs (JavaScript) interpreter-type roles graded as


def split_concat(src, op):
    """Rewrite the Material_ literal as two concatenated literals joined by the language's concat operator."""
    import re
    m = re.search(r'(Material_\w+\s*=\s*)"((?:[^"\\]|\\.)*)"', src)
    if not m or len(m.group(2)) < 8:
        return src
    s = m.group(2); h = len(s) // 2
    if s[h - 1] == '\\':
        h += 1
    return src[:m.start()] + m.group(1) + '"%s" %s "%s"' % (s[:h], op, s[h:]) + src[m.end():]


import re as _re


def comments(s, mark):   # only line-start // comments: '//' also occurs inside base64 materials
    return _re.sub(r'(?m)^(\s*)//', lambda m: m.group(1) + mark, s)


VARIANTS = {   # ext: (source rewrite, expected attack for interpreter roles: value in A, or candidate list)
    '.ts': (lambda s: s, ('cand', ['T1059.007', 'T1059'])),
    '.lua': (lambda s: split_concat(comments(s.replace('const ', 'local '), '--'), '..'), ('value', 'T1059.011')),
    '.rb': (lambda s: split_concat(comments(s.replace('const ', ''), '#'), '+'), ('cand', ['T1059'])),
    # PROXY-EXECUTION / PERSISTENCE carriers (2026-10-10): the real Day 07 fixtures presented under each new extension. Descriptor fields must
    # still be exact against the GM-confirmed answers; the interpreter-attack fields must be OFFERED as ordered candidates, never hard-coded.
    '.hta': (lambda s: s, ('cand', ['T1218.005', 'T1059.005', 'T1059.007'])),
    '.sct': (lambda s: s, ('cand', ['T1218.010', 'T1059.005', 'T1059.007', 'T1218.011'])),
    '.wsc': (lambda s: s, ('cand', ['T1218.010', 'T1059.005', 'T1059.007', 'T1218.011'])),
    '.wsf': (lambda s: s, ('cand', ['T1059.005', 'T1059.007'])),
    '.xsl': (lambda s: s, ('cand', ['T1220'])),
    '.csproj': (lambda s: s, ('cand', ['T1127.001'])),
    '.reg': (lambda s: s, ('cand', ['T1547.001', 'T1112'])),
    '.inf': (lambda s: s, ('cand', ['T1218.003', 'T1218.011'])),
    '.bas': (lambda s: s, ('cand', ['T1059.005'])),
    # PERSISTENCE carriers (lane_progress.py): Day 10 was WMI persistence; its siblings are the likely next carriers
    '.xml': (lambda s: s, ('cand', ['T1053.005'])),
    '.service': (lambda s: s, ('cand', ['T1543.002'])),
    '.timer': (lambda s: s, ('cand', ['T1053.006', 'T1543.002'])),
    '.plist': (lambda s: s, ('cand', ['T1543.001', 'T1543.004', 'T1647'])),
    '.cron': (lambda s: s, ('cand', ['T1053.003'])),
    '.desktop': (lambda s: s, ('cand', ['T1547.013'])),
    '.mof': (lambda s: s, ('cand', ['T1546.003'])),
}
for ext, (rewrite, expect) in (VARIANTS.items() if a7 is not None else ()):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w') as z:
        for n, d in members.items():
            if n.endswith('.mjs'):
                z.writestr(n[:-4] + ext, rewrite(d.decode('utf-8')).encode('utf-8'))
            else:
                z.writestr(n, d)
    tq = json.loads(json.dumps(t7))
    for q in tq['questions']:
        if q['artifact'].strip().endswith('.mjs'):
            q['artifact'] = q['artifact'].strip()[:-4] + ext
    A, un, bad, cand = AS.solve_fields_ext(tq, [b.getvalue()])
    good, bad_v, interp_ok, interp_n = 0, [], True, 0
    for i in mjs_ids:
        if i.endswith('-attack') and str(ref7[i]) == INTERP:
            interp_n += 1
            if expect[0] == 'value':
                interp_ok &= A.get(i) == expect[1]
            else:
                interp_ok &= i not in A and cand.get(i) == expect[1]
        elif i in A and str(A[i]) == str(ref7[i]):
            good += 1
        else:
            bad_v.append(i)
    v_ok = not bad_v and not bad and interp_ok and interp_n > 0
    print('%-34s %s  %d files as %s: %d/%d non-interpreter fields exact, %d interpreter-attack fields %s, wrong/missing %s, '
          'undecodable %s' % ('NEW-LANGUAGE ' + ext, 'PASS' if v_ok else 'FAIL', len(mjs), ext, good, len(mjs_ids) - interp_n,
                               interp_n, ('= %s' % expect[1]) if expect[0] == 'value' else ('-> probe %s' % expect[1]),
                               bad_v[:6], bad))
    ok &= v_ok
    _CASES.append(v_ok)
# COMMENT-WRAPPED MARKER (Day 14 Trust the Process, msbuild .proj): the HUNTRESS_ANALYSIS_V1 marker sits inside a host-language
# comment, so MARK's capture keeps that comment's terminator (' -->'). Base64 payloads survived it silently; hex ones did not.
# Every marker kind must decode under every comment style, and a truncated comment copy must fall back to the <HuntressDescriptor>
# property MSBuild carries it in.
import binascii as _bx
import base64 as _b6
import tempfile as _tf
import solve_poly_d8 as _P

_DESC = ('v=3|language=msbuild_xml|role=downloader|verdict=suspicious|attack=T1105|adapter=http_client|'
         'host_profile=standalone|obfuscation_profile=fragmented_hex|stage_profile=cross_language_handoff|'
         'next_language=jscript|stage_count=3|steps=profile_host,decode_configuration,dispatch_language|'
         'campaign_id=MSBUILD_XML-d5e100e6|url=https://msbuild_xml-d5e100e69e.example.invalid/stage|'
         'file_path=/tmp/huntress-msbuild_xml/.d5e100e69ea58028.stage')


def _enc(kind, s):
    h = _bx.hexlify(s.encode()).decode()
    if kind == 'HEX':
        return h
    if kind == 'B64':
        return _b6.b64encode(s.encode()).decode()
    if kind == 'HB64':
        return _bx.hexlify(_b6.b64encode(s.encode())).decode()
    if kind == 'FRAG':
        return '.'.join(h[i:i + 24] for i in range(0, len(h), 24))
    raise ValueError(kind)


_STYLES = {'xml_comment': '<!-- %s -->', 'c_block': '/* %s */', 'php_close': '<?php /* %s */ ?>',
           'ps_block': '<# %s #>', 'lua_dash': '-- %s --', 'cdata': '<![CDATA[ %s ]]>',
           'bare_line': '// %s',
           # 2026-10-14 (homestation, post-ALLDONE): extend to the remaining common comment syntaxes so NO wrapper
           # can strand a payload again (the Day-14 msbuild XML-comment bug, made exhaustive across carriers).
           'hash_line': '# %s', 'semicolon_line': '; %s', 'batch_rem': 'REM %s',
           'lua_block': '--[[ %s ]]', 'sql_line': '-- %s'}
_md = _tf.mkdtemp(prefix='marker_wrap_')
_wrap_bad, _wrap_n = [], 0
for _style, _fmt in _STYLES.items():
    for _kind in ('HEX', 'B64', 'HB64', 'FRAG'):
        _p = os.path.join(_md, '%s_%s.proj' % (_style, _kind))
        open(_p, 'w').write(_fmt % ('HUNTRESS_ANALYSIS_V1:%s-%s' % (_kind, _enc(_kind, _DESC))) + '\n')
        _wrap_n += 1
        try:
            _k, _kv = _P.desc_of(_p)
            if _kv != dict(x.split('=', 1) for x in _DESC.split('|')):
                _wrap_bad.append('%s/%s: fields differ' % (_style, _kind))
        except Exception as _e:
            _wrap_bad.append('%s/%s: %s' % (_style, _kind, _e))
# property fallback: the comment copy is truncated mid-payload, the <HuntressDescriptor> property is whole
_full = _enc('HEX', _DESC)
_p = os.path.join(_md, 'property_fallback.proj')
open(_p, 'w').write('<!-- HUNTRESS_ANALYSIS_V1:HEX-%s -->\n<Project><PropertyGroup><HuntressDescriptor>%s'
                    '</HuntressDescriptor></PropertyGroup></Project>\n' % (_full[:60], _full))
_wrap_n += 1
try:
    _k, _kv = _P.desc_of(_p)
    if _kv.get('campaign_id') != 'MSBUILD_XML-d5e100e6':
        _wrap_bad.append('property_fallback: fields differ')
except Exception as _e:
    _wrap_bad.append('property_fallback: %s' % _e)
_w_ok = not _wrap_bad
print('%-34s %s  %d marker/comment-style combinations decode (kinds HEX,B64,HB64,FRAG x %d styles + property fallback), '
      'failures %s' % ('COMMENT-WRAPPED MARKER', 'PASS' if _w_ok else 'FAIL', _wrap_n, len(_STYLES), _wrap_bad[:6]))
ok &= _w_ok
_CASES.append(_w_ok)

try:
    import adapter_coverage as AC
    AC.record('script_cases', sum(1 for c in _CASES if c), len(_CASES), all(_CASES))
except Exception:
    pass
print('RESULT:', 'PASS' if ok else 'FAIL')
sys.exit(0 if ok else 1)
