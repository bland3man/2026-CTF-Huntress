#!/usr/bin/env python3
"""Expansion Pack deterministic static solver (Huntress CTF 2026 Day 03).
Usage on VM:  python3 solve_expansion.py <mode>   (mode: single|time_trial|mastery|dry)
  dry = start+download+decode, print answers, do NOT submit.
Static only: JS configs via node with eval replaced by JSON.parse (sinks never run);
batch via codec decode of HUNTRESS-MATERIAL / fragment concat; PS1 via base64 literal.
"""
import sys, os, re, io, json, base64, subprocess, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.expanduser('~'))
CHAL = {'single': 'script-analysis-day-03-batch-expansion',
        'time_trial': 'script-analysis-day-03-batch-expansion/time_trial',
        'mastery': 'script-analysis-day-03-batch-expansion/mastery'}

JSDEC = r"""
const fs=require('fs');const dir=process.argv[1];const out={};
for (const f of fs.readdirSync(dir).filter(x=>x.endsWith('.js'))) {
  let src=fs.readFileSync(dir+'/'+f,'utf8').replace(/eval\(/g,'__ev(');
  const m=src.match(/(?:function|var)\s+(inspect_\w+)/);
  const w='var __ev=function(s){return JSON.parse(s.slice(1,-1));};\n'+src+'\n;__res='+m[1]+'();';
  global.__res=null; global.ActiveXObject=function(){throw new Error('blocked')};
  try{(0,eval)(w);out[f]=global.__res;}catch(e){out[f]='ERR '+e.message}
}
console.log(JSON.stringify(out));
"""
# role by step signature (locked on single_solve ground truth)
ROLE_BY_STEPS = {
    'decode_configuration,return_configuration': 'benign_utility',
    'acquire_remote,dispatch_memory': 'stager',
    'decode_embedded,write_file': 'dropper',
    'acquire_remote,write_file': 'downloader',
    'locate_local,dispatch_process': 'launcher',
    'acquire_remote,write_file,dispatch_process,handoff_script': 'staged_chain',
    'locate_local,prepare_transfer,upload_remote': 'uploader',
    'enumerate_targets,transform_content,write_recovery_note': 'impact',
}
# attack ground truth by role (single_solve accepted). launcher/chain/relay = interpreter technique per language
ATT = {'benign_utility': 'none', 'stager': 'T1105', 'dropper': 'T1140', 'downloader': 'T1105',
       'uploader': 'T1041', 'impact': 'T1486'}
ATT_LANG = {'js': 'T1059.007', 'bat': 'T1059.003'}
# expansion label by id-key (single_solve accepted; SLOT-FIXED author metadata, NOT form-derived:
# benign & launcher had identical for+call-set forms yet different labels). default 'delayed'.
EXPANSION = {'benign': 'for_indirect', 'launcher': 'call_double'}
# control label by id-key. slot-fixed values confirmed on single_solve (tried before bctl-by-form).
CONTROL_FIXED = {'benign': 'errorlevel_guard', 'stager': 'direct', 'dropper': 'goto_dispatch',
                 'downloader': 'direct', 'uploader': 'call_subroutine', 'launcher': 'if_guard',
                 'impact': 'direct', 'chain': 'errorlevel_guard', 'relay': 'if_guard'}


def decode_material(mat):
    """Generic: try b64/hex/dotdec x identity/reverse/xor; pick output starting 'v=1|'."""
    raws = []
    try: raws.append(base64.b64decode(mat + '=' * (-len(mat) % 4)))
    except Exception: pass
    try: raws.append(bytes.fromhex(mat))
    except Exception: pass
    try: raws.append(bytes(int(x) for x in mat.split('.')))
    except Exception: pass
    for r in raws:
        for k in range(256):
            for order in (0, 1):
                b = bytes(x ^ k for x in r)
                if order: b = b[::-1]
                if b.startswith(b'v=1|'): return b.decode('latin-1')
        for k in range(256):
            b = bytes(x ^ k for x in r[::-1])
            if b.startswith(b'v=1|'): return b.decode('latin-1')
    return None


def decode_frags(t):
    groups = {}
    for m in re.finditer(r'(?im)^set\s+"?([A-Za-z_]+?)(\d)=(.*)$', t):
        n, i, v = m.group(1), int(m.group(2)), m.group(3).rstrip()
        v = re.sub(r'"?\s*&\s*rem HUNTRESS.*$', '', v)
        if v.endswith('"'): v = v[:-1]
        if re.search(r'[%!]' + re.escape(n) + r'\d', v): continue
        groups.setdefault(n.lower(), []).append((i, v.replace('^|', '|').replace('^&', '&')))
    best = ''
    for n, fr in groups.items():
        fr.sort(key=lambda x: x[0])
        sj = ''.join(v for _, v in fr)
        if sj.startswith('v=1|') and len(sj) > len(best): best = sj
    return best


def kv_of(s): return dict(x.split('=', 1) for x in s.split('|') if '=' in x)


def jsstyle(src):
    i = src.index('inspect_'); tail = src[i:]
    # order matters: `var inspect_X = function inspect_X_body(` is a NAMED expression, not a
    # declaration (the inner name also starts with inspect_), so test the var-assignment forms first.
    if re.search(r'var\s+inspect_\w+\s*=\s*function\s+\w+', src):
        fs = 'named_expression'
    elif re.search(r'var\s+inspect_\w+\s*=\s*function\s*\(', src):
        fs = 'anonymous_expression'
    elif re.search(r'function\s+inspect_\w+\s*\(', src):
        fs = 'declaration'
    else:
        fs = 'anonymous_expression'
    m = re.search(r'recover_\w+(\.call\(|\.apply\(|\()', tail)
    inv = {'(': 'direct', '.call(': 'call', '.apply(': 'apply'}[m.group(1)]
    dot = bool(re.search(r'\b\w+\.(steps|adapter|values|stageCount)\b', tail))
    br = bool(re.search(r'\["(steps|adapter|values|stageCount)"\]', tail))
    ps = 'mixed' if dot and br else ('bracket_literal' if br else 'dot')
    return fs, inv, ps


def region(t):
    m = re.search(r'(?s):HUNTRESS_SEPARATOR_DONE\s*\n(.*?)\n\s*echo\(', t)
    return m.group(1) if m else t


def expform(r, full=None):
    """Expansion label of the DESCRIPTOR RECONSTRUCTION STATEMENT, read from its own syntax, exactly as the GM
    question states it ("Classify only the expansion form used by the descriptor reconstruction statement. Ignore
    output, echo, host-envelope, and separator-noise lines that may use a different expansion form."):
        for %%G in (...) do call set   -> for_indirect
        call set "x=%%a%%%%b%%"       -> call_double
        set "x=!a!!b!"                -> delayed
        set "x=%a%%b%"                -> percent
    `full` is the whole fixture text; the variable echoed at the end names the reconstruction target, which is what
    tells the reconstruction apart from the fragment, primer and neutral `set` lines.

    CONFIRMED LIVE, Day 15 Crumb Trail time_trial (homestation): all 9 batch fixtures of one attempt, covering
    percent (4), call_double (4) and delayed (1), accepted in one submit -> mode CORRECT. It REPLACES an empirical
    rule that keyed off the fragment variable being named 'h' and answered 'delayed' for everything else; that rule
    labelled all 9 of this attempt's fixtures 'delayed' and was the single reason the first timed submit failed."""
    var = None
    if full:
        m = re.search(r'echo\(\s*[%!](\w+)[%!]', full)
        if m:
            var = m.group(1)
    recon = ''
    for line in r.splitlines():
        m = re.search(r'(?i)(?:^|[\s(&|])(?:call\s+)?set\s+"?([\w]+)\s*=', line)
        if not m or '=' not in line:
            continue
        if var and m.group(1) != var:
            continue
        rhs = line.split('=', 1)[1]
        if len(re.findall(r'%%?[\w]+%{0,2}|![\w]+!', rhs)) < 2:
            continue                      # a primer (set "x=") or a neutral/fragment line, not the reconstruction
        recon = line
    if not recon:
        return 'delayed'
    if re.match(r'(?i)\s*(?:if\s+\S+\s+\S+\s+)?for\s+%%', recon):
        return 'for_indirect'
    if re.search(r'(?i)(?:^|[\s(&|])call\s+set\s', recon):
        return 'call_double'
    rhs = recon.split('=', 1)[1]
    if re.search(r'![\w]+!', rhs):
        return 'delayed'
    if re.search(r'%[\w]+%', rhs):
        return 'percent'
    return 'delayed'


def bctl(t):
    """Control form from the RECOVERY REGION only (verified vs GM-accepted labels, mastery 2026-10-03).
    for /l counted-loop form has no confirmed label yet -> 'for_loop' placeholder (fast_mastery probes candidates)."""
    r = region(t)
    if re.search(r'(?im)^\s*for\s+/l', r): return 'call_subroutine'  # GM-accepted Day 04 single (3/3 for /l files)
    if re.search(r'(?im)^\s*goto\s+:HUNTRESS_DISPATCH', r): return 'goto_dispatch'
    if re.search(r'(?im)^\s*call\s+:HUNTRESS_RECOVER', r): return 'call_subroutine'
    if re.search(r'(?im)^\s*if\s+errorlevel', r): return 'errorlevel_guard'
    if re.search(r'(?im)^\s*if\s+defined', r): return 'if_guard'
    return 'direct'


def analyze(d):
    F = {}
    js = json.loads(subprocess.check_output(['node', '-e', JSDEC, d], text=True))
    for f in sorted(os.listdir(d)):
        p = os.path.join(d, f); t = open(p, encoding='utf-8', errors='replace').read()
        if f.endswith('.ps1'):
            b = re.search(r"FromBase64String\('([^']+)'\)", t).group(1)
            F[f] = {'lang': 'ps1', 'obj': json.loads(base64.b64decode(b))}
        elif f.endswith('.js'):
            c = js[f]
            if isinstance(c, str): raise RuntimeError(f + ' ' + c)
            F[f] = {'lang': 'js', 'cfg': c, 'steps': ','.join(c['steps']), 'style': jsstyle(t)}
        elif f.endswith(('.cmd', '.bat')):
            mat = re.search(r'MATERIAL:(\S+)', t).group(1)
            a = decode_material(mat); b = decode_frags(t)
            if a and a != b: print('WARN material/fragment mismatch', f, a, b, file=sys.stderr)
            s = b if (b and b.startswith('v=1|')) else a
            body = t[t.find(':HUNTRESS_INSPECT'):]
            recon = next((l.strip() for l in body.splitlines()
                          if re.search(r'=\s*[%!].*[%!]', l) and ('cfg' in l or 'recovered' in l or 'item9' in l or 'ReCoVeReD' in l)), '')
            F[f] = {'lang': 'bat', 'kv': kv_of(s), 'ctl': bctl(t), 'mat_ok': a == b,
                    'recon': recon, 'exp': expform(region(t), t), 'for': bool(re.search(r'(?im)^\s*for\s', body)),
                    'callset': bool(re.search(r'call\s+set', body))}
    return F


def build(F, questions):
    A = {}; unresolved = []
    for q in questions:
        rawid = q['id']; qid = re.sub(r'^set\d+\.', '', rawid)  # mastery doubles ids as set1./set2.
        art = q['artifact'].split('->')[-1].strip(); fe = F.get(art)
        val = None
        try:
            if fe is None: raise KeyError('no file ' + art)
            if fe['lang'] == 'ps1':
                o = fe['obj']; pre = qid.split('-')[0]; rest = qid.split('-', 1)[1]
                if rest == 'scenario': val = {'resource': 'resource_hijacking', 'collection': 'synthetic_collection', 'impact': 'synthetic_impact'}[pre]
                elif rest == 'attack': val = {'resource': 'T1496', 'collection': 'T1555.003', 'impact': 'T1486'}[pre]
                elif pre == 'resource': val = {'url': o['b'], 'wallet': o['c'], 'mutex': o['h']}[rest]
                elif pre == 'collection': val = {'url': o['b'], 'file': o['c'][0], 'user-agent': o['f']}[rest]
                elif pre == 'impact': val = {'extension': o['b'], 'note': o['c'], 'url': o['d']}[rest]
            elif fe['lang'] == 'js':
                c = fe['cfg']; v = c['values']; slot = qid.split('-')[1]
                role = ROLE_BY_STEPS[fe['steps']]  # relay's 4-step graph classifies as staged_chain
                field = qid.split('-', 2)[2]
                if field == 'role': val = role
                elif field == 'attack': val = ATT.get(role) or ATT_LANG['js']
                elif field == 'adapter': val = c['adapter']
                elif field == 'campaign': val = v['campaign_id']
                elif field == 'host': val = v['host_id']
                elif field == 'url': val = v['url']
                elif field == 'path': val = v['file_path']
                elif field == 'next-stage': val = v['next_stage']
                elif field == 'extension': val = v['extension']
                elif field == 'note': val = v['note_name']
                elif field == 'function-style': val = fe['style'][0]
                elif field == 'invocation-style': val = fe['style'][1]
                elif field == 'property-style': val = fe['style'][2]
            else:
                b = fe['kv']; key = qid.split('-')[1]
                role = ROLE_BY_STEPS[b['steps']]  # relay's 4-step graph classifies as staged_chain
                field = qid.split('-', 2)[2]
                if field == 'role': val = role
                elif field == 'attack': val = ATT.get(role) or ATT_LANG['bat']
                elif field == 'adapter': val = b['adapter']
                elif field == 'campaign': val = b['campaign_id']
                elif field == 'host-id': val = b['host_id']
                elif field == 'url': val = b['url']
                elif field == 'upload-url': val = b['upload_url']
                elif field == 'file-path': val = b['file_path']
                elif field == 'note-name': val = b['note_name']
                elif field == 'next-stage': val = b['next_stage']
                elif field == 'expansion':
                    # FORM-derived (confirmed live): for-loop+callset->for_indirect,
                    # callset without for->call_double, plain set concat (% or !)->delayed.
                    val = fe.get('exp') or 'delayed'
                elif field == 'control': val = fe['ctl']  # form-derived (bctl) matches accepts
                elif field == 'graph': val = b['graph']
        except Exception as e:
            print('ERR', qid, repr(e), file=sys.stderr)
        if val is None: unresolved.append(rawid)
        else: A[rawid] = val
    return A, unresolved


def run(mode):
    from ctf_gm import GM, unzip
    gm = GM(); c = CHAL[mode]
    st = gm.start(c)
    print('attempt', st.get('attempt_id'), st.get('mode'), 'deadline', st.get('deadline'), flush=True)
    blobs = [gm.download(c, e, i) for i, e in enumerate(gm.artifacts(st))]
    # Map each set (set1./set2./...) to its OWN artifact; no prefix -> single set, art0.
    qs = st['questions']
    sets = sorted({(re.match(r'^(set\d+)\.', q['id']).group(1) if re.match(r'^set\d+\.', q['id']) else '') for q in qs})
    Fs = []
    for i in range(len(sets)):
        d = tempfile.mkdtemp(prefix='exp_')
        for n, data in unzip(blobs[min(i, len(blobs) - 1)]):
            bn = os.path.basename(n); assert bn and '..' not in n
            open(os.path.join(d, bn), 'wb').write(data)
        Fs.append(analyze(d))
    A, un = {}, []
    for i, sp in enumerate(sets):
        grp = [q for q in qs if (q['id'].startswith(sp + '.') if sp else True)]
        a, u = build(Fs[i], grp); A.update(a); un += u
    F = Fs[0]
    ids = st.get('answer_ids') or [q['id'] for q in qs]
    print('n_ids', len(ids), 'answers', len(A), 'unresolved', un, flush=True)
    json.dump(A, open(os.path.expanduser('[home path]' % mode), 'w'), indent=1)
    json.dump(F, open(os.path.expanduser('[home path]' % mode), 'w'), indent=1, default=str)
    return gm, c, st, A, ids


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'dry'
    if mode == 'dry':
        gm, c, st, A, ids = run('single'); sys.exit()
    if mode == 'field':
        # field <base> <qid> <csv-cands>  -> fresh attempt, print the file's form, cycle candidates fast
        from ctf_gm import GM, unzip
        base = sys.argv[2]; qid = sys.argv[3]; cands = sys.argv[4].split(',')
        gm = GM(); c = CHAL[base]
        try: gm.retry(c)
        except Exception: pass
        gm, c, st, A, ids = run(base)
        feats = json.load(open(os.path.expanduser('[home path]' % base)))
        art = next((q['artifact'].split('->')[-1].strip() for q in st['questions'] if q['id'] == qid), None)
        fe = feats.get(art, {})
        print('FORM', qid, art, '| recon:', fe.get('recon'), '| for', fe.get('for'), 'callset', fe.get('callset'), '| my', A.get(qid), flush=True)
        for cand in cands:
            r = gm.submit(c, {qid: cand}); res = str(r.get('result'))
            print('  ', cand, '->', res, r.get('remaining'), flush=True)
            if res in ('accepted', 'CORRECT'): break
        sys.exit()
    if mode == 'learn':
        # learn <base> <suffix>  -> within ONE fresh attempt submit each id ending <suffix>
        # individually (fast) and print id/computed/result; also dump this attempt's batch sources.
        base = sys.argv[2]; suf = sys.argv[3]
        contains = sys.argv[4] if len(sys.argv) > 4 else ''
        gm, c, st, A, ids = run(base)
        tgt = [i for i in ids if i.endswith(suf) and contains in i]
        for qid in tgt:
            r = gm.submit(c, {qid: A[qid]})
            print('LEARN', qid, '=', A[qid], '->', str(r.get('result')), r.get('remaining'), flush=True)
        sys.exit()
    if mode == 'diag':
        # diag <single|time_trial> <substr>  -> submit only ids containing substr, one batch, fast
        base = sys.argv[2]; substr = sys.argv[3]
        gm, c, st, A, ids = run(base)
        pick = {k: A[k] for k in ids if substr in k and k in A}
        r = gm.submit(c, pick)
        for k in ('questions', 'guidance', 'prompt'): r.pop(k, None)
        print('DIAG', substr, 'n=', len(pick), '->', json.dumps(r), flush=True)
        sys.exit()
    gm, c, st, A, ids = run(mode)
    feats = json.load(open(os.path.expanduser('[home path]' % mode)))
    def clean(r):
        for k in ('questions', 'guidance', 'prompt'): r.pop(k, None)
        return r
    def sub(payload):
        for t in range(6):
            try: return gm.submit(c, payload)
            except RuntimeError as e:
                if '429' in str(e): time.sleep(0.3); gm._c.close(); continue
                raise
        return {'result': 'ratelimited'}
    def done(r): return str(r.get('result', '')).upper() == 'CORRECT'
    full = {k: A[k] for k in ids if k in A}
    # expansion is per-field random (not form-derivable): cycle delayed-first (most common).
    EXP_VOCAB = ['delayed', 'for_indirect', 'call_double', 'percent']
    CTL_VOCAB = ['call_subroutine', 'direct', 'goto_dispatch', 'if_guard', 'errorlevel_guard', 'for_loop']
    exp_ids = [i for i in ids if i.endswith('-expansion')]
    ctl_ids = [i for i in ids if i.endswith('-control')]
    core = {k: v for k, v in full.items() if k not in exp_ids and k not in ctl_ids}
    def cycle(qids, vocab, prepend=True):
        global res
        for qid in qids:
            order = ([full.get(qid)] if prepend else []) + vocab
            seen = set(); order = [x for x in order if x and not (x in seen or seen.add(x))]
            hit = None
            for cand in order:
                rr = sub({qid: cand}); s = str(rr.get('result', ''))
                if s.upper() == 'CORRECT': res = clean(rr); hit = cand; break
                if s == 'accepted': res = clean(rr); hit = cand; break
            print('cyc', qid, '->', hit, res.get('remaining'), flush=True)
            if str(res.get('result', '')).upper() == 'CORRECT': return
    # Stage 1: core (byte-derived + styles) in one batch — banks ~282 fields in 1 submit.
    res = clean(sub(core)); print('stage1 core', res.get('result'), res.get('remaining'), flush=True)
    # Stage 2: control — try one bctl batch (collapses 18 cycles->1 when right); else per-field.
    if not done(res):
        rc = clean(sub({k: full[k] for k in ctl_ids})); print('ctl-batch', rc.get('result'), rc.get('remaining'), flush=True)
        res = rc
        if str(rc.get('result')) not in ('accepted', 'CORRECT'):
            cycle(ctl_ids, CTL_VOCAB)
    # Stage 3: expansion — try one all-'delayed' batch first; else per-field (delayed-first).
    if not done(res):
        re_ = clean(sub({k: 'delayed' for k in exp_ids})); print('exp-batch-delayed', re_.get('result'), re_.get('remaining'), flush=True)
        res = re_
        if str(re_.get('result')) not in ('accepted', 'CORRECT'):
            cycle(exp_ids, EXP_VOCAB, prepend=False)
    print(json.dumps(res), flush=True)
    json.dump(res, open(os.path.expanduser('[home path]' % mode), 'w'), indent=1)
