#!/usr/bin/env python3
"""Shell We Begin (Huntress CTF 2026 Day 06) unified static solver.
script_inventory family + VBS (Day04) + Python carriers (Day05) + NEW Bash layer.
Languages: ps1, js, cmd/bat, vbs, py, sh (sh decoded statically by decode_sh.py, never executed).

usage (from framework root, WSL):
  python3 solve_shell.py local                 # offline coverage vs staged task.json (no GM)
  python3 solve_shell.py dry                    # start single, compute, print, NO submit
  python3 solve_shell.py single|time_trial|mastery
  python3 solve_shell.py probe <mode> <substr>  # per-field submit for ids containing substr
"""
import sys, os, re, json, base64, subprocess, tempfile, time
ROOT = os.getcwd()
LIB = os.path.join(ROOT, 'challenges', '_lib')
sys.path.insert(0, LIB)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import solve_script_inventory as S
from decode_vbs import decode as vbs_decode
from decode_sh import decode_file as sh_decode

CID = 'script-analysis-day-06-bash-behavior-graphs'
CHAL = {'single': CID, 'time_trial': CID + '/time_trial', 'mastery': CID + '/mastery'}

STAGE = os.path.join(ROOT, 'challenges', 'Day 06', '_stage', 'Shell_We_Begin')
WORKDIR = os.path.join(STAGE, 'extracted')
OUTDIR = os.path.dirname(os.path.abspath(__file__))

# --- role by step signature (extends S.ROLE_BY_STEPS with py/relay signatures) ---
ROLE_BY_STEPS = dict(S.ROLE_BY_STEPS)
ROLE_BY_STEPS.update({
    'select_fixture_files,transform_copy,write_recovery_note': 'impact',
    'collect_local,encode_archive,transmit_remote': 'uploader',
    'decode_configuration,locate_interpreter,dispatch_next_stage': 'relay',
    'profile_host,acquire_remote,decode_embedded,write_file,dispatch_process': 'staged_chain',
})
# bash role by step signature (Day06). Unknown signatures fall back to heuristics in sh_role().
SH_ROLE = {
    'decode_configuration,return_configuration': 'benign_utility',
    'acquire_remote,dispatch_pipe': 'stager',
    'acquire_remote,dispatch_memory': 'stager',
    'decode_embedded,write_file': 'dropper',
    'acquire_remote,write_file': 'downloader',
    'locate_local,dispatch_process': 'launcher',
    'profile_host,acquire_remote,write_file,change_mode,dispatch_process': 'staged_chain',  # single-solve accepted
}
SH_ATT = {'benign_utility': 'none', 'stager': 'T1105', 'dropper': 'T1140',
          'downloader': 'T1105', 'launcher': 'T1059.004', 'staged_chain': 'T1059.004'}


def sh_role(steps):
    if steps in SH_ROLE:
        return SH_ROLE[steps]
    if steps in ROLE_BY_STEPS:
        return ROLE_BY_STEPS[steps]
    # heuristic fallback for unseen signatures (flagged on stderr; never raises)
    st = steps.split(',')
    if len(st) >= 3:
        r = 'staged_chain'
    elif 'return_configuration' in st or st[0] == 'decode_configuration':
        r = 'benign_utility'
    elif 'decode_embedded' in st:
        r = 'dropper'
    elif 'acquire_remote' in st and 'write_file' in st:
        r = 'downloader'
    elif 'acquire_remote' in st:
        r = 'stager'
    elif any(s.startswith('dispatch') for s in st):
        r = 'launcher'
    else:
        r = 'staged_chain'
    print('WARN unseen sh steps %s -> heuristic role %s' % (steps, r), file=sys.stderr)
    return r
# js/bat/vbs: relay file uses the 4-step chain graph -> staged_chain (their enum has no 'relay').

# attack by role. launcher/staged_chain/relay fall through to language technique.
ATT = dict(S.ATT)  # benign_utility:none, stager:T1105, dropper:T1140, downloader:T1105, uploader:T1041, impact:T1486
ATT_LANG = {'js': 'T1059.007', 'bat': 'T1059.003', 'vbs': 'T1059.005', 'py': 'T1059.006'}


def kv_of(s):
    return dict(x.split('=', 1) for x in s.split('|') if '=' in x)


# ---- Python carrier extractor (safe static eval of pure functions) ----
import decode_bash as DB  # static engine (no fixture execution)


def py_extract(path):
    """Static: ast.literal_eval of MATERIAL_/CODEC_ + codec reproduction (no exec)."""
    return DB.decode_py(path)['kv']


def js_static(d, files):
    """Static JScript config recovery; node (sinks stubbed) only as a per-file fallback."""
    out, miss = {}, []
    for f in files:
        try:
            out[f] = DB.decode_js(os.path.join(d, f))['cfg']
        except Exception:
            miss.append(f)
    if miss:
        print('WARN js static decode failed, node fallback for', miss, file=sys.stderr)
        nj = json.loads(subprocess.check_output(['node', '-e', S.JSDEC, d], text=True))
        for f in miss:
            out[f] = nj.get(f, 'ERR missing')
    return out


def analyze(d, artifact_set):
    """Process only files that are question artifacts. Returns {filename: feature dict}."""
    F = {}
    jsfiles = [f for f in artifact_set if f.endswith('.js')]
    js = {}
    if jsfiles:
        js = js_static(d, [f for f in jsfiles if os.path.exists(os.path.join(d, f))])
    for f in sorted(artifact_set):
        p = os.path.join(d, f)
        if not os.path.exists(p):
            continue
        t = open(p, encoding='utf-8', errors='replace').read()
        if f.endswith('.ps1'):
            m = re.search(r"FromBase64String\('([^']+)'\)", t)
            if not m:
                continue
            F[f] = {'lang': 'ps1', 'obj': json.loads(base64.b64decode(m.group(1)))}
        elif f.endswith('.js'):
            c = js[f]
            if isinstance(c, str):
                raise RuntimeError(f + ' ' + c)
            F[f] = {'lang': 'js', 'cfg': c, 'steps': ','.join(c['steps']), 'style': S.jsstyle(t)}
        elif f.endswith(('.cmd', '.bat')):
            mat = re.search(r'MATERIAL:(\S+)', t)
            a = S.decode_material(mat.group(1)) if mat else None
            b = S.decode_frags(t)
            s = b if (b and b.startswith('v=1|')) else a
            F[f] = {'lang': 'bat', 'kv': kv_of(s), 'ctl': S.bctl(t), 'exp': S.expform(S.region(t))}
        elif f.endswith('.vbs'):
            fmt, tr, txt = vbs_decode(p)
            from solve_dim_dimmer import vbs_ctl
            F[f] = {'lang': 'vbs', 'kv': kv_of(txt), 'rep': fmt, 'tr': tr, 'ctl': vbs_ctl(t)}
        elif f.endswith('.py'):
            F[f] = {'lang': 'py', 'kv': py_extract(p)}
        elif f.endswith('.sh'):
            F[f] = {'lang': 'sh', 'kv': kv_of(sh_decode(p)[2].strip())}
    return F


PY_FIELDS = ['windows-chain', 'host-id', 'file-path', 'upload-url', 'next-stage',
             'handoff-id', 'extension', 'obfuscation', 'carrier', 'syntax',
             'adapter', 'campaign', 'attack', 'role', 'url']
PY_KEY = {'host-id': 'host_id', 'file-path': 'file_path', 'upload-url': 'upload_url',
          'next-stage': 'next_stage', 'handoff-id': 'handoff_id', 'extension': 'extension',
          'windows-chain': 'windows_chain', 'obfuscation': 'obfuscation', 'carrier': 'carrier',
          'syntax': 'syntax', 'adapter': 'adapter', 'campaign': 'campaign_id', 'url': 'url'}


def py_field(idstr):
    for fld in PY_FIELDS:  # longest-first already ordered to avoid url<upload-url clash
        if idstr.endswith('-' + fld):
            return fld
    return None


def build(F, questions):
    A, un = {}, []
    for q in questions:
        rawid = q['id']
        rid = re.sub(r'^set\d+\.', '', rawid)  # mastery may prefix ids with setN.
        art = q['artifact'].split('->')[-1].strip()
        fe = F.get(art)
        val = None
        try:
            if fe is None:
                raise KeyError('no file ' + art)
            L = fe['lang']
            if L == 'ps1':
                o = fe['obj']; pre = rid.split('-')[0]; rest = rid.split('-', 1)[1]
                if rest == 'scenario':
                    val = {'resource': 'resource_hijacking', 'collection': 'synthetic_collection', 'impact': 'synthetic_impact'}[pre]
                elif rest == 'attack':
                    val = {'resource': 'T1496', 'collection': 'T1555.003', 'impact': 'T1486'}[pre]
                elif pre == 'resource':
                    val = {'url': o['b'], 'wallet': o['c'], 'mutex': o['h']}[rest]
                elif pre == 'collection':
                    val = {'url': o['b'], 'file': o['c'][0] if isinstance(o['c'], list) else o['c'], 'user-agent': o['f']}[rest]
                elif pre == 'impact':
                    val = {'extension': o['b'], 'note': o['c'], 'url': o['d']}[rest]
            elif L == 'js':
                c = fe['cfg']; v = c['values']; field = rid.split('-', 2)[2]
                role = sh_role(fe['steps'])
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
            elif L == 'bat':
                b = fe['kv']; field = rid.split('-', 2)[2]
                role = sh_role(b['steps'])
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
                elif field == 'expansion': val = fe.get('exp') or 'delayed'
                elif field == 'control': val = fe['ctl']
                elif field == 'graph': val = b['graph']
            elif L == 'vbs':
                b = fe['kv']; field = rid.split('-', 2)[2]
                role = sh_role(b['steps'])
                if field == 'role': val = role
                elif field == 'attack': val = ATT.get(role) or ATT_LANG['vbs']
                elif field == 'adapter': val = b['adapter']
                elif field == 'campaign': val = b['campaign_id']
                elif field == 'host-id': val = b['host_id']
                elif field == 'url': val = b['url']
                elif field == 'upload-url': val = b['upload_url']
                elif field == 'file-path': val = b['file_path']
                elif field == 'extension': val = b['extension']
                elif field == 'next-stage': val = b['next_stage']
                elif field == 'representation': val = fe['rep']
                elif field == 'transform': val = fe['tr']
                elif field == 'control': val = fe['ctl']
            elif L == 'py':
                b = fe['kv']; field = py_field(rid)
                role = sh_role(b['steps'])
                if field == 'role': val = role
                elif field == 'attack': val = ATT.get(role) or ATT_LANG['py']
                elif field in PY_KEY: val = b[PY_KEY[field]]
            elif L == 'sh':
                b = fe['kv']; field = rid.split('-', 2)[2]
                role = sh_role(b['steps'])
                if field == 'role': val = role
                elif field == 'attack': val = SH_ATT[role]
                elif field == 'adapter': val = b['adapter']
                elif field == 'campaign': val = b['campaign_id']
                elif field == 'stage-count': val = str(int(b['stage_count']))
                elif field == 'steps': val = '>'.join(b['steps'].split(','))
                else: val = b[field.replace('-', '_')]  # host-id/url/file-path/cron-path/...
        except Exception as e:
            print('ERR', rid, repr(e), file=sys.stderr)
        if val is None:
            un.append(rawid)
        else:
            A[rawid] = val
    return A, un


def load_questions():
    t = json.load(open(os.path.join(STAGE, 'task.json'), encoding='utf-8'))
    return t['questions']


def artifact_set(questions):
    return sorted({q['artifact'].split('->')[-1].strip() for q in questions})


# ---------------- GM paths ----------------
def run_gm(mode):
    from ctf_gm import GM, unzip
    gm = GM(); c = CHAL[mode]
    st = gm.start(c)
    print('attempt', st.get('attempt_id'), st.get('mode'), 'deadline', st.get('deadline'), flush=True)
    blobs = [gm.download(c, e, i) for i, e in enumerate(gm.artifacts(st))]
    qs = st['questions']
    sets = sorted({(re.match(r'^(set\d+)\.', q['id']).group(1) if re.match(r'^set\d+\.', q['id']) else '') for q in qs})
    A, un = {}, []
    while len(blobs) < len(sets):  # mastery: one start download, further deliveries via op=artifact&delivery=i
        blobs.append(gm.download(c, '', len(blobs)))
    for i, sp in enumerate(sets):
        d = tempfile.mkdtemp(prefix='shell_')
        for n, data in unzip(blobs[min(i, len(blobs) - 1)]):
            bn = os.path.basename(n); assert bn and '..' not in n
            open(os.path.join(d, bn), 'wb').write(data)
        grp = [q for q in qs if (q['id'].startswith(sp + '.') if sp else True)]
        F = analyze(d, artifact_set(grp))
        a, u = build(F, grp); A.update(a); un += u
    ids = st.get('answer_ids') or [q['id'] for q in qs]
    print('n_ids', len(ids), 'answers', len(A), 'unresolved', len(un), un[:20], flush=True)
    json.dump(A, open(os.path.expanduser('[home path]' % mode.replace('/', '_')), 'w'), indent=1)
    return gm, c, st, A, ids


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'local'
    if mode == 'local':
        qs = load_questions()
        F = analyze(WORKDIR, artifact_set(qs))
        A, un = build(F, qs)
        print('questions', len(qs), 'answers', len(A), 'unresolved', len(un))
        if un:
            print('UNRESOLVED', un)
        json.dump(A, open(os.path.join(OUTDIR, 'local_answers.json'), 'w'), indent=1)
        return
    if mode == 'dry':
        run_gm('single'); return
    if mode == 'probe':
        base, substr = sys.argv[2], sys.argv[3]
        gm, c, st, A, ids = run_gm(base)
        def sub(p):
            for _ in range(6):
                try: return gm.submit(c, p)
                except RuntimeError as e:
                    if '429' in str(e): time.sleep(0.4); continue
                    raise
            return {'result': 'ratelimited'}
        for qid in [i for i in ids if substr in i and i in A]:
            r = sub({qid: A[qid]})
            for k in ('questions', 'guidance', 'prompt'): r.pop(k, None)
            print('PROBE', qid, '=', A[qid], '->', str(r.get('result')), r.get('remaining'), flush=True)
        return
    # full submit for a mode
    gm, c, st, A, ids = run_gm(mode)
    def clean(r):
        for k in ('questions', 'guidance', 'prompt'): r.pop(k, None)
        return r
    def sub(p):
        for _ in range(6):
            try: return gm.submit(c, p)
            except RuntimeError as e:
                if '429' in str(e): time.sleep(0.4); continue
                raise
        return {'result': 'ratelimited'}
    full = {k: A[k] for k in ids if k in A}
    if len(full) < len(ids):
        print('ABORT: incomplete coverage %d/%d - not submitting' % (len(full), len(ids)), flush=True)
        return
    r = clean(sub(full))
    print('BATCH', r.get('result'), r.get('remaining'), flush=True)
    print(json.dumps(r)[:1500], flush=True)
    json.dump(r, open(os.path.expanduser('[home path]' % mode.replace('/', '_')), 'w'), indent=1)


if __name__ == '__main__':
    main()
