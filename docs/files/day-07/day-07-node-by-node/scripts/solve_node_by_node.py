#!/usr/bin/env python3
"""Node by Node (Huntress CTF 2026 Day 07) unified static solver.
script_inventory family + VBS (Day04) + Python carriers (Day05) + Bash (Day06) + NEW Node.js (.mjs) layer
and NEW advanced-bash syntax fixtures (feature/primitive) + NEW roles persistence_descriptor / advanced_syntax
and relay now a distinct enum value.
Languages: ps1, js, cmd/bat, vbs, py, sh, mjs. Nothing is ever executed (static decode only).

usage (from framework root, WSL):
  python3 solve_node_by_node.py local                 # offline coverage vs staged task.json (no GM)
  python3 solve_node_by_node.py dry                    # start single, compute, print, NO submit
  python3 solve_node_by_node.py single|time_trial|mastery
  python3 solve_node_by_node.py probe <mode> <substr>  # per-field submit for ids containing substr
"""
import sys, os, re, json, base64, tempfile, time
ROOT = os.getcwd()
LIB = os.path.join(ROOT, 'challenges', '_lib')
sys.path.insert(0, LIB)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import solve_script_inventory as S
import decode_bash as DB
import decode_node as DN
from decode_vbs import decode as vbs_decode
from solve_dim_dimmer import vbs_ctl

CID = 'script-analysis-day-07-node-operation-graphs'
CHAL = {'single': CID, 'time_trial': CID + '/time_trial', 'mastery': CID + '/mastery'}
STAGE = os.path.join(ROOT, 'challenges', 'Day 07', '_stage', 'Node_by_Node')
WORKDIR = os.path.join(ROOT, 'challenges', 'Day 07', 'Node by Node', 'extract')
OUTDIR = os.path.dirname(os.path.abspath(__file__))

# ---- role from step signature (behavioral). The 4-step chain graph collides between the
# relay-handoff.* (role 'relay') and staged-handoff.* (role 'staged_chain') files, so that one
# signature is disambiguated by the question-id prefix word. ----
STEP_ROLE = {
    'decode_configuration,return_configuration': 'benign_utility',
    'acquire_remote,dispatch_memory': 'stager',
    'acquire_remote,dispatch_pipe': 'stager',
    'decode_embedded,write_file': 'dropper',
    'acquire_remote,write_file': 'downloader',
    'locate_local,dispatch_process': 'launcher',
    'read_file,transmit_remote': 'uploader',
    'locate_local,prepare_transfer,upload_remote': 'uploader',
    'collect_local,encode_archive,transmit_remote': 'uploader',
    'enumerate_targets,transform_content,write_recovery_note': 'impact',
    'select_fixture_files,transform_copy,write_recovery_note': 'impact',
    'decode_configuration,locate_interpreter,dispatch_next_stage': 'relay',
    'build_schedule,register_descriptor': 'persistence_descriptor',
    'profile_host,acquire_remote,write_file,change_mode,dispatch_process': 'staged_chain',
    'profile_host,acquire_remote,decode_embedded,write_file,dispatch_process': 'staged_chain',
    'recognize_syntax,reconstruct_intent': 'advanced_syntax',
}
PREFIX_ROLE = {'benign': 'benign_utility', 'stager': 'stager', 'dropper': 'dropper',
               'downloader': 'downloader', 'uploader': 'uploader', 'launcher': 'launcher',
               'impact': 'impact', 'relay': 'relay', 'chain': 'staged_chain',
               'persistence': 'persistence_descriptor', 'advanced': 'advanced_syntax'}
COLLIDE = 'acquire_remote,write_file,dispatch_process,handoff_script'


def role_of(steps, prefix_word):
    if steps == COLLIDE:
        # relay-handoff.* AND staged-handoff.* share this 4-step graph; BOTH grade as staged_chain
        # (GM-confirmed Single Solve 2026-10-07). The 'relay' enum is reserved for the 3-step
        # decode_configuration,locate_interpreter,dispatch_next_stage signature (python relay carriers).
        return 'staged_chain'
    r = STEP_ROLE.get(steps)
    if r:
        return r
    return PREFIX_ROLE.get(prefix_word)


ATT_ROLE = {'benign_utility': 'none', 'stager': 'T1105', 'dropper': 'T1140',
            'downloader': 'T1105', 'uploader': 'T1041', 'impact': 'T1486'}
ATT_LANG = {'js': 'T1059.007', 'bat': 'T1059.003', 'cmd': 'T1059.003', 'vbs': 'T1059.005',
            'py': 'T1059.006', 'sh': 'T1059.004', 'mjs': 'T1059.007'}


def attack_of(role, lang):
    if role == 'persistence_descriptor':
        return 'T1053.003'          # /etc/cron.d schedule path -> Scheduled Task/Job: Cron (lab-verify)
    if role in ATT_ROLE:
        return ATT_ROLE[role]
    return ATT_LANG[lang]           # launcher / relay / staged_chain / advanced_syntax -> interpreter


# ---- Python carrier field mapping (Day05/06) ----
PY_FIELDS = ['windows-chain', 'host-id', 'file-path', 'upload-url', 'next-stage',
             'handoff-id', 'extension', 'obfuscation', 'carrier', 'syntax',
             'adapter', 'campaign', 'attack', 'role', 'url']
PY_KEY = {'host-id': 'host_id', 'file-path': 'file_path', 'upload-url': 'upload_url',
          'next-stage': 'next_stage', 'handoff-id': 'handoff_id', 'extension': 'extension',
          'windows-chain': 'windows_chain', 'obfuscation': 'obfuscation', 'carrier': 'carrier',
          'syntax': 'syntax', 'adapter': 'adapter', 'campaign': 'campaign_id', 'url': 'url'}


def py_field(idstr):
    for fld in PY_FIELDS:
        if idstr.endswith('-' + fld):
            return fld
    return None


def kv(s):
    return DB.kv_of(s)


def analyze(d, artifact_set):
    F = {}
    for f in sorted(artifact_set):
        p = os.path.join(d, f)
        if not os.path.exists(p):
            continue
        t = open(p, encoding='utf-8', errors='replace').read()
        try:
            if f.endswith('.ps1'):
                m = re.search(r"FromBase64String\('([^']+)'\)", t)
                if not m:
                    continue
                F[f] = {'lang': 'ps1', 'obj': json.loads(base64.b64decode(m.group(1)))}
            elif f.endswith('.js'):
                c = DB.decode_js(p)['cfg']
                F[f] = {'lang': 'js', 'cfg': c, 'steps': ','.join(c['steps']), 'style': S.jsstyle(t)}
            elif f.endswith(('.cmd', '.bat')):
                mat = re.search(r'MATERIAL:(\S+)', t)
                a = S.decode_material(mat.group(1)) if mat else None
                b = S.decode_frags(t)
                s = b if (b and b.startswith('v=1|')) else a
                F[f] = {'lang': 'bat', 'kv': kv(s), 'ctl': S.bctl(t), 'exp': S.expform(S.region(t))}
            elif f.endswith('.vbs'):
                fmt, tr, txt = vbs_decode(p)
                F[f] = {'lang': 'vbs', 'kv': kv(txt), 'rep': fmt, 'tr': tr, 'ctl': vbs_ctl(t)}
            elif f.endswith('.py'):
                F[f] = {'lang': 'py', 'kv': DB.decode_py(p)['kv']}
            elif f.endswith('.sh'):
                try:
                    text = DB.decode_bash(p)['text']
                except Exception:
                    matv, codec = DB.bash_material(t)
                    lenient = lambda b: DB._printable(b) and bytes(b).decode('latin-1').startswith('v=1|')
                    text, _ = DN.robust_decode(matv, codec, valid=lenient)
                F[f] = {'lang': 'sh', 'kv': kv(text)}
            elif f.endswith('.mjs'):
                F[f] = {'lang': 'mjs', 'kv': DN.decode_node(p)['kv']}
        except Exception as e:
            print('DECODE-ERR', f, repr(e), file=sys.stderr)
    return F


def build(F, questions):
    A, un = {}, []
    for q in questions:
        rawid = q['id']
        rid = re.sub(r'^set\d+\.', '', rawid)
        art = q['artifact'].split('->')[-1].strip()
        fe = F.get(art)
        val = None
        try:
            if fe is None:
                raise KeyError('no file ' + art)
            L = fe['lang']
            parts = rid.split('-')
            if L == 'ps1':
                o = fe['obj']; pre = parts[0]; rest = rid.split('-', 1)[1]
                if rest == 'scenario':
                    val = {'resource': 'resource_hijacking', 'collection': 'synthetic_collection',
                           'impact': 'synthetic_impact'}[pre]
                elif rest == 'attack':
                    val = {'resource': 'T1496', 'collection': 'T1555.003', 'impact': 'T1486'}[pre]
                elif pre == 'resource':
                    val = {'url': o['b'], 'wallet': o['c'], 'mutex': o['h']}[rest]
                elif pre == 'collection':
                    val = {'url': o['b'], 'file': o['c'][0] if isinstance(o['c'], list) else o['c'],
                           'user-agent': o['f']}[rest]
                elif pre == 'impact':
                    val = {'extension': o['b'], 'note': o['c'], 'url': o['d']}[rest]
            elif L == 'js':
                c = fe['cfg']; v = c['values']; field = rid.split('-', 2)[2]
                role = role_of(fe['steps'], parts[1])
                if field == 'role': val = role
                elif field == 'attack': val = attack_of(role, 'js')
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
                role = role_of(b['steps'], parts[1])
                if field == 'role': val = role
                elif field == 'attack': val = attack_of(role, 'bat')
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
                role = role_of(b['steps'], parts[1])
                if field == 'role': val = role
                elif field == 'attack': val = attack_of(role, 'vbs')
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
                role = role_of(b['steps'], None)
                if field == 'role': val = role
                elif field == 'attack': val = attack_of(role, 'py')
                elif field in PY_KEY: val = b[PY_KEY[field]]
            elif L == 'sh':
                b = fe['kv']; field = rid.split('-', 2)[2]
                # bash-advanced-<indirect|tokens>-<field>: parts = [bash, advanced, indirect, field...]
                if parts[1] == 'advanced':
                    field = '-'.join(parts[3:])
                    role = 'advanced_syntax'
                    if field == 'role': val = role
                    elif field == 'attack': val = ATT_LANG['sh']
                    elif field == 'feature': val = b['feature']
                    elif field == 'primitive': val = b['primitive']
                    elif field == 'campaign': val = b['campaign_id']
                    elif field == 'stage-count': val = str(int(b['stage_count']))
                    elif field == 'steps': val = '>'.join(b['steps'].split(','))
                else:
                    role = role_of(b['steps'], parts[1])
                    if field == 'role': val = role
                    elif field == 'attack': val = attack_of(role, 'sh')
                    elif field == 'adapter': val = b['adapter']
                    elif field == 'campaign': val = b['campaign_id']
                    elif field == 'stage-count': val = str(int(b['stage_count']))
                    elif field == 'steps': val = '>'.join(b['steps'].split(','))
                    else: val = b[field.replace('-', '_')]
            elif L == 'mjs':
                b = fe['kv']; field = rid.split('-', 2)[2]
                role = role_of(b['steps'], parts[1])
                if field == 'role': val = role
                elif field == 'attack': val = attack_of(role, 'mjs')
                elif field == 'adapter': val = b['adapter']
                elif field == 'campaign': val = b['campaign_id']
                elif field == 'stage-count': val = str(int(b['stage_count']))
                elif field == 'steps': val = '>'.join(b['steps'].split(','))
                elif field == 'host-id': val = b['host_id']
                elif field == 'file-path': val = b['file_path']
                elif field == 'url': val = b['url']
                elif field == 'schedule-path': val = b['schedule_path']
                elif field == 'service-name': val = b['service_name']
        except Exception as e:
            print('ERR', rid, repr(e), file=sys.stderr)
        if val is None:
            un.append(rawid)
        else:
            A[rawid] = val
    return A, un


def load_questions():
    return json.load(open(os.path.join(STAGE, 'task.json'), encoding='utf-8'))['questions']


def artifact_set(questions):
    return sorted({q['artifact'].split('->')[-1].strip() for q in questions})


def run_gm(mode):
    from ctf_gm import GM, unzip
    gm = GM(); c = CHAL[mode]
    st = gm.start(c)
    print('attempt', st.get('attempt_id'), st.get('mode'), 'deadline', st.get('deadline'), flush=True)
    blobs = [gm.download(c, e, i) for i, e in enumerate(gm.artifacts(st))]
    qs = st['questions']
    sets = sorted({(re.match(r'^(set\d+)\.', q['id']).group(1) if re.match(r'^set\d+\.', q['id']) else '')
                   for q in qs})
    # Resolve each set to its fixture zip. Mastery delivers ONE outer zip whose members are the inner
    # AES zips evidence-01.zip / evidence-02.zip (one per set); single/time_trial deliver the 61 fixture
    # files directly. Detect nesting by whether a blob's members are themselves .zip archives.
    set_blobs = []
    for blob in blobs:
        try:
            members = unzip(blob)
        except Exception:
            set_blobs.append(blob); continue
        inner = sorted((n, data) for n, data in members if n.lower().endswith('.zip'))
        if inner:
            set_blobs.extend(data for _, data in inner)
        else:
            set_blobs.append(blob)
    while len(set_blobs) < len(sets):
        set_blobs.append(gm.download(c, '', len(set_blobs)))
    A, un = {}, []
    for i, sp in enumerate(sets):
        d = tempfile.mkdtemp(prefix='node_')
        for n, data in unzip(set_blobs[min(i, len(set_blobs) - 1)]):
            bn = os.path.basename(n); assert bn and '..' not in n
            open(os.path.join(d, bn), 'wb').write(data)
        grp = [q for q in qs if (q['id'].startswith(sp + '.') if sp else True)]
        F = analyze(d, artifact_set(grp))
        a, u = build(F, grp); A.update(a); un += u
    ids = st.get('answer_ids') or [q['id'] for q in qs]
    print('n_ids', len(ids), 'answers', len(A), 'unresolved', len(un), un[:30], flush=True)
    json.dump(A, open(os.path.expanduser('[home path]' % mode.replace('/', '_')), 'w'), indent=1)
    return gm, c, st, A, ids


def _clean(r):
    for k in ('questions', 'guidance', 'prompt'):
        r.pop(k, None)
    return r


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
            for _ in range(8):
                try:
                    return gm.submit(c, p)
                except RuntimeError as e:
                    if '429' in str(e):
                        time.sleep(0.5); continue
                    raise
            return {'result': 'ratelimited'}
        for qid in [i for i in ids if substr in i and i in A]:
            r = _clean(sub({qid: A[qid]}))
            print('PROBE', qid, '=', A[qid], '->', str(r.get('result')), r.get('remaining'), flush=True)
        return
    gm, c, st, A, ids = run_gm(mode)

    def sub(p):
        for _ in range(8):
            try:
                return gm.submit(c, p)
            except RuntimeError as e:
                if '429' in str(e):
                    time.sleep(0.5); continue
                raise
        return {'result': 'ratelimited'}
    full = {k: A[k] for k in ids if k in A}
    if len(full) < len(ids):
        print('ABORT incomplete %d/%d' % (len(full), len(ids)),
              [i for i in ids if i not in full][:30], flush=True)
        return

    def done(r):
        return str(r.get('result', '')).upper() == 'CORRECT'

    # One-shot attempt 1: full batch (atomic; CORRECT iff every field right).
    r = _clean(sub(full))
    print('BATCH', r.get('result'), r.get('remaining'), flush=True)
    # Fallback within the SAME attempt: grouped submits bank cumulatively (accepted fields persist),
    # so a single wrong class never sinks the attempt. Confident byte-derived fields first, then each
    # model class; any class that is not wholly accepted drops to per-field so only true misses remain.
    if not done(r):
        MODEL = ('-role', '-attack', '-scenario', '-control', '-expansion')

        def is_model(i):
            return any(i.endswith(s) for s in MODEL)

        def grp(picklist):
            nonlocal r
            if not picklist:
                return
            rr = _clean(sub({k: A[k] for k in picklist}))
            if str(rr.get('result')) != 'accepted':
                for qid in picklist:
                    rr = _clean(sub({qid: A[qid]}))
                    if str(rr.get('result')) not in ('accepted', 'CORRECT'):
                        print('WRONG', qid, '=', A[qid], '->', rr.get('result'), flush=True)
                    if done(rr):
                        break
            r = rr
        grp([i for i in ids if not is_model(i)])
        for suf in ('-scenario', '-role', '-attack', '-control', '-expansion'):
            if done(r):
                break
            grp([i for i in ids if i.endswith(suf)])
        print('AFTER-FALLBACK', r.get('result'), r.get('remaining'), flush=True)
    print(json.dumps(r)[:600], flush=True)
    json.dump(r, open(os.path.expanduser('[home path]' % mode.replace('/', '_')), 'w'), indent=1)


if __name__ == '__main__':
    main()
