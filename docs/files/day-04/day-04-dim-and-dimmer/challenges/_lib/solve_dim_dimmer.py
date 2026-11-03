#!/usr/bin/env python3
"""Dim and Dimmer (Huntress CTF 2026 Day 04) = Expansion Pack family + VBScript layer.
Static only. Reuses challenges/_lib/solve_script_inventory.py for PS1/JS/BAT; adds VBS.
usage (from framework root, WSL):  python3 solve_dim_dimmer.py dry|single|time_trial|mastery
"""
import sys, os, re, json, tempfile, time
ROOT = os.getcwd()
sys.path.insert(0, os.path.join(ROOT, 'challenges', '_lib'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import solve_script_inventory as S
from decode_vbs import decode as vbs_decode

CID = 'script-analysis-day-04-shell-contrast'
CHAL = {'single': CID, 'time_trial': CID + '/time_trial', 'mastery': CID + '/mastery'}
VBS_CTL_VOCAB = ['direct', 'select_case', 'do_loop', 'while_wend', 'if_then', 'for_loop']


def vbs_ctl(src):
    m = re.search(r'(?s)Function Recover_\w+\(\)(.*?)End Function', src)
    b = m.group(1)
    if re.search(r'(?im)^\s*On Error Resume Next', b): return 'error_guard'   # provisional label (lab-probed)
    if re.search(r'(?im)^\s*Select Case', b): return 'select_case'
    if re.search(r'(?im)^\s*While\b', b): return 'while_once'
    if re.search(r'(?im)^\s*Do\b', b): return 'do_once'
    if re.search(r'(?im)^\s*For\s+\w+\s*=\s*0\s+To\s+0\b', b): return 'for_once'  # provisional label
    return 'direct'


def analyze(d):
    F = S.analyze(d)
    for f in sorted(os.listdir(d)):
        if f.endswith('.vbs'):
            p = os.path.join(d, f); t = open(p, encoding='utf-8', errors='replace').read()
            fmt, tr, txt = vbs_decode(p)
            F[f] = {'lang': 'vbs', 'kv': S.kv_of(txt), 'rep': fmt, 'tr': tr, 'ctl': vbs_ctl(t)}
    return F


def build_vbs(F, questions):
    A, un = {}, []
    for q in questions:
        rawid = q['id']; qid = re.sub(r'^set\d+\.', '', rawid)
        art = q['artifact'].split('->')[-1].strip(); fe = F.get(art); val = None
        try:
            b = fe['kv']; field = qid.split('-', 2)[2]
            role = S.ROLE_BY_STEPS[b['steps']]
            if field == 'role': val = role
            elif field == 'attack': val = S.ATT.get(role) or 'T1059.005'
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
        except Exception as e:
            print('ERR', qid, repr(e), file=sys.stderr)
        if val is None: un.append(rawid)
        else: A[rawid] = val
    return A, un


def build(F, qs):
    v = [q for q in qs if re.sub(r'^set\d+\.', '', q['id']).startswith('vbscript-')]
    o = [q for q in qs if q not in v]
    A, un = S.build(F, o); A2, un2 = build_vbs(F, v); A.update(A2)
    return A, un + un2


def load_local():
    d = os.path.join(ROOT, 'challenges', 'Day 04', 'Dim and Dimmer', 'extracted')
    t = json.load(open(os.path.join(ROOT, 'challenges', 'Day 04', '_stage', 'Dim_and_Dimmer', 'task.json'), encoding='utf-8'))
    return analyze(d), t['questions']


if __name__ == '__main__' and sys.argv[1:] == ['local']:
    F, qs = load_local(); A, un = build(F, qs)
    print(len(A), 'unresolved', un)
    for k in ('vbscript-benign-representation', 'vbscript-benign-transform', 'vbscript-chain-control', 'vbscript-impact-extension'): print(k, A[k])
    json.dump(A, open('/tmp/dd_local.json', 'w'), indent=1)
