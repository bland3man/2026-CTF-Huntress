import sys, re, json, importlib.util, os
sys.path.insert(0, 'challenges/_lib')
import solve_poly_d8 as P
import ctf_gm

src = open('challenges/_lib/autosolve_script.py', encoding='utf-8').read()
orig = re.sub(r"re\.match\(r'\^v=\\d\+\\\|', (\w+)\)", r"\1.startswith('v=1|')", src)
assert orig != src, 'revert regex did not apply'
tmp = '/tmp/autosolve_script_orig.py'
open(tmp, 'w', encoding='utf-8').write(orig)

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

st = ctf_gm.GM().status('script-analysis-day-25-phoenix-stage-chain/time_trial')
blobs = [open('/tmp/tt_evidence.zip', 'rb').read()]
res = {}
for name, path in (('orig', tmp), ('new', 'challenges/_lib/autosolve_script.py')):
    sys.modules.pop('autosolve_script', None)
    m = load(path, 'autosolve_script')
    sys.modules['autosolve_script'] = m
    P.set_strict_for_mode('time_trial')
    A, un, bad, cand = m.solve_fields_ext(st, blobs)
    res[name] = A
    print(name, 'resolved', len(A), 'unresolved', len(un))
o, n = res['orig'], res['new']
diff = [k for k in n if k in o and o[k] != n[k]]
print('changed values:', len(diff))
for k in diff:
    print('  CHANGED', k, repr(o[k]), '->', repr(n[k]))
print('newly resolved:', [k for k in n if k not in o])
json.dump(n, open('/tmp/tt_answers_new.json', 'w'), indent=1)
