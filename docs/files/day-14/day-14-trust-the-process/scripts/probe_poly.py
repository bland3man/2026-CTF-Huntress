import sys, json, os, re
sys.path.insert(0, 'challenges/_lib')
import solve_poly_d8 as P

d = 'challenges/Day 14/Trust the Process/extracted'
for f in sorted(os.listdir(d)):
    if f.endswith('.proj'):
        s = open(os.path.join(d, f), encoding='utf-8', errors='replace').read()
        m = P.MARK.search(s)
        print('--', f)
        print('   kind=', m.group(1), 'payload tail=', repr(m.group(2)[-24:]))
        try:
            k, v = P.desc_of(os.path.join(d, f))
            print('   desc_of ->', k, (list(v.items())[:2] if v else v))
        except Exception as e:
            print('   desc_of RAISED:', type(e).__name__, e)
