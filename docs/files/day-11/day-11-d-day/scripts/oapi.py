import sys, json
sys.path.insert(0, 'challenges/_lib')
from ctf_gm import GM
gm = GM()
o = gm.openapi()
s = json.dumps(o, indent=1)
print("LEN", len(s))
import re
for kw in ("practice", "retry_variants", "unique_attempts", "run_for_time", "hall_of_fame"):
    print("=== " + kw)
    for m in re.finditer(kw, s):
        a = max(0, m.start()-400); b = min(len(s), m.end()+400)
        print(s[a:b].replace("\n", " "))
        print("---")
        break
