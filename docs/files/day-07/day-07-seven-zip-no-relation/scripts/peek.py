import sys, json
sys.path.insert(0, '[local path]')
from ctf_gm import GM
gm = GM()
st = gm._post(op='start', challenge='metadata-forensics-day-07-seven-zip-no-relation')
def short(o):
    if isinstance(o, dict): return {k: short(v) for k, v in o.items()}
    if isinstance(o, list): return [short(v) for v in o[:5]]
    if isinstance(o, str): return o[:120]
    return o
print(json.dumps(short(st), indent=1)[:3000])
