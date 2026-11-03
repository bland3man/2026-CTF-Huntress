import sys, re, urllib.parse
sys.path.insert(0, "challenges/_lib")
from ctf_gm import GM, solve_mode

def compute(st, blobs):
    txt = blobs[0].decode("latin1") if isinstance(blobs[0], bytes) else blobs[0]
    for _ in range(5):
        d = urllib.parse.unquote(txt)
        if d == txt: break
        txt = d
    lines = [l for l in txt.splitlines() if l.strip()]
    m = re.findall(r"[a-z]+-[a-z]+-[a-z]+-\d{2}", lines[-1])
    print("decoded last line:", lines[-1])
    ids = st.get("answer_ids") or ["1"]
    return {str(ids[0]) if not isinstance(ids[0], dict) else ids[0]["id"]: m[-1]}

gm = GM()
res = solve_mode(gm, "warmups-day-07", compute)
print({k: v for k, v in res.items() if k in ("result", "flag", "remaining")})
