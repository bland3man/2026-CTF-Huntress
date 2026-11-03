import sys, re, json
sys.path.insert(0, "challenges/_lib")
from ctf_gm import GM, solve_mode

def peel(b):
    t = b.decode("latin1").strip()
    if re.fullmatch(r"[0-7 \r\n\t]+", t):
        return bytes(int(x, 8) for x in t.split())
    return None

def compute(start, blobs):
    data = blobs[0]
    for _ in range(10):
        n = peel(data)
        if n is None:
            break
        data = n
    text = data.decode("latin1")
    lines = [l for l in text.splitlines() if l.strip()]
    m = re.findall(r"[a-z]+-[a-z]+-[a-z]+-\d\d", lines[-1])
    return {aid: m[-1] for aid in start["answer_ids"]}

if __name__ == "__main__":
    res = solve_mode(GM(), "warmups-day-06", compute)
    print(json.dumps({k: res.get(k) for k in ("result", "remaining")}))
