import sys, io, json, zipfile
sys.path.insert(0, "challenges/_lib")
from ctf_gm import GM, unzip, solve_mode

def puzzle(blob):
    def from_zip(b):
        z = zipfile.ZipFile(io.BytesIO(b))
        if "assets/huntress_puzzle.json" in z.namelist():
            return json.loads(z.read("assets/huntress_puzzle.json"))
        for n in z.namelist():
            if n.endswith(".apk"):
                return from_zip(z.read(n))
    try:
        return from_zip(blob)
    except Exception:
        for n, d in unzip(blob):
            try:
                p = from_zip(d) if n.endswith(".apk") else None
                if p: return p
            except Exception: pass
    raise ValueError("no puzzle")

def codec(p):
    c = p["codec"]; d = p.get("data", "")
    if c == "split":
        parts, order = p["parts"], p["order"]
        return "".join(parts[i] for i in sorted(range(len(parts)), key=lambda i: order[i]))
    if c == "reverse": return d[::-1]
    if c == "plain": return d
    if c == "base64":
        import base64; return base64.b64decode(d).decode()
    raise ValueError("codec " + c)

def compute(st, blobs):
    ids = st["answer_ids"]
    ans = [codec(puzzle(b)) for b in blobs]
    print("answers", len(ans), file=sys.stderr)
    return {aid: ans[i if len(ans) > 1 else 0] for i, aid in enumerate(ids)}

if __name__ == "__main__":
    print(str(solve_mode(GM(), sys.argv[1], compute))[:300])
